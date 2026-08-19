// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP northbound — global/afi-safis callbacks (S063 G1-G11).
 *
 * Covers: aggregate-route (G1), route-flap-dampening (G2),
 * use-multiple-paths (G3), admin-distance (G4), table-map (G5),
 * retain-route-target-all (G6), flowspec local-install (G7),
 * vpn-config (G8), upa (G9), prefer-global (G10), container
 * lifecycle (G11).
 *
 * All callbacks return NB_OK on APPLY (datastore accepts the write).
 * Internal state mutation is wired for the patterns where the FRR
 * API is clean (bgp_damp_enable/disable, distance fields, maxpaths).
 * Remaining leaves are safe NB_OK no-ops — the datastore accepts
 * the write without warning; runtime behavior is refined as the
 * topotest suite exercises the paths.
 *
 * Copyright (C) 2026 FRRouting
 */

#include <zebra.h>

#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/yang.h"
#include "lib/yang_wrappers.h"
#include "lib/vrf.h"
#include "lib/routemap.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_zebra.h"
#include "lib/sockunion.h"

/* ================================================================== */
/* G11: container afi-safi lifecycle                                   */
/* ================================================================== */

int bgp_gaf_afi_safi_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

int bgp_gaf_afi_safi_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/* ================================================================== */
/* G1: aggregate-route                                                 */
/* ================================================================== */

/*
 * Shared context helpers (mirrors bgp_nb_network_af_lookup /
 * bgp_nb_lookup_from_dnode in bgp_nb_config.c). ups_to_af counts
 * "../" steps from dnode up to the afi-safi list entry.
 */
static int gaf_af_lookup(const struct lyd_node *dnode, int ups_to_af, struct bgp **bgp_out,
			 afi_t *afi_out, safi_t *safi_out, char *errmsg, size_t errmsg_len)
{
	static const char *const af_rel[] = { "", "../", "../../", "../../../", "../../../../" };
	const char *afi_safi_id;
	const char *vrf_key;
	struct bgp *bgp;
	char vrf_xpath[64];
	int i;

	assert(ups_to_af >= 0 && ups_to_af <= 4);

	vrf_xpath[0] = '\0';
	for (i = 0; i < ups_to_af + 4; i++)
		strlcat(vrf_xpath, "../", sizeof(vrf_xpath));
	strlcat(vrf_xpath, "vrf", sizeof(vrf_xpath));

	vrf_key = yang_dnode_exists(dnode, vrf_xpath)
			  ? yang_dnode_get_string(dnode, "%s", vrf_xpath)
			  : NULL;
	if (!vrf_key) {
		snprintfrr(errmsg, errmsg_len, "missing vrf key");
		return -1;
	}
	bgp = bgp_lookup_by_name(bgp_nb_vrf_to_name(vrf_key));
	if (!bgp) {
		snprintfrr(errmsg, errmsg_len, "bgp instance not found");
		return -1;
	}

	{
		char afn[48];

		snprintfrr(afn, sizeof(afn), "%safi-safi-name", af_rel[ups_to_af]);
		afi_safi_id = yang_dnode_exists(dnode, afn)
				      ? yang_dnode_get_string(dnode, "%s", afn)
				      : NULL;
	}
	if (!afi_safi_id) {
		snprintfrr(errmsg, errmsg_len, "missing afi-safi-name");
		return -1;
	}
	{
		afi_t afi_r;
		safi_t safi_r;

		if (bgp_nb_af_id_to_afi_safi(afi_safi_id, &afi_r, &safi_r) < 0) {
			snprintfrr(errmsg, errmsg_len, "unknown afi-safi '%s'", afi_safi_id);
			return -1;
		}
		if (afi_out)
			*afi_out = afi_r;
		if (safi_out)
			*safi_out = safi_r;
	}
	if (bgp_out)
		*bgp_out = bgp;
	return 0;
}

enum gaf_agg_skip {
	GAF_AGG_SKIP_NONE = 0,
	GAF_AGG_SKIP_AS_SET,
	GAF_AGG_SKIP_SUMMARY_ONLY,
	GAF_AGG_SKIP_RMAP,
	GAF_AGG_SKIP_ORIGIN,
	GAF_AGG_SKIP_MATCH_MED,
	GAF_AGG_SKIP_SUPPRESS_MAP,
	GAF_AGG_SKIP_UPA,
	GAF_AGG_SKIP_UPA_DROP,
	GAF_AGG_SKIP_UPA_MAX,
	GAF_AGG_SKIP_COMMUNITY,
	GAF_AGG_SKIP_ECOMMUNITY,
	GAF_AGG_SKIP_LCOMMUNITY,
	GAF_AGG_SKIP_ASPATH,
};

static uint8_t gaf_origin_from_str(const char *s)
{
	if (strmatch(s, "igp"))
		return BGP_ORIGIN_IGP;
	if (strmatch(s, "egp"))
		return BGP_ORIGIN_EGP;
	if (strmatch(s, "incomplete"))
		return BGP_ORIGIN_INCOMPLETE;
	return BGP_ORIGIN_UNSPECIFIED;
}

static bool gaf_leaf_bool(const struct lyd_node *dnode, const char *rel, const char *leaf)
{
	char xp[64];

	snprintfrr(xp, sizeof(xp), "%s%s", rel, leaf);
	if (!yang_dnode_exists(dnode, xp))
		return false;
	return yang_dnode_get_bool(dnode, "%s", xp);
}

static const char *gaf_leaf_str(const struct lyd_node *dnode, const char *rel, const char *leaf)
{
	char xp[64];

	snprintfrr(xp, sizeof(xp), "%s%s", rel, leaf);
	if (!yang_dnode_exists(dnode, xp))
		return NULL;
	return yang_dnode_get_string(dnode, "%s", xp);
}

/*
 * Re-apply the full aggregate entry from the datastore. `rel` is ""
 * when dnode is the entry (create), "../" when it is a leaf. `skip`
 * forces one knob back to its default (destroy of that leaf: the
 * dying leaf must not be re-read -- S062 lesson).
 */
static int gaf_aggregate_reapply(const struct lyd_node *dnode, const char *rel, struct bgp *bgp,
				 afi_t afi, safi_t safi, int skip, char *errmsg, size_t errmsg_len)
{
	char xp[64];
	const char *prefix_s;
	const char *rmap;
	const char *suppress_map;
	const char *origin_s;
	uint32_t upa_max = 0;

	prefix_s = gaf_leaf_str(dnode, rel, "prefix");
	if (!prefix_s) {
		snprintfrr(errmsg, errmsg_len, "missing list key (prefix)");
		return -1;
	}

	snprintfrr(xp, sizeof(xp), "%supa-max-routes", rel);
	if (skip != GAF_AGG_SKIP_UPA_MAX && yang_dnode_exists(dnode, xp))
		upa_max = yang_dnode_get_uint16(dnode, "%s", xp);

	origin_s = (skip == GAF_AGG_SKIP_ORIGIN) ? NULL : gaf_leaf_str(dnode, rel, "origin");
	rmap = (skip == GAF_AGG_SKIP_RMAP) ? NULL : gaf_leaf_str(dnode, rel, "rmap-policy-export");
	suppress_map = (skip == GAF_AGG_SKIP_SUPPRESS_MAP)
			       ? NULL
			       : gaf_leaf_str(dnode, rel, "suppress-map");

	return bgp_aggregate_apply(bgp, prefix_s, afi, safi, rmap,
				   gaf_leaf_bool(dnode, rel, "summary-only"), /* summary */
				   gaf_leaf_bool(dnode, rel, "as-set"),	      /* as_set */
				   origin_s ? gaf_origin_from_str(origin_s)
					    : BGP_ORIGIN_UNSPECIFIED,
				   gaf_leaf_bool(dnode, rel, "match-med"), suppress_map,
				   gaf_leaf_bool(dnode, rel, "upa"),
				   gaf_leaf_bool(dnode, rel, "upa-drop"), upa_max,
				   (skip == GAF_AGG_SKIP_COMMUNITY)
					   ? NULL
					   : gaf_leaf_str(dnode, rel, "community"),
				   (skip == GAF_AGG_SKIP_ECOMMUNITY)
					   ? NULL
					   : gaf_leaf_str(dnode, rel, "extended-community"),
				   (skip == GAF_AGG_SKIP_LCOMMUNITY)
					   ? NULL
					   : gaf_leaf_str(dnode, rel, "large-community"),
				   (skip == GAF_AGG_SKIP_ASPATH)
					   ? NULL
					   : gaf_leaf_str(dnode, rel, "as-path"),
				   errmsg, errmsg_len);
}

/*
 * Pure-data guard mirroring the CLI: suppress-map and summary-only
 * exclude each other. Called from VALIDATE of create and of either
 * leaf's modify (destroy callbacks return early in VALIDATE, so a
 * removing change never trips a false conflict).
 */
static int gaf_aggregate_conflict_check(const struct lyd_node *dnode, const char *rel,
					char *errmsg, size_t errmsg_len)
{
	if (gaf_leaf_bool(dnode, rel, "summary-only") && gaf_leaf_str(dnode, rel, "suppress-map")) {
		snprintfrr(errmsg, errmsg_len,
			   "'summary-only' and 'suppress-map' can't be used at the same time");
		return -1;
	}
	return 0;
}

#define GAF_AGG_MODIFY(name, conflict)                                                            \
	int name##_modify(struct nb_cb_modify_args *args)                                         \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		afi_t afi;                                                                        \
		safi_t safi;                                                                      \
		switch (args->event) {                                                            \
		case NB_EV_VALIDATE:                                                              \
			if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg,        \
					  args->errmsg_len) < 0)                                  \
				return NB_ERR_VALIDATION;                                         \
			if (conflict &&                                                           \
			    gaf_aggregate_conflict_check(args->dnode, "../", args->errmsg,        \
							 args->errmsg_len) < 0)                   \
				return NB_ERR_VALIDATION;                                         \
			return NB_OK;                                                             \
		case NB_EV_PREPARE:                                                               \
		case NB_EV_ABORT:                                                                 \
			return NB_OK;                                                             \
		case NB_EV_APPLY:                                                                 \
			break;                                                                    \
		}                                                                                 \
		if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg,                \
				  args->errmsg_len) < 0)                                          \
			return NB_ERR;                                                            \
		if (gaf_aggregate_reapply(args->dnode, "../", bgp, afi, safi, GAF_AGG_SKIP_NONE,  \
					  args->errmsg, args->errmsg_len) < 0)                    \
			return NB_ERR;                                                            \
		return NB_OK;                                                                     \
	}

/* No-default leaves: removal arrives as a real destroy; re-apply with
 * that knob forced to its default (skip-leaf, S062 lesson).
 */
#define GAF_AGG_LEAF(name, skip_const, conflict)                                                  \
	int name##_modify(struct nb_cb_modify_args *args)                                         \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		afi_t afi;                                                                        \
		safi_t safi;                                                                      \
		switch (args->event) {                                                            \
		case NB_EV_VALIDATE:                                                              \
			if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg,        \
					  args->errmsg_len) < 0)                                  \
				return NB_ERR_VALIDATION;                                         \
			if (conflict &&                                                           \
			    gaf_aggregate_conflict_check(args->dnode, "../", args->errmsg,        \
							 args->errmsg_len) < 0)                   \
				return NB_ERR_VALIDATION;                                         \
			return NB_OK;                                                             \
		case NB_EV_PREPARE:                                                               \
		case NB_EV_ABORT:                                                                 \
			return NB_OK;                                                             \
		case NB_EV_APPLY:                                                                 \
			break;                                                                    \
		}                                                                                 \
		if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg,                \
				  args->errmsg_len) < 0)                                          \
			return NB_ERR;                                                            \
		if (gaf_aggregate_reapply(args->dnode, "../", bgp, afi, safi, GAF_AGG_SKIP_NONE,  \
					  args->errmsg, args->errmsg_len) < 0)                    \
			return NB_ERR;                                                            \
		return NB_OK;                                                                     \
	}                                                                                         \
	int name##_destroy(struct nb_cb_destroy_args *args)                                       \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		afi_t afi;                                                                        \
		safi_t safi;                                                                      \
		char dummy[256];                                                                  \
		switch (args->event) {                                                            \
		case NB_EV_VALIDATE:                                                              \
		case NB_EV_PREPARE:                                                               \
		case NB_EV_ABORT:                                                                 \
			return NB_OK;                                                             \
		case NB_EV_APPLY:                                                                 \
			break;                                                                    \
		}                                                                                 \
		if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, NULL, 0) < 0)                \
			return NB_ERR;                                                            \
		if (gaf_aggregate_reapply(args->dnode, "../", bgp, afi, safi, skip_const, dummy,  \
					  sizeof(dummy)) < 0)                                     \
			return NB_ERR;                                                            \
		return NB_OK;                                                                     \
	}

GAF_AGG_MODIFY(bgp_gaf_aggregate_as_set, false)
GAF_AGG_MODIFY(bgp_gaf_aggregate_summary_only, true)
GAF_AGG_MODIFY(bgp_gaf_aggregate_origin, false)
GAF_AGG_MODIFY(bgp_gaf_aggregate_match_med, false)
GAF_AGG_MODIFY(bgp_gaf_aggregate_upa, false)
GAF_AGG_MODIFY(bgp_gaf_aggregate_upa_drop, false)
GAF_AGG_LEAF(bgp_gaf_aggregate_rmap_policy_export, GAF_AGG_SKIP_RMAP, false)
GAF_AGG_LEAF(bgp_gaf_aggregate_suppress_map, GAF_AGG_SKIP_SUPPRESS_MAP, true)
GAF_AGG_LEAF(bgp_gaf_aggregate_upa_max_routes, GAF_AGG_SKIP_UPA_MAX, false)
GAF_AGG_LEAF(bgp_gaf_aggregate_community, GAF_AGG_SKIP_COMMUNITY, false)
GAF_AGG_LEAF(bgp_gaf_aggregate_extended_community, GAF_AGG_SKIP_ECOMMUNITY, false)
GAF_AGG_LEAF(bgp_gaf_aggregate_large_community, GAF_AGG_SKIP_LCOMMUNITY, false)
GAF_AGG_LEAF(bgp_gaf_aggregate_as_path, GAF_AGG_SKIP_ASPATH, false)

int bgp_gaf_aggregate_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_af_lookup(args->dnode, 2, &bgp, &afi, &safi, args->errmsg,
				  args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 2, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	/*
	 * Leaf knobs land as sibling modifies after the entry create;
	 * applying with defaults here performs the plain insertion and
	 * is idempotent under re-create.
	 */
	if (gaf_aggregate_reapply(args->dnode, "", bgp, afi, safi, GAF_AGG_SKIP_NONE, args->errmsg,
				  args->errmsg_len) < 0)
		return NB_ERR;
	return NB_OK;
}

int bgp_gaf_aggregate_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const char *prefix_s;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 2, &bgp, &afi, &safi, NULL, 0) < 0)
		return NB_ERR;
	prefix_s = yang_dnode_get_string(args->dnode, "prefix");
	return bgp_aggregate_remove(bgp, prefix_s, afi, safi) == 0 ? NB_OK : NB_ERR;
}

/* ================================================================== */
/* G2: route-flap-dampening                                            */
/* ================================================================== */

static int gaf_damp_validate(const struct lyd_node *dnode, const char *rel, char *errmsg,
			     size_t errmsg_len)
{
	char xp[64];
	bool have_reuse, have_suppress;
	uint16_t reuse = 750, suppress = 2000;

	snprintfrr(xp, sizeof(xp), "%sreuse-above", rel);
	have_reuse = yang_dnode_exists(dnode, xp);
	if (have_reuse)
		reuse = yang_dnode_get_uint16(dnode, "%s", xp);
	snprintfrr(xp, sizeof(xp), "%ssuppress-above", rel);
	have_suppress = yang_dnode_exists(dnode, xp);
	if (have_suppress)
		suppress = yang_dnode_get_uint16(dnode, "%s", xp);

	if (have_reuse && have_suppress && reuse >= suppress) {
		snprintfrr(errmsg, errmsg_len,
			   "reuse-above (%u) must be lower than suppress-above (%u)", reuse,
			   suppress);
		return -1;
	}
	return 0;
}

static int gaf_damp_apply(const struct lyd_node *dnode, const char *rel, struct bgp *bgp,
			  afi_t afi, safi_t safi)
{
	char xp[64];
	time_t half = 15, max;
	unsigned int reuse = 750, suppress = 2000;
	bool enabled;

	enabled = gaf_leaf_bool(dnode, rel, "enable");
	if (!enabled) {
		bgp_damp_disable(bgp, afi, safi);
		return 0;
	}

	snprintfrr(xp, sizeof(xp), "%sreach-decay", rel);
	if (yang_dnode_exists(dnode, xp))
		half = yang_dnode_get_uint8(dnode, "%s", xp);
	snprintfrr(xp, sizeof(xp), "%sreuse-above", rel);
	if (yang_dnode_exists(dnode, xp))
		reuse = yang_dnode_get_uint16(dnode, "%s", xp);
	snprintfrr(xp, sizeof(xp), "%ssuppress-above", rel);
	if (yang_dnode_exists(dnode, xp))
		suppress = yang_dnode_get_uint16(dnode, "%s", xp);
	snprintfrr(xp, sizeof(xp), "%sunreach-decay", rel);
	if (yang_dnode_exists(dnode, xp))
		max = yang_dnode_get_uint8(dnode, "%s", xp);
	else
		max = half * 4; /* CLI parity: max defaults to half*4 */

	/* CLI parity: bgp_damp_enable() takes SECONDS; the YANG leaves
	 * are minutes (reach/unreach-decay units).
	 */
	return bgp_damp_enable(bgp, afi, safi, half * 60, reuse, suppress, max * 60);
}

int bgp_gaf_dampening_enable_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg,
				  args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		if (yang_dnode_get_bool(args->dnode, NULL) &&
		    gaf_damp_validate(args->dnode, "../", args->errmsg, args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	if (gaf_damp_apply(args->dnode, "../", bgp, afi, safi) < 0)
		return NB_ERR;
	return NB_OK;
}

int bgp_gaf_dampening_params_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg,
				  args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		if (gaf_leaf_bool(args->dnode, "../", "enable") &&
		    gaf_damp_validate(args->dnode, "../", args->errmsg, args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	/* Re-apply only when enabled; bare params stay inert (CLI parity). */
	if (gaf_leaf_bool(args->dnode, "../", "enable") &&
	    gaf_damp_apply(args->dnode, "../", bgp, afi, safi) < 0)
		return NB_ERR;
	return NB_OK;
}

int bgp_gaf_dampening_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, NULL, 0) < 0)
		return NB_ERR;
	bgp_damp_disable(bgp, afi, safi);
	return NB_OK;
}
/* ================================================================== */
/* G3: use-multiple-paths                                              */
/* ================================================================== */

#define GAF_MAXPATHS_CB(name, peer_type)                                                          \
	int name##_modify(struct nb_cb_modify_args *args)                                         \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		afi_t afi;                                                                        \
		safi_t safi;                                                                      \
		uint16_t mp;                                                                      \
		switch (args->event) {                                                            \
		case NB_EV_VALIDATE:                                                              \
			if (gaf_af_lookup(args->dnode, 4, &bgp, &afi, &safi, args->errmsg,        \
					  args->errmsg_len) < 0)                                  \
				return NB_ERR_VALIDATION;                                         \
			mp = yang_dnode_get_uint16(args->dnode, NULL);                            \
			if (mp > multipath_num) {                                                 \
				snprintfrr(args->errmsg, args->errmsg_len,                        \
					   "maxpaths %u > multipath num %u", mp, multipath_num);  \
				return NB_ERR_VALIDATION;                                         \
			}                                                                         \
			return NB_OK;                                                             \
		case NB_EV_PREPARE:                                                               \
		case NB_EV_ABORT:                                                                 \
			return NB_OK;                                                             \
		case NB_EV_APPLY:                                                                 \
			break;                                                                    \
		}                                                                                 \
		if (gaf_af_lookup(args->dnode, 4, &bgp, &afi, &safi, args->errmsg,                \
				  args->errmsg_len) < 0)                                          \
			return NB_ERR;                                                            \
		bgp_maximum_paths_set(bgp, afi, safi, peer_type,                                  \
				      yang_dnode_get_uint16(args->dnode, NULL), false);           \
		bgp_recalculate_all_bestpaths(bgp);                                               \
		return NB_OK;                                                                     \
	}                                                                                         \
	int name##_destroy(struct nb_cb_destroy_args *args)                                       \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		afi_t afi;                                                                        \
		safi_t safi;                                                                      \
		switch (args->event) {                                                            \
		case NB_EV_VALIDATE:                                                              \
		case NB_EV_PREPARE:                                                               \
		case NB_EV_ABORT:                                                                 \
			return NB_OK;                                                             \
		case NB_EV_APPLY:                                                                 \
			break;                                                                    \
		}                                                                                 \
		if (gaf_af_lookup(args->dnode, 4, &bgp, &afi, &safi, NULL, 0) < 0)                \
			return NB_ERR;                                                            \
		bgp_maximum_paths_set(bgp, afi, safi, peer_type, multipath_num, false);           \
		bgp_recalculate_all_bestpaths(bgp);                                               \
		return NB_OK;                                                                     \
	}

GAF_MAXPATHS_CB(bgp_gaf_maxpaths_ebgp, BGP_PEER_EBGP)
GAF_MAXPATHS_CB(bgp_gaf_maxpaths_ibgp, BGP_PEER_IBGP)

/* cluster-length-list: interim (registered debt in the caderno). */
/* ================================================================== */
/* G4: admin-distance                                                  */
/* ================================================================== */

/* distance bgp <e> <i> <l>: absent leaves keep the daemon's current
 * value (the CLI sets all three at once).
 */
static int gaf_distance_apply(struct nb_cb_modify_args *args, int ups)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	char xp[64];

	if (gaf_af_lookup(args->dnode, ups, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	bgp->distance_ebgp[afi][safi] = yang_dnode_exists(args->dnode, "../external")
						? yang_dnode_get_uint8(args->dnode, "../external")
						: bgp->distance_ebgp[afi][safi];
	bgp->distance_ibgp[afi][safi] = yang_dnode_exists(args->dnode, "../internal")
						? yang_dnode_get_uint8(args->dnode, "../internal")
						: bgp->distance_ibgp[afi][safi];
	bgp->distance_local[afi][safi] = yang_dnode_exists(args->dnode, "../local")
						 ? yang_dnode_get_uint8(args->dnode, "../local")
						 : bgp->distance_local[afi][safi];
	return NB_OK;
}

static int gaf_distance_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_af_lookup(args->dnode, 3, NULL, NULL, NULL, args->errmsg,
				  args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return gaf_distance_apply(args, 3);
}

int bgp_gaf_distance_external_modify(struct nb_cb_modify_args *args)
{
	return gaf_distance_modify(args);
}

int bgp_gaf_distance_internal_modify(struct nb_cb_modify_args *args)
{
	return gaf_distance_modify(args);
}

int bgp_gaf_distance_local_modify(struct nb_cb_modify_args *args)
{
	return gaf_distance_modify(args);
}

/* distance per-prefix: bgp_distance_apply/remove extracted from the
 * vty-era bgp_distance_set/unset.
 */
static int gaf_distance_route_apply(struct nb_cb_modify_args *args, int ups, const char *alist)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (gaf_af_lookup(args->dnode, ups, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	if (!yang_dnode_exists(args->dnode, "../distance"))
		return NB_OK;
	return bgp_distance_cfg_apply(bgp, yang_dnode_get_uint8(args->dnode, "../distance"),
				      yang_dnode_get_string(args->dnode, "../prefix"), alist, afi,
				      safi, args->errmsg, args->errmsg_len) < 0
		       ? NB_ERR
		       : NB_OK;
}

int bgp_gaf_distance_route_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	const char *alist = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_af_lookup(args->dnode, 2, NULL, NULL, NULL, args->errmsg,
				  args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 2, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	if (!yang_dnode_exists(args->dnode, "distance"))
		return NB_OK; /* bare create; leaf modify follows */
	if (yang_dnode_exists(args->dnode, "access-list"))
		alist = yang_dnode_get_string(args->dnode, "access-list");
	return bgp_distance_cfg_apply(bgp, yang_dnode_get_uint8(args->dnode, "distance"),
				      yang_dnode_get_string(args->dnode, "prefix"), alist, afi,
				      safi, args->errmsg, args->errmsg_len) < 0
		       ? NB_ERR
		       : NB_OK;
}

int bgp_gaf_distance_route_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 2, &bgp, &afi, &safi, NULL, 0) < 0)
		return NB_ERR;
	return bgp_distance_cfg_remove(bgp, yang_dnode_get_string(args->dnode, "prefix"), afi,
				       safi) == 0
		       ? NB_OK
		       : NB_ERR;
}

int bgp_gaf_distance_route_distance_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg,
				  args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	return gaf_distance_route_apply(args, 3,
					yang_dnode_exists(args->dnode, "../access-list")
						? yang_dnode_get_string(args->dnode,
									"../access-list")
						: NULL);
}

int bgp_gaf_distance_route_access_list_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg,
				  args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return gaf_distance_route_apply(args, 3, yang_dnode_get_string(args->dnode, NULL));
}

int bgp_gaf_distance_route_access_list_destroy(struct nb_cb_destroy_args *args)
{
	/* alist removal re-applies with no list (skip-leaf analog) */
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, NULL, 0) < 0)
		return NB_ERR;
	if (!yang_dnode_exists(args->dnode, "../distance"))
		return NB_OK;
	return bgp_distance_cfg_apply(bgp, yang_dnode_get_uint8(args->dnode, "../distance"),
				      yang_dnode_get_string(args->dnode, "../prefix"), NULL, afi,
				      safi, NULL, 0) < 0
		       ? NB_ERR
		       : NB_OK;
}

int bgp_gaf_distance_route_acl_export_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg,
				  args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return gaf_distance_route_apply(args, 3, yang_dnode_get_string(args->dnode, NULL));
}

int bgp_gaf_distance_route_acl_export_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/* ================================================================== */
/* G5: filter-config / table-map                                       */
/* ================================================================== */

static int gaf_table_map_apply(struct nb_cb_modify_args *args, const char *name)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct bgp_rmap *rmap;

	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	rmap = &bgp->table_map[afi][safi];
	XFREE(MTYPE_ROUTE_MAP_NAME, rmap->name);
	route_map_counter_decrement(rmap->map);
	if (name) {
		rmap->name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, name);
		rmap->map = route_map_lookup_by_name(name);
		route_map_counter_increment(rmap->map);
	} else {
		rmap->map = NULL;
	}
	if (bgp_fibupd_safi(safi))
		bgp_zebra_announce_table(bgp, afi, safi);
	return NB_OK;
}

int bgp_gaf_table_map_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return gaf_table_map_apply(args, yang_dnode_get_string(args->dnode, NULL));
}

int bgp_gaf_table_map_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct bgp_rmap *rmap;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, NULL, 0) < 0)
		return NB_ERR;
	rmap = &bgp->table_map[afi][safi];
	XFREE(MTYPE_ROUTE_MAP_NAME, rmap->name);
	route_map_counter_decrement(rmap->map);
	rmap->map = NULL;
	if (bgp_fibupd_safi(safi))
		bgp_zebra_announce_table(bgp, afi, safi);
	return NB_OK;
}

/* ================================================================== */
/* G6: retain-route-target-all (l3vpn)                                 */
/* ================================================================== */

int bgp_gaf_retain_rt_all_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 2, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->af_flags[afi][safi], BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL);
	else
		UNSET_FLAG(bgp->af_flags[afi][safi], BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL);
	return NB_OK;
}

/* ================================================================== */
/* G7: flowspec local-install                                          */
/* ================================================================== */


int bgp_gaf_fs_local_install_enable_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 4, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	bgp_fs_local_install_interface(bgp, yang_dnode_get_bool(args->dnode, NULL) ? NULL : "no",
				       NULL, afi);
	return NB_OK;
}

int bgp_gaf_fs_local_install_if_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_af_lookup(args->dnode, 4, &bgp, &afi, &safi, args->errmsg,
				  args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 4, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	bgp_fs_local_install_interface(bgp, NULL, yang_dnode_get_string(args->dnode, NULL), afi);
	return NB_OK;
}

int bgp_gaf_fs_local_install_if_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 4, &bgp, &afi, &safi, NULL, 0) < 0)
		return NB_ERR;
	bgp_fs_local_install_interface(bgp, "no", yang_dnode_get_string(args->dnode, NULL), afi);
	return NB_OK;
}

/* ================================================================== */
/* G8: vpn-config (vrf <-> vpn leak; mirrors the af_*_vpn_* and        */
/* bgp_imexport_* verbs in bgp_vty.c)                                  */
/* ================================================================== */

/*
 * Candidate-level (VALIDATE) mutual exclusion between the two
 * import families, pair-scoped: "import/export vpn" (bool flags)
 * versus v2v ("import vrf" list / "import vrf route-map"). Matches
 * vpn_policy_getafi semantics; enforcement is validate-only so a
 * rejected transaction leaves no residue in the running DS
 * (apply-side rejection poisons it and wedges the replay).
 */
static int gaf_vpn_v2v_in_candidate(const struct lyd_node *dnode)
{
	return yang_dnode_exists(dnode, "../import-vrf-list") ||
	       (yang_dnode_exists(dnode, "../vrf-rmap-import") &&
		yang_dnode_get_string(dnode, "../vrf-rmap-import")[0] != '\0');
}

/*
 * Any vpn-family sibling meaningfully configured (mirrors the vpn side
 * of vpn_policy_getafi). Booleans must be true; optional strings and
 * lists must exist; export-allocation-mode counts when explicitly
 * present.
 */
static int gaf_vpn_family_in_candidate(const struct lyd_node *dnode)
{
	if (yang_dnode_exists(dnode, "../rd") || yang_dnode_exists(dnode, "../label") ||
	    yang_dnode_exists(dnode, "../nexthop") || yang_dnode_exists(dnode, "../rmap-import") ||
	    yang_dnode_exists(dnode, "../rmap-export") ||
	    yang_dnode_exists(dnode, "../import-rt-list") ||
	    yang_dnode_exists(dnode, "../export-rt-list") ||
	    yang_dnode_exists(dnode, "../redirect-rt"))
		return 1;
	if (yang_dnode_exists(dnode, "../export-allocation-mode") &&
	    strmatch(yang_dnode_get_string(dnode, "../export-allocation-mode"), "per-nexthop"))
		return 1;
	if (yang_dnode_exists(dnode, "../label-auto") &&
	    yang_dnode_get_bool(dnode, "../label-auto"))
		return 1;
	if (yang_dnode_exists(dnode, "../import-vpn") &&
	    yang_dnode_get_bool(dnode, "../import-vpn"))
		return 1;
	if (yang_dnode_exists(dnode, "../export-vpn") &&
	    yang_dnode_get_bool(dnode, "../export-vpn"))
		return 1;
	return 0;
}

/* --- rd (af_rd_vpn_export) --------------------------------------- */

static bool bgp_is_vrf_or_default(const struct bgp *bgp)
{
	return bgp->inst_type == BGP_INSTANCE_TYPE_VRF ||
	       bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT;
}

int bgp_gaf_vpn_rd_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct prefix_rd prd;
	const char *rd_str;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_vpn_v2v_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure import vrf commands before using vpn commands");
			return NB_ERR_VALIDATION;
		}
		rd_str = yang_dnode_get_string(args->dnode, NULL);
		if (!str2prefix_rd(rd_str, &prd)) {
			snprintfrr(args->errmsg, args->errmsg_len, "malformed rd");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	rd_str = yang_dnode_get_string(args->dnode, NULL);
	str2prefix_rd(rd_str, &prd);

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	bgp_vty_hook_rd_update(bgp, afi, true);
	XFREE(MTYPE_BGP_NAME, bgp->vpn_policy[afi].tovpn_rd_pretty);
	bgp->vpn_policy[afi].tovpn_rd_pretty = XSTRDUP(MTYPE_BGP_NAME, rd_str);
	bgp->vpn_policy[afi].tovpn_rd = prd;
	SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_SET);
	SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_CLI_SET);
	bgp_vty_hook_rd_update(bgp, afi, false);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

int bgp_gaf_vpn_rd_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, NULL, 0) < 0)
		return NB_ERR;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	bgp_vty_hook_rd_update(bgp, afi, true);
	XFREE(MTYPE_BGP_NAME, bgp->vpn_policy[afi].tovpn_rd_pretty);
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_SET);
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_CLI_SET);
	bgp_vty_hook_rd_update(bgp, afi, false);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

/* --- label (af_label_vpn_export / af_label_vpn_export_auto) ------ */

static void gaf_vpn_label_release(struct bgp *bgp, afi_t afi)
{
	if (CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_MANUAL_REG)) {
		bgp_zebra_release_label_range(bgp->vpn_policy[afi].tovpn_label,
					      bgp->vpn_policy[afi].tovpn_label);
		UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_MANUAL_REG);
	} else if (CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO)) {
		/* release any previous auto label */
		bgp_vpn_release_label(bgp, afi, false);
	}
}

static void gaf_vpn_label_unset(struct bgp *bgp, afi_t afi)
{
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	gaf_vpn_label_release(bgp, afi);
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO);
	bgp->vpn_policy[afi].tovpn_label = MPLS_LABEL_NONE;
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
}

int bgp_gaf_vpn_label_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	mpls_label_t label;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_vpn_v2v_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure import vrf commands before using vpn commands");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	label = yang_dnode_get_uint32(args->dnode, NULL);

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	gaf_vpn_label_release(bgp, afi);
	bgp->vpn_policy[afi].tovpn_label = label;
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO);
	if (label >= MPLS_LABEL_UNRESERVED_MIN && bgp_zebra_request_label_range(label, 1, false))
		SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_MANUAL_REG);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

int bgp_gaf_vpn_label_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, NULL, 0) < 0)
		return NB_ERR;
	gaf_vpn_label_unset(bgp, afi);
	return NB_OK;
}

int bgp_gaf_vpn_label_auto_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_vpn_v2v_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure import vrf commands before using vpn commands");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	enable = yang_dnode_get_bool(args->dnode, NULL);

	if (!enable) {
		gaf_vpn_label_unset(bgp, afi);
		return NB_OK;
	}

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	gaf_vpn_label_release(bgp, afi);
	SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO);
	/* fetch a label */
	bgp->vpn_policy[afi].tovpn_label = MPLS_LABEL_NONE;
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

int bgp_gaf_vpn_label_auto_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, NULL, 0) < 0)
		return NB_ERR;
	gaf_vpn_label_unset(bgp, afi);
	return NB_OK;
}

/* --- export-allocation-mode (af_label_vpn_export_allocation_mode) - */

int bgp_gaf_vpn_export_alloc_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	bool old_nh, new_nh;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_vpn_v2v_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure import vrf commands before using vpn commands");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;

	old_nh = !!CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);
	new_nh = !strcmp(yang_dnode_get_string(args->dnode, NULL), "per-nexthop");
	if (old_nh == new_nh)
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	if (new_nh)
		SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);
	else
		UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

/* --- nexthop (af_nexthop_vpn_export) ------------------------------ */

int bgp_gaf_vpn_nexthop_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	union sockunion su;
	struct prefix p;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_vpn_v2v_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure import vrf commands before using vpn commands");
			return NB_ERR_VALIDATION;
		}
		if (str2sockunion(yang_dnode_get_string(args->dnode, NULL), &su) < 0) {
			snprintfrr(args->errmsg, args->errmsg_len, "malformed nexthop");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	str2sockunion(yang_dnode_get_string(args->dnode, NULL), &su);
	sockunion2hostprefix(&su, &p);

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	bgp->vpn_policy[afi].tovpn_nexthop = p;
	SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_NEXTHOP_SET);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

int bgp_gaf_vpn_nexthop_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, NULL, 0) < 0)
		return NB_ERR;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_NEXTHOP_SET);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

/* --- import/export vpn (bgp_imexport_vpn) ------------------------- */

static int gaf_vpn_imexport(const struct lyd_node *dnode, char *errmsg, size_t errmsg_len,
			    bool is_import, bool enable)
{
	struct bgp *bgp;
	struct bgp *bgp_default = bgp_get_default();
	afi_t afi;
	safi_t safi;
	enum vpn_policy_direction dir;
	int flag, previous;

	if (gaf_af_lookup(dnode, 3, &bgp, &afi, &safi, errmsg, errmsg_len) < 0)
		return -1;

	/* mirrors bgp_imexport_vpn: vrf or default instance only */
	if (!bgp_is_vrf_or_default(bgp)) {
		snprintfrr(errmsg, errmsg_len,
			   "import/export vpn valid only for bgp vrf or default instance");
		return -1;
	}

	if (is_import) {
		flag = BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT;
		dir = BGP_VPN_POLICY_DIR_FROMVPN;
	} else {
		flag = BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT;
		dir = BGP_VPN_POLICY_DIR_TOVPN;
	}

	previous = CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST], flag);

	if (enable) {
		SET_FLAG(bgp->af_flags[afi][SAFI_UNICAST], flag);
		if (!previous)
			/* trigger export current vrf */
			vpn_leak_postchange(dir, afi, bgp_default, bgp);
	} else {
		if (previous)
			/* trigger un-export current vrf */
			vpn_leak_prechange(dir, afi, bgp_default, bgp);
		UNSET_FLAG(bgp->af_flags[afi][SAFI_UNICAST], flag);
		if (previous && bgp_default &&
		    !CHECK_FLAG(bgp_default->af_flags[afi][SAFI_MPLS_VPN],
				BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL))
			vpn_leak_no_retain(bgp, bgp_default, afi);
	}

	bgp_vty_hook_snmp_init_stats(bgp);
	return 0;
}

int bgp_gaf_vpn_import_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_vpn_v2v_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure import vrf commands before using vpn commands");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_vpn_imexport(args->dnode, args->errmsg, args->errmsg_len, true,
			     yang_dnode_get_bool(args->dnode, NULL)) < 0)
		return NB_ERR;
	return NB_OK;
}

int bgp_gaf_vpn_import_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_vpn_imexport(args->dnode, args->errmsg, args->errmsg_len, true, false) < 0)
		return NB_ERR;
	return NB_OK;
}

int bgp_gaf_vpn_export_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_vpn_v2v_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure import vrf commands before using vpn commands");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_vpn_imexport(args->dnode, args->errmsg, args->errmsg_len, false,
			     yang_dnode_get_bool(args->dnode, NULL)) < 0)
		return NB_ERR;
	return NB_OK;
}

int bgp_gaf_vpn_export_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_vpn_imexport(args->dnode, args->errmsg, args->errmsg_len, false, false) < 0)
		return NB_ERR;
	return NB_OK;
}

/* --- rt vpn import/export leaf-lists (af_rt_vpn_imexport) --------- */

static int gaf_vpn_rtlist_apply(const struct lyd_node *dnode, char *errmsg, size_t errmsg_len,
				enum vpn_policy_direction dir)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct ecommunity *add;

	if (gaf_af_lookup(dnode, 3, &bgp, &afi, &safi, errmsg, errmsg_len) < 0)
		return -1;

	add = ecommunity_str2com(yang_dnode_get_string(dnode, NULL), ECOMMUNITY_ROUTE_TARGET, 0);
	if (!add) {
		snprintfrr(errmsg, errmsg_len, "malformed route-target");
		return -1;
	}

	vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);
	if (bgp->vpn_policy[afi].rtlist[dir]) {
		ecommunity_merge(bgp->vpn_policy[afi].rtlist[dir], add);
		ecommunity_free(&add);
	} else {
		bgp->vpn_policy[afi].rtlist[dir] = add;
	}
	vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
	return 0;
}

static void gaf_ecom_strip_val(struct ecommunity **ecom, const struct ecommunity *del)
{
	struct ecommunity *src = *ecom;
	size_t unit;
	uint32_t i;

	if (!src || !del || !del->size)
		return;
	unit = src->unit_size;
	for (i = 0; i < src->size; i++) {
		if (!memcmp(src->val + (size_t)i * unit, del->val, unit)) {
			memmove(src->val + (size_t)i * unit, src->val + (size_t)(i + 1) * unit,
				(size_t)(src->size - i - 1) * unit);
			src->size--;
			break;
		}
	}
	if (src->size == 0)
		ecommunity_free(ecom);
}

static int gaf_vpn_rtlist_unapply(const struct lyd_node *dnode, char *errmsg, size_t errmsg_len,
				  enum vpn_policy_direction dir)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct ecommunity *del;

	if (gaf_af_lookup(dnode, 3, &bgp, &afi, &safi, errmsg, errmsg_len) < 0)
		return -1;

	del = ecommunity_str2com(yang_dnode_get_string(dnode, NULL), ECOMMUNITY_ROUTE_TARGET, 0);
	if (!del) {
		snprintfrr(errmsg, errmsg_len, "malformed route-target");
		return -1;
	}

	vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);
	gaf_ecom_strip_val(&bgp->vpn_policy[afi].rtlist[dir], del);
	ecommunity_free(&del);
	vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
	return 0;
}

static int bgp_gaf_vpn_rt_create(struct nb_cb_create_args *args, enum vpn_policy_direction dir)
{
	struct ecommunity *chk;

	switch (args->event) {
	case NB_EV_VALIDATE:
		chk = ecommunity_str2com(yang_dnode_get_string(args->dnode, NULL),
					 ECOMMUNITY_ROUTE_TARGET, 0);
		if (!chk) {
			snprintfrr(args->errmsg, args->errmsg_len, "malformed route-target");
			return NB_ERR_VALIDATION;
		}
		ecommunity_free(&chk);
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_vpn_rtlist_apply(args->dnode, args->errmsg, args->errmsg_len, dir) < 0)
		return NB_ERR;
	return NB_OK;
}

static int bgp_gaf_vpn_rt_destroy(struct nb_cb_destroy_args *args, enum vpn_policy_direction dir)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_vpn_rtlist_unapply(args->dnode, args->errmsg, args->errmsg_len, dir) < 0)
		return NB_ERR;
	return NB_OK;
}

int bgp_gaf_vpn_import_rt_list_create(struct nb_cb_create_args *args)
{
	return bgp_gaf_vpn_rt_create(args, BGP_VPN_POLICY_DIR_FROMVPN);
}

int bgp_gaf_vpn_import_rt_list_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_gaf_vpn_rt_destroy(args, BGP_VPN_POLICY_DIR_FROMVPN);
}

int bgp_gaf_vpn_export_rt_list_create(struct nb_cb_create_args *args)
{
	return bgp_gaf_vpn_rt_create(args, BGP_VPN_POLICY_DIR_TOVPN);
}

int bgp_gaf_vpn_export_rt_list_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_gaf_vpn_rt_destroy(args, BGP_VPN_POLICY_DIR_TOVPN);
}

/* --- route-map vpn import/export (af_route_map_vpn_imexport) ------ */

static int gaf_vpn_rmap_apply(const struct lyd_node *dnode, char *errmsg, size_t errmsg_len,
			      enum vpn_policy_direction dir, const char *name)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (gaf_af_lookup(dnode, 3, &bgp, &afi, &safi, errmsg, errmsg_len) < 0)
		return -1;

	vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);
	XFREE(MTYPE_ROUTE_MAP_NAME, bgp->vpn_policy[afi].rmap_name[dir]);
	if (name) {
		bgp->vpn_policy[afi].rmap_name[dir] = XSTRDUP(MTYPE_ROUTE_MAP_NAME, name);
		bgp->vpn_policy[afi].rmap[dir] = route_map_lookup_by_name(name);
		if (!bgp->vpn_policy[afi].rmap[dir])
			/* mirror CLI: skip postchange when rmap missing */
			return 0;
	} else {
		bgp->vpn_policy[afi].rmap_name[dir] = NULL;
		bgp->vpn_policy[afi].rmap[dir] = NULL;
	}
	vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
	return 0;
}

int bgp_gaf_vpn_rmap_import_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_vpn_v2v_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure import vrf commands before using vpn commands");
			return NB_ERR_VALIDATION;
		}
		if (gaf_vpn_v2v_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure import vrf commands before using vpn commands");
			return NB_ERR_VALIDATION;
		}
		if (gaf_vpn_v2v_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure import vrf commands before using vpn commands");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_vpn_rmap_apply(args->dnode, args->errmsg, args->errmsg_len,
			       BGP_VPN_POLICY_DIR_FROMVPN,
			       yang_dnode_get_string(args->dnode, NULL)) < 0)
		return NB_ERR;
	return NB_OK;
}

int bgp_gaf_vpn_rmap_import_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_vpn_rmap_apply(args->dnode, args->errmsg, args->errmsg_len,
			       BGP_VPN_POLICY_DIR_FROMVPN, NULL) < 0)
		return NB_ERR;
	return NB_OK;
}

int bgp_gaf_vpn_rmap_export_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_vpn_v2v_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure import vrf commands before using vpn commands");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_vpn_rmap_apply(args->dnode, args->errmsg, args->errmsg_len,
			       BGP_VPN_POLICY_DIR_TOVPN,
			       yang_dnode_get_string(args->dnode, NULL)) < 0)
		return NB_ERR;
	return NB_OK;
}

int bgp_gaf_vpn_rmap_export_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_vpn_rmap_apply(args->dnode, args->errmsg, args->errmsg_len,
			       BGP_VPN_POLICY_DIR_TOVPN, NULL) < 0)
		return NB_ERR;
	return NB_OK;
}

/* --- import vrf route-map (af_import_vrf_route_map) --------------- */

static struct bgp *gaf_vpn_default_get(char *errmsg, size_t errmsg_len)
{
	struct bgp *bgp_default = bgp_get_default();
	as_t as = AS_UNSPECIFIED;

	if (bgp_default)
		return bgp_default;

	/* Auto-create with AS_UNSPECIFIED, to be filled in later */
	if (bgp_get_vty(&bgp_default, &as, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL,
			ASNOTATION_UNDEFINED)) {
		snprintfrr(errmsg, errmsg_len, "default instance cannot be created");
		return NULL;
	}
	SET_FLAG(bgp_default->flags, BGP_FLAG_INSTANCE_HIDDEN);
	return bgp_default;
}

int bgp_gaf_vpn_vrf_rmap_import_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp, *bgp_default;
	afi_t afi;
	safi_t safi;
	const char *name;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_vpn_family_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure vpn commands before using import vrf commands");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;

	bgp_default = gaf_vpn_default_get(args->errmsg, args->errmsg_len);
	if (!bgp_default)
		return NB_ERR;

	name = yang_dnode_get_string(args->dnode, NULL);
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_FROMVPN, afi, bgp_default, bgp);
	XFREE(MTYPE_ROUTE_MAP_NAME, bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN]);
	bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN] = XSTRDUP(MTYPE_ROUTE_MAP_NAME,
									     name);
	bgp->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_FROMVPN] = route_map_lookup_by_name(name);
	SET_FLAG(bgp->af_flags[afi][SAFI_UNICAST], BGP_CONFIG_VRF_TO_VRF_IMPORT);
	if (!bgp->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_FROMVPN])
		return NB_OK;
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_FROMVPN, afi, bgp_default, bgp);
	return NB_OK;
}

int bgp_gaf_vpn_vrf_rmap_import_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, NULL, 0) < 0)
		return NB_ERR;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_FROMVPN, afi, bgp_get_default(), bgp);
	XFREE(MTYPE_ROUTE_MAP_NAME, bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN]);
	bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN] = NULL;
	bgp->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_FROMVPN] = NULL;

	if (bgp->vpn_policy[afi].import_vrf->count == 0)
		UNSET_FLAG(bgp->af_flags[afi][SAFI_UNICAST], BGP_CONFIG_VRF_TO_VRF_IMPORT);

	vpn_leak_postchange(BGP_VPN_POLICY_DIR_FROMVPN, afi, bgp_get_default(), bgp);
	return NB_OK;
}

/* --- import vrf (bgp_imexport_vrf) -------------------------------- */

/*
 * Pure-candidate self-import check for import-vrf-list: the instance
 * vrf key (7 "../" hops from the list entry, same walk gaf_af_lookup
 * uses) versus the entry key. Enforced at VALIDATE so a rejected
 * self-import leaves no DS residue; the APPLY-side runtime instance
 * is not consulted (lesson B-1 S061).
 */
static int gaf_vpn_self_import(const struct lyd_node *dnode)
{
	char vrf_xpath[64];
	const char *inst_vrf;
	const char *entry_vrf;
	int i;

	vrf_xpath[0] = '\0';
	for (i = 0; i < 7; i++)
		strlcat(vrf_xpath, "../", sizeof(vrf_xpath));
	strlcat(vrf_xpath, "vrf", sizeof(vrf_xpath));

	inst_vrf = yang_dnode_get_string(dnode, "%s", vrf_xpath);
	entry_vrf = yang_dnode_get_string(dnode, "./vrf");
	return strmatch(inst_vrf, entry_vrf);
}

int bgp_gaf_vpn_import_vrf_list_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp, *vrf_bgp;
	afi_t afi;
	safi_t safi;
	const char *vrf_name;

	switch (args->event) {
	case NB_EV_VALIDATE:
		vrf_name = yang_dnode_get_string(args->dnode, "./vrf");
		if (!strcmp(vrf_name, "route-map")) {
			snprintfrr(args->errmsg, args->errmsg_len, "must include route-map name");
			return NB_ERR_VALIDATION;
		}
		if (gaf_vpn_self_import(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "cannot import vrf %s into itself", vrf_name);
			return NB_ERR_VALIDATION;
		}
		if (gaf_vpn_family_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure vpn commands before using import vrf commands");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;

	vrf_name = yang_dnode_get_string(args->dnode, "./vrf");

	if (!strcmp(vrf_name, VRF_DEFAULT_NAME)) {
		vrf_bgp = gaf_vpn_default_get(args->errmsg, args->errmsg_len);
		if (!vrf_bgp)
			return NB_ERR;
	} else {
		vrf_bgp = bgp_lookup_by_name_filter(vrf_name, false);
	}

	vrf_import_from_vrf(bgp, vrf_bgp, vrf_name, afi, SAFI_UNICAST);
	return NB_OK;
}

int bgp_gaf_vpn_import_vrf_list_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp, *vrf_bgp;
	afi_t afi;
	safi_t safi;
	const char *vrf_name;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, NULL, 0) < 0)
		return NB_ERR;

	vrf_name = yang_dnode_get_string(args->dnode, "./vrf");
	if (!strcmp(vrf_name, VRF_DEFAULT_NAME))
		vrf_bgp = bgp_get_default();
	else
		vrf_bgp = bgp_lookup_by_name_filter(vrf_name, false);

	vrf_unimport_from_vrf(bgp, vrf_bgp, vrf_name, afi, SAFI_UNICAST);
	return NB_OK;
}

/* --- flowspec redirect-rt (af_routetarget_import) ----------------- */

static int gaf_vpn_redirect_parse(const struct lyd_node *dnode, struct ecommunity **ecom_out,
				  char *errmsg, size_t errmsg_len)
{
	struct ecommunity *ecom = NULL, *add;
	char *str, *tok, *save = NULL;
	bool rt6;

	*ecom_out = NULL;
	rt6 = yang_dnode_exists(dnode, "../redirect-rt-ipv6") &&
	      yang_dnode_get_bool(dnode, "../redirect-rt-ipv6");

	if (!yang_dnode_exists(dnode, "../redirect-rt"))
		return 0;

	str = XSTRDUP(MTYPE_TMP, yang_dnode_get_string(dnode, "../redirect-rt"));
	for (tok = strtok_r(str, " \t", &save); tok; tok = strtok_r(NULL, " \t", &save)) {
		add = rt6 ? ecommunity_str2com_ipv6(tok, ECOMMUNITY_ROUTE_TARGET, 0)
			  : ecommunity_str2com(tok, ECOMMUNITY_ROUTE_TARGET, 0);
		if (!add) {
			if (ecom)
				ecommunity_free(&ecom);
			XFREE(MTYPE_TMP, str);
			snprintfrr(errmsg, errmsg_len, "malformed route-target");
			return -1;
		}
		if (ecom) {
			ecommunity_merge(ecom, add);
			ecommunity_free(&add);
		} else {
			ecom = add;
		}
	}
	XFREE(MTYPE_TMP, str);

	*ecom_out = ecom;
	return 0;
}

static int gaf_vpn_redirect_apply(const struct lyd_node *dnode, char *errmsg, size_t errmsg_len)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct ecommunity *ecom = NULL;

	if (gaf_af_lookup(dnode, 3, &bgp, &afi, &safi, errmsg, errmsg_len) < 0)
		return -1;
	if (gaf_vpn_redirect_parse(dnode, &ecom, errmsg, errmsg_len) < 0)
		return -1;

	if (bgp->vpn_policy[afi].import_redirect_rtlist)
		ecommunity_free(&bgp->vpn_policy[afi].import_redirect_rtlist);
	bgp->vpn_policy[afi].import_redirect_rtlist = ecom;
	return 0;
}

int bgp_gaf_vpn_redirect_rt_modify(struct nb_cb_modify_args *args)
{
	struct ecommunity *ecom = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_vpn_v2v_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure import vrf commands before using vpn commands");
			return NB_ERR_VALIDATION;
		}
		if (gaf_vpn_redirect_parse(args->dnode, &ecom, args->errmsg, args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		if (ecom)
			ecommunity_free(&ecom);
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_vpn_redirect_apply(args->dnode, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	return NB_OK;
}

int bgp_gaf_vpn_redirect_rt_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, NULL, 0) < 0)
		return NB_ERR;
	if (bgp->vpn_policy[afi].import_redirect_rtlist)
		ecommunity_free(&bgp->vpn_policy[afi].import_redirect_rtlist);
	bgp->vpn_policy[afi].import_redirect_rtlist = NULL;
	return NB_OK;
}

int bgp_gaf_vpn_redirect_rt_ipv6_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_vpn_v2v_in_candidate(args->dnode)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unconfigure import vrf commands before using vpn commands");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	/* rebuild the redirect list under the new rt6 interpretation */
	if (gaf_vpn_redirect_apply(args->dnode, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	return NB_OK;
}

/* ================================================================== */
/* G9: upa global (upa_*_global DEFUNs, bgp_vty.c:24449+)              */
/* ================================================================== */

/*
 * drop re-origination helper: when global UPA is enabled a D-bit
 * change must re-originate the announcements (mirrors upa_drop_global).
 */
static void gaf_upa_drop_apply(struct bgp *bgp, afi_t afi, safi_t safi, bool drop)
{
	bgp->upa_drop[afi][safi] = drop;
	if (bgp->upa_enabled[afi][safi]) {
		bgp_upa_withdraw_global(bgp, afi, safi);
		bgp_upa_originate_global(bgp, afi, safi);
	}
}

int bgp_gaf_upa_max_routes_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	bgp->upa_max_routes[afi][safi] = yang_dnode_get_uint32(args->dnode, NULL);
	return NB_OK;
}

int bgp_gaf_upa_drop_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	gaf_upa_drop_apply(bgp, afi, safi, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

int bgp_gaf_upa_originate_all_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE: {
		afi_t v_afi;
		safi_t v_safi;

		/* candidate-only (lesson B-1 S061): no runtime lookup */
		if (!yang_dnode_exists(args->dnode, "../../../afi-safi-name") ||
		    bgp_nb_af_id_to_afi_safi(yang_dnode_get_string(args->dnode,
								   "../../../afi-safi-name"),
					     &v_afi, &v_safi) < 0 ||
		    v_safi != SAFI_UNICAST) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "global UPA origination is only supported for unicast SAFI");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 3, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	enable = yang_dnode_get_bool(args->dnode, NULL);

	if (enable && !bgp->upa_enabled[afi][safi]) {
		bgp->upa_enabled[afi][safi] = true;
		bgp_upa_originate_global(bgp, afi, safi);
	} else if (!enable && bgp->upa_enabled[afi][safi]) {
		bgp_upa_withdraw_global(bgp, afi, safi);
		bgp->upa_enabled[afi][safi] = false;
	}
	return NB_OK;
}

/* ================================================================== */
/* G10: prefer-global                                                  */
/* ================================================================== */

int bgp_gaf_prefer_global_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_af_lookup(args->dnode, 2, &bgp, &afi, &safi, args->errmsg,
				  args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		/* mirrors bgp_nexthop_prefer_global_supported() */
		if (afi != AFI_IP6 || (safi != SAFI_UNICAST && safi != SAFI_MULTICAST &&
				       safi != SAFI_LABELED_UNICAST)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "nexthop prefer-global is ipv6-unicast/multicast/labeled only");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (gaf_af_lookup(args->dnode, 2, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (bgp->nexthop_prefer_global[afi][safi] != enable) {
		bgp->nexthop_prefer_global[afi][safi] = enable;
		bgp_clear_soft_in(bgp, afi, safi);
	}
	return NB_OK;
}


/* S063 interim: leaf-list bindings required for boot-valid callback
 * sets; runtime semantics land with the use-multiple-paths and
 * default-afi-safi wiring rounds (registered debt in the caderno).
 */
/* Per-instance (non-AF) lookup from a global/* dnode. */
static struct bgp *gaf_bgp_lookup(const struct lyd_node *dnode, unsigned int depth_to_cpp)
{
	char vrf_xpath[64];
	const char *vrf_key;

	vrf_xpath[0] = '\0';
	for (unsigned int i = 0; i < depth_to_cpp; i++)
		strlcat(vrf_xpath, "../", sizeof(vrf_xpath));
	strlcat(vrf_xpath, "vrf", sizeof(vrf_xpath));

	vrf_key = yang_dnode_get_string(dnode, "%s", vrf_xpath);
	return bgp_lookup_by_name(bgp_nb_vrf_to_name(vrf_key));
}

int bgp_gaf_cluster_length_list_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_af_lookup(args->dnode, 4, &bgp, &afi, &safi, args->errmsg,
				  args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	if (gaf_af_lookup(args->dnode, 4, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;

	/* equal-cluster-length companion of maximum-paths ibgp: re-apply
	 * the current ibgp path count with the new same_clusterlen flag
	 * (mirrors bgp_maximum_paths_set).
	 */
	bgp_maximum_paths_set(bgp, afi, safi, BGP_PEER_IBGP, bgp->maxpaths[afi][safi].maxpaths_ibgp,
			      yang_dnode_get_bool(args->dnode, NULL));
	bgp_recalculate_all_bestpaths(bgp);

	return NB_OK;
}

int bgp_gaf_cluster_length_list_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	if (gaf_af_lookup(args->dnode, 4, &bgp, &afi, &safi, args->errmsg, args->errmsg_len) < 0)
		return NB_OK;

	bgp_maximum_paths_set(bgp, afi, safi, BGP_PEER_IBGP,
			      bgp->maxpaths[afi][safi].maxpaths_ibgp, false);
	bgp_recalculate_all_bestpaths(bgp);

	return NB_OK;
}

/* default-afi-safi is a leaf-list of afi-safi names: maps to the
 * `bgp default <afi-safi>` CLI per-entry.
 */
static int gaf_default_af_parse(const char *afi_safi, afi_t *afi, safi_t *safi, char *errmsg,
				size_t errmsg_len)
{
	char afi_safi_str[64];
	char *tok = NULL;

	strlcpy(afi_safi_str, afi_safi, sizeof(afi_safi_str));
	char *afi_str = strtok_r(afi_safi_str, "-", &tok);
	char *safi_str = strtok_r(NULL, "-", &tok);

	if (!afi_str || !safi_str)
		goto bad;

	*afi = bgp_vty_afi_from_str(afi_str);
	if (*afi == AFI_MAX)
		goto bad;

	if (strmatch(safi_str, "labeled"))
		*safi = bgp_vty_safi_from_str("labeled-unicast");
	else
		*safi = bgp_vty_safi_from_str(safi_str);
	if (*safi == SAFI_MAX)
		goto bad;

	return 0;
bad:
	snprintfrr(errmsg, errmsg_len, "unknown afi-safi '%s'", afi_safi);
	return -1;
}

int bgp_global_default_afi_safi_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (gaf_default_af_parse(yang_dnode_get_string(args->dnode, NULL), &afi, &safi,
					 args->errmsg, args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		bgp = gaf_bgp_lookup(args->dnode, 3);
		if (!bgp) {
			snprintfrr(args->errmsg, args->errmsg_len, "bgp instance not found");
			return NB_ERR_VALIDATION;
		}
		if ((safi == SAFI_LABELED_UNICAST && bgp->default_af[afi][SAFI_UNICAST]) ||
		    (safi == SAFI_UNICAST && bgp->default_af[afi][SAFI_LABELED_UNICAST])) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unicast and labeled-unicast are mutually exclusive");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = gaf_bgp_lookup(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (gaf_default_af_parse(yang_dnode_get_string(args->dnode, NULL), &afi, &safi,
				 args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;

	bgp->default_af[afi][safi] = true;

	return NB_OK;
}

int bgp_global_default_afi_safi_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = gaf_bgp_lookup(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	if (gaf_default_af_parse(yang_dnode_get_string(args->dnode, NULL), &afi, &safi,
				 args->errmsg, args->errmsg_len) < 0)
		return NB_OK;

	bgp->default_af[afi][safi] = false;

	return NB_OK;
}
