// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP northbound — callback implementations.
 *
 * Copyright (C) 2026 FRRouting
 */

#include <zebra.h>

#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/routemap.h"
#include "lib/yang.h"
#include "lib/yang_wrappers.h"
#include "lib/vrf.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_nb_bmp.h"
#include "bgpd/bgp_conditional_adv.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_ls.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_vty.h"
#include "lib/vxlan.h"

/* ------------------------------------------------------------------------ */
/* control-plane-protocol context (frr-bgp:bgp container)                    */
/* ------------------------------------------------------------------------ */

/*
 * Map a YANG vrf key value ("default" or a vrf name) to the bgp instance
 * name expected by bgp_get()/bgp_lookup_by_name(), which is NULL for the
 * default vrf.
 */
static const char *bgp_nb_vrf_to_name(const char *vrf_key)
{
	if (!vrf_key || strmatch(vrf_key, VRF_DEFAULT_NAME))
		return NULL;
	return vrf_key;
}

/*
 * Map the YANG vrf key to a bgp_instance_type. View instances are signalled
 * via a separate `instance-type-view` leaf (handled separately); here we
 * default to VRF when vrf != "default", DEFAULT otherwise. View detection
 * is added when that leaf's callback lands.
 */
static enum bgp_instance_type bgp_nb_inst_type(const char *vrf_key)
{
	if (!vrf_key || strmatch(vrf_key, VRF_DEFAULT_NAME))
		return BGP_INSTANCE_TYPE_DEFAULT;
	return BGP_INSTANCE_TYPE_VRF;
}

/*
 * Look up the bgp instance owning a given dnode by walking up to the
 * control-plane-protocol list entry and reading its `vrf` key.
 *
 * Returns NULL if no instance exists for that vrf yet. Callers in modify
 * callbacks should treat NULL as NB_ERR (the parent CREATE should have
 * already run; if it didn't, the schema/lifecycle is broken).
 *
 * `depth` is the number of `../` hops from `dnode` to the
 * control-plane-protocol entry. Examples:
 *   - `bgp` container          -> 1 (`../`)
 *   - `bgp/global`             -> 2 (`../../`)
 *   - `bgp/global/<leaf>`      -> 3 (`../../../`)
 *   - `bgp/global/<container>/<leaf>` -> 4
 */
static struct bgp *bgp_nb_lookup_from_dnode(const struct lyd_node *dnode,
					    unsigned int depth_to_cpp)
{
	char vrf_xpath[64];
	const char *vrf_key;

	/* Build "../" * depth + "vrf". */
	vrf_xpath[0] = '\0';
	for (unsigned int i = 0; i < depth_to_cpp; i++)
		strlcat(vrf_xpath, "../", sizeof(vrf_xpath));
	strlcat(vrf_xpath, "vrf", sizeof(vrf_xpath));

	vrf_key = yang_dnode_get_string(dnode, "%s", vrf_xpath);
	return bgp_lookup_by_name(bgp_nb_vrf_to_name(vrf_key));
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp
 *
 * Triggered when a YANG client creates the bgp presence container. Wraps
 * bgp_get() so the struct bgp lifecycle is identical to what the legacy
 * DEFUN(router_bgp) sets up. Idempotent: if the instance already exists
 * (e.g. created earlier via legacy CLI), associates the existing pointer
 * with the dnode and returns NB_OK.
 *
 * handles the default and per-VRF cases. View instances
 * (`instance-type-view = true`) are not yet supported — returns
 * NB_ERR_VALIDATION when that leaf is set. Wiring for the
 * view-type leaf into bgp_get()'s BGP_INSTANCE_TYPE_VIEW path.
 */
int bgp_router_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *vrf_key;
	as_t as;
	const char *bgp_name;
	enum bgp_instance_type inst_type;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/*
		 * Reject view-type instances — we don't
		 * yet plumb the BGP_INSTANCE_TYPE_VIEW path through NB.
		 * Detect it via the optional instance-type-view leaf.
		 */
		if (yang_dnode_exists(args->dnode, "global/instance-type-view")
		    && yang_dnode_get_bool(args->dnode,
					    "global/instance-type-view")) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "view instances not yet supported via NB; "
				   "use vtysh `router bgp ASN view NAME`");
			return NB_ERR_VALIDATION;
		}
		/*
		 * If this is a fresh-creation path (no existing struct bgp for
		 * this vrf key), require local-as to be present in the same
		 * transaction. Catching this at validate prevents sibling
		 * leaf callbacks from starting on a half-built instance.
		 */
		vrf_key = yang_dnode_get_string(args->dnode, "../vrf");
		bgp_name = bgp_nb_vrf_to_name(vrf_key);
		if (!bgp_lookup_by_name(bgp_name)
		    && !yang_dnode_exists(args->dnode, "global/local-as")) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "local-as is mandatory when creating a new BGP instance via NB");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;

	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;

	case NB_EV_APPLY:
		break;
	}

	vrf_key = yang_dnode_get_string(args->dnode, "../vrf");
	bgp_name = bgp_nb_vrf_to_name(vrf_key);
	inst_type = bgp_nb_inst_type(vrf_key);

	/*
	 * If the instance already exists (legacy DEFUN(router_bgp) ran
	 * earlier, or a sibling NB write created it during this transaction),
	 * just associate the existing pointer with this dnode and we're done.
	 */
	bgp = bgp_lookup_by_name(bgp_name);
	if (bgp) {
		nb_running_set_entry(args->dnode, bgp);
		return NB_OK;
	}

	/*
	 * Fresh creation. local-as presence was already validated at
	 * NB_EV_VALIDATE; an internal bug if it's missing now.
	 */
	if (!yang_dnode_exists(args->dnode, "global/local-as")) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "internal error: local-as missing at apply; validate stage skipped?");
		return NB_ERR;
	}
	as = (as_t)yang_dnode_get_uint32(args->dnode, "global/local-as");

	/*
	 * bgp_get_vty (no vty involved despite the name) layers the
	 * frr-defaults profile flags (RFC 8212 ebgp-requires-policy,
	 * enforce-first-as, suppress-duplicates, ...) on top of bgp_get()
	 * for freshly created instances, exactly like DEFUN(router_bgp).
	 * Plain bgp_get() would leave an NB-created instance without the
	 * secure defaults: mgmtd never delivers default-valued leaves
	 * (no diff), so nothing else applies them.
	 */
	ret = bgp_get_vty(&bgp, &as, bgp_name, inst_type, NULL,
			  ASNOTATION_UNDEFINED);
	if (ret < 0 || !bgp) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "bgp_get_vty() failed for AS %u vrf %s (ret %d)", as,
			   vrf_key, ret);
		return NB_ERR;
	}

	nb_running_set_entry(args->dnode, bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp
 */
int bgp_router_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_unset_entry(args->dnode);
	if (!bgp) {
		/*
		 * Possible if the bgp instance was created via legacy DEFUN
		 * and never associated with this dnode. Fall back to a vrf
		 * lookup so the destroy still succeeds.
		 */
		bgp = bgp_nb_lookup_from_dnode(args->dnode, 1);
		if (!bgp)
			return NB_OK; /* nothing to do */
	}

	bgp_delete(bgp);
	return NB_OK;
}

/* ------------------------------------------------------------------------ */
/* global leaves */
/* ------------------------------------------------------------------------ */

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/router-id
 *
 * The leaf type is yang:dotted-quad (RFC 6991). The internal setter
 * `bgp_router_id_static_set()` triggers session-state side effects, so
 * we run it only in NB_EV_APPLY.
 */
int bgp_global_router_id_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct in_addr router_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	/* router-id leaf -> 3 hops to control-plane-protocol entry. */
	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "bgp instance not found for router-id modify");
		return NB_ERR;
	}

	yang_dnode_get_ipv4(&router_id, args->dnode, NULL);
	bgp_router_id_static_set(bgp, router_id);
	return NB_OK;
}

int bgp_global_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct in_addr zero;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK; /* parent destroy will follow */

	zero.s_addr = INADDR_ANY;
	bgp_router_id_static_set(bgp, zero);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/default-shutdown
 *
 * Maps directly to bgp->autoshutdown. YANG default false matches the
 * internal default (autoshutdown=0 at init time).
 */
int bgp_global_default_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp->autoshutdown = yang_dnode_get_bool(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_default_shutdown_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->autoshutdown = false;
	return NB_OK;
}

/*
 * Boolean flag-toggle template: a leaf maps directly to one bit in
 * `bgp->flags`. `value=true` sets the flag, anything else clears it,
 * and the destroy callback clears it. Used by show-hostname and
 * show-nexthop-hostname (and any future leaf with identical semantics).
 */
static int bgp_global_flag_toggle_modify(struct nb_cb_modify_args *args,
					  uint64_t flag, unsigned int depth)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, depth);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, flag);
	else
		UNSET_FLAG(bgp->flags, flag);
	return NB_OK;
}

static int bgp_global_flag_toggle_destroy(struct nb_cb_destroy_args *args,
					   uint64_t flag, unsigned int depth)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, depth);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, flag);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/show-hostname
 *
 * YANG default false matches the absent-flag default in bgp->flags.
 */
int bgp_global_show_hostname_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args, BGP_FLAG_SHOW_HOSTNAME, 3);
}

int bgp_global_show_hostname_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args, BGP_FLAG_SHOW_HOSTNAME, 3);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/show-nexthop-hostname
 */
int bgp_global_show_nexthop_hostname_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args,
					     BGP_FLAG_SHOW_NEXTHOP_HOSTNAME,
					     3);
}

int bgp_global_show_nexthop_hostname_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args,
					      BGP_FLAG_SHOW_NEXTHOP_HOSTNAME,
					      3);
}

/*
 * Boolean flag-toggle with bestpath recompute side-effect. Same shape as
 * bgp_global_flag_toggle_modify but also calls
 * bgp_recalculate_all_bestpaths() after the flag change. Used for any
 * leaf under route-selection-options that influences bestpath.
 */
static int bgp_global_flag_bestpath_modify(struct nb_cb_modify_args *args,
					    uint64_t flag, unsigned int depth)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, depth);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, flag);
	else
		UNSET_FLAG(bgp->flags, flag);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

static int bgp_global_flag_bestpath_destroy(struct nb_cb_destroy_args *args,
					     uint64_t flag, unsigned int depth)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, depth);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, flag);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-selection-options/always-compare-med
 *
 * Depth 4 (extra hop through route-selection-options container).
 */
int bgp_global_always_compare_med_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args,
					       BGP_FLAG_ALWAYS_COMPARE_MED,
					       4);
}

int bgp_global_always_compare_med_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args,
						BGP_FLAG_ALWAYS_COMPARE_MED,
						4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-selection-options/external-compare-router-id
 *
 * (yang leaf `external-compare-router-id` <-> CLI `bgp bestpath compare-routerid`)
 */
int bgp_global_external_compare_router_id_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args, BGP_FLAG_COMPARE_ROUTER_ID,
					       4);
}

int bgp_global_external_compare_router_id_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args,
						BGP_FLAG_COMPARE_ROUTER_ID,
						4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-selection-options/ignore-as-path-length
 *
 * (yang leaf `ignore-as-path-length` <-> CLI `bgp bestpath as-path ignore`)
 */
int bgp_global_ignore_as_path_length_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args, BGP_FLAG_ASPATH_IGNORE, 4);
}

int bgp_global_ignore_as_path_length_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args, BGP_FLAG_ASPATH_IGNORE,
						4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-selection-options/aspath-confed
 *
 * (yang leaf `aspath-confed` <-> CLI `bgp bestpath as-path confed`)
 */
int bgp_global_aspath_confed_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args, BGP_FLAG_ASPATH_CONFED, 4);
}

int bgp_global_aspath_confed_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args, BGP_FLAG_ASPATH_CONFED,
						4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-selection-options/confed-med
 */
int bgp_global_confed_med_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args, BGP_FLAG_MED_CONFED, 4);
}

int bgp_global_confed_med_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args, BGP_FLAG_MED_CONFED, 4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-selection-options/missing-as-worst-med
 */
int bgp_global_missing_as_worst_med_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args,
					       BGP_FLAG_MED_MISSING_AS_WORST,
					       4);
}

int bgp_global_missing_as_worst_med_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args,
						BGP_FLAG_MED_MISSING_AS_WORST,
						4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/global-neighbor-config/log-neighbor-changes
 *
 * Depth 4 (extra hop through global-neighbor-config). Pure flag toggle.
 */
int bgp_global_log_neighbor_changes_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args,
					     BGP_FLAG_LOG_NEIGHBOR_CHANGES, 4);
}

int bgp_global_log_neighbor_changes_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args,
					      BGP_FLAG_LOG_NEIGHBOR_CHANGES, 4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/import-check
 *
 * Depth 3. Side effect: calls bgp_static_redo_import_check() which is
 * idempotent — safe to invoke on every APPLY whether or not the flag
 * actually changed.
 */
int bgp_global_import_check_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
	bgp_static_redo_import_check(bgp);
	return NB_OK;
}

int bgp_global_import_check_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
	bgp_static_redo_import_check(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/global-neighbor-config/packet-quanta-config/wpkt-quanta
 *
 * Depth 5 (global > global-neighbor-config > packet-quanta-config > leaf).
 * Uses atomic store because the value is read from a writer thread.
 */
int bgp_global_wpkt_quanta_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint32_t quanta;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 5);
	if (!bgp)
		return NB_ERR;

	quanta = yang_dnode_get_uint32(args->dnode, NULL);
	atomic_store_explicit(&bgp->wpkt_quanta, quanta, memory_order_relaxed);
	return NB_OK;
}

int bgp_global_wpkt_quanta_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 5);
	if (!bgp)
		return NB_OK;

	atomic_store_explicit(&bgp->wpkt_quanta, BGP_WRITE_PACKET_MAX,
			      memory_order_relaxed);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/global-neighbor-config/packet-quanta-config/rpkt-quanta
 */
int bgp_global_rpkt_quanta_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint32_t quanta;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 5);
	if (!bgp)
		return NB_ERR;

	quanta = yang_dnode_get_uint32(args->dnode, NULL);
	atomic_store_explicit(&bgp->rpkt_quanta, quanta, memory_order_relaxed);
	return NB_OK;
}

int bgp_global_rpkt_quanta_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 5);
	if (!bgp)
		return NB_OK;

	atomic_store_explicit(&bgp->rpkt_quanta, BGP_READ_PACKET_MAX,
			      memory_order_relaxed);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/global-update-group-config/coalesce-time
 *
 * Setting this leaf disables the heuristic auto-coalesce (mirrors the
 * legacy DEFUN behaviour). Destroy re-enables heuristic mode and restores
 * the BGP_DEFAULT_SUBGROUP_COALESCE_TIME baseline.
 */
int bgp_global_coalesce_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->heuristic_coalesce = false;
	bgp->coalesce_time = yang_dnode_get_uint32(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_coalesce_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->heuristic_coalesce = true;
	bgp->coalesce_time = BGP_DEFAULT_SUBGROUP_COALESCE_TIME;
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/global-update-group-config/subgroup-pkt-queue-size
 */
int bgp_global_subgroup_pkt_queue_size_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp_default_subgroup_pkt_queue_max_set(
		bgp, yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

int bgp_global_subgroup_pkt_queue_size_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp_default_subgroup_pkt_queue_max_unset(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/confederation/identifier
 *
 * Depth 4 (../../../vrf from /confederation/identifier).
 * bgp_confederation_id_set wants both the as_t and a textual form for
 * as-dot rendering; we synthesise the textual form with snprintf.
 */
int bgp_global_confederation_identifier_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	as_t as;
	char as_str[16];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	as = (as_t)yang_dnode_get_uint32(args->dnode, NULL);
	snprintfrr(as_str, sizeof(as_str), "%u", as);
	bgp_confederation_id_set(bgp, as, as_str);
	return NB_OK;
}

int bgp_global_confederation_identifier_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp_confederation_id_unset(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/confederation/member-as  (leaf-list)
 *
 * Depth from leaf-list entry to CPP = 4. Each entry is one AS number.
 */
int bgp_global_confederation_member_as_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	as_t as;
	char as_buf[16];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	as = (as_t)yang_dnode_get_uint32(args->dnode, NULL);
	snprintfrr(as_buf, sizeof(as_buf), "%u", as);
	bgp_confederation_peers_add(bgp, as, as_buf);
	return NB_OK;
}

int bgp_global_confederation_member_as_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	as_t as;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	as = (as_t)yang_dnode_get_uint32(args->dnode, NULL);
	bgp_confederation_peers_remove(bgp, as);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/minimum-holdtime
 *
 * Depth 3. Direct assignment to bgp->default_min_holdtime; no side effects.
 * Default on destroy: 0 (no minimum).
 */
int bgp_global_minimum_holdtime_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->default_min_holdtime = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_minimum_holdtime_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->default_min_holdtime = 0;
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/allow-martian-nexthop
 */
int bgp_global_allow_martian_nexthop_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp->allow_martian = yang_dnode_get_bool(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_allow_martian_nexthop_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->allow_martian = false;
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/use-underlays-nexthop-weight
 *
 * Maps to BGP_FLAG_USE_RECURSIVE_WEIGHT — when set, BGP propagates the
 * underlay nexthop weight up to Zebra during recursive nexthop resolution.
 */
int bgp_global_use_underlays_nexthop_weight_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args,
					     BGP_FLAG_USE_RECURSIVE_WEIGHT, 3);
}

int bgp_global_use_underlays_nexthop_weight_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args,
					      BGP_FLAG_USE_RECURSIVE_WEIGHT, 3);
}

/*
 * XPath:
 *   .../bgp/global/route-reflector/allow-outbound-policy
 *
 * Depth 4 (route-reflector container hop). Side effects:
 * `update_group_announce_rrclients` (regenerates rr-client updates) +
 * vty-less soft-out clear.
 */
int bgp_global_route_reflector_allow_outbound_policy_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
	update_group_announce_rrclients(bgp);
	bgp_clear_star_soft_out_quiet(bgp);
	return NB_OK;
}

int bgp_global_route_reflector_allow_outbound_policy_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
	update_group_announce_rrclients(bgp);
	bgp_clear_star_soft_out_quiet(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/bgp-ls-distribute  (presence container)
 *
 * Presence-container creation enables BGP-LS topology distribution.
 * Destroy disables and withdraws all NLRIs.
 */
int bgp_global_bgp_ls_distribute_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 7);
	if (!bgp)
		return NB_ERR;

	if (!bgp->ls_info) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "BGP-LS not initialized for this instance");
		return NB_ERR;
	}

	/*
	 * instance-id (if present) is handled by its own modify callback, so
	 * here we only flip the enable bit and trigger an export. If the
	 * client writes instance-id in the same transaction the export will
	 * be re-done with the new value after modify runs.
	 */
	bgp->ls_info->enable_distribution = true;
	(void)bgp_ls_export_bgp_topology(bgp);
	return NB_OK;
}

int bgp_global_bgp_ls_distribute_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 7);
	if (!bgp || !bgp->ls_info)
		return NB_OK;

	bgp_ls_withdraw_all(bgp);
	bgp->ls_info->enable_distribution = false;
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/afi-safis/afi-safi/link-state/distribute/
 *     bgp-fabric-link-state/instance-id
 *
 * Depth 8. If distribution is already enabled and the instance-id changes,
 * withdraw existing NLRIs then re-export with the new id.
 */
int bgp_global_bgp_ls_distribute_instance_id_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint64_t new_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 8);
	if (!bgp || !bgp->ls_info)
		return NB_ERR;

	new_id = yang_dnode_get_uint64(args->dnode, NULL);
	if (bgp->ls_info->enable_distribution &&
	    bgp->ls_info->instance_id != new_id)
		bgp_ls_withdraw_all(bgp);

	bgp->ls_info->instance_id = new_id;
	if (bgp->ls_info->enable_distribution)
		(void)bgp_ls_export_bgp_topology(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/afi-safis/afi-safi/{ipv4,ipv6}-unicast/
 *     redistribution-list[route-type][route-instance]
 *
 * The schema only places the list inside the two unicast containers,
 * so the AFI comes straight from the afi-safi identity. ups_to_af is
 * the hop count from dnode to the afi-safi list entry (2 for the list
 * entry itself, 3 for its metric/rmap-policy-import leaves); the
 * control-plane-protocol node sits 4 hops above that.
 */
static int bgp_nb_redist_lookup(const struct lyd_node *dnode, int ups_to_af,
				struct bgp **bgp_out, afi_t *afi_out,
				int *type_out, unsigned short *instance_out)
{
	static const char *const af_rel[] = { NULL, "../", "../../",
					      "../../../" };
	static const char *const list_rel[] = { NULL, "", "", "../" };
	const char *afi_safi_id;
	char rel_xpath[64];
	struct bgp *bgp;

	assert(ups_to_af >= 2 && ups_to_af <= 3);

	bgp = bgp_nb_lookup_from_dnode(dnode, ups_to_af + 4);
	if (!bgp)
		return -1;

	snprintfrr(rel_xpath, sizeof(rel_xpath), "%safi-safi-name",
		   af_rel[ups_to_af]);
	afi_safi_id = yang_dnode_get_string(dnode, "%s", rel_xpath);
	if (!afi_safi_id)
		return -1;
	if (strstr(afi_safi_id, "ipv4-unicast"))
		*afi_out = AFI_IP;
	else if (strstr(afi_safi_id, "ipv6-unicast"))
		*afi_out = AFI_IP6;
	else
		return -1;

	snprintfrr(rel_xpath, sizeof(rel_xpath), "%sroute-type",
		   list_rel[ups_to_af]);
	*type_out = yang_dnode_get_enum(dnode, "%s", rel_xpath);
	snprintfrr(rel_xpath, sizeof(rel_xpath), "%sroute-instance",
		   list_rel[ups_to_af]);
	*instance_out = yang_dnode_get_uint16(dnode, "%s", rel_xpath);
	*bgp_out = bgp;
	return 0;
}

int bgp_global_af_redistribution_list_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	int type;
	unsigned short instance;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (yang_dnode_get_enum(args->dnode, "route-type") ==
		    ZEBRA_ROUTE_BGP) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "cannot redistribute bgp into bgp");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_redist_lookup(args->dnode, 2, &bgp, &afi, &type,
				 &instance) < 0)
		return NB_ERR;
	bgp_redist_add(bgp, afi, type, instance);
	if (bgp_redistribute_set(bgp, afi, type, instance, false) !=
	    CMD_SUCCESS) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "failed to register redistribution with zebra");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_global_af_redistribution_list_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	int type;
	unsigned short instance;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_redist_lookup(args->dnode, 2, &bgp, &afi, &type,
				 &instance) < 0)
		return NB_OK;
	bgp_redistribute_unset(bgp, afi, type, instance);
	return NB_OK;
}

int bgp_global_af_redistribution_metric_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgp_redist *red;
	afi_t afi;
	int type;
	unsigned short instance;
	bool changed;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_redist_lookup(args->dnode, 3, &bgp, &afi, &type,
				 &instance) < 0)
		return NB_ERR;
	red = bgp_redist_lookup(bgp, afi, type, instance);
	if (!red)
		return NB_ERR;
	changed = bgp_redistribute_metric_set(bgp, red, afi, type,
					      yang_dnode_get_uint32(args->dnode,
								    NULL));
	(void)bgp_redistribute_set(bgp, afi, type, instance, changed);
	return NB_OK;
}

int bgp_global_af_redistribution_metric_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgp_redist *red;
	afi_t afi;
	int type;
	unsigned short instance;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_redist_lookup(args->dnode, 3, &bgp, &afi, &type,
				 &instance) < 0)
		return NB_OK;
	red = bgp_redist_lookup(bgp, afi, type, instance);
	if (!red || !red->redist_metric_flag)
		return NB_OK;
	red->redist_metric_flag = 0;
	red->redist_metric = 0;
	(void)bgp_redistribute_set(bgp, afi, type, instance, true);
	return NB_OK;
}

int bgp_global_af_redistribution_rmap_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgp_redist *red;
	afi_t afi;
	int type;
	unsigned short instance;
	const char *name;
	bool changed;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_redist_lookup(args->dnode, 3, &bgp, &afi, &type,
				 &instance) < 0)
		return NB_ERR;
	red = bgp_redist_lookup(bgp, afi, type, instance);
	if (!red)
		return NB_ERR;
	name = yang_dnode_get_string(args->dnode, NULL);
	changed = bgp_redistribute_rmap_set(red, name,
					    route_map_lookup_by_name(name));
	(void)bgp_redistribute_set(bgp, afi, type, instance, changed);
	return NB_OK;
}

int bgp_global_af_redistribution_rmap_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgp_redist *red;
	afi_t afi;
	int type;
	unsigned short instance;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_redist_lookup(args->dnode, 3, &bgp, &afi, &type,
				 &instance) < 0)
		return NB_OK;
	red = bgp_redist_lookup(bgp, afi, type, instance);
	if (!red || !red->rmap.name)
		return NB_OK;
	XFREE(MTYPE_ROUTE_MAP_NAME, red->rmap.name);
	route_map_counter_decrement(red->rmap.map);
	red->rmap.map = NULL;
	(void)bgp_redistribute_set(bgp, afi, type, instance, true);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/route-selection-options/bestpath-aigp
 */
int bgp_global_bestpath_aigp_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args, BGP_FLAG_COMPARE_AIGP, 4);
}

int bgp_global_bestpath_aigp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args, BGP_FLAG_COMPARE_AIGP, 4);
}

/*
 * XPath:
 *   .../bgp/global/route-selection-options/bestpath-use-imported-attributes
 */
int bgp_global_bestpath_use_imported_attributes_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args,
				BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS, 4);
}

int bgp_global_bestpath_use_imported_attributes_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args,
				BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS, 4);
}

/*
 * XPath:
 *   .../bgp/global/global-neighbor-config/dynamic-neighbors-limit
 *
 * Depth 4. Per `bgp_listen_limit_set` signature, limit is `int`.
 */
int bgp_global_dynamic_neighbors_limit_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp_listen_limit_set(bgp,
			     (int)yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

int bgp_global_dynamic_neighbors_limit_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp_listen_limit_unset(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/med-config  (container)
 *
 * `bgp max-med administrative [VALUE]` and `bgp max-med on-startup TIME [VALUE]`
 * set 4 related fields on bgp atomically (v_maxmed_admin, maxmed_admin_value,
 * v_maxmed_onstartup, maxmed_onstartup_value). YANG models them as separate
 * leaves; we collect them with an `apply_finish` callback on the container
 * and call `bgp_maxmed_update(bgp)` once.
 *
 * Destroy clears admin/onstartup and resets values to defaults.
 */
void bgp_global_med_config_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return;

	bgp->v_maxmed_admin = yang_dnode_exists(args->dnode,
						 "enable-med-admin")
		? (yang_dnode_get_bool(args->dnode, "enable-med-admin") ? 1 : 0)
		: BGP_MAXMED_ADMIN_UNCONFIGURED;
	bgp->maxmed_admin_value = yang_dnode_exists(args->dnode,
						     "max-med-admin")
		? yang_dnode_get_uint32(args->dnode, "max-med-admin")
		: BGP_MAXMED_VALUE_DEFAULT;
	bgp->v_maxmed_onstartup = yang_dnode_exists(args->dnode,
						     "max-med-onstart-up-time")
		? yang_dnode_get_uint32(args->dnode, "max-med-onstart-up-time")
		: BGP_MAXMED_ONSTARTUP_UNCONFIGURED;
	bgp->maxmed_onstartup_value = yang_dnode_exists(
		args->dnode, "max-med-onstart-up-value")
		? yang_dnode_get_uint32(args->dnode, "max-med-onstart-up-value")
		: BGP_MAXMED_VALUE_DEFAULT;

	bgp_maxmed_update(bgp);
	return;
}

int bgp_global_med_config_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->v_maxmed_admin = BGP_MAXMED_ADMIN_UNCONFIGURED;
	bgp->maxmed_admin_value = BGP_MAXMED_VALUE_DEFAULT;
	if (bgp->t_maxmed_onstartup) {
		event_cancel(&bgp->t_maxmed_onstartup);
		bgp->maxmed_onstartup_over = 1;
	}
	bgp->v_maxmed_onstartup = BGP_MAXMED_ONSTARTUP_UNCONFIGURED;
	bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;
	bgp_maxmed_update(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/default-software-version-capability
 *
 * The YANG enum maps to two mutually-exclusive flag bits in bgp->flags:
 *   "disabled"  -> clear both
 *   "old"       -> set BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD
 *   "new"       -> set BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW
 *
 * Bit-collision fix: `BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS` previously
 * shared bit 45 with `BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW`. Moved to
 * bit 47 in `bgpd.h` so this callback no longer flips an unrelated flag.
 */
int bgp_global_default_software_version_capability_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	UNSET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
	UNSET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);

	value = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(value, "old-encoding"))
		SET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
	else if (strmatch(value, "latest-encoding"))
		SET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);
	return NB_OK;
}

int bgp_global_default_software_version_capability_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
	UNSET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/tcp-keepalive  (presence container)
 *
 * apply_finish reads the three child leaves and calls
 * bgp_tcp_keepalive_set() atomically. Destroy calls _unset.
 */
void bgp_global_tcp_keepalive_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return;

	/*
	 * Non-presence container with three optional leaves: the setter
	 * needs all of idle/interval/probes, so anything less (including
	 * a client deleting them to disable keepalives) means unset.
	 */
	if (!yang_dnode_exists(args->dnode, "idle") ||
	    !yang_dnode_exists(args->dnode, "interval") ||
	    !yang_dnode_exists(args->dnode, "probes")) {
		bgp_tcp_keepalive_unset(bgp);
		return;
	}

	bgp_tcp_keepalive_set(bgp,
			      yang_dnode_get_uint16(args->dnode, "idle"),
			      yang_dnode_get_uint16(args->dnode, "interval"),
			      (uint16_t)yang_dnode_get_uint8(args->dnode,
							      "probes"));
	return;
}

/*
 * `timers bgp KEEPALIVE HOLDTIME` legacy DEFUN calls bgp_timers_set with
 * all 4 params (keepalive, holdtime, connect_retry, delayopen). YANG has
 * leaves hold-time, keepalive and connect-retry-interval all under the
 * global/global-config-timers container. Per-leaf modify callback reads
 * all sibling leaves (or uses defaults) and calls the setter. Bit
 * wasteful when 2 leaves change in the same transaction (setter runs
 * twice) but correct in all cases.
 */
static int bgp_global_timers_apply(const struct lyd_node *dnode)
{
	struct bgp *bgp;
	uint32_t keepalive = DFLT_BGP_KEEPALIVE;
	uint32_t holdtime = DFLT_BGP_HOLDTIME;
	uint32_t connect_retry = DFLT_BGP_CONNECT_RETRY;

	bgp = bgp_nb_lookup_from_dnode(dnode, 4);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_exists(dnode, "../keepalive"))
		keepalive = yang_dnode_get_uint16(dnode, "../keepalive");
	if (yang_dnode_exists(dnode, "../hold-time"))
		holdtime = yang_dnode_get_uint16(dnode, "../hold-time");
	if (yang_dnode_exists(dnode, "../connect-retry-interval"))
		connect_retry = yang_dnode_get_uint16(
			dnode, "../connect-retry-interval");

	bgp_timers_set(NULL, bgp, keepalive, holdtime, connect_retry,
		       BGP_DEFAULT_DELAYOPEN);
	return NB_OK;
}

int bgp_global_hold_time_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_global_timers_apply(args->dnode);
}

int bgp_global_hold_time_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_global_timers_apply(args->dnode);
}

int bgp_global_keepalive_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_global_timers_apply(args->dnode);
}

int bgp_global_keepalive_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_global_timers_apply(args->dnode);
}

/*
 * XPath:
 *   .../bgp/global/reject-as-sets
 *
 * Toggles bgp->reject_as_sets and resets all peers so the new policy
 * takes effect on re-establish. Direct field, not a flag bit.
 */
int bgp_global_reject_as_sets_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node, *nnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp->reject_as_sets = yang_dnode_get_bool(args->dnode, NULL);
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		peer_set_last_reset(peer, PEER_DOWN_AS_SETS_REJECT);
		peer_notify_config_change(peer->connection);
	}
	return NB_OK;
}

int bgp_global_reject_as_sets_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node, *nnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->reject_as_sets = false;
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		peer_set_last_reset(peer, PEER_DOWN_AS_SETS_REJECT);
		peer_notify_config_change(peer->connection);
	}
	return NB_OK;
}

/*
 * graceful-restart `enabled` and `graceful-restart-disable` leaves —
 * per-instance only (the CONFIG_NODE/global mode in legacy DEFUNs stays).
 * Direct field/flag toggle on the bgp.
 */
int bgp_global_graceful_restart_enabled_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_RESTART);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_RESTART);
	return NB_OK;
}

int bgp_global_graceful_restart_enabled_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_RESTART);
	return NB_OK;
}

int bgp_global_graceful_restart_restart_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->restart_time = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_graceful_restart_restart_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->restart_time = BGP_DEFAULT_RESTART_TIME;
	return NB_OK;
}

int bgp_global_graceful_restart_selection_deferral_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->select_defer_time = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_graceful_restart_selection_deferral_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->select_defer_time = BGP_DEFAULT_SELECT_DEFERRAL_TIME;
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/administrative-shutdown  (presence container)
 *
 * The leaf carries the enable bit; the when-guarded sibling
 * shutdown-message carries the RFC 8203 text. The modify callback reads
 * both from the candidate tree, so whichever order the transaction
 * applies them in, the net state is right.
 */
int bgp_global_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *msg = NULL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (!yang_dnode_get_bool(args->dnode, NULL)) {
		bgp_shutdown_disable(bgp);
		return NB_OK;
	}

	if (yang_dnode_exists(args->dnode, "../shutdown-message"))
		msg = yang_dnode_get_string(args->dnode,
					    "../shutdown-message");
	bgp_shutdown_enable(bgp, msg);
	return NB_OK;
}

int bgp_global_shutdown_message_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	/* when-guarded by shutdown=true; re-apply with the new message. */
	bgp_shutdown_enable(bgp, yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_global_shutdown_message_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	/*
	 * If the same transaction also cleared the shutdown leaf, its
	 * modify already disabled shutdown -- don't re-enable it here.
	 */
	if (!CHECK_FLAG(bgp->flags, BGP_FLAG_SHUTDOWN))
		return NB_OK;

	bgp_shutdown_enable(bgp, NULL);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/enforce-first-as-global
 *
 * Distinct from neighbor-level enforce-first-as. On change, walks all
 * peers and triggers a soft inbound policy re-evaluation per AFI/SAFI.
 */
int bgp_global_enforce_first_as_global_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node;
	afi_t afi;
	safi_t safi;
	bool enabled;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	enabled = yang_dnode_get_bool(args->dnode, NULL);
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS) == enabled)
		return NB_OK;

	if (enabled)
		SET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer))
		FOREACH_AFI_SAFI (afi, safi)
			peer_on_policy_change(peer, afi, safi, 0);
	return NB_OK;
}

int bgp_global_enforce_first_as_global_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node;
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

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp || !CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS))
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer))
		FOREACH_AFI_SAFI (afi, safi)
			peer_on_policy_change(peer, afi, safi, 0);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/suppress-duplicates
 *
 * Pure flag toggle. YANG default was previously "true" — corrected to
 * "false" in the schema this iteration to match the implementation's
 * legacy CLI default (`no suppress-duplicates` at startup).
 */
int bgp_global_suppress_duplicates_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args, BGP_FLAG_SUPPRESS_DUPLICATES,
					     3);
}

int bgp_global_suppress_duplicates_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args, BGP_FLAG_SUPPRESS_DUPLICATES,
					      3);
}

/*
 * XPath:
 *   .../bgp/global/ebgp-requires-policy
 *
 * Pure flag toggle. YANG default likewise corrected to "false" to match
 * the FRR CLI default.
 */
int bgp_global_ebgp_requires_policy_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args, BGP_FLAG_EBGP_REQUIRES_POLICY,
					     3);
}

int bgp_global_ebgp_requires_policy_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args, BGP_FLAG_EBGP_REQUIRES_POLICY,
					      3);
}

/*
 * XPath:
 *   .../bgp/global/fast-external-failover  (default "true")
 *
 * Inverted-flag mapping: the bgp internal flag BGP_FLAG_NO_FAST_EXT_FAILOVER
 * gates the OPPOSITE semantics — flag SET means fast failover DISABLED.
 * So YANG `true` (= fast failover enabled) maps to flag UNSET, and YANG
 * `false` maps to flag SET.
 */
int bgp_global_fast_external_failover_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		UNSET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	return NB_OK;
}

int bgp_global_fast_external_failover_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	/* Default state matches YANG default "true" → flag UNSET. */
	UNSET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/route-selection-options/deterministic-med
 *
 * VALIDATE-phase reject: cannot disable deterministic-med if any peer is
 * using addpath_type that requires it. Mirrors the legacy DEFUN check.
 * APPLY: flag toggle + bestpath recalc.
 */
int bgp_global_deterministic_med_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	if (args->event == NB_EV_VALIDATE) {
		bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
		if (!bgp)
			return NB_OK; /* parent create handles it */
		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (!enable &&
		    CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED)) {
			struct listnode *node, *nnode;
			struct peer *peer;
			afi_t afi;
			safi_t safi;

			for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
				FOREACH_AFI_SAFI (afi, safi)
					if (bgp_addpath_dmed_required(
						    peer->addpath_type[afi][safi])) {
						snprintfrr(args->errmsg,
							   args->errmsg_len,
							   "deterministic-med cannot be disabled while addpath-tx-bestpath-per-AS is in use");
						return NB_ERR_VALIDATION;
					}
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_global_flag_bestpath_modify(args, BGP_FLAG_DETERMINISTIC_MED,
					       4);
}

int bgp_global_deterministic_med_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args,
						BGP_FLAG_DETERMINISTIC_MED, 4);
}

/*
 * XPath:
 *   .../bgp/global/labeled-unicast-explicit-null
 *
 * Enum → two flag bits (IPV4, IPV6). YANG `both` = set both, `ipv4-only` =
 * set IPV4 only, `ipv6-only` = set IPV6 only, `disabled` = clear both.
 */
int bgp_global_labeled_unicast_explicit_null_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	UNSET_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL);
	UNSET_FLAG(bgp->flags, BGP_FLAG_LU_IPV6_EXPLICIT_NULL);

	value = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(value, "both")) {
		SET_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL);
		SET_FLAG(bgp->flags, BGP_FLAG_LU_IPV6_EXPLICIT_NULL);
	} else if (strmatch(value, "ipv4-only")) {
		SET_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL);
	} else if (strmatch(value, "ipv6-only")) {
		SET_FLAG(bgp->flags, BGP_FLAG_LU_IPV6_EXPLICIT_NULL);
	}
	return NB_OK;
}

int bgp_global_labeled_unicast_explicit_null_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL);
	UNSET_FLAG(bgp->flags, BGP_FLAG_LU_IPV6_EXPLICIT_NULL);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/ipv6-auto-ra
 *
 * Inverted flag mapping (similar to fast-external-failover).
 * YANG `true`  (= auto-RA enabled, default) → BGP_FLAG_IPV6_NO_AUTO_RA UNSET
 * YANG `false` (= auto-RA disabled)         → BGP_FLAG_IPV6_NO_AUTO_RA SET
 *
 * The legacy CLI also supports a CONFIG_NODE form that affects bm->flags;
 * that branch stays in the legacy DEFPY. This NB callback only handles
 * the per-instance form.
 */
int bgp_global_ipv6_auto_ra_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		UNSET_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA);
	return NB_OK;
}

int bgp_global_ipv6_auto_ra_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/route-selection-options/allow-multiple-as
 *
 * Maps to BGP_FLAG_ASPATH_MULTIPATH_RELAX. Note: legacy `no` clears
 * multi-path-as-set too; that's expressed in YANG via the when-clause
 * on multi-path-as-set (becomes invalid when allow-multiple-as=false).
 */
int bgp_global_allow_multiple_as_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args,
				BGP_FLAG_ASPATH_MULTIPATH_RELAX, 4);
}

int bgp_global_allow_multiple_as_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
	UNSET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/route-selection-options/multi-path-as-set
 */
int bgp_global_multi_path_as_set_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args,
				BGP_FLAG_MULTIPATH_RELAX_AS_SET, 4);
}

int bgp_global_multi_path_as_set_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args,
				BGP_FLAG_MULTIPATH_RELAX_AS_SET, 4);
}

/*
 * XPath:
 *   .../bgp/global/route-selection-options/peer-type-multipath-relax
 */
int bgp_global_peer_type_multipath_relax_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args,
				BGP_FLAG_PEERTYPE_MULTIPATH_RELAX, 4);
}

int bgp_global_peer_type_multipath_relax_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args,
				BGP_FLAG_PEERTYPE_MULTIPATH_RELAX, 4);
}

/*
 * XPath:
 *   .../bgp/global/graceful-shutdown/enable
 *
 * Per-instance graceful-shutdown. VALIDATE-phase reject if the global
 * `bm->flags & BM_FLAG_GRACEFUL_SHUTDOWN` is set (matches the legacy
 * DEFUN's check). On APPLY, toggle BGP_FLAG_GRACEFUL_SHUTDOWN and
 * trigger the import/redistribute/soft-clear sequence via the legacy
 * helper (uses vty-less clear variants we added earlier).
 */
int bgp_global_graceful_shutdown_enable_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "per-vrf graceful-shutdown not permitted with global graceful-shutdown");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN) == enable)
		return NB_OK;

	if (enable)
		SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);

	bgp_static_redo_import_check(bgp);
	bgp_redistribute_redo(bgp);
	bgp_clear_star_soft_out_quiet(bgp);
	bgp_clear_star_soft_in_quiet(bgp);
	return NB_OK;
}

int bgp_global_graceful_shutdown_enable_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp || !CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN))
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);
	bgp_static_redo_import_check(bgp);
	bgp_redistribute_redo(bgp);
	bgp_clear_star_soft_out_quiet(bgp);
	bgp_clear_star_soft_in_quiet(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/suppress-fib-pending  (presence container)
 *
 * apply_finish reads adv-delay (default 1000ms) and calls
 * suppress-fib-pending is a plain boolean leaf; the advertisement
 * delay rides in the when-guarded sibling suppress-fib-pending-delay
 * (default 1000 ms, so it never sees a destroy).
 */
int bgp_global_suppress_fib_pending_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool on;
	uint16_t delay = BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	on = yang_dnode_get_bool(args->dnode, NULL);
	if (on &&
	    yang_dnode_exists(args->dnode, "../suppress-fib-pending-delay"))
		delay = yang_dnode_get_uint16(
			args->dnode, "../suppress-fib-pending-delay");
	bgp_suppress_fib_pending_set(bgp, on, delay);
	return NB_OK;
}

int bgp_global_suppress_fib_pending_delay_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	/* when-guarded by suppress-fib-pending = true; re-apply. */
	bgp_suppress_fib_pending_set(bgp, true,
				     yang_dnode_get_uint16(args->dnode, NULL));
	return NB_OK;
}

int bgp_global_suppress_fib_pending_delay_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	/*
	 * The leaf also vanishes when its when-guard goes false because
	 * the same transaction turned suppress-fib-pending off -- that
	 * modify already cleared the state, so don't re-enable it here.
	 */
	if (!CHECK_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_FIB_PENDING))
		return NB_OK;

	bgp_suppress_fib_pending_set(bgp, true,
				     BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/advertisement-delay-global
 *
 * Per-instance advertisement-delay (bgp->v_advertisement_delay).
 */
int bgp_global_advertisement_delay_global_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->v_advertisement_delay = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_advertisement_delay_global_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->v_advertisement_delay = BGP_ADVERTISEMENT_DELAY_DEFAULT;
	if (bgp->advertisement_delay_started && !bgp->advertisement_delay_over) {
		event_cancel(&bgp->t_advertisement_delay);
		bgp->advertisement_delay_started = 0;
		bgp->advertisement_delay_over = 0;
	}
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/global-config-timers/update-delay-time
 *
 * Per-instance update-delay. Legacy DEFUN rejects if the global form
 * (`bm->v_update_delay`) is set — replicate with NB_EV_VALIDATE.
 * The companion `establish-wait-time` leaf (same container) defaults
 * to update-delay-time when not separately set (legacy semantic).
 */
int bgp_global_update_delay_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t update_delay, establish_wait;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bm->v_update_delay) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "per-vrf update-delay not permitted with global update-delay");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	update_delay = yang_dnode_get_uint16(args->dnode, NULL);
	bgp->v_update_delay = update_delay;
	/* If establish-wait is unset, mirror update-delay (legacy semantic). */
	if (yang_dnode_exists(args->dnode, "../establish-wait-time")) {
		establish_wait = yang_dnode_get_uint16(args->dnode,
						       "../establish-wait-time");
		if (update_delay < establish_wait) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "update-delay less than establish-wait");
			return NB_ERR;
		}
		bgp->v_establish_wait = establish_wait;
	} else {
		bgp->v_establish_wait = update_delay;
	}
	return NB_OK;
}

int bgp_global_update_delay_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->v_update_delay = BGP_UPDATE_DELAY_DEFAULT;
	bgp->v_establish_wait = BGP_UPDATE_DELAY_DEFAULT;
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/global-config-timers/establish-wait-time
 *
 * Only meaningful in conjunction with update-delay-time. The update-delay
 * modify callback handles the cross-leaf validation; here we just stash
 * the value.
 */
int bgp_global_establish_wait_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->v_establish_wait = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_establish_wait_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->v_establish_wait = bgp->v_update_delay;
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/global-config-timers/connect-retry-interval
 *
 * Per-instance connect-retry timer default.
 */
int bgp_global_connect_retry_interval_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->default_connect_retry = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_connect_retry_interval_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->default_connect_retry = BGP_DEFAULT_CONNECT_RETRY;
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/conditional-advertisement-period
 *
 * Sets bgp->condition_check_period. On no-form / destroy, also clears
 * PEER_STATUS_COND_ADV_PENDING flag from all peers (legacy semantic).
 */
int bgp_global_conditional_advertisement_period_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->condition_check_period = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_conditional_advertisement_period_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node, *nnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp || bgp->condition_check_period ==
		    DEFAULT_CONDITIONAL_ROUTES_POLL_TIME)
		return NB_OK;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		UNSET_FLAG(peer->sflags, PEER_STATUS_COND_ADV_PENDING);
	bgp->condition_check_period = DEFAULT_CONDITIONAL_ROUTES_POLL_TIME;
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/default-originate-timer
 *
 * Sets bgp->rmap_def_originate_eval_timer. Destroy/no cancels any
 * in-flight evaluation event and zeros the timer.
 */
int bgp_global_default_originate_timer_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->rmap_def_originate_eval_timer = yang_dnode_get_uint16(args->dnode,
								     NULL);
	if (bgp->t_rmap_def_originate_eval)
		event_cancel(&bgp->t_rmap_def_originate_eval);
	return NB_OK;
}

int bgp_global_default_originate_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->rmap_def_originate_eval_timer = 0;
	if (bgp->t_rmap_def_originate_eval)
		event_cancel(&bgp->t_rmap_def_originate_eval);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/bestpath-bandwidth
 *
 * Enum → bgp->lb_handling. Side effect: redo zebra route announcements
 * for every (afi,safi) since lb_handling affects route install metadata.
 */
int bgp_global_bestpath_bandwidth_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *value;
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

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	value = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(value, "ignore"))
		bgp->lb_handling = BGP_LINK_BW_IGNORE_BW;
	else if (strmatch(value, "skip-missing"))
		bgp->lb_handling = BGP_LINK_BW_SKIP_MISSING;
	else if (strmatch(value, "default-weight-for-missing"))
		bgp->lb_handling = BGP_LINK_BW_DEFWT_4_MISSING;
	else
		bgp->lb_handling = BGP_LINK_BW_ECMP;

	FOREACH_AFI_SAFI (afi, safi) {
		if (!bgp_fibupd_safi(safi))
			continue;
		bgp_zebra_announce_table(bgp, afi, safi);
	}
	return NB_OK;
}

int bgp_global_bestpath_bandwidth_destroy(struct nb_cb_destroy_args *args)
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

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->lb_handling = BGP_LINK_BW_ECMP;
	FOREACH_AFI_SAFI (afi, safi) {
		if (!bgp_fibupd_safi(safi))
			continue;
		bgp_zebra_announce_table(bgp, afi, safi);
	}
	return NB_OK;
}

/*
 * Re-send a BGP capability to every peer of `bgp` after a capability-bearing
 * config knob (graceful-restart, notification, LLGR, etc.) changes.
 * Shared between graceful-restart-notification and llgr-stalepath callbacks.
 */
static void bgp_resend_capability_all_peers(struct bgp *bgp,
					     uint8_t capability_code,
					     uint8_t action)
{
	struct peer *peer;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
				    capability_code, action);
}

/*
 * XPath:
 *   .../bgp/global/graceful-restart-notification
 */
int bgp_global_graceful_restart_notification_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
	bgp_resend_capability_all_peers(bgp, CAPABILITY_CODE_RESTART,
					CAPABILITY_ACTION_SET);
	return NB_OK;
}

int bgp_global_graceful_restart_notification_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
	bgp_resend_capability_all_peers(bgp, CAPABILITY_CODE_RESTART,
					CAPABILITY_ACTION_SET);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/long-lived-graceful-restart-stale-time
 *
 * Sets bgp->llgr_stale_time and re-sends the LLGR capability with the
 * appropriate ACTION_SET / _UNSET. Destroy resets to default and sends
 * ACTION_UNSET.
 */
int bgp_global_long_lived_graceful_restart_stale_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->llgr_stale_time = yang_dnode_get_uint32(args->dnode, NULL);
	bgp_resend_capability_all_peers(bgp, CAPABILITY_CODE_LLGR,
					CAPABILITY_ACTION_SET);
	return NB_OK;
}

int bgp_global_long_lived_graceful_restart_stale_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->llgr_stale_time = BGP_DEFAULT_LLGR_STALE_TIME;
	bgp_resend_capability_all_peers(bgp, CAPABILITY_CODE_LLGR,
					CAPABILITY_ACTION_UNSET);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/fast-convergence
 */
int bgp_global_fast_convergence_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp->fast_convergence = yang_dnode_get_bool(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_fast_convergence_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->fast_convergence = false;
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/default-link-local-capability
 */
int bgp_global_default_link_local_capability_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args,
					     BGP_FLAG_LINK_LOCAL_CAPABILITY, 3);
}

int bgp_global_default_link_local_capability_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(
		args, BGP_FLAG_LINK_LOCAL_CAPABILITY, 3);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/default-dynamic-capability
 */
int bgp_global_default_dynamic_capability_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args, BGP_FLAG_DYNAMIC_CAPABILITY,
					     3);
}

int bgp_global_default_dynamic_capability_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args, BGP_FLAG_DYNAMIC_CAPABILITY,
					      3);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-reflector/route-reflector-cluster-id
 *
 * Depth 4. The YANG type is bt:rr-cluster-id-type (dotted-quad or uint32).
 * Side effect: bgp_clear_star_soft_out (peer outbound updates are dependent
 * on cluster-id), invoked via the vty-less helper.
 */
int bgp_global_route_reflector_cluster_id_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct in_addr cluster;
	const char *value;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/* Parse-check the cluster-id format up front so a malformed
		 * value is rejected before apply. */
		value = yang_dnode_get_string(args->dnode, NULL);
		if (inet_aton(value, &cluster) == 0) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "malformed route-reflector-cluster-id: %s",
				   value);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	value = yang_dnode_get_string(args->dnode, NULL);
	if (inet_aton(value, &cluster) == 0) {
		/* Shouldn't happen — validated above. Return NB_ERR (not
		 * VALIDATION) since apply-stage errors are not validation. */
		snprintfrr(args->errmsg, args->errmsg_len,
			   "internal: cluster-id reparse failed: %s", value);
		return NB_ERR;
	}

	bgp_cluster_id_set(bgp, &cluster);
	bgp_clear_star_soft_out_quiet(bgp);
	return NB_OK;
}

int bgp_global_route_reflector_cluster_id_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp_cluster_id_unset(bgp);
	bgp_clear_star_soft_out_quiet(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-reflector/no-client-reflect
 *
 * Inverse semantics: yang `no-client-reflect=true` ↔ internal
 * BGP_FLAG_NO_CLIENT_TO_CLIENT set ↔ CLI `no bgp client-to-client reflection`.
 * Side effect: bgp_clear_star_soft_out_quiet (peer outbound is dependent).
 */
int bgp_global_no_client_reflect_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	bgp_clear_star_soft_out_quiet(bgp);
	return NB_OK;
}

int bgp_global_no_client_reflect_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	bgp_clear_star_soft_out_quiet(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/local-pref
 *
 * Depth 3. Side effect: bgp_clear_star_soft_in_quiet so existing inbound
 * paths are re-evaluated with the new default local-preference attribute.
 */
int bgp_global_local_pref_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp_default_local_preference_set(
		bgp, yang_dnode_get_uint32(args->dnode, NULL));
	bgp_clear_star_soft_in_quiet(bgp);
	return NB_OK;
}

int bgp_global_local_pref_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp_default_local_preference_unset(bgp);
	bgp_clear_star_soft_in_quiet(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/ebgp-multihop-connected-route-check
 *
 * YANG semantics (per the leaf description): true = disable check.
 * Maps to BGP_FLAG_DISABLE_NH_CONNECTED_CHK. Side effect: soft inbound
 * clear so existing routes are re-evaluated against the new check policy.
 */
int bgp_global_ebgp_multihop_connected_route_check_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	bgp_clear_star_soft_in_quiet(bgp);
	return NB_OK;
}

int bgp_global_ebgp_multihop_connected_route_check_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	bgp_clear_star_soft_in_quiet(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/graceful-restart/rib-stale-time
 *
 * Depth 4 (extra hop through graceful-restart container). Side effect:
 * bgp_zebra_stale_timer_update pushes the new value to zebra.
 */
int bgp_global_graceful_restart_rib_stale_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->rib_stale_time = yang_dnode_get_uint16(args->dnode, NULL);
	(void)bgp_zebra_stale_timer_update(bgp);
	return NB_OK;
}

int bgp_global_graceful_restart_rib_stale_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->rib_stale_time = BGP_DEFAULT_RIB_STALE_TIME;
	(void)bgp_zebra_stale_timer_update(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/graceful-restart/preserve-fw-entry
 *
 * Per-instance only — the cross-mode CONFIG/BGP-NODE legacy behaviour is
 * preserved by the still-extant `bgp graceful-restart preserve-fw-state`
 * DEFUN keeping its CONFIG_NODE branch for the bm->flags global form.
 * (This NB path covers BGP_NODE only, which is what NB modelling expresses.)
 */
int bgp_global_graceful_restart_preserve_fw_entry_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args, BGP_FLAG_GR_PRESERVE_FWD, 4);
}

int bgp_global_graceful_restart_preserve_fw_entry_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args, BGP_FLAG_GR_PRESERVE_FWD,
					      4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/graceful-restart/stale-routes-time
 *
 * Depth 4. Direct write to bgp->stalepath_time. The legacy DEFUN dispatches
 * CONFIG_NODE vs BGP_NODE; here we cover per-instance only.
 */
int bgp_global_graceful_restart_stale_routes_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->stalepath_time = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_graceful_restart_stale_routes_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
	return NB_OK;
}

/* ------------------------------------------------------------------------ */
/* neighbor list + neighbor-remote-as */
/* ------------------------------------------------------------------------ */

/*
 * Resolve the bgp instance and the neighbor's remote-address from a dnode
 * positioned at depth `depth_to_cpp` hops above the control-plane-protocol
 * entry. Examples:
 *   - neighbor list entry          depth_to_cpp = 3 (../../../vrf)
 *   - neighbor-remote-as container depth_to_cpp = 4
 *   - leaf under remote-as         depth_to_cpp = 5
 *
 * `neighbor_dnode` is the dnode of the `neighbor` list entry — descendants
 * pass an ancestor xpath to walk back up to it.
 */
static struct bgp *bgp_nb_lookup_neighbor_su(const struct lyd_node *dnode,
					      const char *neighbor_xpath,
					      union sockunion *su,
					      unsigned int depth_to_cpp)
{
	const char *remote_addr;
	struct bgp *bgp;

	bgp = bgp_nb_lookup_from_dnode(dnode, depth_to_cpp);
	if (!bgp)
		return NULL;

	remote_addr = yang_dnode_get_string(dnode, "%s", neighbor_xpath);
	if (str2sockunion(remote_addr, su) < 0)
		return NULL;

	return bgp;
}

/*
 * Convert YANG `as-type` enum string into the internal `enum peer_asn_type`.
 * YANG values (from frr-bgp-types:as-type) include: as-specified, internal,
 * external, unconfigured (and from FRR-style usage: auto).
 */
static enum peer_asn_type bgp_nb_yang_as_type(const char *yang_value)
{
	if (!yang_value)
		return AS_UNSPECIFIED;
	if (strmatch(yang_value, "as-specified"))
		return AS_SPECIFIED;
	if (strmatch(yang_value, "internal"))
		return AS_INTERNAL;
	if (strmatch(yang_value, "external"))
		return AS_EXTERNAL;
	if (strmatch(yang_value, "auto"))
		return AS_AUTO;
	return AS_UNSPECIFIED;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/neighbors/neighbor
 *
 * Creates the peer. The `neighbor-remote-as/remote-as-type` leaf is
 * mandatory in YANG, so it's guaranteed present in the dnode tree at
 * APPLY time. If type is `as-specified`, `remote-as` is required too
 * (enforced by YANG when-clause).
 *
 * peer_remote_as() is idempotent on existing peers (changes AS); for a
 * new peer it allocates via peer_create internally. We don't separately
 * call peer_create.
 */
int bgp_neighbor_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *remote_addr;
	union sockunion su;
	const char *as_type_str;
	enum peer_asn_type as_type;
	as_t as = 0;
	const char *as_str = NULL;
	char as_buf[16];
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/* Parse-check the format-sensitive inputs up front. */
		remote_addr = yang_dnode_get_string(args->dnode,
						    "remote-address");
		if (str2sockunion(remote_addr, &su) < 0) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "invalid neighbor remote-address: %s",
				   remote_addr);
			return NB_ERR_VALIDATION;
		}
		as_type_str = yang_dnode_get_string(
			args->dnode, "neighbor-remote-as/remote-as-type");
		as_type = bgp_nb_yang_as_type(as_type_str);
		if (as_type == AS_UNSPECIFIED) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "unsupported remote-as-type: %s",
				   as_type_str);
			return NB_ERR_VALIDATION;
		}
		if (as_type == AS_SPECIFIED &&
		    !yang_dnode_exists(args->dnode,
				       "neighbor-remote-as/remote-as")) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "remote-as required when remote-as-type is as-specified");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "bgp instance not found for neighbor create");
		return NB_ERR;
	}

	remote_addr = yang_dnode_get_string(args->dnode, "remote-address");
	if (str2sockunion(remote_addr, &su) < 0) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "internal: remote-address reparse failed: %s",
			   remote_addr);
		return NB_ERR;
	}

	as_type_str = yang_dnode_get_string(args->dnode,
					    "neighbor-remote-as/remote-as-type");
	as_type = bgp_nb_yang_as_type(as_type_str);
	if (as_type == AS_UNSPECIFIED) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "internal: bad remote-as-type at apply: %s",
			   as_type_str);
		return NB_ERR;
	}

	if (as_type == AS_SPECIFIED) {
		if (!yang_dnode_exists(args->dnode,
				       "neighbor-remote-as/remote-as")) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "internal: remote-as missing at apply");
			return NB_ERR;
		}
		as = (as_t)yang_dnode_get_uint32(
			args->dnode, "neighbor-remote-as/remote-as");
		snprintfrr(as_buf, sizeof(as_buf), "%u", as);
		as_str = as_buf;
	}

	bgp_need_listening(bgp, NULL);
	ret = peer_remote_as(bgp, &su, NULL, &as, as_type, as_str);
	if (ret < 0) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "peer_remote_as failed for %s (ret %d)", remote_addr,
			   ret);
		return NB_ERR;
	}

	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/neighbors/neighbor
 */
int bgp_neighbor_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	union sockunion su;
	struct peer *peer;
	const char *remote_addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	remote_addr = yang_dnode_get_string(args->dnode, "remote-address");
	if (str2sockunion(remote_addr, &su) < 0)
		return NB_OK;

	peer = peer_lookup(bgp, &su);
	if (!peer)
		return NB_OK;

	peer_delete(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/neighbor-remote-as/remote-as-type
 *
 * Triggered on transitions between as-type values on an existing neighbor.
 * For a fresh neighbor, bgp_neighbor_create already wires the type; this
 * callback handles the modify case.
 */
int bgp_neighbor_remote_as_type_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	union sockunion su;
	struct peer *peer;
	enum peer_asn_type new_type;
	as_t as = 0;
	const char *as_str = NULL;
	char as_buf[16];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_neighbor_su(args->dnode, "../../remote-address", &su,
					 5);
	if (!bgp)
		return NB_ERR;

	peer = peer_lookup(bgp, &su);
	if (!peer)
		return NB_OK; /* parent create will run first */

	new_type = bgp_nb_yang_as_type(yang_dnode_get_string(args->dnode, NULL));
	if (new_type == AS_SPECIFIED &&
	    yang_dnode_exists(args->dnode, "../remote-as")) {
		as = (as_t)yang_dnode_get_uint32(args->dnode, "../remote-as");
		snprintfrr(as_buf, sizeof(as_buf), "%u", as);
		as_str = as_buf;
	}

	peer_as_change(peer, as, new_type, as_str);
	return NB_OK;
}

int bgp_neighbor_remote_as_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	union sockunion su;
	struct peer *peer;
	as_t as;
	char as_buf[16];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_neighbor_su(args->dnode, "../../remote-address", &su,
					 5);
	if (!bgp)
		return NB_ERR;

	peer = peer_lookup(bgp, &su);
	if (!peer)
		return NB_OK;

	as = (as_t)yang_dnode_get_uint32(args->dnode, NULL);
	snprintfrr(as_buf, sizeof(as_buf), "%u", as);
	peer_as_change(peer, as, AS_SPECIFIED, as_buf);
	return NB_OK;
}

int bgp_neighbor_remote_as_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}
	/*
	 * The remote-as leaf is gated by a when-clause; destroying it means
	 * the remote-as-type leaf is moving away from `as-specified`. The
	 * type-modify callback owns the side effect; nothing to do here.
	 */
	return NB_OK;
}

/*
 * Lookup the peer owning the dnode at `depth_to_cpp` hops above the
 * control-plane-protocol entry. `neighbor_rel_xpath` is the relative xpath
 * from the dnode up to the `neighbor` list entry (used to read the
 * remote-address key). Returns NULL if peer not found.
 */
static struct peer *bgp_nb_lookup_peer(const struct lyd_node *dnode,
				       const char *neighbor_rel_xpath,
				       unsigned int depth_to_cpp)
{
	struct bgp *bgp;
	union sockunion su;
	const char *remote_addr;
	char xpath_buf[64];

	bgp = bgp_nb_lookup_from_dnode(dnode, depth_to_cpp);
	if (!bgp)
		return NULL;

	snprintfrr(xpath_buf, sizeof(xpath_buf), "%s/remote-address",
		   neighbor_rel_xpath);
	remote_addr = yang_dnode_get_string(dnode, "%s", xpath_buf);
	if (str2sockunion(remote_addr, &su) < 0)
		return NULL;

	return peer_lookup(bgp, &su);
}

/*
 * Generic per-neighbor boolean flag toggle. A leaf at depth_to_cpp hops
 * from CPP maps to a single PEER_FLAG_* bit via peer_flag_set/_unset.
 * `neighbor_rel` is the relative xpath from the leaf to the neighbor list
 * entry, e.g. ".." for a direct child, "../.." for a leaf inside a
 * container under neighbor, etc.
 */
static int peer_flag_toggle_modify(struct nb_cb_modify_args *args,
				    uint64_t flag, const char *neighbor_rel,
				    unsigned int depth_to_cpp)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, neighbor_rel, depth_to_cpp);
	if (!peer)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, flag);
	else
		peer_flag_unset(peer, flag);
	return NB_OK;
}

static int peer_flag_toggle_destroy(struct nb_cb_destroy_args *args,
				     uint64_t flag, const char *neighbor_rel,
				     unsigned int depth_to_cpp)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, neighbor_rel, depth_to_cpp);
	if (!peer)
		return NB_OK;

	peer_flag_unset(peer, flag);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/password
 *
 * Depth from leaf to CPP = 4 (`../../../../vrf`). neighbor_rel = ".." (leaf
 * is a direct child of neighbor).
 */
int bgp_neighbor_password_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	const char *pwd;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;

	pwd = yang_dnode_get_string(args->dnode, NULL);
	if (peer_password_set(peer, pwd) != 0) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "peer_password_set failed");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_neighbor_password_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;

	peer_password_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/description
 *
 * Optional textual description. Setter and unset are non-failing.
 */
int bgp_neighbor_description_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;

	peer_description_set(peer, yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_neighbor_description_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;

	peer_description_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/passive-mode
 */
int bgp_neighbor_passive_mode_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_PASSIVE, "..", 4);
}

int bgp_neighbor_passive_mode_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_PASSIVE, "..", 4);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/solo
 */
int bgp_neighbor_solo_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_LONESOUL, "..", 4);
}

int bgp_neighbor_solo_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_LONESOUL, "..", 4);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/enforce-first-as
 *
 * YANG default true matches the existing semantic: if you destroy this
 * leaf, the flag is unset (i.e., enforce is OFF in code terms). The CLI
 * `bgp enforce-first-as` is per-bgp; the per-neighbor knob lives here in
 * YANG.
 */
int bgp_neighbor_enforce_first_as_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_ENFORCE_FIRST_AS, "..",
					4);
}

int bgp_neighbor_enforce_first_as_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_ENFORCE_FIRST_AS, "..",
					 4);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/ttl-security
 *
 * Direct neighbor leaf (depth 4). Internal setter wants `int gtsm_hops`.
 */
int bgp_neighbor_ttl_security_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint8_t hops;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;

	hops = yang_dnode_get_uint8(args->dnode, NULL);
	if (peer_ttl_security_hops_set(peer, hops) != 0) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "peer_ttl_security_hops_set failed");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_neighbor_ttl_security_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;

	peer_ttl_security_hops_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/admin-shutdown/enable
 *
 * Container hop adds one to depth: 5 levels back to control-plane-protocol.
 * neighbor_rel = "../.." since this leaf is two hops up to the neighbor.
 */
int bgp_neighbor_admin_shutdown_enable_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_SHUTDOWN, "../..", 5);
}

int bgp_neighbor_admin_shutdown_enable_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_SHUTDOWN, "../..", 5);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/admin-shutdown/message
 *
 * Shutdown communication message (RFC 8203, draft-ietf-idr-shutdown-06).
 */
int bgp_neighbor_admin_shutdown_message_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	peer_tx_shutdown_message_set(peer,
				     yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_neighbor_admin_shutdown_message_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_tx_shutdown_message_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/ebgp-multihop/enabled
 *
 * When enabled without an explicit multihop-ttl, FRR uses the default TTL
 * (MAXTTL). When the multihop-ttl leaf is also set in the same transaction,
 * the ttl callback will run separately and refine the TTL.
 */
int bgp_neighbor_ebgp_multihop_enabled_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_ebgp_multihop_set(peer, MAXTTL, true);
	else
		peer_ebgp_multihop_unset(peer, true);
	return NB_OK;
}

int bgp_neighbor_ebgp_multihop_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_ebgp_multihop_unset(peer, true);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/ebgp-multihop/multihop-ttl
 */
int bgp_neighbor_ebgp_multihop_ttl_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	if (peer_ebgp_multihop_set(peer,
				   yang_dnode_get_uint8(args->dnode, NULL),
				   true) != 0) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "peer_ebgp_multihop_set failed");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_neighbor_ebgp_multihop_ttl_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_ebgp_multihop_unset(peer, true);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/ebgp-multihop/disable-connected-check
 */
int bgp_neighbor_ebgp_multihop_disable_connected_check_modify(
	struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_DISABLE_CONNECTED_CHECK,
					"../..", 5);
}

int bgp_neighbor_ebgp_multihop_disable_connected_check_destroy(
	struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_DISABLE_CONNECTED_CHECK,
					 "../..", 5);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/update-source/ip
 *
 * Container hop + choice/case; depth from leaf to CPP = 5, neighbor_rel = "../..".
 */
int bgp_neighbor_update_source_ip_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	union sockunion su;
	const char *ip;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ip = yang_dnode_get_string(args->dnode, NULL);
		if (str2sockunion(ip, &su) < 0) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "invalid update-source ip: %s", ip);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	ip = yang_dnode_get_string(args->dnode, NULL);
	if (str2sockunion(ip, &su) < 0) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "internal: update-source ip reparse failed: %s", ip);
		return NB_ERR;
	}

	peer_update_source_addr_set(peer, &su);
	return NB_OK;
}

int bgp_neighbor_update_source_ip_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_update_source_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/update-source/interface
 */
int bgp_neighbor_update_source_interface_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	if (peer_update_source_if_set(peer,
				      yang_dnode_get_string(args->dnode, NULL)) !=
	    0) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "peer_update_source_if_set failed");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_neighbor_update_source_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_update_source_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/timers/connect-time
 */
int bgp_neighbor_timers_connect_time_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	if (peer_timers_connect_set(peer,
				    yang_dnode_get_uint16(args->dnode, NULL)) !=
	    0) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "peer_timers_connect_set failed");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_neighbor_timers_connect_time_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_timers_connect_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/timers/advertise-interval
 */
int bgp_neighbor_timers_advertise_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	if (peer_advertise_interval_set(
		    peer, yang_dnode_get_uint16(args->dnode, NULL)) != 0) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "peer_advertise_interval_set failed");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_neighbor_timers_advertise_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_advertise_interval_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/local-as  (container)
 *
 * `peer_local_as_set()` takes (as, no_prepend, replace_as, dual_as, as_str)
 * as a single atomic call. The three child leaves (`local-as`, `no-prepend`,
 * `replace-as`) get their own modify callbacks in a transaction, so instead
 * of running the setter from each leaf, we use an apply_finish callback on
 * the container — fires once after all leaves in the transaction are
 * committed.
 */
void bgp_neighbor_local_as_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct peer *peer;
	as_t as = 0;
	bool no_prepend = false;
	bool replace_as = false;
	char as_buf[16] = "";

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return;

	if (yang_dnode_exists(args->dnode, "local-as")) {
		as = (as_t)yang_dnode_get_uint32(args->dnode, "local-as");
		snprintfrr(as_buf, sizeof(as_buf), "%u", as);
	}
	if (yang_dnode_exists(args->dnode, "no-prepend"))
		no_prepend = yang_dnode_get_bool(args->dnode, "no-prepend");
	if (yang_dnode_exists(args->dnode, "replace-as"))
		replace_as = yang_dnode_get_bool(args->dnode, "replace-as");

	if (as == 0) {
		/*
		 * If the local-as leaf is absent the container is a noop —
		 * the per-leaf no_prepend/replace_as modifiers are meaningful
		 * only when local-as is set.
		 */
		return;
	}

	peer_local_as_set(peer, as, no_prepend, replace_as, false, as_buf);
	return;
}

int bgp_neighbor_local_as_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;

	peer_local_as_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/bfd-options  (container)
 *
 * Apply-finish over the container. Reads the `enable` leaf and configures
 * BFD accordingly, then writes detect-multiplier / min-rx / min-tx into
 * peer->bfd_config and calls bgp_peer_config_apply() once.
 */
void bgp_neighbor_bfd_options_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct peer *peer;
	bool enable;

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return;

	enable = yang_dnode_exists(args->dnode, "enable") &&
		 yang_dnode_get_bool(args->dnode, "enable");

	if (!enable) {
		bgp_peer_remove_bfd_config(peer);
		return;
	}

	bgp_peer_configure_bfd(peer, true);
	if (yang_dnode_exists(args->dnode, "detect-multiplier"))
		peer->bfd_config->detection_multiplier =
			yang_dnode_get_uint8(args->dnode, "detect-multiplier");
	if (yang_dnode_exists(args->dnode, "required-min-rx"))
		peer->bfd_config->min_rx =
			yang_dnode_get_uint16(args->dnode, "required-min-rx");
	if (yang_dnode_exists(args->dnode, "desired-min-tx"))
		peer->bfd_config->min_tx =
			yang_dnode_get_uint16(args->dnode, "desired-min-tx");
	if (yang_dnode_exists(args->dnode, "check-cp-failure"))
		peer->bfd_config->cbit =
			yang_dnode_get_bool(args->dnode, "check-cp-failure");

	bgp_peer_config_apply(peer, NULL);
	return;
}

int bgp_neighbor_bfd_options_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;

	bgp_peer_remove_bfd_config(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/capability-options/dynamic-capability
 */
int bgp_neighbor_capabilities_dynamic_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_DYNAMIC_CAPABILITY,
					"../..", 5);
}

int bgp_neighbor_capabilities_dynamic_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_DYNAMIC_CAPABILITY,
					 "../..", 5);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/capability-options/strict-capability
 */
int bgp_neighbor_capabilities_strict_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_STRICT_CAP_MATCH,
					"../..", 5);
}

int bgp_neighbor_capabilities_strict_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_STRICT_CAP_MATCH,
					 "../..", 5);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/capability-options/override-capability
 */
int bgp_neighbor_capabilities_override_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_OVERRIDE_CAPABILITY,
					"../..", 5);
}

int bgp_neighbor_capabilities_override_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_OVERRIDE_CAPABILITY,
					 "../..", 5);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/capability-options/extended-nexthop-capability
 */
int bgp_neighbor_capabilities_extended_nexthop_modify(
	struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_CAPABILITY_ENHE,
					"../..", 5);
}

int bgp_neighbor_capabilities_extended_nexthop_destroy(
	struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_CAPABILITY_ENHE,
					 "../..", 5);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/capability-options/capability-negotiate
 *
 * INVERTED mapping: YANG `capability-negotiate = true` means negotiate
 * capabilities normally (no `dont-capability-negotiate`); YANG `false`
 * means set PEER_FLAG_DONT_CAPABILITY (suppress capability negotiation).
 */
int bgp_neighbor_capabilities_negotiate_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_unset(peer, PEER_FLAG_DONT_CAPABILITY);
	else
		peer_flag_set(peer, PEER_FLAG_DONT_CAPABILITY);
	return NB_OK;
}

int bgp_neighbor_capabilities_negotiate_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_flag_unset(peer, PEER_FLAG_DONT_CAPABILITY);
	return NB_OK;
}

/*
 * Direct-child neighbor boolean flag NB callbacks.
 * Leaf is at neighbor[remote-address]/<leaf>, depth-to-CPP = 4,
 * neighbor_rel = "..".
 */
#define BGP_NEIGHBOR_FLAG_CB(_name, _flag)                                     \
	int bgp_neighbor_##_name##_modify(struct nb_cb_modify_args *args)      \
	{                                                                      \
		return peer_flag_toggle_modify(args, (_flag), "..", 4);        \
	}                                                                      \
	int bgp_neighbor_##_name##_destroy(struct nb_cb_destroy_args *args)    \
	{                                                                      \
		return peer_flag_toggle_destroy(args, (_flag), "..", 4);       \
	}

/* For leaves with a yang default: the framework never delivers destroy. */
#define BGP_NEIGHBOR_FLAG_MOD_CB(_name, _flag)                                 \
	int bgp_neighbor_##_name##_modify(struct nb_cb_modify_args *args)      \
	{                                                                      \
		return peer_flag_toggle_modify(args, (_flag), "..", 4);        \
	}

/* per-AF per-peer flag toggles */

/*
 * Per-AF config nodes live under per-AFI containers inside the
 * afi-safi list entry:
 *   .../neighbors/neighbor[remote-address]/afi-safis/
 *     afi-safi[afi-safi-name]/<afi-container>[/<group>]/<leaf>
 *
 * `ups` is the number of `../` hops from the callback dnode to the
 * afi-safi list entry: 1 for a node directly in the entry, 2 for
 * <afi-container>/<leaf>, 3 for <afi-container>/<group>/<leaf>.
 * The neighbor entry sits 2 more hops up, and depth-to-CPP = 5 + ups.
 *
 * AFI/SAFI extracted from the afi-safi-name key.
 */
static int bgp_nb_af_id_to_afi_safi(const char *afi_safi_id, afi_t *afi_out,
				    safi_t *safi_out);

static struct peer *bgp_nb_peer_ctx_lookup(const struct lyd_node *af_entry);

static int bgp_nb_peer_af_lookup(const struct lyd_node *dnode, int ups,
				 struct peer **peer_out, afi_t *afi_out,
				 safi_t *safi_out)
{
	const struct lyd_node *af_entry;
	struct peer *peer;
	const char *afi_safi_id;

	assert(ups >= 1 && ups <= 3);

	/*
	 * afi-safi entries are instantiated under neighbors/neighbor,
	 * neighbors/unnumbered-neighbor and peer-groups/peer-group;
	 * resolve the peer by probing the context list key so the
	 * per-AF callbacks serve all three contexts (PL pattern).
	 */
	af_entry = yang_dnode_get_parent(dnode, "afi-safi");
	if (!af_entry)
		return -1;

	peer = bgp_nb_peer_ctx_lookup(af_entry);
	if (!peer)
		return -1;

	afi_safi_id = yang_dnode_get_string(af_entry, "afi-safi-name");
	if (!afi_safi_id)
		return -1;

	if (bgp_nb_af_id_to_afi_safi(afi_safi_id, afi_out, safi_out) < 0)
		return -1;
	*peer_out = peer;
	return 0;
}

/*
 * Shared afi-safi identity resolver (prefixed identity, e.g.
 * "frr-routing:ipv4-unicast"). More specific ids match first:
 * "l3vpn-ipv4-unicast" contains "ipv4-unicast" as a substring, so
 * the plain-unicast checks must come last.
 */
const char *bgp_nb_af_yang_name(afi_t afi, safi_t safi)
{
	if (afi == AFI_IP && safi == SAFI_UNICAST)
		return "frr-routing:ipv4-unicast";
	if (afi == AFI_IP6 && safi == SAFI_UNICAST)
		return "frr-routing:ipv6-unicast";
	if (afi == AFI_IP && safi == SAFI_LABELED_UNICAST)
		return "frr-routing:ipv4-labeled-unicast";
	if (afi == AFI_IP6 && safi == SAFI_LABELED_UNICAST)
		return "frr-routing:ipv6-labeled-unicast";
	if (afi == AFI_IP && safi == SAFI_MPLS_VPN)
		return "frr-routing:l3vpn-ipv4-unicast";
	if (afi == AFI_IP6 && safi == SAFI_MPLS_VPN)
		return "frr-routing:l3vpn-ipv6-unicast";
	if (afi == AFI_IP && safi == SAFI_MULTICAST)
		return "frr-routing:ipv4-multicast";
	if (afi == AFI_IP6 && safi == SAFI_MULTICAST)
		return "frr-routing:ipv6-multicast";
	if (afi == AFI_IP && safi == SAFI_UNREACH)
		return "frr-routing:ipv4-unreachability";
	if (afi == AFI_IP6 && safi == SAFI_UNREACH)
		return "frr-routing:ipv6-unreachability";
	if (afi == AFI_L2VPN && safi == SAFI_EVPN)
		return "frr-routing:l2vpn-evpn";
	if (afi == AFI_L2VPN && safi == SAFI_UNICAST)
		return "frr-routing:l2vpn-vpls";
	return NULL;
}

static int bgp_nb_af_id_to_afi_safi(const char *afi_safi_id, afi_t *afi_out,
				    safi_t *safi_out)
{
	if (strstr(afi_safi_id, "l3vpn-ipv4-unicast")) {
		*afi_out = AFI_IP;  *safi_out = SAFI_MPLS_VPN;
	} else if (strstr(afi_safi_id, "l3vpn-ipv6-unicast")) {
		*afi_out = AFI_IP6; *safi_out = SAFI_MPLS_VPN;
	} else if (strstr(afi_safi_id, "ipv4-labeled-unicast")) {
		*afi_out = AFI_IP;  *safi_out = SAFI_LABELED_UNICAST;
	} else if (strstr(afi_safi_id, "ipv6-labeled-unicast")) {
		*afi_out = AFI_IP6; *safi_out = SAFI_LABELED_UNICAST;
	} else if (strstr(afi_safi_id, "ipv4-unicast")) {
		*afi_out = AFI_IP;  *safi_out = SAFI_UNICAST;
	} else if (strstr(afi_safi_id, "ipv6-unicast")) {
		*afi_out = AFI_IP6; *safi_out = SAFI_UNICAST;
	} else if (strstr(afi_safi_id, "ipv4-multicast")) {
		*afi_out = AFI_IP;  *safi_out = SAFI_MULTICAST;
	} else if (strstr(afi_safi_id, "ipv6-multicast")) {
		*afi_out = AFI_IP6; *safi_out = SAFI_MULTICAST;
	} else if (strstr(afi_safi_id, "ipv4-flowspec")) {
		*afi_out = AFI_IP;  *safi_out = SAFI_FLOWSPEC;
	} else if (strstr(afi_safi_id, "ipv6-flowspec")) {
		*afi_out = AFI_IP6; *safi_out = SAFI_FLOWSPEC;
	} else if (strstr(afi_safi_id, "l2vpn-evpn")) {
		*afi_out = AFI_L2VPN; *safi_out = SAFI_EVPN;
	} else if (strstr(afi_safi_id, "l2vpn-vpls")) {
		*afi_out = AFI_L2VPN; *safi_out = SAFI_UNICAST;
	} else if (strstr(afi_safi_id, "ipv4-unreachability")) {
		*afi_out = AFI_IP;  *safi_out = SAFI_UNREACH;
	} else if (strstr(afi_safi_id, "ipv6-unreachability")) {
		*afi_out = AFI_IP6; *safi_out = SAFI_UNREACH;
	} else {
		return -1;
	}
	return 0;
}

/*
 * Turn a legacy bgpd setter result into a northbound result: semantic
 * failures (e.g. route-reflector-client on an eBGP peer) must fail the
 * commit with the daemon's own error text instead of returning a false
 * commit-OK. NULL from bgp_create_error_str() means success.
 */
static int bgp_nb_setter_result(int ret, char *errmsg, size_t errmsg_len)
{
	const char *str = bgp_create_error_str(ret);

	if (!str)
		return NB_OK;
	snprintfrr(errmsg, errmsg_len, "%s", str);
	return NB_ERR;
}

static int peer_af_flag_toggle_modify(struct nb_cb_modify_args *args,
				      uint64_t flag, int ups)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_peer_af_lookup(args->dnode, ups, &peer, &afi, &safi) < 0)
		return NB_ERR;
	if (yang_dnode_get_bool(args->dnode, NULL))
		ret = peer_af_flag_set(peer, afi, safi, flag);
	else
		ret = peer_af_flag_unset(peer, afi, safi, flag);
	return bgp_nb_setter_result(ret, args->errmsg, args->errmsg_len);
}

static int peer_af_flag_toggle_destroy(struct nb_cb_destroy_args *args,
				       uint64_t flag, int ups)
{
	struct peer *peer;
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
	if (bgp_nb_peer_af_lookup(args->dnode, ups, &peer, &afi, &safi) < 0)
		return NB_OK;
	return bgp_nb_setter_result(peer_af_flag_unset(peer, afi, safi, flag),
				    args->errmsg, args->errmsg_len);
}

#define BGP_NEIGHBOR_AF_FLAG_CB(_name, _flag, _ups)                            \
	int bgp_neighbor_af_##_name##_modify(struct nb_cb_modify_args *args)   \
	{                                                                      \
		return peer_af_flag_toggle_modify(args, (_flag), (_ups));      \
	}                                                                      \
	int bgp_neighbor_af_##_name##_destroy(struct nb_cb_destroy_args *args) \
	{                                                                      \
		return peer_af_flag_toggle_destroy(args, (_flag), (_ups));     \
	}

/* For leaves with a yang default: the framework never delivers destroy. */
#define BGP_NEIGHBOR_AF_FLAG_MOD_CB(_name, _flag, _ups)                        \
	int bgp_neighbor_af_##_name##_modify(struct nb_cb_modify_args *args)   \
	{                                                                      \
		return peer_af_flag_toggle_modify(args, (_flag), (_ups));      \
	}

/* ups: hops from the leaf to the afi-safi list entry (see lookup above). */
BGP_NEIGHBOR_AF_FLAG_MOD_CB(soft_reconfig_in, PEER_FLAG_SOFT_RECONFIG, 2)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(as_override, PEER_FLAG_AS_OVERRIDE, 3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(rr_client, PEER_FLAG_REFLECTOR_CLIENT, 3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(rs_client, PEER_FLAG_RSERVER_CLIENT, 3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(nexthop_self, PEER_FLAG_NEXTHOP_SELF, 3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(nexthop_self_force, PEER_FLAG_FORCE_NEXTHOP_SELF, 3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(remove_private_as, PEER_FLAG_REMOVE_PRIVATE_AS, 3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(remove_private_as_all, PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
			3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(remove_private_as_replace,
			PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE, 3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(remove_private_as_all_replace,
			PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE, 3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(nexthop_local_unchanged,
			PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED, 2)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(send_community, PEER_FLAG_SEND_COMMUNITY, 3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(send_ext_community, PEER_FLAG_SEND_EXT_COMMUNITY, 3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(send_large_community, PEER_FLAG_SEND_LARGE_COMMUNITY,
			3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(accept_own, PEER_FLAG_ACCEPT_OWN, 2)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(disable_addpath_rx, PEER_FLAG_DISABLE_ADDPATH_RX, 3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(attr_unchanged_as_path,
			PEER_FLAG_AS_PATH_UNCHANGED, 3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(attr_unchanged_next_hop,
			PEER_FLAG_NEXTHOP_UNCHANGED, 3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(attr_unchanged_med,
			PEER_FLAG_MED_UNCHANGED, 3)
BGP_NEIGHBOR_AF_FLAG_MOD_CB(upa, PEER_FLAG_UPA, 2)

/*
 * encapsulation/type is a leaf-list: each entry maps to one
 * PEER_FLAG_CONFIG_ENCAPSULATION_* bit.
 */
static uint64_t bgp_nb_encapsulation_flag(const char *type)
{
	if (strmatch(type, "mpls"))
		return PEER_FLAG_CONFIG_ENCAPSULATION_MPLS;
	if (strmatch(type, "srv6"))
		return PEER_FLAG_CONFIG_ENCAPSULATION_SRV6;
	if (strmatch(type, "srv6-relax"))
		return PEER_FLAG_CONFIG_ENCAPSULATION_SRV6_RELAX;
	return 0;
}

int bgp_neighbor_af_encapsulation_type_create(struct nb_cb_create_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	uint64_t flag;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_peer_af_lookup(args->dnode, 3, &peer, &afi, &safi) < 0)
		return NB_ERR;
	flag = bgp_nb_encapsulation_flag(
		yang_dnode_get_string(args->dnode, NULL));
	if (!flag)
		return NB_ERR;
	return bgp_nb_setter_result(peer_af_flag_set(peer, afi, safi, flag),
				    args->errmsg, args->errmsg_len);
}

int bgp_neighbor_af_encapsulation_type_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	uint64_t flag;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_peer_af_lookup(args->dnode, 3, &peer, &afi, &safi) < 0)
		return NB_OK;
	flag = bgp_nb_encapsulation_flag(
		yang_dnode_get_string(args->dnode, NULL));
	if (!flag)
		return NB_OK;
	return bgp_nb_setter_result(peer_af_flag_unset(peer, afi, safi, flag),
				    args->errmsg, args->errmsg_len);
}

/*
 * add-paths/path-type drives bgp_addpath_set_peer_type with an enum
 * strategy, not a peer flag bit: all -> BGP_ADDPATH_ALL, per-as ->
 * BGP_ADDPATH_BEST_PER_AS, none -> BGP_ADDPATH_NONE.
 */
static enum bgp_addpath_strat bgp_nb_addpath_strat(const char *path_type)
{
	if (strmatch(path_type, "all"))
		return BGP_ADDPATH_ALL;
	if (strmatch(path_type, "per-as"))
		return BGP_ADDPATH_BEST_PER_AS;
	return BGP_ADDPATH_NONE;
}

int bgp_neighbor_af_add_paths_path_type_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (bgp_nb_peer_af_lookup(args->dnode, 3, &peer, &afi, &safi) < 0)
		return NB_ERR;
	bgp_addpath_set_peer_type(peer, afi, safi,
				  bgp_nb_addpath_strat(yang_dnode_get_string(
					  args->dnode, NULL)),
				  0);
	return NB_OK;
}

int bgp_neighbor_af_add_paths_path_type_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	if (bgp_nb_peer_af_lookup(args->dnode, 3, &peer, &afi, &safi) < 0)
		return NB_OK;
	bgp_addpath_set_peer_type(peer, afi, safi, BGP_ADDPATH_NONE, 0);
	return NB_OK;
}

/*
 * Per-AF activate/deactivate. enabled=true → peer_activate, =false →
 * peer_deactivate.
 */
int bgp_neighbor_af_enabled_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
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
	if (bgp_nb_peer_af_lookup(args->dnode, 1, &peer, &afi, &safi) < 0)
		return NB_ERR;
	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_activate(peer, afi, safi);
	else
		peer_deactivate(peer, afi, safi);
	return NB_OK;
}

int bgp_neighbor_af_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
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
	if (bgp_nb_peer_af_lookup(args->dnode, 1, &peer, &afi, &safi) < 0)
		return NB_OK;
	peer_deactivate(peer, afi, safi);
	return NB_OK;
}

/*
 * Per-AF route-map filters:
 * neighbor/afi-safis/afi-safi/<AF>/filter-config/{rmap-import,rmap-export}.
 * peer_route_map_set() propagates to peer-group members and schedules
 * the policy refresh (peer_on_policy_change), so modify/destroy map 1:1
 * onto the legacy setters. Like the CLI path, the filter binds by name:
 * the referenced route-map does not have to exist yet.
 */
static int bgp_neighbor_af_rmap_filter_modify(struct nb_cb_modify_args *args,
					      int direct)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *name;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_peer_af_lookup(args->dnode, 3, &peer, &afi, &safi) < 0)
		return NB_ERR;
	name = yang_dnode_get_string(args->dnode, NULL);
	return bgp_nb_setter_result(peer_route_map_set(peer, afi, safi, direct,
						       name,
						       route_map_lookup_by_name(
							       name)),
				    args->errmsg, args->errmsg_len);
}

static int bgp_neighbor_af_rmap_filter_destroy(struct nb_cb_destroy_args *args,
					       int direct)
{
	struct peer *peer;
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
	if (bgp_nb_peer_af_lookup(args->dnode, 3, &peer, &afi, &safi) < 0)
		return NB_OK;
	return bgp_nb_setter_result(peer_route_map_unset(peer, afi, safi,
							 direct),
				    args->errmsg, args->errmsg_len);
}

int bgp_neighbor_af_rmap_import_modify(struct nb_cb_modify_args *args)
{
	return bgp_neighbor_af_rmap_filter_modify(args, RMAP_IN);
}

int bgp_neighbor_af_rmap_import_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_neighbor_af_rmap_filter_destroy(args, RMAP_IN);
}

int bgp_neighbor_af_rmap_export_modify(struct nb_cb_modify_args *args)
{
	return bgp_neighbor_af_rmap_filter_modify(args, RMAP_OUT);
}

int bgp_neighbor_af_rmap_export_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_neighbor_af_rmap_filter_destroy(args, RMAP_OUT);
}

/*
 * Prefix limits (G-PL): the structure-neighbor-prefix-limit grouping
 * is instantiated under neighbors/neighbor, neighbors/unnumbered-
 * neighbor and peer-groups/peer-group, once per AFI-SAFI container;
 * the three contexts share these callbacks. The peer is resolved by
 * probing the context list key: remote-address (numbered), interface
 * (unnumbered) or peer-group-name (peer-group; the legacy setters fan
 * the config out to the group members themselves).
 *
 * direction "in" maps onto peer_maximum_prefix_set()/unset() (the
 * pmax/threshold/restart/warning/force knob family); direction "out"
 * maps onto peer_maximum_prefix_out_set()/unset() (pmax_out, which
 * takes no options in the legacy internals). The legacy setter
 * consumes all inbound knobs at once, so every leaf (re)applies it
 * with the current values of its siblings -- the datastore is the
 * source of truth and each callback re-derives the full knob set.
 */
static const struct lyd_node *bgp_nb_pl_dlist(const struct lyd_node *dnode)
{
	if (dnode->schema && !strcmp(dnode->schema->name, "direction-list"))
		return dnode;
	return yang_dnode_get_parent(dnode, "direction-list");
}

static struct peer *bgp_nb_peer_ctx_lookup(const struct lyd_node *af_entry)
{
	struct bgp *bgp;
	union sockunion su;
	struct peer_group *group;

	bgp = bgp_nb_lookup_from_dnode(af_entry, 5);
	if (!bgp)
		return NULL;

	if (yang_dnode_exists(af_entry, "../../remote-address")) {
		const char *remote = yang_dnode_get_string(
			af_entry, "../../remote-address");

		if (str2sockunion(remote, &su) == 0)
			return peer_lookup(bgp, &su);
		return NULL;
	}
	if (yang_dnode_exists(af_entry, "../../interface"))
		return peer_lookup_by_conf_if(
			bgp, yang_dnode_get_string(af_entry,
						   "../../interface"));
	if (yang_dnode_exists(af_entry, "../../peer-group-name")) {
		group = peer_group_lookup(
			bgp, yang_dnode_get_string(af_entry,
						   "../../peer-group-name"));
		return group ? group->conf : NULL;
	}
	return NULL;
}

static int bgp_nb_pl_lookup(const struct lyd_node *dnode,
			    struct peer **peer_out, afi_t *afi_out,
			    safi_t *safi_out, const char **direction_out,
			    char *errmsg, size_t errmsg_len)
{
	const struct lyd_node *af_entry, *dl;
	const char *afi_safi_id;

	dl = bgp_nb_pl_dlist(dnode);
	if (!dl) {
		snprintfrr(errmsg, errmsg_len,
			   "prefix-limit: no direction-list ancestor");
		return -1;
	}
	af_entry = yang_dnode_get_parent(dl, "afi-safi");
	if (!af_entry) {
		snprintfrr(errmsg, errmsg_len,
			   "prefix-limit: no afi-safi ancestor");
		return -1;
	}
	afi_safi_id = yang_dnode_get_string(af_entry, "afi-safi-name");
	if (!afi_safi_id ||
	    bgp_nb_af_id_to_afi_safi(afi_safi_id, afi_out, safi_out) < 0) {
		snprintfrr(errmsg, errmsg_len,
			   "prefix-limit: unsupported afi-safi '%s'",
			   afi_safi_id ? afi_safi_id : "(null)");
		return -1;
	}
	*peer_out = bgp_nb_peer_ctx_lookup(af_entry);
	if (!*peer_out) {
		snprintfrr(errmsg, errmsg_len, "prefix-limit: peer not found");
		return -1;
	}
	*direction_out = yang_dnode_get_string(dl, "direction");
	if (!*direction_out) {
		snprintfrr(errmsg, errmsg_len,
			   "prefix-limit: missing direction key");
		return -1;
	}
	return 0;
}

/*
 * skip_leaf: on a DESTROY callback the dnode still shows the OLD
 * tree, so the dying leaf would be re-read and its value RE-APPLIED.
 * Callers pass the schema name of the leaf being destroyed; every
 * option read ignores that leaf so the knob keeps its default.
 */
static int bgp_nb_pl_apply_inbound(struct peer *peer, afi_t afi, safi_t safi,
				   const struct lyd_node *dl,
				   const char *skip_leaf, char *errmsg,
				   size_t errmsg_len)
{
	uint32_t max;
	uint8_t threshold = MAXIMUM_PREFIX_THRESHOLD_DEFAULT;
	uint16_t restart = 0;
	bool warning = false;
	bool force = false;

	max = yang_dnode_get_uint32(dl, "max-prefixes");
	if (yang_dnode_exists(dl, "force-check"))
		force = yang_dnode_get_bool(dl, "force-check");

	/*
	 * YANG choice: at most one option case is instantiated, but a
	 * multi-leaf case (tr/tw) can have ONE leaf destroyed while the
	 * sibling stays. Read each leaf individually and honour skip_leaf
	 * per leaf, so destroying the threshold of tr/tw resets only the
	 * threshold and keeps the timer/warning of the surviving case.
	 */
	if ((!skip_leaf || strcmp(skip_leaf, "warning-only"))
	    && yang_dnode_exists(dl, "options/warning-only"))
		warning = yang_dnode_get_bool(dl, "options/warning-only");
	if ((!skip_leaf || strcmp(skip_leaf, "restart-timer"))
	    && yang_dnode_exists(dl, "options/restart-timer"))
		restart = yang_dnode_get_uint16(dl,
						"options/restart-timer");
	if ((!skip_leaf || strcmp(skip_leaf, "shutdown-threshold-pct"))
	    && yang_dnode_exists(dl, "options/shutdown-threshold-pct"))
		threshold = yang_dnode_get_uint8(
			dl, "options/shutdown-threshold-pct");
	if ((!skip_leaf || strcmp(skip_leaf, "tr-shutdown-threshold-pct"))
	    && yang_dnode_exists(dl, "options/tr-shutdown-threshold-pct"))
		threshold = yang_dnode_get_uint8(
			dl, "options/tr-shutdown-threshold-pct");
	if ((!skip_leaf || strcmp(skip_leaf, "tr-restart-timer"))
	    && yang_dnode_exists(dl, "options/tr-restart-timer"))
		restart = yang_dnode_get_uint16(dl,
						"options/tr-restart-timer");
	if ((!skip_leaf || strcmp(skip_leaf, "tw-shutdown-threshold-pct"))
	    && yang_dnode_exists(dl, "options/tw-shutdown-threshold-pct"))
		threshold = yang_dnode_get_uint8(
			dl, "options/tw-shutdown-threshold-pct");
	if ((!skip_leaf || strcmp(skip_leaf, "tw-warning-only"))
	    && yang_dnode_exists(dl, "options/tw-warning-only"))
		warning = yang_dnode_get_bool(dl, "options/tw-warning-only");

	return bgp_nb_setter_result(
		peer_maximum_prefix_set(peer, afi, safi, max, threshold,
					warning, restart, force),
		errmsg, errmsg_len);
}

int bgp_peer_af_prefix_limit_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	/*
	 * Nothing to apply on bare entry creation: max-prefixes is
	 * mandatory and its modify callback drives the legacy setters
	 * with the full knob set once the sibling leaves land.
	 */
	return NB_OK;
}

int bgp_peer_af_prefix_limit_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *direction;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_pl_lookup(args->dnode, &peer, &afi, &safi, &direction,
			     args->errmsg, args->errmsg_len) < 0)
		return NB_OK;
	if (strmatch(direction, "out"))
		return bgp_nb_setter_result(
			peer_maximum_prefix_out_unset(peer, afi, safi),
			args->errmsg, args->errmsg_len);
	return bgp_nb_setter_result(
		peer_maximum_prefix_unset(peer, afi, safi),
		args->errmsg, args->errmsg_len);
}

int bgp_peer_af_prefix_limit_max_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *direction;
	const struct lyd_node *dl;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_pl_lookup(args->dnode, &peer, &afi, &safi, &direction,
			     args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	dl = bgp_nb_pl_dlist(args->dnode);
	if (strmatch(direction, "out"))
		return bgp_nb_setter_result(
			peer_maximum_prefix_out_set(
				peer, afi, safi,
				yang_dnode_get_uint32(args->dnode, NULL)),
			args->errmsg, args->errmsg_len);
	return bgp_nb_pl_apply_inbound(peer, afi, safi, dl, NULL,
				       args->errmsg, args->errmsg_len);
}

int bgp_peer_af_prefix_limit_force_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *direction;
	const struct lyd_node *dl;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!yang_dnode_get_bool(args->dnode, NULL))
			return NB_OK;
		dl = bgp_nb_pl_dlist(args->dnode);
		direction = dl ? yang_dnode_get_string(dl, "direction")
			       : NULL;
		if (!direction || strmatch(direction, "out")) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "force-check is only valid for the inbound direction");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_pl_lookup(args->dnode, &peer, &afi, &safi, &direction,
			     args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;
	dl = bgp_nb_pl_dlist(args->dnode);
	return bgp_nb_pl_apply_inbound(peer, afi, safi, dl, NULL,
				       args->errmsg, args->errmsg_len);
}

static int bgp_nb_pl_option_common(const struct lyd_node *dnode,
				   const char *skip_leaf, char *errmsg,
				   size_t errmsg_len)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *direction;
	const struct lyd_node *dl;

	if (bgp_nb_pl_lookup(dnode, &peer, &afi, &safi, &direction, errmsg,
			     errmsg_len) < 0)
		return NB_ERR;
	/* option leaves only exist for direction=in (schema when). */
	dl = bgp_nb_pl_dlist(dnode);
	return bgp_nb_pl_apply_inbound(peer, afi, safi, dl, skip_leaf,
				       errmsg, errmsg_len);
}

int bgp_peer_af_prefix_limit_option_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		/*
		 * The tr/tw cases are two-leaf shapes: a timer (or
		 * warning) without its own threshold leaf would be
		 * accepted by the schema but silently ignored by the
		 * reapply (which reads the threshold as default), so
		 * reject the half-case up front.
		 */
		if (args->dnode->schema
		    && !strcmp(args->dnode->schema->name, "tr-restart-timer")
		    && !yang_dnode_exists(
			       args->dnode, "../tr-shutdown-threshold-pct")) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "tr-restart-timer requires tr-shutdown-threshold-pct");
			return NB_ERR_VALIDATION;
		}
		if (args->dnode->schema
		    && !strcmp(args->dnode->schema->name, "tw-warning-only")
		    && !yang_dnode_exists(
			       args->dnode, "../tw-shutdown-threshold-pct")) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "tw-warning-only requires tw-shutdown-threshold-pct");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_pl_option_common(args->dnode, NULL, args->errmsg,
				       args->errmsg_len);
}

int bgp_peer_af_prefix_limit_option_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	/*
	 * The dnode shows the OLD tree: skip the dying leaf so the
	 * reapply keeps the default instead of resurrecting the value
	 * being destroyed.
	 */
	return bgp_nb_pl_option_common(
		args->dnode,
		args->dnode->schema ? args->dnode->schema->name : NULL,
		args->errmsg, args->errmsg_len);
}

/*
 * Per-AF neighbor fanout (S059): the l2vpn-evpn per-neighbor knobs
 * under neighbors/neighbor, neighbors/unnumbered-neighbor and
 * peer-groups/peer-group. The callbacks resolve the peer through the
 * context-probing lookup above, so the same callbacks serve all three
 * contexts, and every knob maps 1:1 onto the legacy setter the CLI
 * DEFUNs call (peer_allowas_in_set, peer_distribute_set,
 * peer_advertise_map_set, peer_unsuppress_map_set, the addpath and
 * SoO paths). Multi-leaf knobs follow the Fase B datastore-truth
 * pattern: each callback re-derives the full knob set from the
 * sibling leaves and destroy skips the dying leaf (the dnode shows
 * the OLD tree on destroy).
 */

/*
 * addpath-rx-paths-limit: the flag table maps the limit flag to
 * peer_change_none, so the capability announce is driven here exactly
 * like the CLI DEFUN does (flag, then the send limit, then the
 * dynamic capability update).
 */
static int bgp_nb_addpath_rx_limit_apply(const struct lyd_node *dnode,
					 char *errmsg, size_t errmsg_len,
					 bool set)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	int ret;

	if (bgp_nb_peer_af_lookup(dnode, 3, &peer, &afi, &safi) < 0)
		return set ? NB_ERR : NB_OK;
	ret = set ? peer_af_flag_set(peer, afi, safi,
				     PEER_FLAG_ADDPATH_RX_PATHS_LIMIT)
		  : peer_af_flag_unset(peer, afi, safi,
				       PEER_FLAG_ADDPATH_RX_PATHS_LIMIT);
	peer->addpath_paths_limit[afi][safi].send =
		set ? yang_dnode_get_uint16(dnode, NULL) : 0;
	bgp_capability_send(peer->connection, afi, safi,
			    CAPABILITY_CODE_PATHS_LIMIT,
			    CAPABILITY_ACTION_SET);
	return bgp_nb_setter_result(ret, errmsg, errmsg_len);
}

int bgp_neighbor_af_addpath_rx_limit_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_addpath_rx_limit_apply(args->dnode, args->errmsg,
					     args->errmsg_len, true);
}

int bgp_neighbor_af_addpath_rx_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_addpath_rx_limit_apply(args->dnode, args->errmsg,
					     args->errmsg_len, false);
}

/*
 * addpath-tx-best-selected: only instantiable when path-type is
 * best-selected (schema when); destroy resets the count like the
 * legacy "no" form.
 */
static int bgp_nb_addpath_best_selected_apply(
	const struct lyd_node *dnode, bool set)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	if (bgp_nb_peer_af_lookup(dnode, 3, &peer, &afi, &safi) < 0)
		return set ? NB_ERR : NB_OK;
	bgp_addpath_set_peer_type(peer, afi, safi,
				  BGP_ADDPATH_BEST_SELECTED,
				  set ? yang_dnode_get_uint8(dnode, NULL)
				      : 0);
	return NB_OK;
}

int bgp_neighbor_af_addpath_best_selected_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_addpath_best_selected_apply(args->dnode, true);
}

int bgp_neighbor_af_addpath_best_selected_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_addpath_best_selected_apply(args->dnode, false);
}

/*
 * allowas-in: one legacy knob fed by three sibling leaves
 * (allow-own-as, allow-own-origin-as, allowas-in-route-map). The
 * datastore is the source of truth: every modify re-applies the
 * setter with all surviving siblings and every destroy skips the
 * dying leaf; nothing left standing maps onto peer_allowas_in_unset.
 */
static int bgp_nb_allowas_in_apply(const struct lyd_node *dnode,
				   const char *skip_leaf, char *errmsg,
				   size_t errmsg_len)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *aspo;
	const char *rmap = NULL;
	int num = BGP_ALLOWAS_IN_DEFAULT;
	bool origin = false;
	bool have_any = false;

	/* destroy must not abort the transaction (house convention) */
	if (bgp_nb_peer_af_lookup(dnode, 3, &peer, &afi, &safi) < 0)
		return skip_leaf ? NB_OK : NB_ERR;

	aspo = yang_dnode_get_parent(dnode, "as-path-options");
	if (!aspo)
		return NB_ERR;

	if ((!skip_leaf || !strmatch(skip_leaf, "allow-own-as"))
	    && yang_dnode_exists(aspo, "allow-own-as")) {
		num = yang_dnode_get_uint8(aspo, "allow-own-as");
		have_any = true;
	}
	if ((!skip_leaf || !strmatch(skip_leaf, "allow-own-origin-as"))
	    && yang_dnode_exists(aspo, "allow-own-origin-as")
	    && yang_dnode_get_bool(aspo, "allow-own-origin-as")) {
		origin = true;
		have_any = true;
	}
	if ((!skip_leaf || !strmatch(skip_leaf, "allowas-in-route-map"))
	    && yang_dnode_exists(aspo, "allowas-in-route-map")) {
		rmap = yang_dnode_get_string(aspo, "allowas-in-route-map");
		have_any = true;
	}

	if (!have_any)
		return bgp_nb_setter_result(
			peer_allowas_in_unset(peer, afi, safi), errmsg,
			errmsg_len);

	if (origin)
		num = 0;
	return bgp_nb_setter_result(
		peer_allowas_in_set(peer, afi, safi, num, origin, rmap),
		errmsg, errmsg_len);
}

int bgp_neighbor_af_allow_own_as_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_allowas_in_apply(args->dnode, NULL, args->errmsg,
				       args->errmsg_len);
}

int bgp_neighbor_af_allow_own_as_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_allowas_in_apply(
		args->dnode,
		args->dnode->schema ? args->dnode->schema->name : NULL,
		args->errmsg, args->errmsg_len);
}

int bgp_neighbor_af_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_allowas_in_apply(args->dnode, NULL, args->errmsg,
				       args->errmsg_len);
}

int bgp_neighbor_af_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_allowas_in_apply(
		args->dnode,
		args->dnode->schema ? args->dnode->schema->name : NULL,
		args->errmsg, args->errmsg_len);
}

int bgp_neighbor_af_allowas_in_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_allowas_in_apply(args->dnode, NULL, args->errmsg,
				       args->errmsg_len);
}

int bgp_neighbor_af_allowas_in_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_allowas_in_apply(
		args->dnode,
		args->dnode->schema ? args->dnode->schema->name : NULL,
		args->errmsg, args->errmsg_len);
}

/*
 * Conditional advertisement: the legacy knob needs the advertise-map
 * AND the condition together, so a half-configured tree programs
 * nothing; the knob arms once both halves exist. Destroy reads the
 * OLD tree (the dying pair is still visible) and tears the pair down.
 */
static int bgp_nb_cond_adv_apply(const struct lyd_node *dnode, bool set,
				 char *errmsg, size_t errmsg_len)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *ca;
	const char *adv = NULL;
	const char *cond = NULL;
	bool condition = CONDITION_EXIST;

	if (bgp_nb_peer_af_lookup(dnode, 3, &peer, &afi, &safi) < 0)
		return set ? NB_ERR : NB_OK;

	ca = yang_dnode_get_parent(dnode, "conditional-advertisement");
	if (!ca)
		return set ? NB_ERR : NB_OK;

	if (yang_dnode_exists(ca, "advertise-map"))
		adv = yang_dnode_get_string(ca, "advertise-map");
	if (yang_dnode_exists(ca, "exist-map")) {
		cond = yang_dnode_get_string(ca, "exist-map");
		condition = CONDITION_EXIST;
	} else if (yang_dnode_exists(ca, "non-exist-map")) {
		cond = yang_dnode_get_string(ca, "non-exist-map");
		condition = CONDITION_NON_EXIST;
	}

	if (set) {
		if (!adv || !cond)
			return NB_OK;
		return bgp_nb_setter_result(
			peer_advertise_map_set(
				peer, afi, safi, adv,
				route_map_lookup_by_name(adv), cond,
				route_map_lookup_by_name(cond), condition),
			errmsg, errmsg_len);
	}

	if (!adv && !cond)
		return NB_OK;
	return bgp_nb_setter_result(
		peer_advertise_map_unset(
			peer, afi, safi, adv, adv ? route_map_lookup_by_name(adv) : NULL,
			cond, cond ? route_map_lookup_by_name(cond) : NULL,
			condition),
		errmsg, errmsg_len);
}

int bgp_neighbor_af_cond_adv_advertise_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_cond_adv_apply(args->dnode, true, args->errmsg,
				     args->errmsg_len);
}

int bgp_neighbor_af_cond_adv_advertise_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_cond_adv_apply(args->dnode, false, args->errmsg,
				     args->errmsg_len);
}

int bgp_neighbor_af_cond_adv_exist_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_cond_adv_apply(args->dnode, true, args->errmsg,
				     args->errmsg_len);
}

int bgp_neighbor_af_cond_adv_exist_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_cond_adv_apply(args->dnode, false, args->errmsg,
				     args->errmsg_len);
}

int bgp_neighbor_af_cond_adv_non_exist_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_cond_adv_apply(args->dnode, true, args->errmsg,
				     args->errmsg_len);
}

int bgp_neighbor_af_cond_adv_non_exist_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_cond_adv_apply(args->dnode, false, args->errmsg,
				     args->errmsg_len);
}

/*
 * Per-AF name-based filters: distribute-list (access-list),
 * filter-list (as-path access-list) and prefix-list. Same shape as
 * the route-map filters above: bind by name, the referenced object
 * does not have to exist yet.
 */
static int bgp_neighbor_af_name_filter_modify(
	struct nb_cb_modify_args *args, int kind, int direct)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const char *name;
	int ret = 0;

	if (bgp_nb_peer_af_lookup(args->dnode, 3, &peer, &afi, &safi) < 0)
		return NB_ERR;
	name = yang_dnode_get_string(args->dnode, NULL);
	switch (kind) {
	case 0:
		ret = peer_distribute_set(peer, afi, safi, direct, name);
		break;
	case 1:
		ret = peer_aslist_set(peer, afi, safi, direct, name);
		break;
	case 2:
		ret = peer_prefix_list_set(peer, afi, safi, direct, name);
		break;
	}
	return bgp_nb_setter_result(ret, args->errmsg, args->errmsg_len);
}

static int bgp_neighbor_af_name_filter_destroy(
	struct nb_cb_destroy_args *args, int kind, int direct)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	int ret = 0;

	if (bgp_nb_peer_af_lookup(args->dnode, 3, &peer, &afi, &safi) < 0)
		return NB_OK;
	switch (kind) {
	case 0:
		ret = peer_distribute_unset(peer, afi, safi, direct);
		break;
	case 1:
		ret = peer_aslist_unset(peer, afi, safi, direct);
		break;
	case 2:
		ret = peer_prefix_list_unset(peer, afi, safi, direct);
		break;
	}
	return bgp_nb_setter_result(ret, args->errmsg, args->errmsg_len);
}

#define BGP_NEIGHBOR_AF_NAME_FILTER_CB(_kind, _direct, _kindname, _dirname)    \
	int bgp_neighbor_af_##_kindname##_##_dirname##_modify(                 \
		struct nb_cb_modify_args *args)                               \
	{                                                                      \
		return bgp_neighbor_af_name_filter_modify(args, (_kind),     \
							  (_direct));             \
	}                                                                      \
	int bgp_neighbor_af_##_kindname##_##_dirname##_destroy(                \
		struct nb_cb_destroy_args *args)                              \
	{                                                                      \
		return bgp_neighbor_af_name_filter_destroy(args, (_kind),     \
							   (_direct));            \
	}

BGP_NEIGHBOR_AF_NAME_FILTER_CB(0, FILTER_IN, access_list, import)
BGP_NEIGHBOR_AF_NAME_FILTER_CB(0, FILTER_OUT, access_list, export)
BGP_NEIGHBOR_AF_NAME_FILTER_CB(1, FILTER_IN, as_path_filter, import)
BGP_NEIGHBOR_AF_NAME_FILTER_CB(1, FILTER_OUT, as_path_filter, export)
BGP_NEIGHBOR_AF_NAME_FILTER_CB(2, FILTER_IN, plist, import)
BGP_NEIGHBOR_AF_NAME_FILTER_CB(2, FILTER_OUT, plist, export)

/*
 * unsuppress-map: one legacy knob (filter->usmap) exposed as import
 * and export leaves. Whatever leaf survives wins; nothing left maps
 * onto peer_unsuppress_map_unset.
 */
static int bgp_nb_usmap_apply(const struct lyd_node *dnode,
			      const char *skip_leaf, char *errmsg,
			      size_t errmsg_len)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	const struct lyd_node *fc;
	const char *name = NULL;

	if (bgp_nb_peer_af_lookup(dnode, 3, &peer, &afi, &safi) < 0)
		return skip_leaf ? NB_OK : NB_ERR;

	fc = yang_dnode_get_parent(dnode, "filter-config");
	if (!fc)
		return NB_ERR;

	if ((!skip_leaf || !strmatch(skip_leaf, "unsuppress-map-export"))
	    && yang_dnode_exists(fc, "unsuppress-map-export"))
		name = yang_dnode_get_string(fc, "unsuppress-map-export");
	if (!name
	    && (!skip_leaf || !strmatch(skip_leaf, "unsuppress-map-import"))
	    && yang_dnode_exists(fc, "unsuppress-map-import"))
		name = yang_dnode_get_string(fc, "unsuppress-map-import");

	if (name)
		return bgp_nb_setter_result(
			peer_unsuppress_map_set(
				peer, afi, safi, name,
				route_map_lookup_by_name(name)),
			errmsg, errmsg_len);
	return bgp_nb_setter_result(
		peer_unsuppress_map_unset(peer, afi, safi), errmsg,
		errmsg_len);
}

int bgp_neighbor_af_unsuppress_map_export_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_usmap_apply(args->dnode, NULL, args->errmsg,
				  args->errmsg_len);
}

int bgp_neighbor_af_unsuppress_map_export_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_usmap_apply(
		args->dnode,
		args->dnode->schema ? args->dnode->schema->name : NULL,
		args->errmsg, args->errmsg_len);
}

int bgp_neighbor_af_unsuppress_map_import_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_usmap_apply(args->dnode, NULL, args->errmsg,
				  args->errmsg_len);
}

int bgp_neighbor_af_unsuppress_map_import_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_usmap_apply(
		args->dnode,
		args->dnode->schema ? args->dnode->schema->name : NULL,
		args->errmsg, args->errmsg_len);
}

/*
 * Site-of-Origin: parse in VALIDATE so a malformed community fails
 * the commit instead of poisoning the APPLY path (S058 lesson).
 */
int bgp_neighbor_af_soo_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	struct ecommunity *ecomm_soo;
	const char *str;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE: {
		struct ecommunity *probe;

		probe = ecommunity_str2com(
			yang_dnode_get_string(args->dnode, NULL),
			ECOMMUNITY_SITE_ORIGIN, 0);
		if (!probe) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "Malformed SoO extended community");
			return NB_ERR_VALIDATION;
		}
		ecommunity_free(&probe);
		return NB_OK;
	}
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_peer_af_lookup(args->dnode, 3, &peer, &afi, &safi) < 0)
		return NB_ERR;
	str = yang_dnode_get_string(args->dnode, NULL);
	ecomm_soo = ecommunity_str2com(str, ECOMMUNITY_SITE_ORIGIN, 0);
	if (!ecomm_soo) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "Malformed SoO extended community");
		return NB_ERR;
	}
	ecommunity_str(ecomm_soo);

	if (!ecommunity_match(peer->soo[afi][safi], ecomm_soo)) {
		ecommunity_free(&peer->soo[afi][safi]);
		peer->soo[afi][safi] = ecomm_soo;
		peer_af_flag_unset(peer, afi, safi, PEER_FLAG_SOO);
	} else {
		ecommunity_free(&ecomm_soo);
	}

	ret = peer_af_flag_set(peer, afi, safi, PEER_FLAG_SOO);
	return bgp_nb_setter_result(ret, args->errmsg, args->errmsg_len);
}

int bgp_neighbor_af_soo_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
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
	if (bgp_nb_peer_af_lookup(args->dnode, 3, &peer, &afi, &safi) < 0)
		return NB_OK;
	ecommunity_free(&peer->soo[afi][safi]);
	return bgp_nb_setter_result(
		peer_af_flag_unset(peer, afi, safi, PEER_FLAG_SOO),
		args->errmsg, args->errmsg_len);
}

/*
 * Network configuration (G-NC): the per-AFI-SAFI "network <prefix>"
 * static routes. Plain AFs keep a flat network-config[prefix] list;
 * the two l3vpn AFs nest a prefix-list[prefix] list under
 * network-config[rd] (label-index mandatory there, mirroring the
 * legacy `network X rd R label N` knob). These callbacks reuse the
 * same primitives as the legacy bgp_static_set() path in
 * bgp_route.c so the resulting struct bgp_static and BGP RIB state
 * are identical, and the CLI keeps legacy authority through the
 * dual-write funnel in bgp_static_set() itself.
 */
static int bgp_nb_af_network_vpn_create(struct nb_cb_create_args *args,
					struct bgp *bgp, afi_t afi,
					safi_t safi);
static int bgp_nb_af_network_vpn_destroy(struct nb_cb_destroy_args *args,
					 struct bgp *bgp, afi_t afi,
					 safi_t safi);

static int bgp_nb_network_af_lookup(const struct lyd_node *dnode,
				    int ups_to_af, struct bgp **bgp_out,
				    afi_t *afi_out, safi_t *safi_out)
{
	static const char *const af_rel[] = {NULL, "../", "../../",
					      "../../../", "../../../../"};
	const char *afi_safi_id;
	char rel_xpath[64];
	struct bgp *bgp;

	assert(ups_to_af >= 1 && ups_to_af <= 4);

	bgp = bgp_nb_lookup_from_dnode(dnode, ups_to_af + 4);
	if (!bgp)
		return -1;

	snprintfrr(rel_xpath, sizeof(rel_xpath), "%safi-safi-name",
		   af_rel[ups_to_af]);
	afi_safi_id = yang_dnode_get_string(dnode, "%s", rel_xpath);
	if (!afi_safi_id)
		return -1;
	if (bgp_nb_af_id_to_afi_safi(afi_safi_id, afi_out, safi_out) < 0)
		return -1;
	*bgp_out = bgp;
	return 0;
}

static int bgp_nb_network_prefix_parse(const char *prefix_str, afi_t afi,
				       struct prefix *p, char *errmsg,
				       size_t errmsg_len)
{
	if (!str2prefix(prefix_str, p)) {
		snprintfrr(errmsg, errmsg_len, "malformed prefix '%s'",
			   prefix_str);
		return -1;
	}
	apply_mask(p);
	if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6)) {
		snprintfrr(errmsg, errmsg_len,
			   "malformed prefix (link-local address)");
		return -1;
	}
	return 0;
}

static int bgp_nb_network_rd_parse(const char *rd_str, struct prefix_rd *prd,
				   char *errmsg, size_t errmsg_len)
{
	if (!str2prefix_rd(rd_str, prd)) {
		snprintfrr(errmsg, errmsg_len, "malformed rd '%s'", rd_str);
		return -1;
	}
	return 0;
}

static void bgp_nb_network_rmap_bind(struct bgp_static *bgp_static,
				     const char *name)
{
	XFREE(MTYPE_ROUTE_MAP_NAME, bgp_static->rmap.name);
	route_map_counter_decrement(bgp_static->rmap.map);
	if (name) {
		bgp_static->rmap.name =
			XSTRDUP(MTYPE_ROUTE_MAP_NAME, name);
		bgp_static->rmap.map = route_map_lookup_by_name(name);
		route_map_counter_increment(bgp_static->rmap.map);
	} else {
		bgp_static->rmap.map = NULL;
	}
}

static void bgp_nb_network_apply(struct bgp *bgp, const struct prefix *p,
				 struct bgp_static *bgp_static, afi_t afi,
				 safi_t safi)
{
	bgp_static->valid = 1;
	if (!bgp_static->backdoor)
		bgp_static_update(bgp, p, bgp_static, afi, safi);
}

static struct bgp_dest *bgp_nb_network_vpn_table(struct bgp *bgp, afi_t afi,
						 safi_t safi,
						 const char *rd_str,
						 struct prefix_rd *prd,
						 bool create, char *errmsg,
						 size_t errmsg_len)
{
	struct bgp_dest *pdest;

	if (bgp_nb_network_rd_parse(rd_str, prd, errmsg, errmsg_len) < 0)
		return NULL;
	pdest = bgp_node_lookup(bgp->static_routes[afi][safi],
				(struct prefix *)prd);
	if (!pdest) {
		if (!create) {
			snprintfrr(errmsg, errmsg_len,
				   "no static route rd %s", rd_str);
			return NULL;
		}
		pdest = bgp_node_get(bgp->static_routes[afi][safi],
				     (struct prefix *)prd);
		if (!bgp_dest_has_bgp_path_info_data(pdest))
			bgp_dest_set_bgp_table_info(
				pdest, bgp_table_init(bgp, afi, safi));
	}
	return pdest;
}

int bgp_global_af_network_config_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct prefix p;
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_network_af_lookup(
			    args->dnode, 2, &bgp, &afi, &safi) == 0 &&
		    safi != SAFI_MPLS_VPN &&
		    yang_dnode_exists(args->dnode, "prefix") &&
		    bgp_nb_network_prefix_parse(
			    yang_dnode_get_string(args->dnode, "prefix"), afi,
			    &p, args->errmsg, args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_network_af_lookup(args->dnode, 2, &bgp, &afi, &safi) < 0)
		return NB_ERR;
	/*
	 * The l3vpn entry is keyed by rd (no prefix leaf): route to the
	 * vpn helpers BEFORE any prefix read -- the yang wrappers abort
	 * the daemon on a missing node.
	 */
	if (safi == SAFI_MPLS_VPN)
		return bgp_nb_af_network_vpn_create(args, bgp, afi, safi);
	if (bgp_nb_network_prefix_parse(
		    yang_dnode_get_string(args->dnode, "prefix"), afi, &p,
		    args->errmsg, args->errmsg_len) < 0)
		return NB_ERR;

	dest = bgp_node_get(bgp->static_routes[afi][safi], &p);
	if (bgp_dest_get_bgp_static_info(dest)) {
		/* idempotent re-create: keep the existing static */
		bgp_dest_unlock_node(dest);
		return NB_OK;
	}
	bgp_static = bgp_static_new();
	bgp_static->backdoor =
		yang_dnode_exists(args->dnode, "backdoor")
			&& yang_dnode_get_bool(args->dnode, "backdoor");
	bgp_static->valid = 0;
	bgp_static->igpmetric = 0;
	bgp_static->igpnexthop.s_addr = INADDR_ANY;
	bgp_static->label_index =
		yang_dnode_exists(args->dnode, "label-index")
			? yang_dnode_get_uint32(args->dnode, "label-index")
			: BGP_INVALID_LABEL_INDEX;
	if (yang_dnode_exists(args->dnode, "rmap-policy-export"))
		bgp_nb_network_rmap_bind(
			bgp_static,
			yang_dnode_get_string(args->dnode,
					      "rmap-policy-export"));
	bgp_dest_set_bgp_static_info(dest, bgp_static);
	bgp_nb_network_apply(bgp, &p, bgp_static, afi, safi);
	return NB_OK;
}

int bgp_global_af_network_config_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct prefix p;
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_network_af_lookup(args->dnode, 2, &bgp, &afi, &safi) < 0)
		return NB_OK;
	/* l3vpn entry: keyed by rd; no prefix leaf to parse. */
	if (safi == SAFI_MPLS_VPN)
		return bgp_nb_af_network_vpn_destroy(args, bgp, afi, safi);
	if (bgp_nb_network_prefix_parse(
		    yang_dnode_get_string(args->dnode, "prefix"), afi, &p,
		    NULL, 0) < 0)
		return NB_OK;

	dest = bgp_node_lookup(bgp->static_routes[afi][safi], &p);
	if (!dest)
		return NB_OK;
	bgp_static = bgp_dest_get_bgp_static_info(dest);
	if (bgp_static) {
		if (!bgp_static->backdoor)
			bgp_static_withdraw(bgp, &p, afi, safi, NULL);
		bgp_static_free(bgp_static);
	}
	bgp_dest_set_bgp_static_info(dest, NULL);
	dest = bgp_dest_unlock_node(dest);
	assert(dest);
	bgp_dest_unlock_node(dest);
	return NB_OK;
}

static struct bgp_static *bgp_nb_network_static_lookup(
	struct bgp *bgp, afi_t afi, safi_t safi, const struct prefix *p,
	struct bgp_dest **dest_out, char *errmsg, size_t errmsg_len)
{
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;

	dest = bgp_node_lookup(bgp->static_routes[afi][safi], p);
	if (!dest) {
		snprintfrr(errmsg, errmsg_len,
			   "can't find static route specified");
		return NULL;
	}
	bgp_static = bgp_dest_get_bgp_static_info(dest);
	if (!bgp_static) {
		bgp_dest_unlock_node(dest);
		snprintfrr(errmsg, errmsg_len,
			   "can't find static route specified");
		return NULL;
	}
	*dest_out = dest;
	return bgp_static;
}

static int bgp_nb_network_backdoor_common(const struct lyd_node *dnode,
					  bool backdoor, char *errmsg,
					  size_t errmsg_len)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct prefix p;
	struct bgp_dest *dest = NULL;
	struct bgp_static *bgp_static;
	bool need_update;

	if (bgp_nb_network_af_lookup(dnode, 3, &bgp, &afi, &safi) < 0)
		return NB_ERR;
	if (bgp_nb_network_prefix_parse(
		    yang_dnode_get_string(dnode, "../prefix"), afi, &p, errmsg,
		    errmsg_len) < 0)
		return NB_ERR;
	bgp_static = bgp_nb_network_static_lookup(bgp, afi, safi, &p, &dest,
						  errmsg, errmsg_len);
	if (!bgp_static)
		return NB_ERR;
	need_update = bgp_static->valid
		      && bgp_static->backdoor != backdoor;
	bgp_static->backdoor = backdoor;
	if (need_update)
		bgp_static_withdraw(bgp, &p, afi, safi, NULL);
	bgp_dest_unlock_node(dest);
	bgp_nb_network_apply(bgp, &p, bgp_static, afi, safi);
	return NB_OK;
}

int bgp_global_af_network_backdoor_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_network_backdoor_common(
		args->dnode, yang_dnode_get_bool(args->dnode, NULL),
		args->errmsg, args->errmsg_len);
}

static int bgp_nb_network_label_common(const struct lyd_node *dnode,
				       bool removed, char *errmsg,
				       size_t errmsg_len)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct prefix p;
	struct bgp_dest *dest = NULL;
	struct bgp_static *bgp_static;
	uint32_t label_index;

	if (bgp_nb_network_af_lookup(dnode, 3, &bgp, &afi, &safi) < 0)
		return NB_ERR;
	if (bgp_nb_network_prefix_parse(
		    yang_dnode_get_string(dnode, "../prefix"), afi, &p, errmsg,
		    errmsg_len) < 0)
		return NB_ERR;
	bgp_static = bgp_nb_network_static_lookup(bgp, afi, safi, &p, &dest,
						  errmsg, errmsg_len);
	if (!bgp_static)
		return NB_ERR;
	label_index = removed ? BGP_INVALID_LABEL_INDEX
			      : yang_dnode_get_uint32(dnode, NULL);
	if (bgp_static->label_index != BGP_INVALID_LABEL_INDEX &&
	    bgp_static->label_index != label_index) {
		bgp_dest_unlock_node(dest);
		snprintfrr(errmsg, errmsg_len, "cannot change label-index");
		return NB_ERR;
	}
	if (bgp_static->label_index != label_index) {
		bgp_static->label_index = label_index;
		encode_label(label_index, &bgp_static->label);
	}
	bgp_dest_unlock_node(dest);
	return NB_OK;
}

int bgp_global_af_network_label_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_network_label_common(args->dnode, false,
					   args->errmsg, args->errmsg_len);
}

int bgp_global_af_network_label_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_network_label_common(args->dnode, true,
					   args->errmsg, args->errmsg_len);
}

static int bgp_nb_network_rmap_common(const struct lyd_node *dnode,
				      const char *name, char *errmsg,
				      size_t errmsg_len)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct prefix p;
	struct bgp_dest *dest = NULL;
	struct bgp_static *bgp_static;

	if (bgp_nb_network_af_lookup(dnode, 3, &bgp, &afi, &safi) < 0)
		return NB_ERR;
	if (bgp_nb_network_prefix_parse(
		    yang_dnode_get_string(dnode, "../prefix"), afi, &p, errmsg,
		    errmsg_len) < 0)
		return NB_ERR;
	bgp_static = bgp_nb_network_static_lookup(bgp, afi, safi, &p, &dest,
						  errmsg, errmsg_len);
	if (!bgp_static)
		return NB_ERR;
	bgp_nb_network_rmap_bind(bgp_static, name);
	bgp_dest_unlock_node(dest);
	/*
	 * Re-originate so attribute changes take effect, mirroring the
	 * end state of the legacy `network X route-map NAME` re-issue.
	 */
	bgp_static->valid = 0;
	bgp_nb_network_apply(bgp, &p, bgp_static, afi, safi);
	return NB_OK;
}

int bgp_global_af_network_rmap_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_network_rmap_common(
		args->dnode, yang_dnode_get_string(args->dnode, NULL),
		args->errmsg, args->errmsg_len);
}

int bgp_global_af_network_rmap_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_network_rmap_common(args->dnode, NULL, args->errmsg,
					  args->errmsg_len);
}

/* l3vpn: network-config[rd] creates/destroys the per-RD static table. */
static int bgp_nb_af_network_vpn_create(struct nb_cb_create_args *args,
					struct bgp *bgp, afi_t afi,
					safi_t safi)
{
	struct prefix_rd prd;
	struct bgp_dest *pdest;

	pdest = bgp_nb_network_vpn_table(
		bgp, afi, safi, yang_dnode_get_string(args->dnode, "rd"),
		&prd, true, args->errmsg, args->errmsg_len);
	if (!pdest)
		return NB_ERR;
	return NB_OK;
}

static int bgp_nb_af_network_vpn_destroy(struct nb_cb_destroy_args *args,
					 struct bgp *bgp, afi_t afi,
					 safi_t safi)
{
	struct prefix_rd prd;
	struct bgp_dest *pdest, *dest;
	struct bgp_table *table;
	struct bgp_static *bgp_static;
	struct prefix p;

	if (bgp_nb_network_rd_parse(yang_dnode_get_string(args->dnode, "rd"),
				    &prd, NULL, 0) < 0)
		return NB_OK;
	pdest = bgp_node_lookup(bgp->static_routes[afi][safi],
				(struct prefix *)&prd);
	if (!pdest)
		return NB_OK;
	/*
	 * Withdraw and free every prefix under the RD. The empty RD
	 * node itself is kept, matching the legacy lifecycle where
	 * RD-level nodes persist for the instance lifetime.
	 */
	table = bgp_dest_get_bgp_table_info(pdest);
	if (table) {
		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			bgp_static = bgp_dest_get_bgp_static_info(dest);
			if (!bgp_static)
				continue;
			p = *bgp_dest_get_prefix(dest);
			bgp_static_withdraw(bgp, &p, afi, safi, &prd);
			bgp_static_free(bgp_static);
			bgp_dest_set_bgp_static_info(dest, NULL);
		}
	}
	return NB_OK;
}

/* l3vpn: prefix-list[prefix] entries inside network-config[rd]. */
/*
 * The caller may hand the prefix-list ENTRY or one of its LEAVES
 * (libyang creates the ancestors implicitly on a leaf update, so a
 * "create" often arrives as a leaf modify). Normalize to the entry
 * first: every relative read below ("prefix", "../rd") and the hop
 * count to the afi-safi entry (3) are only valid from the entry
 * itself. The yang wrappers abort the daemon on a missed node, so
 * the schema-name walk replaces fragile depth counting.
 */
static int bgp_nb_network_pl_lookup(const struct lyd_node *dnode,
				    struct bgp **bgp_out, afi_t *afi_out,
				    safi_t *safi_out, struct prefix *p,
				    struct prefix_rd *prd, char *errmsg,
				    size_t errmsg_len)
{
	if (dnode->schema && strcmp(dnode->schema->name, "prefix-list"))
		dnode = yang_dnode_get_parent(dnode, "prefix-list");
	if (!dnode)
		return -1;
	if (bgp_nb_network_af_lookup(dnode, 3, bgp_out, afi_out, safi_out)
	    < 0)
		return -1;
	if (bgp_nb_network_prefix_parse(
		    yang_dnode_get_string(dnode, "prefix"), *afi_out, p,
		    errmsg, errmsg_len) < 0)
		return -1;
	if (!bgp_nb_network_vpn_table(*bgp_out, *afi_out, *safi_out,
				      yang_dnode_get_string(dnode, "../rd"),
				      prd, false, errmsg, errmsg_len))
		return -1;
	return 0;
}

int bgp_global_af_network_pl_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct prefix p;
	struct prefix_rd prd;
	struct bgp_dest *pdest, *dest;
	struct bgp_table *table;
	struct bgp_static *bgp_static;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_network_af_lookup(
			    args->dnode, 3, &bgp, &afi, &safi) == 0 &&
		    bgp_nb_network_prefix_parse(
			    yang_dnode_get_string(args->dnode, "prefix"), afi,
			    &p, args->errmsg, args->errmsg_len) < 0)
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_network_pl_lookup(args->dnode, &bgp, &afi, &safi, &p,
				     &prd, args->errmsg, args->errmsg_len)
	    < 0)
		return NB_ERR;
	pdest = bgp_node_lookup(bgp->static_routes[afi][safi],
				(struct prefix *)&prd);
	if (!pdest)
		return NB_ERR;
	table = bgp_dest_get_bgp_table_info(pdest);
	dest = bgp_node_get(table, &p);
	if (bgp_dest_get_bgp_static_info(dest)) {
		bgp_dest_unlock_node(dest);
		return NB_OK;
	}
	bgp_static = bgp_static_new();
	bgp_static->valid = 0;
	bgp_static->igpmetric = 0;
	bgp_static->igpnexthop.s_addr = INADDR_ANY;
	bgp_static->label_index =
		yang_dnode_get_uint32(args->dnode, "label-index");
	encode_label(bgp_static->label_index, &bgp_static->label);
	bgp_static->prd = prd;
	bgp_static->prd_pretty = XSTRDUP(
		MTYPE_BGP_NAME,
		yang_dnode_get_string(args->dnode, "../rd"));
	if (yang_dnode_exists(args->dnode, "rmap-policy-export"))
		bgp_nb_network_rmap_bind(
			bgp_static,
			yang_dnode_get_string(args->dnode,
					      "rmap-policy-export"));
	bgp_dest_set_bgp_static_info(dest, bgp_static);
	bgp_nb_network_apply(bgp, &p, bgp_static, afi, safi);
	return NB_OK;
}

int bgp_global_af_network_pl_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct prefix p;
	struct prefix_rd prd;
	struct bgp_dest *pdest, *dest;
	struct bgp_table *table;
	struct bgp_static *bgp_static;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_network_pl_lookup(args->dnode, &bgp, &afi, &safi, &p,
				     &prd, NULL, 0) < 0)
		return NB_OK;
	pdest = bgp_node_lookup(bgp->static_routes[afi][safi],
				(struct prefix *)&prd);
	if (!pdest)
		return NB_OK;
	table = bgp_dest_get_bgp_table_info(pdest);
	dest = bgp_node_lookup(table, &p);
	if (!dest)
		return NB_OK;
	bgp_static = bgp_dest_get_bgp_static_info(dest);
	if (bgp_static) {
		bgp_static_withdraw(bgp, &p, afi, safi, &prd);
		bgp_static_free(bgp_static);
	}
	bgp_dest_set_bgp_static_info(dest, NULL);
	dest = bgp_dest_unlock_node(dest);
	assert(dest);
	bgp_dest_unlock_node(dest);
	return NB_OK;
}

int bgp_global_af_network_pl_label_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct prefix p;
	struct prefix_rd prd;
	struct bgp_dest *pdest, *dest = NULL;
	struct bgp_table *table;
	struct bgp_static *bgp_static;
	uint32_t label_index;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_network_pl_lookup(args->dnode, &bgp, &afi, &safi, &p,
				     &prd, args->errmsg, args->errmsg_len)
	    < 0)
		return NB_ERR;
	pdest = bgp_node_lookup(bgp->static_routes[afi][safi],
				(struct prefix *)&prd);
	if (!pdest)
		return NB_ERR;
	table = bgp_dest_get_bgp_table_info(pdest);
	dest = bgp_node_lookup(table, &p);
	if (!dest) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "can't find static route specified");
		return NB_ERR;
	}
	bgp_static = bgp_dest_get_bgp_static_info(dest);
	if (!bgp_static) {
		bgp_dest_unlock_node(dest);
		snprintfrr(args->errmsg, args->errmsg_len,
			   "can't find static route specified");
		return NB_ERR;
	}
	label_index = yang_dnode_get_uint32(args->dnode, NULL);
	if (bgp_static->label_index != BGP_INVALID_LABEL_INDEX &&
	    bgp_static->label_index != label_index) {
		bgp_dest_unlock_node(dest);
		snprintfrr(args->errmsg, args->errmsg_len,
			   "cannot change label-index");
		return NB_ERR;
	}
	if (bgp_static->label_index != label_index) {
		bgp_static->label_index = label_index;
		encode_label(label_index, &bgp_static->label);
		if (bgp_static->valid && !bgp_static->backdoor) {
			bgp_static_withdraw(bgp, &p, afi, safi, &prd);
			bgp_static_update(bgp, &p, bgp_static, afi, safi);
		}
	}
	bgp_dest_unlock_node(dest);
	return NB_OK;
}

static int bgp_nb_network_pl_rmap_common(const struct lyd_node *dnode,
					 const char *name, char *errmsg,
					 size_t errmsg_len)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;
	struct prefix p;
	struct prefix_rd prd;
	struct bgp_dest *pdest, *dest = NULL;
	struct bgp_table *table;
	struct bgp_static *bgp_static;

	if (bgp_nb_network_pl_lookup(dnode, &bgp, &afi, &safi, &p, &prd,
				     errmsg, errmsg_len) < 0)
		return NB_ERR;
	pdest = bgp_node_lookup(bgp->static_routes[afi][safi],
				(struct prefix *)&prd);
	if (!pdest)
		return NB_ERR;
	table = bgp_dest_get_bgp_table_info(pdest);
	dest = bgp_node_lookup(table, &p);
	if (!dest) {
		snprintfrr(errmsg, errmsg_len,
			   "can't find static route specified");
		return NB_ERR;
	}
	bgp_static = bgp_dest_get_bgp_static_info(dest);
	if (!bgp_static) {
		bgp_dest_unlock_node(dest);
		snprintfrr(errmsg, errmsg_len,
			   "can't find static route specified");
		return NB_ERR;
	}
	bgp_nb_network_rmap_bind(bgp_static, name);
	bgp_dest_unlock_node(dest);
	bgp_static->valid = 0;
	bgp_nb_network_apply(bgp, &p, bgp_static, afi, safi);
	return NB_OK;
}

int bgp_global_af_network_pl_rmap_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_network_pl_rmap_common(
		args->dnode, yang_dnode_get_string(args->dnode, NULL),
		args->errmsg, args->errmsg_len);
}

int bgp_global_af_network_pl_rmap_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_network_pl_rmap_common(args->dnode, NULL,
					     args->errmsg,
					     args->errmsg_len);
}

BGP_NEIGHBOR_FLAG_MOD_CB(aigp, PEER_FLAG_AIGP)
BGP_NEIGHBOR_FLAG_MOD_CB(ip_transparent, PEER_FLAG_IP_TRANSPARENT)
BGP_NEIGHBOR_FLAG_MOD_CB(extended_link_bandwidth, PEER_FLAG_EXTENDED_LINK_BANDWIDTH)
BGP_NEIGHBOR_FLAG_MOD_CB(disable_link_bw_encoding_ieee,
		     PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE)
BGP_NEIGHBOR_FLAG_MOD_CB(extended_optional_parameters,
		     PEER_FLAG_EXTENDED_OPT_PARAMS)
BGP_NEIGHBOR_FLAG_MOD_CB(send_nexthop_characteristics,
		     PEER_FLAG_SEND_NHC_ATTRIBUTE)
BGP_NEIGHBOR_FLAG_MOD_CB(rpki_strict, PEER_FLAG_RPKI_STRICT)
BGP_NEIGHBOR_FLAG_MOD_CB(as_loop_detection, PEER_FLAG_AS_LOOP_DETECTION)
BGP_NEIGHBOR_FLAG_MOD_CB(peer_graceful_shutdown, PEER_FLAG_GRACEFUL_SHUTDOWN)

/*
 * Capability leaves moved under the capability-options container:
 * neighbor[remote-address]/capability-options/<leaf>, depth-to-CPP = 5,
 * neighbor_rel = "../..".
 */
/*
 * Capability-option leaves all carry yang defaults: the framework
 * never delivers destroy, so only the modify half is generated.
 */
#define BGP_NEIGHBOR_CAPOPT_FLAG_CB(_name, _flag)                              \
	int bgp_neighbor_##_name##_modify(struct nb_cb_modify_args *args)      \
	{                                                                      \
		return peer_flag_toggle_modify(args, (_flag), "../..", 5);     \
	}

BGP_NEIGHBOR_CAPOPT_FLAG_CB(capability_fqdn, PEER_FLAG_CAPABILITY_FQDN)
BGP_NEIGHBOR_CAPOPT_FLAG_CB(capability_link_local,
			    PEER_FLAG_CAPABILITY_LINK_LOCAL)

/*
 * capability-options/software-version-capability enumeration maps onto
 * the two peer flag bits: disabled -> neither, old-encoding ->
 * PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD, latest-encoding ->
 * PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW.
 */
int bgp_neighbor_capability_software_version_modify(
	struct nb_cb_modify_args *args)
{
	struct peer *peer;
	const char *val;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	val = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(val, "old-encoding")) {
		peer_flag_unset(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);
	} else if (strmatch(val, "latest-encoding")) {
		peer_flag_unset(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);
	} else {
		peer_flag_unset(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);
		peer_flag_unset(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);
	}
	return NB_OK;
}

int bgp_neighbor_capability_software_version_destroy(
	struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;
	peer_flag_unset(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);
	peer_flag_unset(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/timers/delayopen
 */
int bgp_neighbor_timers_delayopen_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint16_t v;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;
	v = yang_dnode_get_uint16(args->dnode, NULL);
	peer_timers_delayopen_set(peer, v);
	return NB_OK;
}

int bgp_neighbor_timers_delayopen_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;
	peer_timers_delayopen_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/admin-shutdown (apply_finish)
 *
 * Only the rtt/rtt-count leaves are wired (parity with the old
 * shutdown-rtt container); enable/message stay stubbed. The container is
 * non-presence, so disabling is expressed by deleting the rtt leaf --
 * handled by the rtt destroy callback below, and guarded here so a
 * change to a stubbed sibling can't set the flag with no rtt configured.
 */
void bgp_neighbor_admin_shutdown_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct peer *peer;

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return;
	if (!yang_dnode_exists(args->dnode, "rtt"))
		return;
	peer->rtt_expected = yang_dnode_get_uint16(args->dnode, "rtt");
	peer->rtt_keepalive_conf = yang_dnode_get_uint8(args->dnode,
							"rtt-count");
	peer_flag_set(peer, PEER_FLAG_RTT_SHUTDOWN);
	return;
}

int bgp_neighbor_admin_shutdown_rtt_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;
	peer_flag_unset(peer, PEER_FLAG_RTT_SHUTDOWN);
	peer->rtt_expected = 0;
	peer->rtt_keepalive_conf = 1;
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/tcp-mss
 */
int bgp_neighbor_tcp_mss_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint32_t mss;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;
	mss = yang_dnode_get_uint32(args->dnode, NULL);
	peer_tcp_mss_set(peer, mss);
	return NB_OK;
}

int bgp_neighbor_tcp_mss_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer_tcp_mss_unset(peer);
	return NB_OK;
}



/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/local-role/{role,strict-mode}
 *
 * Compound container: both leaves contribute to peer_role_set(peer, role,
 * strict_mode). Use apply_finish on the container so role and strict-mode
 * are applied atomically.
 */
void bgp_neighbor_local_role_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct peer *peer;
	const char *role_str;
	uint8_t role;
	bool strict_mode = false;

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return;

	if (yang_dnode_exists(args->dnode, "./role")) {
		role_str = yang_dnode_get_string(args->dnode, "./role");
		if (!strcmp(role_str, "provider"))
			role = ROLE_PROVIDER;
		else if (!strcmp(role_str, "rs-server"))
			role = ROLE_RS_SERVER;
		else if (!strcmp(role_str, "rs-client"))
			role = ROLE_RS_CLIENT;
		else if (!strcmp(role_str, "customer"))
			role = ROLE_CUSTOMER;
		else if (!strcmp(role_str, "peer"))
			role = ROLE_PEER;
		else
			role = ROLE_UNDEFINED;

		if (yang_dnode_exists(args->dnode, "./strict-mode"))
			strict_mode = yang_dnode_get_bool(args->dnode,
							  "./strict-mode");
		peer_role_set(peer, role, strict_mode);
	}
	return;
}

int bgp_neighbor_local_role_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer_role_unset(peer);
	return NB_OK;
}

/*
 * Per-peer graceful-restart trio. YANG choice in
 * structure-neighbor-group-graceful-restart:
 *   graceful-restart/enable
 *   graceful-restart/graceful-restart-helper
 *   graceful-restart/graceful-restart-disable
 *
 * Each leaf is 2 hops up to neighbor (../..) and depth 5 to CPP.
 * Internal effect is bgp_neighbor_graceful_restart_*_set / _unset
 * helpers — for now, just set the corresponding PEER_FLAG via toggle
 * template; full peer-reset side effects are deferred to the dual-write
 * CLI path (same GR compromise).
 */
int bgp_neighbor_gr_enable_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_GRACEFUL_RESTART,
					"../..", 5);
}
int bgp_neighbor_gr_enable_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_GRACEFUL_RESTART,
					 "../..", 5);
}
int bgp_neighbor_gr_helper_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_GRACEFUL_RESTART_HELPER,
					"../..", 5);
}
int bgp_neighbor_gr_helper_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_GRACEFUL_RESTART_HELPER,
					 "../..", 5);
}
int bgp_neighbor_gr_disable_modify(struct nb_cb_modify_args *args)
{
	/* No PEER_FLAG_GRACEFUL_RESTART_DISABLE — the legacy CLI clears
	 * PEER_FLAG_GRACEFUL_RESTART. Mirror that semantic here. */
	return peer_flag_toggle_destroy((struct nb_cb_destroy_args *)args,
					 PEER_FLAG_GRACEFUL_RESTART, "../..", 5);
}
int bgp_neighbor_gr_disable_destroy(struct nb_cb_destroy_args *args)
{
	/* Re-inherit global on destroy — leave flag as-is. */
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/timers (apply_finish on container)
 *
 * keepalive + hold-time are paired (peer_timers_set). Use apply_finish
 * so both leaves are applied atomically when either changes.
 */
void bgp_neighbor_timers_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct peer *peer;
	uint32_t keepalive = 0, holdtime = 0;
	bool have_k = false, have_h = false;

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return;

	if (yang_dnode_exists(args->dnode, "./keepalive")) {
		keepalive = yang_dnode_get_uint16(args->dnode, "./keepalive");
		have_k = true;
	}
	if (yang_dnode_exists(args->dnode, "./hold-time")) {
		holdtime = yang_dnode_get_uint16(args->dnode, "./hold-time");
		have_h = true;
	}
	if (have_k && have_h)
		peer_timers_set(peer, keepalive, holdtime);
	return;
}

int bgp_neighbor_timers_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer_timers_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/oad
 *
 * Sub-sort knob (not a peer flag). True => set sub_sort to BGP_PEER_EBGP_OAD
 * iff peer is EBGP. False/destroy => clear sub_sort.
 */
int bgp_neighbor_oad_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	bool oad;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;
	oad = yang_dnode_get_bool(args->dnode, NULL);
	if (oad && peer->sort == BGP_PEER_EBGP)
		peer->sub_sort = BGP_PEER_EBGP_OAD;
	else
		peer->sub_sort = 0;
	return NB_OK;
}

int bgp_neighbor_oad_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer->sub_sort = 0;
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/ls-local-link-id
 *   .../neighbors/neighbor[remote-address]/ls-remote-link-id
 */
int bgp_neighbor_ls_local_link_id_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint32_t v;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;
	v = yang_dnode_get_uint32(args->dnode, NULL);
	peer->ls_local_link_id = v;
	peer_flag_set(peer, PEER_FLAG_LS_LOCAL_LINK_ID);
	return NB_OK;
}

int bgp_neighbor_ls_local_link_id_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer->ls_local_link_id = 0;
	peer_flag_unset(peer, PEER_FLAG_LS_LOCAL_LINK_ID);
	return NB_OK;
}

int bgp_neighbor_ls_remote_link_id_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint32_t v;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;
	v = yang_dnode_get_uint32(args->dnode, NULL);
	peer->ls_remote_link_id = v;
	/* PEER_FLAG_LS_REMOTE_LINK_ID = (1ULL << 50) — declared after
	 * LS_LOCAL_LINK_ID in bgpd.h. */
#ifdef PEER_FLAG_LS_REMOTE_LINK_ID
	peer_flag_set(peer, PEER_FLAG_LS_REMOTE_LINK_ID);
#endif
	return NB_OK;
}

int bgp_neighbor_ls_remote_link_id_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer->ls_remote_link_id = 0;
#ifdef PEER_FLAG_LS_REMOTE_LINK_ID
	peer_flag_unset(peer, PEER_FLAG_LS_REMOTE_LINK_ID);
#endif
	return NB_OK;
}

/* ------------------------------------------------------------------------ */
/* peer-group list */
/* ------------------------------------------------------------------------ */

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/peer-groups/peer-group
 *
 * Depth from list entry to CPP = 3. peer_group_get() is idempotent (returns
 * existing group if name matches), matching the legacy DEFUN behaviour.
 */
int bgp_peer_group_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *name;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	name = yang_dnode_get_string(args->dnode, "peer-group-name");
	if (!peer_group_get(bgp, name)) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "peer_group_get failed for %s", name);
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_peer_group_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *name;
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "peer-group-name");
	group = peer_group_lookup(bgp, name);
	if (!group)
		return NB_OK;

	peer_group_delete(group);
	return NB_OK;
}

/*
 * leaf-list listen-range entry helper.
 *
 * For a leaf-list, the dnode's value IS the entry. Use
 * yang_dnode_get_string(args->dnode, NULL) to read it. The depth pattern:
 * leaf-list entry sits at depth 4 from CPP (peer-groups, peer-group,
 * leaf-list, entry-value).
 */
static int peer_group_listen_range_apply(const struct lyd_node *dnode, int af,
					  bool add)
{
	struct bgp *bgp;
	const char *pg_name;
	const char *prefix_str;
	struct peer_group *group;
	struct prefix p = {};

	bgp = bgp_nb_lookup_from_dnode(dnode, 4);
	if (!bgp)
		return NB_ERR;

	pg_name = yang_dnode_get_string(dnode, "../peer-group-name");
	group = peer_group_lookup(bgp, pg_name);
	if (!group)
		return NB_ERR;

	prefix_str = yang_dnode_get_string(dnode, NULL);
	if (str2prefix(prefix_str, &p) == 0)
		/* Should have been caught at NB_EV_VALIDATE. */
		return NB_ERR;
	p.family = af;

	if (add) {
		if (peer_group_listen_range_add(group, &p) != 0)
			return NB_ERR;
	} else {
		if (peer_group_listen_range_del(group, &p) != 0)
			return NB_ERR;
	}
	return NB_OK;
}

/* Parse-check the prefix at NB_EV_VALIDATE so a malformed value is rejected
 * before any sibling apply callback runs. */
static int peer_group_listen_range_validate(const struct lyd_node *dnode,
					    char *errmsg, size_t errmsg_len)
{
	const char *prefix_str = yang_dnode_get_string(dnode, NULL);
	struct prefix p = {};

	if (str2prefix(prefix_str, &p) == 0) {
		snprintfrr(errmsg, errmsg_len,
			   "invalid listen-range prefix: %s", prefix_str);
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

int bgp_peer_group_ipv4_listen_range_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_VALIDATE)
		return peer_group_listen_range_validate(args->dnode,
							args->errmsg,
							args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return peer_group_listen_range_apply(args->dnode, AF_INET, true);
}

int bgp_peer_group_ipv4_listen_range_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return peer_group_listen_range_apply(args->dnode, AF_INET, false);
}

int bgp_peer_group_ipv6_listen_range_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_VALIDATE)
		return peer_group_listen_range_validate(args->dnode,
							args->errmsg,
							args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return peer_group_listen_range_apply(args->dnode, AF_INET6, true);
}

int bgp_peer_group_ipv6_listen_range_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return peer_group_listen_range_apply(args->dnode, AF_INET6, false);
}


/* ------------------------------------------------------------------------ */
/* cli_show callbacks                                                        */
/*                                                                           */
/* bgpd uses a dual-write model: DEFPY_YANG bodies invoke legacy setters     */
/* that update the in-memory `struct bgp` / `struct peer`, and the legacy   */
/* `bgp_config_write_*` functions render `show running-config` from that    */
/* state. These cli_show callbacks render the YANG datastore for mgmtd's    */
/* `show yang config-data` and become authoritative for `show running-      */
/* config` once `FRR_MGMTD_BACKEND` is set on bgpd_di.                      */
/* ------------------------------------------------------------------------ */

/*
 * Generic helper: emit "<keyword>" if true, " no <keyword>" only when
 * show_defaults && default-false.
 */
static void bgp_nb_show_global_bool(struct vty *vty,
				    const struct lyd_node *dnode,
				    const char *keyword, bool show_defaults)
{
	bool v = yang_dnode_get_bool(dnode, NULL);
	if (v)
		vty_out(vty, " %s\n", keyword);
	else if (show_defaults)
		vty_out(vty, " no %s\n", keyword);
}

/* cli_show emitters. */

void bgp_global_router_id_cli_show(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults)
{
	const char *rid = yang_dnode_get_string(dnode, NULL);
	if (rid && strcmp(rid, "0.0.0.0"))
		vty_out(vty, " bgp router-id %s\n", rid);
}

void bgp_global_default_shutdown_cli_show(struct vty *vty,
					  const struct lyd_node *dnode,
					  bool show_defaults)
{
	bgp_nb_show_global_bool(vty, dnode, "bgp default shutdown",
				show_defaults);
}

void bgp_global_log_neighbor_changes_cli_show(struct vty *vty,
					      const struct lyd_node *dnode,
					      bool show_defaults)
{
	bgp_nb_show_global_bool(vty, dnode, "bgp log-neighbor-changes",
				show_defaults);
}

void bgp_global_fast_convergence_cli_show(struct vty *vty,
					  const struct lyd_node *dnode,
					  bool show_defaults)
{
	bgp_nb_show_global_bool(vty, dnode, "bgp fast-convergence",
				show_defaults);
}

void bgp_global_allow_martian_nexthop_cli_show(struct vty *vty,
					       const struct lyd_node *dnode,
					       bool show_defaults)
{
	bgp_nb_show_global_bool(vty, dnode, "bgp allow-martian-nexthop",
				show_defaults);
}

void bgp_neighbor_passive_mode_cli_show(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s passive\n", peer);
}

void bgp_neighbor_solo_cli_show(struct vty *vty,
				const struct lyd_node *dnode,
				bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s solo\n", peer);
}

void bgp_neighbor_enforce_first_as_cli_show(struct vty *vty,
					    const struct lyd_node *dnode,
					    bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s enforce-first-as\n", peer);
}

void bgp_neighbor_description_cli_show(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	const char *desc = yang_dnode_get_string(dnode, NULL);
	if (desc && *desc)
		vty_out(vty, " neighbor %s description %s\n", peer, desc);
}

void bgp_neighbor_password_cli_show(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	const char *pwd = yang_dnode_get_string(dnode, NULL);
	if (pwd && *pwd)
		vty_out(vty, " neighbor %s password %s\n", peer, pwd);
}

/* generic boolean-flag cli_show emitters. */

/* Generic emitter for a `bgp <keyword>` global boolean leaf. */
#define BGP_GLOBAL_BOOL_CLI_SHOW(_name, _keyword)                              \
	void bgp_global_##_name##_cli_show(struct vty *vty,                    \
					   const struct lyd_node *dnode,       \
					   bool show_defaults)                 \
	{                                                                      \
		if (yang_dnode_get_bool(dnode, NULL))                          \
			vty_out(vty, " bgp %s\n", _keyword);                   \
	}

BGP_GLOBAL_BOOL_CLI_SHOW(deterministic_med, "bestpath as-path multipath-relax deterministic-med")
BGP_GLOBAL_BOOL_CLI_SHOW(always_compare_med, "always-compare-med")
BGP_GLOBAL_BOOL_CLI_SHOW(import_check, "network import-check")
BGP_GLOBAL_BOOL_CLI_SHOW(suppress_duplicates, "bestpath suppress-duplicates")
BGP_GLOBAL_BOOL_CLI_SHOW(reject_as_sets, "reject-as-sets")
BGP_GLOBAL_BOOL_CLI_SHOW(ebgp_requires_policy, "ebgp-requires-policy")
BGP_GLOBAL_BOOL_CLI_SHOW(show_hostname, "show-hostname")
BGP_GLOBAL_BOOL_CLI_SHOW(show_nexthop_hostname, "show-nexthop-hostname")
BGP_GLOBAL_BOOL_CLI_SHOW(graceful_shutdown, "graceful-shutdown")
BGP_GLOBAL_BOOL_CLI_SHOW(no_client_to_client_reflection, "no client-to-client reflection")
BGP_GLOBAL_BOOL_CLI_SHOW(cluster_id_self, "cluster-id self")
BGP_GLOBAL_BOOL_CLI_SHOW(disable_ebgp_connected_route_check, "disable-ebgp-connected-route-check")
BGP_GLOBAL_BOOL_CLI_SHOW(enforce_first_as_global, "enforce-first-as")
BGP_GLOBAL_BOOL_CLI_SHOW(default_link_local_capability, "default link-local-capability")
BGP_GLOBAL_BOOL_CLI_SHOW(default_dynamic_capability, "default dynamic-capability")
BGP_GLOBAL_BOOL_CLI_SHOW(use_underlays_nexthop_weight, "use-underlays-nexthop-weight")
BGP_GLOBAL_BOOL_CLI_SHOW(peer_type_multipath_relax, "bgp bestpath peer-type multipath-relax")
BGP_GLOBAL_BOOL_CLI_SHOW(ipv6_auto_ra, "bgp ipv6-auto-ra")

/* Generic emitter for a `neighbor X <keyword>` boolean leaf (peer-level). */
#define BGP_NEIGHBOR_BOOL_CLI_SHOW(_name, _keyword)                            \
	void bgp_neighbor_##_name##_cli_show(struct vty *vty,                  \
					     const struct lyd_node *dnode,     \
					     bool show_defaults)               \
	{                                                                      \
		const char *peer =                                             \
			yang_dnode_get_string(dnode, "../remote-address");     \
		if (yang_dnode_get_bool(dnode, NULL))                          \
			vty_out(vty, " neighbor %s %s\n", peer, _keyword);     \
	}

BGP_NEIGHBOR_BOOL_CLI_SHOW(aigp, "aigp")
BGP_NEIGHBOR_BOOL_CLI_SHOW(ip_transparent, "ip-transparent")
BGP_NEIGHBOR_BOOL_CLI_SHOW(extended_link_bandwidth, "extended-link-bandwidth")
BGP_NEIGHBOR_BOOL_CLI_SHOW(disable_link_bw_encoding_ieee, "disable-link-bw-encoding-ieee")
BGP_NEIGHBOR_BOOL_CLI_SHOW(extended_optional_parameters, "extended-optional-parameters")
BGP_NEIGHBOR_BOOL_CLI_SHOW(send_nexthop_characteristics, "send-nexthop-characteristics")
BGP_NEIGHBOR_BOOL_CLI_SHOW(rpki_strict, "rpki strict")
/* Same emitter for leaves one container below the neighbor entry
 * (capability-options/...): the peer key is two levels up. */
#define BGP_NEIGHBOR_SUB_BOOL_CLI_SHOW(_name, _keyword)                        \
	void bgp_neighbor_##_name##_cli_show(struct vty *vty,                  \
		const struct lyd_node *dnode, bool show_defaults)              \
	{                                                                      \
		const char *peer =                                             \
			yang_dnode_get_string(dnode, "../../remote-address");  \
		if (yang_dnode_get_bool(dnode, NULL))                          \
			vty_out(vty, " neighbor %s %s\n", peer, _keyword);     \
	}

BGP_NEIGHBOR_SUB_BOOL_CLI_SHOW(capability_fqdn, "capability fqdn")
BGP_NEIGHBOR_SUB_BOOL_CLI_SHOW(capability_link_local, "capability link-local")
BGP_NEIGHBOR_BOOL_CLI_SHOW(as_loop_detection, "sender-as-path-loop-detection")
BGP_NEIGHBOR_BOOL_CLI_SHOW(oad, "oad")
BGP_NEIGHBOR_BOOL_CLI_SHOW(peer_graceful_shutdown, "graceful-shutdown")

/* Per-AF flag cli_show — emits "neighbor X <keyword>" under
 * `address-family Y` enter/exit block. The afi-safi parent key
 * disambiguates the address-family scope; bgp_config_write_family is
 * responsible for emitting the surrounding `address-family ... exit-
 * address-family` block in legacy code, so cli_show here only emits
 * the inner per-neighbor command. */
#define BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(_name, _keyword)                         \
	void bgp_neighbor_af_##_name##_cli_show(struct vty *vty,               \
		const struct lyd_node *dnode, bool show_defaults)              \
	{                                                                      \
		const char *peer = bgp_nb_af_peer_name(dnode);                 \
		if (yang_dnode_get_bool(dnode, NULL))                          \
			vty_out(vty, "  neighbor %s %s\n", peer, _keyword);    \
	}

static const char *bgp_nb_af_ctx_key(const struct lyd_node *af_entry);

/*
 * Peer name for per-AF cli_show: probe the context list key so the
 * same emitter serves numbered, unnumbered and peer-group rows.
 */
static const char *bgp_nb_af_peer_name(const struct lyd_node *dnode)
{
	const struct lyd_node *af_entry;

	af_entry = yang_dnode_get_parent(dnode, "afi-safi");
	if (!af_entry)
		return NULL;
	return bgp_nb_af_ctx_key(af_entry);
}

BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(soft_reconfig_in, "soft-reconfiguration inbound")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(as_override, "as-override")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(rr_client, "route-reflector-client")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(rs_client, "route-server-client")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(nexthop_self, "next-hop-self")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(nexthop_self_force, "next-hop-self force")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(remove_private_as, "remove-private-AS")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(remove_private_as_all, "remove-private-AS all")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(remove_private_as_replace,
			      "remove-private-AS replace-AS")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(remove_private_as_all_replace,
			      "remove-private-AS all replace-AS")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(nexthop_local_unchanged,
			      "nexthop-local unchanged")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(send_community, "send-community")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(send_ext_community, "send-community extended")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(send_large_community, "send-community large")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(accept_own, "accept-own")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(disable_addpath_rx, "disable-addpath-rx")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(upa, "upa")

/* add-paths/path-type enum: one emitter for both legacy keywords. */
void bgp_neighbor_af_add_paths_path_type_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = bgp_nb_af_peer_name(dnode);
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (strmatch(val, "all"))
		vty_out(vty, "  neighbor %s addpath-tx-all-paths\n", peer);
	else if (strmatch(val, "per-as"))
		vty_out(vty, "  neighbor %s addpath-tx-bestpath-per-AS\n",
			peer);
}

/*
 * Per-AF route-map filter: "neighbor X route-map NAME in|out". The
 * rmap leaves sit under filter-config, so the peer key is 5 levels up
 * like the <AFI>/<group>/<leaf> nodes.
 */
static void bgp_neighbor_af_rmap_filter_cli_show(struct vty *vty,
						 const struct lyd_node *dnode,
						 const char *direct)
{
	const char *peer = bgp_nb_af_peer_name(dnode);

	vty_out(vty, "  neighbor %s route-map %s %s\n", peer,
		yang_dnode_get_string(dnode, NULL), direct);
}

void bgp_neighbor_af_rmap_import_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	bgp_neighbor_af_rmap_filter_cli_show(vty, dnode, "in");
}

void bgp_neighbor_af_rmap_export_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	bgp_neighbor_af_rmap_filter_cli_show(vty, dnode, "out");
}

/* addpath counters: one line per leaf, ctx-aware peer name. */
void bgp_neighbor_af_addpath_rx_limit_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  neighbor %s addpath-rx-paths-limit %u\n",
		bgp_nb_af_peer_name(dnode),
		yang_dnode_get_uint16(dnode, NULL));
}

void bgp_neighbor_af_addpath_best_selected_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  neighbor %s addpath-tx-best-selected %u\n",
		bgp_nb_af_peer_name(dnode),
		yang_dnode_get_uint8(dnode, NULL));
}

/*
 * allowas-in: the legacy writer emits ONE line from the three
 * sibling leaves, so only the most significant present leaf renders
 * (allow-own-as, then a true allow-own-origin-as, then the
 * route-map) and the siblings stay silent.
 */
static void bgp_nb_allowas_in_cli_show_common(struct vty *vty,
	const struct lyd_node *dnode, const char *self_leaf)
{
	const struct lyd_node *aspo;
	const char *peer = bgp_nb_af_peer_name(dnode);
	const char *rmap = NULL;
	const char *designated;
	bool origin = false;
	int num = BGP_ALLOWAS_IN_DEFAULT;

	aspo = yang_dnode_get_parent(dnode, "as-path-options");
	if (!aspo)
		return;

	designated = yang_dnode_exists(aspo, "allow-own-as")
			     ? "allow-own-as"
			     : ((yang_dnode_exists(aspo,
						   "allow-own-origin-as")
				 && yang_dnode_get_bool(
					 aspo, "allow-own-origin-as"))
					? "allow-own-origin-as"
					: (yang_dnode_exists(
						   aspo,
						   "allowas-in-route-map")
					       ? "allowas-in-route-map"
					       : NULL));
	if (!designated || !strmatch(self_leaf, designated))
		return;

	if (yang_dnode_exists(aspo, "allow-own-as"))
		num = yang_dnode_get_uint8(aspo, "allow-own-as");
	if (yang_dnode_exists(aspo, "allow-own-origin-as"))
		origin = yang_dnode_get_bool(aspo,
					     "allow-own-origin-as");
	if (yang_dnode_exists(aspo, "allowas-in-route-map"))
		rmap = yang_dnode_get_string(aspo,
					     "allowas-in-route-map");

	vty_out(vty, "  neighbor %s allowas-in", peer);
	if (rmap)
		vty_out(vty, " route-map %s", rmap);
	if (origin)
		vty_out(vty, " origin\n");
	else if (num != BGP_ALLOWAS_IN_DEFAULT)
		vty_out(vty, " %d\n", num);
	else
		vty_out(vty, "\n");
}

void bgp_neighbor_af_allow_own_as_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	bgp_nb_allowas_in_cli_show_common(vty, dnode, "allow-own-as");
}

void bgp_neighbor_af_allow_own_origin_as_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	bgp_nb_allowas_in_cli_show_common(vty, dnode,
					  "allow-own-origin-as");
}

void bgp_neighbor_af_allowas_in_route_map_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	bgp_nb_allowas_in_cli_show_common(vty, dnode,
					  "allowas-in-route-map");
}

/*
 * Conditional advertisement: only the advertise-map leaf renders,
 * and only once the condition half exists (the knob arms as a pair).
 */
static void bgp_nb_cond_adv_cli_show_common(struct vty *vty,
	const struct lyd_node *dnode)
{
	const struct lyd_node *ca;
	const char *peer = bgp_nb_af_peer_name(dnode);

	ca = yang_dnode_get_parent(dnode,
				   "conditional-advertisement");
	if (!ca || !yang_dnode_exists(ca, "advertise-map"))
		return;
	if (yang_dnode_exists(ca, "exist-map"))
		vty_out(vty, "  neighbor %s advertise-map %s exist-map %s\n",
			peer, yang_dnode_get_string(ca, "advertise-map"),
			yang_dnode_get_string(ca, "exist-map"));
	else if (yang_dnode_exists(ca, "non-exist-map"))
		vty_out(vty,
			"  neighbor %s advertise-map %s non-exist-map %s\n",
			peer, yang_dnode_get_string(ca, "advertise-map"),
			yang_dnode_get_string(ca, "non-exist-map"));
}

void bgp_neighbor_af_cond_adv_advertise_map_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	bgp_nb_cond_adv_cli_show_common(vty, dnode);
}

void bgp_neighbor_af_cond_adv_exist_map_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	/* rendered by the advertise-map leaf */
}

void bgp_neighbor_af_cond_adv_non_exist_map_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	/* rendered by the advertise-map leaf */
}

/*
 * Name-based filters: "distribute-list|filter-list|prefix-list NAME
 * in|out", one line per leaf.
 */
#define BGP_NEIGHBOR_AF_NAME_FILTER_CLI_SHOW(_kindname, _dirname, _keyword, _direct) \
	void bgp_neighbor_af_##_kindname##_##_dirname##_cli_show(           \
		struct vty *vty, const struct lyd_node *dnode,              \
		bool show_defaults)                                         \
	{                                                                      \
		vty_out(vty, "  neighbor %s " _keyword " %s " _direct "\n",    \
			bgp_nb_af_peer_name(dnode),                          \
			yang_dnode_get_string(dnode, NULL));                 \
	}

BGP_NEIGHBOR_AF_NAME_FILTER_CLI_SHOW(access_list, import,
				     "distribute-list", "in")
BGP_NEIGHBOR_AF_NAME_FILTER_CLI_SHOW(access_list, export,
				     "distribute-list", "out")
BGP_NEIGHBOR_AF_NAME_FILTER_CLI_SHOW(as_path_filter, import,
				     "filter-list", "in")
BGP_NEIGHBOR_AF_NAME_FILTER_CLI_SHOW(as_path_filter, export,
				     "filter-list", "out")
BGP_NEIGHBOR_AF_NAME_FILTER_CLI_SHOW(plist, import, "prefix-list", "in")
BGP_NEIGHBOR_AF_NAME_FILTER_CLI_SHOW(plist, export, "prefix-list", "out")

/*
 * unsuppress-map: one legacy knob, so the export leaf renders and
 * the import leaf only renders when export is absent.
 */
void bgp_neighbor_af_unsuppress_map_export_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  neighbor %s unsuppress-map %s\n",
		bgp_nb_af_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

void bgp_neighbor_af_unsuppress_map_import_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *fc;

	fc = yang_dnode_get_parent(dnode, "filter-config");
	if (fc && yang_dnode_exists(fc, "unsuppress-map-export"))
		return;
	vty_out(vty, "  neighbor %s unsuppress-map %s\n",
		bgp_nb_af_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

void bgp_neighbor_af_soo_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  neighbor %s soo %s\n",
		bgp_nb_af_peer_name(dnode),
		yang_dnode_get_string(dnode, NULL));
}

/*
 * Prefix-limit cli_show: rendered from the max-prefixes leaf so each
 * direction-list entry prints exactly one legacy line (matching
 * bgp_config_write_family byte for byte).
 */
static const char *bgp_nb_af_ctx_key(const struct lyd_node *af_entry)
{
	if (yang_dnode_exists(af_entry, "../../remote-address"))
		return yang_dnode_get_string(af_entry,
					     "../../remote-address");
	if (yang_dnode_exists(af_entry, "../../interface"))
		return yang_dnode_get_string(af_entry, "../../interface");
	return yang_dnode_get_string(af_entry,
				     "../../peer-group-name");
}

void bgp_peer_af_prefix_limit_max_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const struct lyd_node *dl, *af_entry;
	const char *key, *direction;

	dl = yang_dnode_get_parent(dnode, "direction-list");
	af_entry = yang_dnode_get_parent(dl, "afi-safi");
	key = bgp_nb_af_ctx_key(af_entry);
	direction = yang_dnode_get_string(dl, "direction");

	if (strmatch(direction, "out")) {
		vty_out(vty, "  neighbor %s maximum-prefix-out %s\n", key,
			yang_dnode_get_string(dnode, NULL));
		return;
	}
	vty_out(vty, "  neighbor %s maximum-prefix %s", key,
		yang_dnode_get_string(dnode, NULL));
	if (yang_dnode_exists(dl, "options/shutdown-threshold-pct"))
		vty_out(vty, " %s",
			yang_dnode_get_string(dl,
					      "options/shutdown-threshold-pct"));
	if (yang_dnode_exists(dl, "options/tr-shutdown-threshold-pct"))
		vty_out(vty, " %s",
			yang_dnode_get_string(
				dl, "options/tr-shutdown-threshold-pct"));
	if (yang_dnode_exists(dl, "options/tw-shutdown-threshold-pct"))
		vty_out(vty, " %s",
			yang_dnode_get_string(
				dl, "options/tw-shutdown-threshold-pct"));
	if ((yang_dnode_exists(dl, "options/warning-only")
	     && yang_dnode_get_bool(dl, "options/warning-only"))
	    || (yang_dnode_exists(dl, "options/tw-warning-only")
		&& yang_dnode_get_bool(dl, "options/tw-warning-only")))
		vty_out(vty, " warning-only");
	if (yang_dnode_exists(dl, "options/restart-timer"))
		vty_out(vty, " restart %s",
			yang_dnode_get_string(dl,
					      "options/restart-timer"));
	if (yang_dnode_exists(dl, "options/tr-restart-timer"))
		vty_out(vty, " restart %s",
			yang_dnode_get_string(
				dl, "options/tr-restart-timer"));
	if (yang_dnode_exists(dl, "force-check")
	    && yang_dnode_get_bool(dl, "force-check"))
		vty_out(vty, " force");
	vty_out(vty, "\n");
}

/*
 * Network-config cli_show: rendered from the list entry (plain AFs)
 * and from the prefix-list entry (l3vpn), matching the legacy
 * `network` lines byte for byte.
 */
void bgp_global_af_network_config_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  network %s", yang_dnode_get_string(dnode, "prefix"));
	if (yang_dnode_exists(dnode, "label-index"))
		vty_out(vty, " label-index %s",
			yang_dnode_get_string(dnode, "label-index"));
	if (yang_dnode_exists(dnode, "rmap-policy-export"))
		vty_out(vty, " route-map %s",
			yang_dnode_get_string(dnode, "rmap-policy-export"));
	if (yang_dnode_exists(dnode, "backdoor")
	    && yang_dnode_get_bool(dnode, "backdoor"))
		vty_out(vty, " backdoor");
	vty_out(vty, "\n");
}

void bgp_global_af_network_pl_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "  network %s rd %s label %s",
		yang_dnode_get_string(dnode, "prefix"),
		yang_dnode_get_string(dnode, "../rd"),
		yang_dnode_get_string(dnode, "label-index"));
	if (yang_dnode_exists(dnode, "rmap-policy-export"))
		vty_out(vty, " route-map %s",
			yang_dnode_get_string(dnode, "rmap-policy-export"));
	vty_out(vty, "\n");
}

/* value-style cli_show emitters. */

/* uint global leaf → `bgp <keyword> <value>` */
#define BGP_GLOBAL_UINT_CLI_SHOW(_name, _keyword)                              \
	void bgp_global_##_name##_cli_show(struct vty *vty,                    \
		const struct lyd_node *dnode, bool show_defaults)              \
	{                                                                      \
		vty_out(vty, " bgp %s %s\n", _keyword,                         \
			yang_dnode_get_string(dnode, NULL));                   \
	}

BGP_GLOBAL_UINT_CLI_SHOW(coalesce_time, "coalesce-time")
BGP_GLOBAL_UINT_CLI_SHOW(subgroup_pkt_queue_size, "subgroup-pkt-queue-size")
BGP_GLOBAL_UINT_CLI_SHOW(wpkt_quanta, "write-quanta")
BGP_GLOBAL_UINT_CLI_SHOW(rpkt_quanta, "read-quanta")
BGP_GLOBAL_UINT_CLI_SHOW(minimum_holdtime, "minimum-holdtime")
BGP_GLOBAL_UINT_CLI_SHOW(dynamic_neighbors_limit, "listen limit")
BGP_GLOBAL_UINT_CLI_SHOW(advertisement_delay_global, "advertise-delay")
BGP_GLOBAL_UINT_CLI_SHOW(update_delay_time, "update-delay")
BGP_GLOBAL_UINT_CLI_SHOW(restart_time, "graceful-restart restart-time")
BGP_GLOBAL_UINT_CLI_SHOW(selection_deferral_time, "graceful-restart select-defer-time")

/* Boolean route-selection-options children -- live under
 * bestpath/route-selection-options group */
#define BGP_GLOBAL_RSO_BOOL_CLI_SHOW(_name, _keyword)                          \
	void bgp_global_##_name##_cli_show(struct vty *vty,                    \
		const struct lyd_node *dnode, bool show_defaults)              \
	{                                                                      \
		if (yang_dnode_get_bool(dnode, NULL))                          \
			vty_out(vty, " bgp %s\n", _keyword);                   \
	}

BGP_GLOBAL_RSO_BOOL_CLI_SHOW(external_compare_router_id,
			     "bestpath compare-routerid")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(ignore_as_path_length,
			     "bestpath as-path ignore")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(aspath_confed, "bestpath as-path confed")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(confed_med, "bestpath med confed")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(missing_as_worst_med, "bestpath med missing-as-worst")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(bestpath_aigp, "bestpath aigp")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(bestpath_use_imported_attributes,
			     "bestpath use-imported-attributes")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(allow_multiple_as,
			     "bestpath as-path multipath-relax")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(multi_path_as_set,
			     "bestpath as-path multipath-relax as-set")

/* Misc value leaves */
void bgp_global_confederation_identifier_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp confederation identifier %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_confederation_member_as_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp confederation peers %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/* Container apply_finish cli_show emitters — emit the whole compound
 * CLI line from the container dnode. */
void bgp_neighbor_local_as_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	const char *as = NULL;
	bool noprep = false, repas = false, dual = false;

	if (!yang_dnode_exists(dnode, "./local-as"))
		return;
	as = yang_dnode_get_string(dnode, "./local-as");
	if (yang_dnode_exists(dnode, "./no-prepend"))
		noprep = yang_dnode_get_bool(dnode, "./no-prepend");
	if (yang_dnode_exists(dnode, "./replace-as"))
		repas = yang_dnode_get_bool(dnode, "./replace-as");
	if (yang_dnode_exists(dnode, "./dual-as"))
		dual = yang_dnode_get_bool(dnode, "./dual-as");

	vty_out(vty, " neighbor %s local-as %s", peer, as);
	if (noprep)
		vty_out(vty, " no-prepend");
	if (repas)
		vty_out(vty, " replace-as");
	if (dual)
		vty_out(vty, " dual-as");
	vty_out(vty, "\n");
}

void bgp_neighbor_timers_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_exists(dnode, "./keepalive") &&
	    yang_dnode_exists(dnode, "./hold-time")) {
		vty_out(vty, " neighbor %s timers %s %s\n", peer,
			yang_dnode_get_string(dnode, "./keepalive"),
			yang_dnode_get_string(dnode, "./hold-time"));
	}
	if (yang_dnode_exists(dnode, "./connect-time"))
		vty_out(vty, " neighbor %s timers connect %s\n", peer,
			yang_dnode_get_string(dnode, "./connect-time"));
	if (yang_dnode_exists(dnode, "./advertise-interval"))
		vty_out(vty, " neighbor %s advertisement-interval %s\n", peer,
			yang_dnode_get_string(dnode, "./advertise-interval"));
}

void bgp_neighbor_local_role_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_exists(dnode, "./role")) {
		const char *role = yang_dnode_get_string(dnode, "./role");
		bool strict = yang_dnode_exists(dnode, "./strict-mode") &&
			      yang_dnode_get_bool(dnode, "./strict-mode");
		vty_out(vty, " neighbor %s local-role %s%s\n", peer, role,
			strict ? " strict-mode" : "");
	}
}

void bgp_neighbor_admin_shutdown_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");

	if (yang_dnode_exists(dnode, "enable") &&
	    yang_dnode_get_bool(dnode, "enable")) {
		if (yang_dnode_exists(dnode, "message"))
			vty_out(vty, " neighbor %s shutdown message %s\n",
				peer,
				yang_dnode_get_string(dnode, "message"));
		else
			vty_out(vty, " neighbor %s shutdown\n", peer);
	}
	if (yang_dnode_exists(dnode, "rtt")) {
		vty_out(vty, " neighbor %s shutdown rtt %s", peer,
			yang_dnode_get_string(dnode, "rtt"));
		if (yang_dnode_exists(dnode, "rtt-count"))
			vty_out(vty, " count %s",
				yang_dnode_get_string(dnode, "rtt-count"));
		vty_out(vty, "\n");
	}
}

void bgp_neighbor_ebgp_multihop_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_exists(dnode, "./enabled") &&
	    yang_dnode_get_bool(dnode, "./enabled")) {
		if (yang_dnode_exists(dnode, "./multihop-ttl"))
			vty_out(vty, " neighbor %s ebgp-multihop %s\n", peer,
				yang_dnode_get_string(dnode, "./multihop-ttl"));
		else
			vty_out(vty, " neighbor %s ebgp-multihop\n", peer);
	}
	if (yang_dnode_exists(dnode, "./disable-connected-check") &&
	    yang_dnode_get_bool(dnode, "./disable-connected-check"))
		vty_out(vty, " neighbor %s disable-connected-check\n", peer);
}

/* Single-leaf neighbor value emitters */
void bgp_neighbor_ttl_security_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	vty_out(vty, " neighbor %s ttl-security hops %s\n", peer,
		yang_dnode_get_string(dnode, NULL));
}

void bgp_neighbor_tcp_mss_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	vty_out(vty, " neighbor %s tcp-mss %s\n", peer,
		yang_dnode_get_string(dnode, NULL));
}


void bgp_neighbor_timers_delayopen_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode,
						 "../../remote-address");
	vty_out(vty, " neighbor %s timers delayopen %s\n", peer,
		yang_dnode_get_string(dnode, NULL));
}

void bgp_neighbor_ls_local_link_id_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	vty_out(vty, " neighbor %s local-link-id %s\n", peer,
		yang_dnode_get_string(dnode, NULL));
}

void bgp_neighbor_ls_remote_link_id_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	vty_out(vty, " neighbor %s remote-link-id %s\n", peer,
		yang_dnode_get_string(dnode, NULL));
}

void bgp_neighbor_neighbor_remote_as_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	const char *t;
	if (!yang_dnode_exists(dnode, "./remote-as-type"))
		return;
	t = yang_dnode_get_string(dnode, "./remote-as-type");
	if (!strcmp(t, "as-specified") &&
	    yang_dnode_exists(dnode, "./remote-as"))
		vty_out(vty, " neighbor %s remote-as %s\n", peer,
			yang_dnode_get_string(dnode, "./remote-as"));
	else
		vty_out(vty, " neighbor %s remote-as %s\n", peer, t);
}

void bgp_neighbor_update_source_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_exists(dnode, "./ip"))
		vty_out(vty, " neighbor %s update-source %s\n", peer,
			yang_dnode_get_string(dnode, "./ip"));
	if (yang_dnode_exists(dnode, "./interface"))
		vty_out(vty, " neighbor %s update-source %s\n", peer,
			yang_dnode_get_string(dnode, "./interface"));
}

void bgp_neighbor_capabilities_dynamic_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s capability dynamic\n", peer);
}

void bgp_neighbor_capabilities_strict_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s strict-capability-match\n", peer);
}

void bgp_neighbor_capabilities_override_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s override-capability\n", peer);
}

void bgp_neighbor_capabilities_extended_nexthop_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s capability extended-nexthop\n", peer);
}

void bgp_neighbor_capabilities_negotiate_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	/* INVERTED: false means dont-negotiate; true is default. */
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s dont-capability-negotiate\n", peer);
}

/* additional global boolean+value cli_show emitters. */

void bgp_global_fast_external_failover_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	/* Inverted vs BGP_FLAG_NO_FAST_EXT_FAILOVER: true enables, but the
	 * legacy CLI only surfaces the negative form.
	 */
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp fast-external-failover\n");
}

void bgp_global_labeled_unicast_explicit_null_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);
	if (val && strcmp(val, "disable"))
		vty_out(vty, " bgp labeled-unicast explicit-null %s\n", val);
}

void bgp_global_allow_outbound_policy_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp route-reflector allow-outbound-policy\n");
}

void bgp_global_instance_id_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp instance-id %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_default_software_version_capability_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (strmatch(val, "old-encoding"))
		vty_out(vty, " bgp default software-version-capability\n");
	else if (strmatch(val, "latest-encoding"))
		vty_out(vty,
			" bgp default software-version-capability latest-encoding\n");
}

void bgp_global_establish_wait_time_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp default establish-wait-time %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_connect_retry_interval_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp default connect-retry %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_conditional_advertisement_period_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp conditional-advertisement timer %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_default_originate_timer_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp default originate-timer %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_bestpath_bandwidth_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp bestpath bandwidth %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_graceful_restart_notification_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart notification\n");
}

void bgp_global_long_lived_graceful_restart_stale_time_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp long-lived-graceful-restart stale-time %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_route_reflector_cluster_id_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp cluster-id %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_no_client_reflect_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp client-to-client reflection\n");
}

void bgp_global_local_pref_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp default local-preference %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_ebgp_multihop_connected_route_check_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp ebgp-multihop-connected-route-check\n");
}

void bgp_global_rib_stale_time_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp graceful-restart rib-stale-time %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_preserve_fw_entry_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart preserve-fw-state\n");
}

void bgp_global_stale_routes_time_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp graceful-restart stalepath-time %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_med_config_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_exists(dnode, "./enable-med-admin") &&
	    yang_dnode_get_bool(dnode, "./enable-med-admin")) {
		vty_out(vty, " bgp max-med administrative");
		if (yang_dnode_exists(dnode, "./med-admin-val"))
			vty_out(vty, " %s",
				yang_dnode_get_string(dnode, "./med-admin-val"));
		vty_out(vty, "\n");
	}
}

void bgp_global_tcp_keepalive_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_exists(dnode, "./idle") &&
	    yang_dnode_exists(dnode, "./interval") &&
	    yang_dnode_exists(dnode, "./count"))
		vty_out(vty, " bgp tcp-keepalive %s %s %s\n",
			yang_dnode_get_string(dnode, "./idle"),
			yang_dnode_get_string(dnode, "./interval"),
			yang_dnode_get_string(dnode, "./count"));
}

void bgp_global_shutdown_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (!yang_dnode_get_bool(dnode, NULL))
		return;
	if (yang_dnode_exists(dnode, "../shutdown-message"))
		vty_out(vty, " bgp shutdown message %s\n",
			yang_dnode_get_string(dnode, "../shutdown-message"));
	else
		vty_out(vty, " bgp shutdown\n");
}

void bgp_global_suppress_fib_pending_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *delay = NULL;

	if (!yang_dnode_get_bool(dnode, NULL))
		return;
	if (yang_dnode_exists(dnode, "../suppress-fib-pending-delay"))
		delay = yang_dnode_get_string(dnode,
					      "../suppress-fib-pending-delay");
	if (delay && strcmp(delay, "1000"))
		vty_out(vty, " bgp suppress-fib-pending %s\n", delay);
	else
		vty_out(vty, " bgp suppress-fib-pending\n");
}

void bgp_global_bgp_ls_distribute_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	/* Presence container: existing means distribution is enabled. */
	vty_out(vty, "  distribute bgp-fabric-link-state\n");
}

/*
 * One emitter on the redistribution-list entry renders the whole legacy
 * line; the metric and rmap-policy-import leaves are handled here and
 * register bgp_nb_handled_by_parent_cli_show.
 */
void bgp_global_af_redistribution_list_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	uint16_t instance = yang_dnode_get_uint16(dnode, "route-instance");

	vty_out(vty, "  redistribute %s",
		yang_dnode_get_string(dnode, "route-type"));
	if (instance)
		vty_out(vty, " %u", instance);
	if (yang_dnode_exists(dnode, "metric"))
		vty_out(vty, " metric %s",
			yang_dnode_get_string(dnode, "metric"));
	if (yang_dnode_exists(dnode, "rmap-policy-import"))
		vty_out(vty, " route-map %s",
			yang_dnode_get_string(dnode, "rmap-policy-import"));
	vty_out(vty, "\n");
}

void bgp_neighbor_bfd_options_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_exists(dnode, "./enable") &&
	    yang_dnode_get_bool(dnode, "./enable"))
		vty_out(vty, " neighbor %s bfd\n", peer);
}

void bgp_neighbor_gr_enable_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s graceful-restart\n", peer);
}

void bgp_neighbor_gr_helper_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s graceful-restart-helper\n", peer);
}

void bgp_neighbor_gr_disable_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s graceful-restart-disable\n", peer);
}

void bgp_neighbor_capability_software_version_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode,
						 "../../remote-address");
	const char *val = yang_dnode_get_string(dnode, NULL);

	if (strmatch(val, "old-encoding"))
		vty_out(vty, " neighbor %s capability software-version\n",
			peer);
	else if (strmatch(val, "latest-encoding"))
		vty_out(vty,
			" neighbor %s capability software-version latest-encoding\n",
			peer);
}

void bgp_peer_group_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "./peer-group-name");
	vty_out(vty, " neighbor %s peer-group\n", name);
}

void bgp_peer_group_ipv4_listen_range_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "../peer-group-name");
	vty_out(vty, " bgp listen range %s peer-group %s\n",
		yang_dnode_get_string(dnode, NULL), name);
}

void bgp_peer_group_ipv6_listen_range_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "../peer-group-name");
	vty_out(vty, " bgp listen range %s peer-group %s\n",
		yang_dnode_get_string(dnode, NULL), name);
}

/*
 * Used for leaves whose parent container's cli_show emits the full
 * compound CLI block (e.g. timers, local-as, admin-shutdown). Wiring
 * this against child leaves silences any duplicate emission.
 */
void bgp_nb_handled_by_parent_cli_show(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults)
{
	(void)vty;
	(void)dnode;
	(void)show_defaults;
}

/*
 * ==== EVPN global (l2vpn-evpn) — Fase C fatia 1 ====
 *
 * The global half of the EVPN AF subtree is wired to the same
 * internals the CLI DEFUNs in bgp_evpn_vty.c call (evpn_* helpers),
 * plus the prefix-limit fanout under l2vpn-evpn which reuses the
 * shared callbacks from Fase B. Plumbing only: no new daemon
 * behaviour. The CLI keeps legacy authority (show running-config
 * renders from the internals through bgp_config_write_evpn_info).
 *
 * `depth` in bgp_nb_evpn_bgp() is the number of ../ hops from the
 * callback dnode to the control-plane-protocol entry:
 *   - leaf directly under l2vpn-evpn           -> 6
 *   - leaf under one container (dad, mh, ...)  -> 7
 *   - leaf under ip-vrf/ipvX-unicast           -> 8
 *   - vni list entry                           -> 6
 *   - leaf inside a vni entry                  -> 7
 */
static struct bgp *bgp_nb_evpn_bgp(const struct lyd_node *dnode,
				   unsigned int depth, char *errmsg,
				   size_t errmsg_len)
{
	struct bgp *bgp = bgp_nb_lookup_from_dnode(dnode, depth);

	if (!bgp) {
		snprintfrr(errmsg, errmsg_len,
			   "l2vpn-evpn: bgp instance not found");
		return NULL;
	}
	return bgp;
}

static vni_t bgp_nb_evpn_vni_key(const struct lyd_node *dnode)
{
	return yang_dnode_get_uint32(dnode, "vni");
}

/*
 * Resolve the bgpevpn for a callback dnode: either the vni list
 * entry itself (create/destroy) or a leaf inside it (rd, route
 * targets). Leaf-level reads MUST go through the parent entry --
 * the yang wrappers abort the daemon on a missing node.
 */
static struct bgpevpn *bgp_nb_evpn_vni_lookup(const struct lyd_node *dnode,
					      struct bgp *bgp)
{
	const struct lyd_node *entry;

	if (dnode->schema && !strcmp(dnode->schema->name, "vni"))
		entry = dnode;
	else {
		entry = yang_dnode_get_parent(dnode, "vni");
		if (!entry)
			return NULL;
	}
	return bgp_evpn_lookup_vni(
		bgp, yang_dnode_get_uint32(entry, "vni"));
}


/*
 * Parse one route-target string into a configured RT. Handles the
 * import-only wildcard '*:NN'/'*:MN' exactly like the CLI parser
 * (the '*' is rewritten to '0' for ecommunity_str2com). Called in
 * VALIDATE so malformed-yang-legal values fail the whole batch
 * before anything is applied. Caller owns the result.
 */
static struct bgp_evpn_cfgd_rt *
bgp_nb_evpn_cfgd_rt_from_str(const char *rt_str, bool wildcard_ok,
			     char *errmsg, size_t errmsg_len)
{
	struct ecommunity *ecom;
	struct bgp_evpn_cfgd_rt *cfgd_rt;
	bool is_wildcard = false;
	char buf[RT_ADDRSTRLEN];

	if (rt_str[0] == '*') {
		if (!wildcard_ok) {
			snprintfrr(errmsg, errmsg_len,
				   "%% Wildcard '*' only applicable for import: %s",
				   rt_str);
			return NULL;
		}
		strlcpy(buf, rt_str, sizeof(buf));
		buf[0] = '0';
		rt_str = buf;
		is_wildcard = true;
	}

	ecom = ecommunity_str2com(rt_str, ECOMMUNITY_ROUTE_TARGET, 0);
	if (!ecom) {
		snprintfrr(errmsg, errmsg_len,
			   "%% Malformed Route Target: %s", rt_str);
		return NULL;
	}
	ecommunity_str(ecom);
	cfgd_rt = bgp_evpn_cfgd_rt_from_ecom(ecom, is_wildcard);
	ecommunity_free(&ecom);
	if (!cfgd_rt)
		snprintfrr(errmsg, errmsg_len,
			   "%% Malformed Route Target: %s", rt_str);
	return cfgd_rt;
}

/*
 * Dispatch the import/export direction from the leaf-list schema name
 * (import-route-target / export-route-target, plain and -auto).
 */
static enum bgp_evpn_rt_direction bgp_nb_evpn_rt_direction(
	const struct lyd_node *dnode)
{
	if (!strncmp(dnode->schema->name, "import", strlen("import")))
		return RT_TYPE_IMPORT;
	return RT_TYPE_EXPORT;
}

/* ---- advertise-all-vni / advertise-default-gateway / advertise-svi-ip */

int bgp_global_evpn_advertise_all_vni_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = bgp_nb_evpn_bgp(args->dnode, 6, args->errmsg,
				      args->errmsg_len);
		if (!bgp)
			return NB_ERR_VALIDATION;
		if (yang_dnode_get_bool(args->dnode, NULL)) {
			struct bgp *bgp_evpn = bgp_get_evpn();

			if (bgp_evpn && bgp_evpn != bgp) {
				snprintfrr(args->errmsg, args->errmsg_len,
					   "%% Please unconfigure EVPN in %s",
					   bgp_evpn->name_pretty);
				return NB_ERR_VALIDATION;
			}
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 6, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	if (yang_dnode_get_bool(args->dnode, NULL))
		evpn_set_advertise_all_vni(bgp);
	else
		evpn_unset_advertise_all_vni(bgp);
	return NB_OK;
}

static int bgp_nb_evpn_af_enabled_validate(struct nb_cb_modify_args *args,
					   unsigned int depth)
{
	struct bgp *bgp;

	if (!yang_dnode_get_bool(args->dnode, NULL))
		return NB_OK;
	bgp = bgp_nb_evpn_bgp(args->dnode, depth, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR_VALIDATION;
	if (!EVPN_ENABLED(bgp)) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "This command is only supported under the EVPN VRF");
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

int bgp_global_evpn_advertise_default_gw_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_evpn_af_enabled_validate(args, 6);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 6, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	if (yang_dnode_get_bool(args->dnode, NULL))
		evpn_set_advertise_default_gw(bgp, NULL);
	else
		evpn_unset_advertise_default_gw(bgp, NULL);
	return NB_OK;
}

int bgp_global_evpn_advertise_svi_ip_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_evpn_af_enabled_validate(args, 6);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 6, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	evpn_set_advertise_svi_macip(
		bgp, NULL, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

int bgp_global_evpn_autort_rfc8365_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 6, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	if (yang_dnode_get_bool(args->dnode, NULL))
		evpn_set_autort_rfc8365(bgp, true, true);
	else
		evpn_unset_autort_rfc8365(bgp, true, true);
	return NB_OK;
}

int bgp_global_evpn_default_originate_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	afi_t afi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	afi = strmatch(args->dnode->schema->name, "ipv4") ? AFI_IP
							  : AFI_IP6;
	bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	evpn_process_default_originate_cmd(
		bgp, afi, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

int bgp_global_evpn_resolve_overlay_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = bgp_nb_evpn_bgp(args->dnode, 6, args->errmsg,
				      args->errmsg_len);
		if (!bgp)
			return NB_ERR_VALIDATION;
		if (bgp != bgp_get_evpn()) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "This command is only supported under EVPN VRF");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 6, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	bgp_evpn_set_unset_resolve_overlay_index(
		bgp, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

int bgp_global_evpn_flooding_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *mode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 6, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	mode = yang_dnode_get_string(args->dnode, NULL);
	bgp->vxlan_flood_ctrl = strmatch(mode, "disable")
					? VXLAN_FLOOD_DISABLED
					: VXLAN_FLOOD_HEAD_END_REPL;
	bgp_evpn_flood_control_change(bgp);
	return NB_OK;
}

int bgp_global_evpn_soo_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp, *bgp_evpn;
	struct ecommunity *ecomm_soo;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = bgp_nb_evpn_bgp(args->dnode, 6, args->errmsg,
				      args->errmsg_len);
		if (!bgp)
			return NB_ERR_VALIDATION;
		bgp_evpn = bgp_get_evpn();
		if (!bgp_evpn || !bgp_evpn->evpn_info || bgp != bgp_evpn) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "%% Please configure MAC-VRF SoO in the EVPN underlay");
			return NB_ERR_VALIDATION;
		}
		ecomm_soo = ecommunity_str2com(
			yang_dnode_get_string(args->dnode, NULL),
			ECOMMUNITY_SITE_ORIGIN, 0);
		if (!ecomm_soo) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "%% Malformed SoO extended community");
			return NB_ERR_VALIDATION;
		}
		ecommunity_free(&ecomm_soo);
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 6, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	ecomm_soo = ecommunity_str2com(
		yang_dnode_get_string(args->dnode, NULL),
		ECOMMUNITY_SITE_ORIGIN, 0);
	if (!ecomm_soo) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "%% Malformed SoO extended community");
		return NB_ERR;
	}
	ecommunity_str(ecomm_soo);
	bgp_evpn_handle_global_macvrf_soo_change(bgp, ecomm_soo);
	return NB_OK;
}

int bgp_global_evpn_soo_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp, *bgp_evpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 6, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	bgp_evpn = bgp_get_evpn();
	if (bgp_evpn && bgp_evpn->evpn_info)
		bgp_evpn_handle_global_macvrf_soo_change(bgp_evpn,
							 NULL);
	return NB_OK;
}

/*
 * dup-addr-detection: combined reapply from the datastore (the DS is
 * the source of truth), mirroring the Fase B prefix-limit reapply.
 * skip_leaf is the schema name of a leaf being destroyed so the OLD
 * tree read does not resurrect the dying value.
 */
static int bgp_nb_evpn_dad_apply(struct bgp *bgp, const struct lyd_node *dnode,
				 const char *skip_leaf)
{
	const struct lyd_node *dad;
	bool enable = true;
	bool freeze = false;
	uint16_t max_moves = EVPN_DAD_DEFAULT_MAX_MOVES;
	uint16_t time = EVPN_DAD_DEFAULT_TIME;
	uint32_t freeze_time = 0;

	dad = yang_dnode_get_parent(dnode, "duplicate-address-detection");
	if (!dad)
		return NB_ERR;

	if ((!skip_leaf || strcmp(skip_leaf, "enable"))
	    && yang_dnode_exists(dad, "enable"))
		enable = yang_dnode_get_bool(dad, "enable");
	if ((!skip_leaf || strcmp(skip_leaf, "max-moves"))
	    && yang_dnode_exists(dad, "max-moves"))
		max_moves = yang_dnode_get_uint16(dad, "max-moves");
	if ((!skip_leaf || strcmp(skip_leaf, "time"))
	    && yang_dnode_exists(dad, "time"))
		time = yang_dnode_get_uint16(dad, "time");
	if ((!skip_leaf || strcmp(skip_leaf, "freeze-time"))
	    && yang_dnode_exists(dad, "freeze-time")) {
		freeze = true;
		freeze_time = yang_dnode_get_uint16(dad, "freeze-time");
	}
	if ((!skip_leaf || strcmp(skip_leaf, "freeze-permanent"))
	    && yang_dnode_exists(dad, "freeze-permanent"))
		freeze = true;

	bgp->evpn_info->dup_addr_detect = enable;
	bgp->evpn_info->dad_max_moves = max_moves;
	bgp->evpn_info->dad_time = time;
	bgp->evpn_info->dad_freeze = freeze;
	bgp->evpn_info->dad_freeze_time = freeze_time;
	bgp_zebra_dup_addr_detection(bgp);
	return NB_OK;
}

static int bgp_nb_evpn_dad_common(struct nb_cb_modify_args *args,
				  unsigned int depth)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = bgp_nb_evpn_bgp(args->dnode, depth, args->errmsg,
				      args->errmsg_len);
		if (!bgp)
			return NB_ERR_VALIDATION;
		if (!EVPN_ENABLED(bgp)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "This command is only supported under the EVPN VRF");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, depth, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	return bgp_nb_evpn_dad_apply(bgp, args->dnode, NULL);
}

int bgp_global_evpn_dad_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_evpn_dad_common(args, 7);
}

int bgp_global_evpn_dad_freeze_time_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_evpn_dad_common(args, 7);
}

int bgp_global_evpn_dad_freeze_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	return bgp_nb_evpn_dad_apply(bgp, args->dnode, "freeze-time");
}

int bgp_global_evpn_dad_freeze_permanent_create(
	struct nb_cb_create_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	return bgp_nb_evpn_dad_apply(bgp, args->dnode, NULL);
}

int bgp_global_evpn_dad_freeze_permanent_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	return bgp_nb_evpn_dad_apply(bgp, args->dnode, "freeze-permanent");
}

/* ---- multihoming global knobs (bgp_mh_info) ---- */

int bgp_global_evpn_use_es_l3nhg_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp_mh_info->host_routes_use_l3nhg =
		yang_dnode_get_bool(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_evpn_ead_evi_rx_modify(struct nb_cb_modify_args *args)
{
	bool old_ead_evi_rx;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	/*
	 * The leaf is the DISABLE knob: disable-ead-evi-rx true means
	 * the EAD-EVI rx activation is turned off.
	 */
	old_ead_evi_rx = !yang_dnode_get_bool(args->dnode, NULL);
	if (old_ead_evi_rx != bgp_mh_info->enable_ead_evi_rx) {
		bgp_mh_info->enable_ead_evi_rx = old_ead_evi_rx;
		bgp_evpn_switch_ead_evi_rx();
	}
	return NB_OK;
}

int bgp_global_evpn_ead_evi_tx_modify(struct nb_cb_modify_args *args)
{
	bool old_ead_evi_tx;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	old_ead_evi_tx = !yang_dnode_get_bool(args->dnode, NULL);
	if (old_ead_evi_tx != bgp_mh_info->enable_ead_evi_tx) {
		bgp_mh_info->enable_ead_evi_tx = old_ead_evi_tx;
		bgp_evpn_switch_ead_evi_tx();
	}
	return NB_OK;
}

int bgp_global_evpn_ead_es_frag_limit_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp_mh_info->evi_per_es_frag =
		yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_evpn_ead_es_frag_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp_mh_info->evi_per_es_frag = BGP_EVPN_MAX_EVI_PER_ES_FRAG;
	return NB_OK;
}

/*
 * On add the helper takes ownership of ecom; on remove the caller
 * keeps it (mirrors the CLI DEFUNs).
 */
static int bgp_nb_evpn_ead_es_rt_apply(enum nb_event event,
				       const struct lyd_node *dnode,
				       bool is_add, char *errmsg,
				       size_t errmsg_len)
{
	struct bgp *bgp;
	struct ecommunity *ecom;
	const char *rt_str;

	rt_str = yang_dnode_get_string(dnode, NULL);

	if (event == NB_EV_VALIDATE) {
		ecom = ecommunity_str2com(rt_str,
					  ECOMMUNITY_ROUTE_TARGET, 0);
		if (!ecom) {
			snprintfrr(errmsg, errmsg_len,
				   "%% Malformed Route Target list");
			return NB_ERR_VALIDATION;
		}
		ecommunity_free(&ecom);
		return NB_OK;
	}
	if (event != NB_EV_APPLY)
		return NB_OK;

	ecom = ecommunity_str2com(rt_str, ECOMMUNITY_ROUTE_TARGET, 0);
	if (!ecom) {
		snprintfrr(errmsg, errmsg_len,
			   "%% Malformed Route Target list");
		return NB_ERR;
	}
	ecommunity_str(ecom);

	bgp = bgp_nb_evpn_bgp(dnode, 7, errmsg, errmsg_len);
	if (!bgp) {
		ecommunity_free(&ecom);
		return NB_ERR;
	}
	if (!is_add
	    && !bgp_evpn_rt_matches_existing(bgp_mh_info->ead_es_export_rtl,
					     ecom)) {
		snprintfrr(errmsg, errmsg_len,
			   "%% RT specified does not match EAD-ES RT configuration");
		ecommunity_free(&ecom);
		return NB_ERR;
	}
	if (is_add
	    && bgp_evpn_rt_matches_existing(bgp_mh_info->ead_es_export_rtl,
					    ecom)) {
		ecommunity_free(&ecom);
		return NB_OK;
	}
	bgp_evpn_mh_config_ead_export_rt(bgp, ecom, !is_add);
	if (!is_add)
		ecommunity_free(&ecom);
	return NB_OK;
}

int bgp_global_evpn_ead_es_rt_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE: {
		struct bgp *bgp;

		bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
				      args->errmsg_len);
		if (!bgp)
			return NB_ERR_VALIDATION;
		if (!EVPN_ENABLED(bgp)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "This command is only supported under EVPN VRF");
			return NB_ERR_VALIDATION;
		}
		break;
	}
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_evpn_ead_es_rt_apply(args->event, args->dnode, true,
					   args->errmsg, args->errmsg_len);
}

int bgp_global_evpn_ead_es_rt_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_evpn_ead_es_rt_apply(args->event, args->dnode, false,
					   args->errmsg, args->errmsg_len);
}

/* ---- advertise-pip (L3VNI VRF only) ---- */

static int bgp_nb_evpn_pip_vrf_validate(struct nb_cb_modify_args *args,
					unsigned int depth)
{
	struct bgp *bgp = bgp_nb_evpn_bgp(args->dnode, depth, args->errmsg,
					  args->errmsg_len);

	if (!bgp)
		return NB_ERR_VALIDATION;
	if (EVPN_ENABLED(bgp)) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "This command is supported under L3VNI BGP EVPN VRF");
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

int bgp_global_evpn_pip_enable_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_evpn_pip_vrf_validate(args, 7);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	bgp_evpn_pip_enable_set(bgp, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

int bgp_global_evpn_pip_ip_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct in_addr ip;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_evpn_pip_vrf_validate(args, 7);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	yang_dnode_get_ipv4(&ip, args->dnode, NULL);
	bgp_evpn_pip_ip_set(bgp, ip);
	return NB_OK;
}

int bgp_global_evpn_pip_ip_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	bgp_evpn_pip_ip_unset(bgp);
	return NB_OK;
}

int bgp_global_evpn_pip_mac_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct ethaddr mac;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_evpn_pip_vrf_validate(args, 7);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	yang_dnode_get_mac(&mac, args->dnode, NULL);
	bgp_evpn_pip_mac_set(bgp, &mac);
	return NB_OK;
}

int bgp_global_evpn_pip_mac_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	bgp_evpn_pip_mac_unset(bgp);
	return NB_OK;
}

/* ---- ip-vrf (L3VNI VRF) ---- */

int bgp_global_evpn_vrf_rd_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct prefix_rd prd;
	const char *rd_str;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
				      args->errmsg_len);
		if (!bgp)
			return NB_ERR_VALIDATION;
		if (!str2prefix_rd(yang_dnode_get_string(args->dnode, NULL),
				   &prd)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "%% Malformed Route Distinguisher");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	rd_str = yang_dnode_get_string(args->dnode, NULL);
	str2prefix_rd(rd_str, &prd);
	if (!bgp_evpn_vrf_rd_matches_existing(bgp, &prd))
		evpn_configure_vrf_rd(bgp, &prd, rd_str);
	return NB_OK;
}

int bgp_global_evpn_vrf_rd_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	if (!is_vrf_rd_configured(bgp))
		return NB_OK;
	evpn_unconfigure_vrf_rd(bgp);
	return NB_OK;
}

static int bgp_nb_evpn_vrf_rt_apply(enum nb_event event,
				    const struct lyd_node *dnode, bool is_add,
				    char *errmsg, size_t errmsg_len)
{
	struct bgp *bgp;
	struct bgp_evpn_cfgd_rt *cfgd_rt;
	enum bgp_evpn_rt_direction direction;
	const char *rt_str;

	rt_str = yang_dnode_get_string(dnode, NULL);
	direction = bgp_nb_evpn_rt_direction(dnode);

	if (event == NB_EV_VALIDATE) {
		cfgd_rt = bgp_nb_evpn_cfgd_rt_from_str(
			rt_str, direction == RT_TYPE_IMPORT, errmsg,
			errmsg_len);
		if (!cfgd_rt)
			return NB_ERR_VALIDATION;
		bgp_evpn_cfgd_rt_free(cfgd_rt);
		return NB_OK;
	}
	if (event != NB_EV_APPLY)
		return NB_OK;

	cfgd_rt = bgp_nb_evpn_cfgd_rt_from_str(
		rt_str, direction == RT_TYPE_IMPORT, errmsg, errmsg_len);
	if (!cfgd_rt)
		return NB_ERR;

	bgp = bgp_nb_evpn_bgp(dnode, 7, errmsg, errmsg_len);
	if (!bgp) {
		bgp_evpn_cfgd_rt_free(cfgd_rt);
		return NB_ERR;
	}
	if (is_add) {
		if (vrf_rt_add(bgp, cfgd_rt, direction) != 0) {
			/*
			 * Idempotent re-create (CLI-converged state):
			 * mirror the EAD-ES behaviour and accept it.
			 */
			bgp_evpn_cfgd_rt_free(cfgd_rt);
			return NB_OK;
		}
	} else {
		if (vrf_rt_del(bgp, cfgd_rt, direction) != 0) {
			snprintfrr(errmsg, errmsg_len,
				   "%% RT specified does not match configuration for this VRF: %s",
				   rt_str);
		}
		bgp_evpn_cfgd_rt_free(cfgd_rt);
	}
	return NB_OK;
}

int bgp_global_evpn_vrf_rt_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_evpn_vrf_rt_apply(args->event, args->dnode, true,
					args->errmsg, args->errmsg_len);
}

int bgp_global_evpn_vrf_rt_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_evpn_vrf_rt_apply(args->event, args->dnode, false,
					args->errmsg, args->errmsg_len);
}

int bgp_global_evpn_vrf_rt_auto_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (bgp_nb_evpn_rt_direction(args->dnode) == RT_TYPE_IMPORT) {
		if (enable)
			bgp_evpn_configure_import_auto_rt_for_vrf(
				bgp, BGP_EVPN_AUTORT_ADD_ALWAYS);
		else
			bgp_evpn_unconfigure_import_auto_rt_for_vrf(bgp);
	} else {
		if (enable)
			bgp_evpn_configure_export_auto_rt_for_vrf(
				bgp, BGP_EVPN_AUTORT_ADD_ALWAYS);
		else
			bgp_evpn_unconfigure_export_auto_rt_for_vrf(bgp);
	}
	return NB_OK;
}

/*
 * type-5 advertise: combined reapply from the ipvX-unicast container
 * (the DS is the source of truth). disable clears flags, rmap and
 * withdraws, mirroring the CLI no-form.
 */
static int bgp_nb_evpn_t5_apply(struct bgp *bgp, const struct lyd_node *t5c,
				const char *skip_leaf)
{
	afi_t afi;
	bool enable = false, gw = false;
	const char *rmap = NULL;

	afi = strmatch(t5c->schema->name, "ipv4-unicast") ? AFI_IP
							  : AFI_IP6;
	if (yang_dnode_exists(t5c, "enable"))
		enable = yang_dnode_get_bool(t5c, "enable");
	/*
	 * DESTROY callbacks see the OLD tree: skip the dying leaf so the
	 * reapply keeps the default instead of resurrecting its value.
	 */
	if ((!skip_leaf || strcmp(skip_leaf, "gateway-ip"))
	    && yang_dnode_exists(t5c, "gateway-ip"))
		gw = yang_dnode_get_bool(t5c, "gateway-ip");
	if ((!skip_leaf || strcmp(skip_leaf, "route-map"))
	    && yang_dnode_exists(t5c, "route-map"))
		rmap = yang_dnode_get_string(t5c, "route-map");

	if (!enable) {
		bgp_evpn_advertise_type5_unset(bgp, afi);
		return NB_OK;
	}
	/*
	 * Return code 1 is "already configured" -- an idempotent
	 * no-op for a programmatic re-commit of the same state.
	 */
	(void)bgp_evpn_advertise_type5_set(bgp, afi, gw, rmap);
	return NB_OK;
}

static const struct lyd_node *bgp_nb_evpn_t5_container(
	const struct lyd_node *dnode)
{
	const struct lyd_node *t5c;

	t5c = yang_dnode_get_parent(dnode, "ipv4-unicast");
	if (!t5c)
		t5c = yang_dnode_get_parent(dnode, "ipv6-unicast");
	return t5c;
}

static int bgp_nb_evpn_t5_common(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *t5c;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 8, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	t5c = bgp_nb_evpn_t5_container(args->dnode);
	if (!t5c) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "%% Only ipv4 unicast or ipv6 unicast are supported");
		return NB_ERR;
	}
	return bgp_nb_evpn_t5_apply(bgp, t5c, NULL);
}

int bgp_global_evpn_t5_enable_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_evpn_t5_common(args);
}

int bgp_global_evpn_t5_gateway_ip_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_evpn_t5_common(args);
}

int bgp_global_evpn_t5_gateway_ip_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *t5c;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 8, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	t5c = bgp_nb_evpn_t5_container(args->dnode);
	if (!t5c)
		return NB_ERR;
	return bgp_nb_evpn_t5_apply(
		bgp, t5c,
		args->dnode->schema ? args->dnode->schema->name : NULL);
}

int bgp_global_evpn_t5_rmap_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_evpn_t5_common(args);
}

int bgp_global_evpn_t5_rmap_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const struct lyd_node *t5c;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 8, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	t5c = bgp_nb_evpn_t5_container(args->dnode);
	if (!t5c)
		return NB_ERR;
	return bgp_nb_evpn_t5_apply(
		bgp, t5c,
		args->dnode->schema ? args->dnode->schema->name : NULL);
}

/* ---- vni (L2VNI) list ---- */

int bgp_global_evpn_vni_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 6, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	vpn = evpn_create_update_vni(bgp, bgp_nb_evpn_vni_key(args->dnode));
	if (!vpn) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "%% Failed to create VNI");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_global_evpn_vni_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 6, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	vpn = bgp_nb_evpn_vni_lookup(args->dnode, bgp);
	if (!vpn || !is_vni_configured(vpn))
		return NB_OK;
	evpn_delete_vni(bgp, vpn);
	return NB_OK;
}

static struct bgpevpn *bgp_nb_evpn_vni_from_leaf(
	const struct lyd_node *dnode, unsigned int depth, struct bgp **bgp_out,
	char *errmsg, size_t errmsg_len)
{
	struct bgp *bgp = bgp_nb_evpn_bgp(dnode, depth, errmsg, errmsg_len);

	if (!bgp)
		return NULL;
	*bgp_out = bgp;
	return bgp_evpn_lookup_vni(bgp, yang_dnode_get_uint32(dnode, "../vni"));
}

static int bgp_nb_evpn_vni_validate(const struct lyd_node *dnode,
				    unsigned int depth, char *errmsg,
				    size_t errmsg_len)
{
	struct bgp *bgp = bgp_nb_evpn_bgp(dnode, depth, errmsg, errmsg_len);

	if (!bgp)
		return NB_ERR_VALIDATION;
	if (!EVPN_ENABLED(bgp)) {
		snprintfrr(errmsg, errmsg_len,
			   "This command is only supported under EVPN VRF");
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

int bgp_global_evpn_vni_rd_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;
	struct prefix_rd prd;
	const char *rd_str;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_evpn_vni_validate(args->dnode, 7, args->errmsg,
					     args->errmsg_len)
		    != NB_OK)
			return NB_ERR_VALIDATION;
		if (!str2prefix_rd(yang_dnode_get_string(args->dnode, NULL),
				   &prd)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "%% Malformed Route Distinguisher");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	vpn = bgp_nb_evpn_vni_lookup(args->dnode, bgp);
	if (!vpn) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "%% Specified VNI does not exist");
		return NB_ERR;
	}
	rd_str = yang_dnode_get_string(args->dnode, NULL);
	str2prefix_rd(rd_str, &prd);
	if (!bgp_evpn_rd_matches_existing(vpn, &prd))
		evpn_configure_rd(bgp, vpn, &prd, rd_str);
	return NB_OK;
}

int bgp_global_evpn_vni_rd_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	bgp = bgp_nb_evpn_bgp(args->dnode, 7, args->errmsg,
			      args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	vpn = bgp_nb_evpn_vni_lookup(args->dnode, bgp);
	if (!vpn) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "%% Specified VNI does not exist");
		return NB_ERR;
	}
	if (!is_rd_configured(vpn))
		return NB_OK;
	evpn_unconfigure_rd(bgp, vpn);
	return NB_OK;
}

static int bgp_nb_evpn_vni_rt_apply(enum nb_event event,
				    const struct lyd_node *dnode, bool is_add,
				    char *errmsg, size_t errmsg_len)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;
	struct bgp_evpn_cfgd_rt *cfgd_rt;
	enum bgp_evpn_rt_direction direction;
	const char *rt_str;

	rt_str = yang_dnode_get_string(dnode, NULL);
	direction = bgp_nb_evpn_rt_direction(dnode);

	if (event == NB_EV_VALIDATE) {
		if (bgp_nb_evpn_vni_validate(dnode, 7, errmsg, errmsg_len)
		    != NB_OK)
			return NB_ERR_VALIDATION;
		cfgd_rt = bgp_nb_evpn_cfgd_rt_from_str(
			rt_str, direction == RT_TYPE_IMPORT, errmsg,
			errmsg_len);
		if (!cfgd_rt)
			return NB_ERR_VALIDATION;
		bgp_evpn_cfgd_rt_free(cfgd_rt);
		return NB_OK;
	}
	if (event != NB_EV_APPLY)
		return NB_OK;

	cfgd_rt = bgp_nb_evpn_cfgd_rt_from_str(
		rt_str, direction == RT_TYPE_IMPORT, errmsg, errmsg_len);
	if (!cfgd_rt)
		return NB_ERR;

	bgp = bgp_nb_evpn_bgp(dnode, 7, errmsg, errmsg_len);
	if (!bgp) {
		bgp_evpn_cfgd_rt_free(cfgd_rt);
		return NB_ERR;
	}
	vpn = bgp_nb_evpn_vni_lookup(dnode, bgp);
	if (!vpn) {
		bgp_evpn_cfgd_rt_free(cfgd_rt);
		snprintfrr(errmsg, errmsg_len,
			   "%% Specified VNI does not exist");
		return NB_ERR;
	}
	if (is_add) {
		if (l2vni_rt_add(bgp, vpn, cfgd_rt, direction) != 0) {
			/*
			 * Idempotent re-create (CLI-converged state):
			 * mirror the EAD-ES behaviour and accept it.
			 */
			bgp_evpn_cfgd_rt_free(cfgd_rt);
			return NB_OK;
		}
	} else {
		if (l2vni_rt_del(bgp, vpn, cfgd_rt, direction) != 0) {
			snprintfrr(errmsg, errmsg_len,
				   "%% RT specified does not match configuration for this VNI: %s",
				   rt_str);
		}
		bgp_evpn_cfgd_rt_free(cfgd_rt);
	}
	return NB_OK;
}

int bgp_global_evpn_vni_rt_create(struct nb_cb_create_args *args)
{
	return bgp_nb_evpn_vni_rt_apply(args->event, args->dnode, true,
					args->errmsg, args->errmsg_len);
}

int bgp_global_evpn_vni_rt_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	return bgp_nb_evpn_vni_rt_apply(args->event, args->dnode, false,
					args->errmsg, args->errmsg_len);
}

int bgp_global_evpn_vni_adv_gw_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	vpn = bgp_nb_evpn_vni_from_leaf(args->dnode, 7, &bgp, args->errmsg,
					args->errmsg_len);
	if (!vpn)
		return NB_ERR;
	if (yang_dnode_get_bool(args->dnode, NULL))
		evpn_set_advertise_default_gw(bgp, vpn);
	else
		evpn_unset_advertise_default_gw(bgp, vpn);
	return NB_OK;
}

int bgp_global_evpn_vni_adv_svi_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	vpn = bgp_nb_evpn_vni_from_leaf(args->dnode, 7, &bgp, args->errmsg,
					args->errmsg_len);
	if (!vpn)
		return NB_ERR;
	evpn_set_advertise_svi_macip(
		bgp, vpn, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

int bgp_global_evpn_vni_adv_subnet_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	vpn = bgp_nb_evpn_vni_from_leaf(args->dnode, 7, &bgp, args->errmsg,
					args->errmsg_len);
	if (!vpn)
		return NB_ERR;
	if (yang_dnode_get_bool(args->dnode, NULL))
		evpn_set_advertise_subnet(bgp, vpn);
	else
		evpn_unset_advertise_subnet(bgp, vpn);
	return NB_OK;
}

int bgp_global_evpn_vni_flooding_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;
	const char *mode;
	enum vxlan_flood_control flood_ctrl = VXLAN_FLOOD_INHERIT_GLOBAL;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	vpn = bgp_nb_evpn_vni_from_leaf(args->dnode, 7, &bgp, args->errmsg,
					args->errmsg_len);
	if (!vpn)
		return NB_ERR;
	mode = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(mode, "disable"))
		flood_ctrl = VXLAN_FLOOD_DISABLED;
	else if (strmatch(mode, "head-end-replication"))
		flood_ctrl = VXLAN_FLOOD_HEAD_END_REPL;
	if (vpn->vxlan_flood_ctrl == flood_ctrl)
		return NB_OK;
	vpn->vxlan_flood_ctrl = flood_ctrl;
	bgp_evpn_flood_control_change(bgp);
	return NB_OK;
}

/*
 * ---- bmp monitor -------------------------------------------------------
 * global/bmp-config/target-list/afi-safis/afi-safi/l2vpn-evpn/
 * common-config/{pre,post-policy,loc-rib}: mirror the "bmp monitor
 * <afi> <safi> <policy>" CLI onto bmp_monitor_apply(), the shared
 * internal the DEFUN calls, so the datastore and the bgpd internals
 * cannot drift apart.
 *
 * bgp_bmp.c is a dlopen module: it cannot be linked from here, so it
 * publishes its internals through bgp_nb_bmp_ops at load time. While
 * the module is not loaded the commit fails with an explicit error.
 * Since s061 the target group no longer needs to pre-exist: the
 * target-list create is wired, so a leaf commit creates the group on
 * demand (the create applies before the leaf, pre-order). The CLI
 * seeding flow still works (get_target is get-or-create).
 */
struct bgp_nb_bmp_ops bgp_nb_bmp_ops;

static bool bgp_nb_bmp_module_loaded(char *errmsg, size_t errmsg_len);

/*
 * Resolve the bmp target group and afi/safi for one monitor leaf.
 * Read-only; runs at APPLY (s061: since the target-list create is
 * wired, a leaf commit creates the group on demand, so a missing
 * target at VALIDATE is no longer an error -- the create applies
 * first, pre-order). Returns 0 with *bt_out/*afi_out/*safi_out
 * filled, -1 with errmsg.
 */
static int bgp_nb_bmp_afimon_resolve(struct nb_cb_modify_args *args,
				     afi_t *afi_out, safi_t *safi_out,
				     struct bmp_targets **bt_out)
{
	const struct lyd_node *af_entry, *target_entry;
	const char *afi_safi_id, *name;
	struct bmp_targets *bt;
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	if (!bgp_nb_bmp_ops.find_target || !bgp_nb_bmp_ops.monitor_apply) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "bmp monitor: the bgpd_bmp module is not loaded");
		return -1;
	}

	/* afi-safi list entry -> target-name key of the enclosing bmp
	 * target-list; the control-plane-protocol entry carrying the
	 * vrf key sits 9 hops up from the leaf.
	 */
	af_entry = yang_dnode_get_parent(args->dnode, "afi-safi");
	target_entry = af_entry ?
		yang_dnode_get_parent(af_entry, "target-list") : NULL;
	if (!target_entry) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "bmp monitor: missing bmp target-list");
		return -1;
	}

	name = yang_dnode_get_string(target_entry, "target-name");
	afi_safi_id = yang_dnode_get_string(af_entry, "afi-safi-name");
	if (bgp_nb_af_id_to_afi_safi(afi_safi_id, &afi, &safi) < 0) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "bmp monitor: unknown afi-safi %s", afi_safi_id);
		return -1;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 9);
	if (!bgp) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "bmp monitor: bgp instance not found");
		return -1;
	}

	bt = bgp_nb_bmp_ops.find_target(bgp, name);
	if (!bt) {
		snprintfrr(args->errmsg, args->errmsg_len, "bmp targets %s not found",
			   name);
		return -1;
	}

	*bt_out = bt;
	*afi_out = afi;
	*safi_out = safi;
	return 0;
}

static int bgp_nb_bmp_afimon_modify(struct nb_cb_modify_args *args,
				    uint8_t flag)
{
	struct bmp_targets *bt = NULL;
	afi_t afi = 0;
	safi_t safi = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	if (bgp_nb_bmp_afimon_resolve(args, &afi, &safi, &bt) < 0)
		return NB_ERR;

	bgp_nb_bmp_ops.monitor_apply(bt, afi, safi, flag,
				     yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

int bgp_bmp_monitor_pre_policy_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_bmp_afimon_modify(args, BMP_MON_PREPOLICY);
}

int bgp_bmp_monitor_post_policy_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_bmp_afimon_modify(args, BMP_MON_POSTPOLICY);
}

int bgp_bmp_monitor_loc_rib_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_bmp_afimon_modify(args, BMP_MON_LOC_RIB);
}

/* ==== bmp target lifecycle and knobs (s061) ==== */

/*
 * The bmp callbacks below resolve the owning bgp instance and bmp
 * target by walking the datastore parents by name (no hardcoded
 * depths) and apply the change through the bgp_nb_bmp_ops bridge:
 * bgp_bmp.c is a dlopen module and cannot be linked from here.
 * VALIDATE only probes the bridge (all ops pointers are published
 * atomically by the module init, so probing the s060 pair is
 * enough -- all ops are assigned as one block by the module
 * init and FRR never dlcloses a loaded module); the target
 * resolution runs at APPLY. A leaf commit
 * against a target that does not exist creates the target: the
 * datastore ancestors apply first (pre-order), so by the time the
 * leaf applies the target exists -- no pre-creation is needed and
 * no partial apply can happen (create-on-demand, s061).
 */
static bool bgp_nb_bmp_module_loaded(char *errmsg, size_t errmsg_len)
{
	if (!bgp_nb_bmp_ops.find_target || !bgp_nb_bmp_ops.monitor_apply) {
		snprintfrr(errmsg, errmsg_len,
			   "bmp: the bgpd_bmp module is not loaded");
		return false;
	}
	return true;
}

static struct bgp *bgp_nb_bmp_bgp_lookup(const struct lyd_node *dnode,
					 char *errmsg, size_t errmsg_len)
{
	const struct lyd_node *cpp;
	const char *vrf_key;
	struct bgp *bgp;

	cpp = yang_dnode_get_parent(dnode, "control-plane-protocol");
	if (!cpp) {
		snprintfrr(errmsg, errmsg_len, "bmp: missing control-plane-protocol");
		return NULL;
	}
	vrf_key = yang_dnode_get_string(cpp, "vrf");
	if (!bgp_lookup_by_name(bgp_nb_vrf_to_name(vrf_key))) {
		snprintfrr(errmsg, errmsg_len,
			   "bmp: bgp instance not found");
		return NULL;
	}
	return bgp_lookup_by_name(bgp_nb_vrf_to_name(vrf_key));
}

static struct bmp_targets *bgp_nb_bmp_target_lookup(
	const struct lyd_node *dnode, char *errmsg, size_t errmsg_len)
{
	const struct lyd_node *target_entry;
	const char *name;
	struct bgp *bgp;
	struct bmp_targets *bt;

	target_entry = yang_dnode_get_parent(dnode, "target-list");
	if (!target_entry) {
		snprintfrr(errmsg, errmsg_len, "bmp: missing bmp target-list");
		return NULL;
	}
	name = yang_dnode_get_string(target_entry, "target-name");
	bgp = bgp_nb_bmp_bgp_lookup(target_entry, errmsg, errmsg_len);
	if (!bgp)
		return NULL;
	bt = bgp_nb_bmp_ops.find_target(bgp, name);
	if (!bt)
		snprintfrr(errmsg, errmsg_len, "bmp targets %s not found",
			   name);
	return bt;
}

/*
 * bmp target-list lifecycle: create wires bmp_targets_get (the same
 * get-or-create the CLI uses), destroy wires bmp_targets_put.
 * Destroy stays tolerant of a missing runtime target: it only has
 * to clean up, and legacy CLI-created targets are not tracked by
 * the datastore.
 */
int bgp_bmp_target_list_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/* module probe only: VALIDATEs run before ANY apply, so
		 * a transaction creating the bgp instance (local-as)
		 * together with bmp nodes must not need the runtime
		 * instance here (r2 B-1); the lookup stays at APPLY
		 */
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_bmp_bgp_lookup(args->dnode, args->errmsg,
				    args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	bgp_nb_bmp_ops.get_target(
		bgp, yang_dnode_get_string(args->dnode, "target-name"));
	return NB_OK;
}

int bgp_bmp_target_list_destroy(struct nb_cb_destroy_args *args)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		/* nothing to clean up on the runtime side */
		return NB_OK;
	bgp_nb_bmp_ops.put_target(bt);
	return NB_OK;
}

/*
 * The afi-safi list entry of a bmp target carries no runtime state
 * of its own (the state lives in the monitor leaves); destroying
 * one clears any monitor flags still set through the same
 * monitor_apply internal the leaves use.
 */
int bgp_bmp_af_list_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		return NB_OK;
	}

	return NB_OK;
}

int bgp_bmp_af_list_destroy(struct nb_cb_destroy_args *args)
{
	struct bmp_targets *bt;
	const char *afi_safi_id;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_OK;
	afi_safi_id = yang_dnode_get_string(args->dnode, "afi-safi-name");
	if (bgp_nb_af_id_to_afi_safi(afi_safi_id, &afi, &safi) < 0) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "bmp: unknown afi-safi %s", afi_safi_id);
		return NB_ERR;
	}
	bgp_nb_bmp_ops.monitor_apply(bt, afi, safi, BMP_MON_PREPOLICY,
				     false);
	bgp_nb_bmp_ops.monitor_apply(bt, afi, safi, BMP_MON_POSTPOLICY,
				     false);
	bgp_nb_bmp_ops.monitor_apply(bt, afi, safi, BMP_MON_LOC_RIB,
				     false);
	return NB_OK;
}

/* global mirror-buffer-limit: no bmp target involved */
int bgp_bmp_mirror_buffer_limit_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/* module probe only (r2 B-1): lookup at APPLY */
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_bmp_bgp_lookup(args->dnode, args->errmsg,
				    args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	bgp_nb_bmp_ops.mirror_limit_set(
		bgp, yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

int bgp_bmp_mirror_buffer_limit_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_bmp_bgp_lookup(args->dnode, args->errmsg,
				    args->errmsg_len);
	if (!bgp)
		return NB_ERR;
	/* "no bmp mirror buffer-limit" maps to unlimited */
	bgp_nb_bmp_ops.mirror_limit_set(bgp, ~0UL);
	return NB_OK;
}

/* import-vrf leaf-list entries */
int bgp_bmp_import_vrf_create(struct nb_cb_create_args *args)
{
	const struct lyd_node *cpp;
	struct bmp_targets *bt;
	const char *own_name;
	const char *vrfname;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		/* The own-instance mistake is knowable from the
		 * datastore alone (leaf value vs the enclosing
		 * control-plane-protocol vrf key): reject it at
		 * VALIDATE, before the on-demand target create
		 * applies and orphans a runtime target. Mirrors the
		 * runtime check of bmp_import_vrf_apply (-1).
		 */
		cpp = yang_dnode_get_parent(args->dnode,
					    "control-plane-protocol");
		if (!cpp) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "bmp: missing control-plane-protocol");
			return NB_ERR_VALIDATION;
		}
		own_name = bgp_nb_vrf_to_name(
			yang_dnode_get_string(cpp, "vrf"));
		vrfname = yang_dnode_get_string(args->dnode, NULL);
		if (!vrfname || !vrfname[0]) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "bmp: empty import-vrf-view name");
			return NB_ERR_VALIDATION;
		}
		if ((own_name == NULL && vrfname == NULL) ||
		    (own_name && vrfname &&
		     strmatch(vrfname, own_name))) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "bmp: cannot import our own BGP instance");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_ERR;
	ret = bgp_nb_bmp_ops.import_vrf_set(
		bt, yang_dnode_get_string(args->dnode, NULL), true);
	if (ret == -3)
		/* imported entry exists but its bgp is gone: keep the
		 * runtime change consistent with the CLI (success)
		 */
		return NB_OK;
	if (ret == -1)
		snprintfrr(args->errmsg, args->errmsg_len,
			   "bmp: cannot import our own BGP instance");
	else if (ret == -4)
		snprintfrr(args->errmsg, args->errmsg_len,
			   "bmp: BGP instance not found");
	if (ret < 0)
		return NB_ERR;
	return NB_OK;
}

int bgp_bmp_import_vrf_destroy(struct nb_cb_destroy_args *args)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_OK;
	bgp_nb_bmp_ops.import_vrf_set(
		bt, yang_dnode_get_string(args->dnode, NULL), false);
	return NB_OK;
}

/* incoming (listener) session-list entries */
int bgp_bmp_listener_create(struct nb_cb_create_args *args)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_ERR;
	if (bgp_nb_bmp_ops.listener_add(
		    bt, yang_dnode_get_string(args->dnode, "address"),
		    (uint16_t)yang_dnode_get_uint32(args->dnode, "tcp-port")) < 0) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "bmp listener: invalid address");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_bmp_listener_destroy(struct nb_cb_destroy_args *args)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_OK;
	bgp_nb_bmp_ops.listener_del(
		bt, yang_dnode_get_string(args->dnode, "address"),
		(uint16_t)yang_dnode_get_uint32(args->dnode, "tcp-port"));
	return NB_OK;
}

/* outgoing (connect) session-list entries and their leaves */
int bgp_bmp_connect_create(struct nb_cb_create_args *args)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_ERR;
	bgp_nb_bmp_ops.connect_add(
		bt, yang_dnode_get_string(args->dnode, "hostname"),
		(uint16_t)yang_dnode_get_uint32(args->dnode, "tcp-port"));
	return NB_OK;
}

int bgp_bmp_connect_destroy(struct nb_cb_destroy_args *args)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_OK;
	bgp_nb_bmp_ops.connect_del(
		bt, yang_dnode_get_string(args->dnode, "hostname"),
		(uint16_t)yang_dnode_get_uint32(args->dnode, "tcp-port"));
	return NB_OK;
}

static int bgp_bmp_connect_leaf_apply(struct nb_cb_modify_args *args,
				      bool min_retry)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_ERR;
	if (bgp_nb_bmp_ops.connect_retry_set(
		    bt, yang_dnode_get_string(args->dnode, "../hostname"),
		    (uint16_t)yang_dnode_get_uint32(args->dnode, "../tcp-port"),
		    min_retry,
		    yang_dnode_get_uint32(args->dnode, NULL)) < 0) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "bmp connect: session not found");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_bmp_connect_min_retry_modify(struct nb_cb_modify_args *args)
{
	return bgp_bmp_connect_leaf_apply(args, true);
}

int bgp_bmp_connect_max_retry_modify(struct nb_cb_modify_args *args)
{
	return bgp_bmp_connect_leaf_apply(args, false);
}

int bgp_bmp_connect_srcif_modify(struct nb_cb_modify_args *args)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_ERR;
	if (bgp_nb_bmp_ops.connect_srcif_set(
		    bt, yang_dnode_get_string(args->dnode, "../hostname"),
		    (uint16_t)yang_dnode_get_uint32(args->dnode, "../tcp-port"),
		    yang_dnode_get_string(args->dnode, NULL)) < 0) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "bmp connect: session not found");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_bmp_connect_srcif_destroy(struct nb_cb_destroy_args *args)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_OK;
	bgp_nb_bmp_ops.connect_srcif_set(
		bt, yang_dnode_get_string(args->dnode, "../hostname"),
		(uint16_t)yang_dnode_get_uint32(args->dnode, "../tcp-port"), NULL);
	return NB_OK;
}

/* access-list knobs */
static int bgp_bmp_acl_apply(struct nb_cb_modify_args *args, bool ipv6)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_ERR;
	bgp_nb_bmp_ops.acl_set(bt, ipv6,
			       yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_bmp_ipv4_acl_modify(struct nb_cb_modify_args *args)
{
	return bgp_bmp_acl_apply(args, false);
}

int bgp_bmp_ipv6_acl_modify(struct nb_cb_modify_args *args)
{
	return bgp_bmp_acl_apply(args, true);
}

static int bgp_bmp_acl_destroy(struct nb_cb_destroy_args *args, bool ipv6)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_OK;
	bgp_nb_bmp_ops.acl_set(bt, ipv6, NULL);
	return NB_OK;
}

int bgp_bmp_ipv4_acl_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_bmp_acl_destroy(args, false);
}

int bgp_bmp_ipv6_acl_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_bmp_acl_destroy(args, true);
}

/* mirror knob */
int bgp_bmp_mirror_modify(struct nb_cb_modify_args *args)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_ERR;
	bgp_nb_bmp_ops.mirror_set(bt, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}

/* stats knobs */
int bgp_bmp_stats_time_modify(struct nb_cb_modify_args *args)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_ERR;
	bgp_nb_bmp_ops.stats_interval_set(
		bt, yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

int bgp_bmp_stats_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_OK;
	/* no default in the model: destroy stops the stats timer */
	bgp_nb_bmp_ops.stats_interval_set(bt, 0);
	return NB_OK;
}

int bgp_bmp_stats_experimental_modify(struct nb_cb_modify_args *args)
{
	struct bmp_targets *bt;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_nb_bmp_module_loaded(args->errmsg, args->errmsg_len))
			return NB_ERR_VALIDATION;
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bt = bgp_nb_bmp_target_lookup(args->dnode, args->errmsg,
				      args->errmsg_len);
	if (!bt)
		return NB_ERR;
	bgp_nb_bmp_ops.stats_experimental_set(
		bt, yang_dnode_get_bool(args->dnode, NULL));
	return NB_OK;
}
