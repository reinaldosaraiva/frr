// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP northbound — daemon-level + global non-AF + interface callbacks
 * (S063 R2, rodada 3b).
 *
 * Covers: update-delay, advertisement-delay, establish-wait,
 * rmap-delay, graceful-restart, graceful-shutdown, queue-limit,
 * ipv6-auto-ra, no-rib, send-extra-data, session-dscp,
 * suppress-fib-pending, community-alias, as-notation,
 * default-afi-safi, local-as, mpls-bgp-forwarding.
 *
 * Daemon-level leaves mirror the CONFIG_NODE branches of the legacy
 * DEFUNs (bm->* mutation plus per-instance propagation); per-instance
 * leaves mirror the existing northbound handlers in bgp_nb_config.c.
 * The med-config and global tcp-keepalive leaves stay no-ops on
 * purpose: their non-presence containers carry native apply_finish
 * callbacks that read every leaf at commit time.
 *
 * Copyright (C) 2026 FRRouting
 */

#include <zebra.h>

#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/yang.h"
#include "lib/yang_wrappers.h"
#include "lib/vrf.h"
#include "lib/if.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_community_alias.h"
#include "bgpd/bgp_nb.h"

#ifndef IPTOS_PREC_INTERNETCONTROL
#define IPTOS_PREC_INTERNETCONTROL 0xc0 /* CS6 */
#endif

static struct bgp *daemon_lookup_bgp(const struct lyd_node *dnode, unsigned int depth_to_cpp)
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

/* Mirror of the static bgp_update_graceful_restart_capability() in
 * bgp_vty.c: reset the session so the updated capability is exchanged.
 */
static void daemon_gr_restart_capability_update(struct peer *peer)
{
	enum peer_mode peer_gr_mode;
	enum global_mode global_gr_mode;

	global_gr_mode = bgp_global_gr_mode_get(peer->bgp);
	peer_gr_mode = bgp_peer_gr_mode_get(peer);

	if (!((peer_gr_mode == PEER_GR) ||
	      (peer_gr_mode == PEER_GLOBAL_INHERIT && global_gr_mode == GLOBAL_GR)))
		return;

	if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status)) {
		peer_set_last_reset(peer, PEER_DOWN_CAPABILITY_CHANGE);
		bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE, BGP_NOTIFY_CEASE_CONFIG_CHANGE);
	}
}

/* Core of the legacy bgp_global_gr_config_vty() minus the vty output:
 * bm flag bookkeeping plus bgp_gr_update_all() on every instance.
 */
static int daemon_gr_apply(bool on, bool disable, char *errmsg, size_t errmsg_len)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	int ret = BGP_GR_SUCCESS;

	if (disable) {
		if ((on && CHECK_FLAG(bm->flags, BM_FLAG_GR_DISABLED)) ||
		    (!on && !CHECK_FLAG(bm->flags, BM_FLAG_GR_DISABLED)))
			return NB_OK;
	} else {
		if ((on && CHECK_FLAG(bm->flags, BM_FLAG_GR_RESTARTER)) ||
		    (!on && !CHECK_FLAG(bm->flags, BM_FLAG_GR_RESTARTER)))
			return NB_OK;
	}

	if (on) {
		if (disable) {
			UNSET_FLAG(bm->flags, BM_FLAG_GR_RESTARTER);
			SET_FLAG(bm->flags, BM_FLAG_GR_DISABLED);
		} else {
			SET_FLAG(bm->flags, BM_FLAG_GR_RESTARTER);
			UNSET_FLAG(bm->flags, BM_FLAG_GR_DISABLED);
		}
	} else {
		if (disable)
			UNSET_FLAG(bm->flags, BM_FLAG_GR_DISABLED);
		else
			UNSET_FLAG(bm->flags, BM_FLAG_GR_RESTARTER);
	}

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		ret = bgp_gr_update_all(bgp,
					disable ? (on ? GLOBAL_DISABLE_CMD : NO_GLOBAL_DISABLE_CMD)
						: (on ? GLOBAL_GR_CMD : NO_GLOBAL_GR_CMD));
		VTY_BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(bgp, bgp->peer, ret);
		if (ret != BGP_GR_SUCCESS) {
			snprintfrr(errmsg, errmsg_len,
				   "applying global graceful-restart to vrf %s failed",
				   bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT ? VRF_DEFAULT_NAME
									       : bgp->name);
			return NB_ERR;
		}
	}

	return NB_OK;
}

/* ================================================================== */
/* Daemon-level leaves (bgp_option.* / bm.*)                           */
/* ================================================================== */

int bgp_daemon_update_delay_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint16_t update_delay, establish_wait;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/* Mirror bgp_global_update_delay_config_vty(): reject the
		 * global form while a per-vrf update-delay exists.
		 */
		if (bm->v_update_delay == BGP_UPDATE_DELAY_DEFAULT) {
			for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
				if (bgp->v_update_delay != BGP_UPDATE_DELAY_DEFAULT) {
					snprintfrr(args->errmsg, args->errmsg_len,
						   "per-vrf update-delay already set");
					return NB_ERR_VALIDATION;
				}
			}
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	update_delay = yang_dnode_get_uint16(args->dnode, NULL);
	if (yang_dnode_exists(args->dnode, "../establish-wait-time")) {
		establish_wait = yang_dnode_get_uint16(args->dnode, "../establish-wait-time");
	} else {
		establish_wait = update_delay;
	}

	bm->v_update_delay = update_delay;
	bm->v_establish_wait = establish_wait;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->v_update_delay = bm->v_update_delay;
		bgp->v_establish_wait = bm->v_establish_wait;
	}

	return NB_OK;
}

int bgp_daemon_update_delay_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm->v_update_delay = BGP_UPDATE_DELAY_DEFAULT;
	bm->v_establish_wait = bm->v_update_delay;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->v_update_delay = bm->v_update_delay;
		bgp->v_establish_wait = bm->v_establish_wait;
	}

	return NB_OK;
}

int bgp_daemon_adv_delay_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm->v_advertisement_delay = yang_dnode_get_uint16(args->dnode, NULL);

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp->v_advertisement_delay = bm->v_advertisement_delay;

	return NB_OK;
}

int bgp_daemon_adv_delay_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm->v_advertisement_delay = BGP_ADVERTISEMENT_DELAY_DEFAULT;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp->v_advertisement_delay = bm->v_advertisement_delay;

	return NB_OK;
}

int bgp_daemon_establish_wait_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm->v_establish_wait = yang_dnode_get_uint16(args->dnode, NULL);

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp->v_establish_wait = bm->v_establish_wait;

	return NB_OK;
}

int bgp_daemon_establish_wait_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm->v_establish_wait = bm->v_update_delay;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp->v_establish_wait = bm->v_establish_wait;

	return NB_OK;
}

int bgp_daemon_rmap_delay_modify(struct nb_cb_modify_args *args)
{
	uint16_t delay;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	/* Mirror bgp_set_route_map_delay_timer (CONFIG_NODE form). */
	delay = yang_dnode_get_uint16(args->dnode, NULL);
	bm->rmap_update_timer = delay;

	if (!delay && event_is_scheduled(bm->t_rmap_update)) {
		event_cancel(&bm->t_rmap_update);
		event_execute(bm->master, bgp_route_map_update_timer, NULL, 0, NULL);
	}

	return NB_OK;
}

int bgp_daemon_gr_enabled_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	return daemon_gr_apply(yang_dnode_get_bool(args->dnode, NULL), false, args->errmsg,
			       args->errmsg_len);
}

int bgp_daemon_gr_enabled_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	return daemon_gr_apply(false, false, args->errmsg, args->errmsg_len);
}

int bgp_daemon_gr_disable_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	return daemon_gr_apply(yang_dnode_get_bool(args->dnode, NULL), true, args->errmsg,
			       args->errmsg_len);
}

int bgp_daemon_gr_disable_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	return daemon_gr_apply(false, true, args->errmsg, args->errmsg_len);
}

int bgp_daemon_gr_restart_time_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode, *pnode, *pnnode;
	struct bgp *bgp;
	struct peer *peer;
	uint16_t restart;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	/* Mirror the CONFIG_NODE branch of the legacy DEFUN. */
	restart = yang_dnode_get_uint16(args->dnode, NULL);
	bm->restart_time = restart;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->restart_time = restart;
		for (ALL_LIST_ELEMENTS(bgp->peer, pnode, pnnode, peer)) {
			if (!peer->connection)
				continue;
			if (!CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_RCV) ||
			    !CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_ADV))
				daemon_gr_restart_capability_update(peer);
			else
				bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
						    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_SET);
		}
	}

	return NB_OK;
}

int bgp_daemon_gr_stale_time_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint16_t stale_time;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	/* Mirror bgp_global_graceful_restart_rib_stale_time_modify()
	 * across every instance.
	 */
	stale_time = yang_dnode_get_uint16(args->dnode, NULL);

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->rib_stale_time = stale_time;
		(void)bgp_zebra_stale_timer_update(bgp);
	}

	return NB_OK;
}

int bgp_daemon_gr_stale_time_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm->stalepath_time = BGP_DEFAULT_STALEPATH_TIME;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp->stalepath_time = bm->stalepath_time;

	return NB_OK;
}

int bgp_daemon_gr_stale_routes_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm->stalepath_time = yang_dnode_get_uint16(args->dnode, NULL);

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp->stalepath_time = bm->stalepath_time;

	return NB_OK;
}

int bgp_daemon_gr_ll_stale_time_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode, *pnode, *pnnode;
	struct bgp *bgp;
	struct peer *peer;
	uint32_t llgr_time;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	/* Mirror bgp_global_long_lived_graceful_restart_stale_time_modify()
	 * across every instance.
	 */
	llgr_time = yang_dnode_get_uint32(args->dnode, NULL);

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->llgr_stale_time = llgr_time;
		for (ALL_LIST_ELEMENTS(bgp->peer, pnode, pnnode, peer)) {
			if (!peer->connection)
				continue;
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_LLGR, CAPABILITY_ACTION_SET);
		}
	}

	return NB_OK;
}

int bgp_daemon_gr_ll_stale_time_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode, *pnode, *pnnode;
	struct bgp *bgp;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->llgr_stale_time = BGP_DEFAULT_LLGR_STALE_TIME;
		for (ALL_LIST_ELEMENTS(bgp->peer, pnode, pnnode, peer)) {
			if (!peer->connection)
				continue;
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_LLGR, CAPABILITY_ACTION_UNSET);
		}
	}

	return NB_OK;
}

int bgp_daemon_gr_select_defer_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint16_t defer_time;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	defer_time = yang_dnode_get_uint16(args->dnode, NULL);
	bm->select_defer_time = defer_time;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->select_defer_time = defer_time;
		if (defer_time == 0)
			SET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
	}

	return NB_OK;
}

int bgp_daemon_gr_disable_eor_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
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

	enable = yang_dnode_get_bool(args->dnode, NULL);

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (enable)
			SET_FLAG(bgp->flags, BGP_FLAG_GR_DISABLE_EOR);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_GR_DISABLE_EOR);
	}

	return NB_OK;
}

int bgp_daemon_gr_notification_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode, *pnode, *pnnode;
	struct bgp *bgp;
	struct peer *peer;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	enable = yang_dnode_get_bool(args->dnode, NULL);

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (enable)
			SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
		for (ALL_LIST_ELEMENTS(bgp->peer, pnode, pnnode, peer)) {
			if (!peer->connection)
				continue;
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_SET);
		}
	}

	return NB_OK;
}

int bgp_daemon_gr_notification_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);

	return NB_OK;
}

int bgp_daemon_gr_preserve_fw_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
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

	enable = yang_dnode_get_bool(args->dnode, NULL);

	if (enable)
		SET_FLAG(bm->flags, BM_FLAG_GR_PRESERVE_FWD);
	else
		UNSET_FLAG(bm->flags, BM_FLAG_GR_PRESERVE_FWD);

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (enable)
			SET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
	}

	return NB_OK;
}

int bgp_daemon_gs_enable_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (yang_dnode_get_bool(args->dnode, NULL) &&
		    CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "global graceful-shutdown already set");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	enable = yang_dnode_get_bool(args->dnode, NULL);
	if ((bool)CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN) == enable)
		return NB_OK;

	if (enable)
		SET_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN);
	else
		UNSET_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN);

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp_static_redo_import_check(bgp);
		bgp_redistribute_redo(bgp);
		bgp_clear_star_soft_out_quiet(bgp);
		bgp_clear_star_soft_in_quiet(bgp);
	}

	return NB_OK;
}

int bgp_daemon_input_queue_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm->inq_limit = yang_dnode_get_uint32(args->dnode, NULL);

	return NB_OK;
}

int bgp_daemon_input_queue_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm->inq_limit = BM_DEFAULT_Q_LIMIT;

	return NB_OK;
}

int bgp_daemon_output_queue_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm->outq_limit = yang_dnode_get_uint32(args->dnode, NULL);

	return NB_OK;
}

int bgp_daemon_output_queue_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm->outq_limit = BM_DEFAULT_Q_LIMIT;

	return NB_OK;
}

int bgp_daemon_ipv6_auto_ra_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
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

	enable = yang_dnode_get_bool(args->dnode, NULL);

	COND_FLAG(bm->flags, BM_FLAG_IPV6_NO_AUTO_RA, !enable);
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		COND_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA, !enable);

	return NB_OK;
}

int bgp_daemon_no_rib_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	if (yang_dnode_get_bool(args->dnode, NULL))
		bgp_option_norib_set_runtime();
	else
		bgp_option_norib_unset_runtime();

	return NB_OK;
}

int bgp_daemon_send_extra_data_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	COND_FLAG(bm->flags, BM_FLAG_SEND_EXTRA_DATA_TO_ZEBRA,
		  yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}

int bgp_daemon_session_dscp_modify(struct nb_cb_modify_args *args)
{
	uint8_t dscp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	dscp = yang_dnode_get_uint8(args->dnode, NULL);
	bm->ip_tos = dscp << 2;

	return NB_OK;
}

int bgp_daemon_session_dscp_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm->ip_tos = IPTOS_PREC_INTERNETCONTROL;

	return NB_OK;
}

int bgp_daemon_suppress_fib_modify(struct nb_cb_modify_args *args)
{
	uint16_t adv_delay;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	/* The legacy CLI always carries the delay (defaulting to
	 * BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY); read the sibling leaf so a
	 * delay-only knob set in the same transaction is not clobbered.
	 */
	adv_delay = yang_dnode_exists(args->dnode, "../suppress-fib-pending-delay")
			    ? yang_dnode_get_uint16(args->dnode, "../suppress-fib-pending-delay")
			    : BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY;

	bm_wait_for_fib_set(yang_dnode_get_bool(args->dnode, NULL), adv_delay);

	return NB_OK;
}

int bgp_daemon_suppress_fib_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm_wait_for_fib_set(false, BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY);

	return NB_OK;
}

int bgp_daemon_suppress_fib_delay_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm_wait_for_fib_set(yang_dnode_exists(args->dnode, "../suppress-fib-pending") &&
				    yang_dnode_get_bool(args->dnode, "../suppress-fib-pending"),
			    yang_dnode_get_uint16(args->dnode, NULL));

	return NB_OK;
}

int bgp_daemon_suppress_fib_delay_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bm_wait_for_fib_set(yang_dnode_exists(args->dnode, "../suppress-fib-pending") &&
				    yang_dnode_get_bool(args->dnode, "../suppress-fib-pending"),
			    BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY);

	return NB_OK;
}

/* community-alias list: the create is structural (entry); the mandatory
 * alias leaf modify performs the hash inserts, mirroring the CLI
 * upsert semantics of bgp_community_alias.
 */
int bgp_daemon_community_alias_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		return NB_OK;
	}

	return NB_OK;
}

int bgp_daemon_community_alias_destroy(struct nb_cb_destroy_args *args)
{
	struct community_alias ca = {};

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	strlcpy(ca.community, yang_dnode_get_string(args->dnode, "community"),
		sizeof(ca.community));
	bgp_ca_alias_delete(&ca);
	bgp_ca_community_delete(&ca);

	return NB_OK;
}

int bgp_daemon_community_alias_modify(struct nb_cb_modify_args *args)
{
	struct community_alias ca = {};
	const char *community, *alias;
	struct community_alias *lookup_community, *lookup_alias;

	switch (args->event) {
	case NB_EV_VALIDATE:
		community = yang_dnode_get_string(args->dnode, "../community");
		{
			struct community *com = community_str2com(community);

			if (com)
				community_free(&com);
			else if (!lcommunity_str2com(community)) {
				snprintfrr(args->errmsg, args->errmsg_len,
					   "invalid community format");
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

	community = yang_dnode_get_string(args->dnode, "../community");
	alias = yang_dnode_get_string(args->dnode, NULL);
	strlcpy(ca.community, community, sizeof(ca.community));
	strlcpy(ca.alias, alias, sizeof(ca.alias));

	lookup_alias = bgp_ca_alias_lookup(&ca);
	lookup_community = bgp_ca_community_lookup(&ca);

	if (lookup_alias) {
		strlcpy(ca.community, lookup_alias->community, sizeof(ca.community));
		if (bgp_ca_community_lookup(&ca)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "community (%s) already has this alias (%s)",
				   lookup_alias->community, alias);
			return NB_ERR;
		}
		bgp_ca_alias_delete(&ca);
		strlcpy(ca.community, community, sizeof(ca.community));
	}

	if (lookup_community) {
		strlcpy(ca.alias, lookup_community->alias, sizeof(ca.alias));
		if (bgp_ca_alias_lookup(&ca)) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "alias (%s) already has this community (%s)",
				   lookup_community->alias, community);
			return NB_ERR;
		}
		bgp_ca_community_delete(&ca);
		strlcpy(ca.alias, alias, sizeof(ca.alias));
	}

	bgp_ca_alias_insert(&ca);
	bgp_ca_community_insert(&ca);

	return NB_OK;
}

/* ================================================================== */
/* Global (per-instance) non-AF leaves                                 */
/* ================================================================== */

int bgp_global_as_notation_modify(struct nb_cb_modify_args *args)
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

	bgp = daemon_lookup_bgp(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	value = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(value, "plain"))
		bgp->asnotation = ASNOTATION_PLAIN;
	else if (strmatch(value, "dot"))
		bgp->asnotation = ASNOTATION_DOT;
	else
		bgp->asnotation = ASNOTATION_DOTPLUS;

	/* config-write renders the notation only under this flag (the
	 * CLI sets it when the instance is created with as-notation).
	 */
	SET_FLAG(bgp->config, BGP_CONFIG_ASNOTATION);

	return NB_OK;
}

int bgp_global_as_notation_destroy(struct nb_cb_destroy_args *args)
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

	bgp = daemon_lookup_bgp(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->asnotation = ASNOTATION_PLAIN;
	UNSET_FLAG(bgp->config, BGP_CONFIG_ASNOTATION);

	return NB_OK;
}

int bgp_global_rmap_delay_modify(struct nb_cb_modify_args *args)
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

	/* Upstream models rmap-delay-time twice (bgp-daemon and
	 * global-config-timers) but only the daemon-wide
	 * bm->rmap_update_timer exists; the per-instance leaf is an alias
	 * for the same field.
	 */
	bgp = daemon_lookup_bgp(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bm->rmap_update_timer = yang_dnode_get_uint16(args->dnode, NULL);

	return NB_OK;
}

int bgp_global_gr_disable_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = daemon_lookup_bgp(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	/* Mirror bgp_inst_gr_config_vty(vty, bgp, on, disable=true). */
	ret = bgp_gr_update_all(bgp, yang_dnode_get_bool(args->dnode, NULL)
					     ? GLOBAL_DISABLE_CMD
					     : NO_GLOBAL_DISABLE_CMD);
	VTY_BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(bgp, bgp->peer, ret);

	return NB_OK;
}

int bgp_global_gr_disable_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = daemon_lookup_bgp(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	ret = bgp_gr_update_all(bgp, NO_GLOBAL_DISABLE_CMD);
	VTY_BGP_GR_ROUTER_DETECT_AND_SEND_CAPABILITY_TO_ZEBRA(bgp, bgp->peer, ret);

	return NB_OK;
}

int bgp_global_gr_disable_eor_modify(struct nb_cb_modify_args *args)
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

	bgp = daemon_lookup_bgp(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	COND_FLAG(bgp->flags, BGP_FLAG_GR_DISABLE_EOR, yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}

int bgp_global_local_as_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/* During instance creation the struct does not exist yet
		 * (create runs in APPLY); skip the check there and let
		 * APPLY enforce it.
		 */
		bgp = daemon_lookup_bgp(args->dnode, 3);
		if (bgp && yang_dnode_get_uint32(args->dnode, NULL) != bgp->as) {
			snprintfrr(args->errmsg, args->errmsg_len,
				   "instance AS is fixed at creation (current %u)", bgp->as);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = daemon_lookup_bgp(args->dnode, 3);
	if (!bgp)
		return NB_ERR;
	if (yang_dnode_get_uint32(args->dnode, NULL) != bgp->as) {
		snprintfrr(args->errmsg, args->errmsg_len,
			   "instance AS is fixed at creation (current %u)", bgp->as);
		return NB_ERR;
	}

	return NB_OK;
}

/* med-config leaves: no-op on purpose. The non-presence med-config
 * container carries the native bgp_global_med_config_apply_finish
 * that reads every leaf at commit time, so per-leaf callbacks would
 * duplicate (or race) that work.
 */
int bgp_global_med_admin_enable_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int bgp_global_med_admin_max_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int bgp_global_med_onstart_time_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int bgp_global_med_onstart_time_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int bgp_global_med_onstart_value_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

/* tcp-keepalive leaves under global-config-timers: no-op on purpose —
 * the container carries the native bgp_global_tcp_keepalive_apply_finish.
 */
int bgp_global_tcp_keepalive_idle_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int bgp_global_tcp_keepalive_idle_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int bgp_global_tcp_keepalive_interval_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int bgp_global_tcp_keepalive_interval_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int bgp_global_tcp_keepalive_probes_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int bgp_global_tcp_keepalive_probes_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/* ================================================================== */
/* Interface leaves (frr-interface:lib augment)                       */
/* ================================================================== */

int bgp_if_mpls_bgp_forwarding_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct bgp_interface *iifp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iifp = ifp->info;
	if (!iifp) {
		snprintfrr(args->errmsg, args->errmsg_len, "interface %s not available", ifp->name);
		return NB_ERR;
	}

	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (CHECK_FLAG(iifp->flags, BGP_INTERFACE_MPLS_BGP_FORWARDING) == enable)
		return NB_OK;

	COND_FLAG(iifp->flags, BGP_INTERFACE_MPLS_BGP_FORWARDING, enable);

	/* trigger a nht update on eBGP sessions */
	if (if_is_operative(ifp))
		bgp_nht_ifp_up(ifp);

	return NB_OK;
}

int bgp_if_mpls_l3vpn_multi_domain_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct bgp_interface *iifp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	iifp = ifp->info;
	if (!iifp) {
		snprintfrr(args->errmsg, args->errmsg_len, "interface %s not available", ifp->name);
		return NB_ERR;
	}

	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (CHECK_FLAG(iifp->flags, BGP_INTERFACE_MPLS_L3VPN_SWITCHING) == enable)
		return NB_OK;

	COND_FLAG(iifp->flags, BGP_INTERFACE_MPLS_L3VPN_SWITCHING, enable);

	if (if_is_operative(ifp))
		bgp_nht_ifp_up(ifp);

	return NB_OK;
}
