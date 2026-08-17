// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP northbound — module registration, XPath macros, callback declarations.
 *
 * Copyright (C) 2026 FRRouting
 */

#ifndef _FRR_BGP_NB_H_
#define _FRR_BGP_NB_H_

#include "lib/northbound.h"
#include "lib/vrf.h"

#include "bgpd/bgpd.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_bgp_info;

#define BGP_INSTANCE_KEY_XPATH                                                 \
	"/frr-routing:routing/control-plane-protocols/"                        \
	"control-plane-protocol[type='%s'][name='%s'][vrf='%s']"

#define BGP_CONTAINER_XPATH	   BGP_INSTANCE_KEY_XPATH "/frr-bgp:bgp"
#define BGP_GLOBAL_XPATH	   BGP_CONTAINER_XPATH "/global"
#define BGP_GLOBAL_ROUTER_ID_XPATH BGP_GLOBAL_XPATH "/router-id"
#define BGP_NEIGHBORS_XPATH	   BGP_CONTAINER_XPATH "/neighbors"
#define BGP_NEIGHBOR_XPATH                                                     \
	BGP_NEIGHBORS_XPATH "/neighbor[remote-address='%s']"
#define BGP_UNNUMBERED_NEIGHBOR_XPATH                                           \
	BGP_NEIGHBORS_XPATH "/unnumbered-neighbor[interface='%s']"
#define BGP_PEER_GROUPS_XPATH	   BGP_CONTAINER_XPATH "/peer-groups"
#define BGP_PEER_GROUP_XPATH                                                   \
	BGP_PEER_GROUPS_XPATH "/peer-group[peer-group-name='%s']"

static inline const char *bgp_nb_cpp_name(const struct bgp *bgp)
{
	return (bgp->name && bgp->inst_type == BGP_INSTANCE_TYPE_VIEW)
		       ? bgp->name
		       : "bgp";
}

static inline const char *bgp_nb_vrf_key(const struct bgp *bgp)
{
	return (bgp->name && bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
		       ? bgp->name
		       : VRF_DEFAULT_NAME;
}

/* control-plane-protocol context */
int bgp_router_create(struct nb_cb_create_args *args);
int bgp_router_destroy(struct nb_cb_destroy_args *args);

/* global leaves */
int bgp_global_router_id_modify(struct nb_cb_modify_args *args);
int bgp_global_router_id_destroy(struct nb_cb_destroy_args *args);
int bgp_global_default_shutdown_modify(struct nb_cb_modify_args *args);
int bgp_global_default_shutdown_destroy(struct nb_cb_destroy_args *args);
int bgp_global_show_hostname_modify(struct nb_cb_modify_args *args);
int bgp_global_show_hostname_destroy(struct nb_cb_destroy_args *args);
int bgp_global_show_nexthop_hostname_modify(struct nb_cb_modify_args *args);
int bgp_global_show_nexthop_hostname_destroy(struct nb_cb_destroy_args *args);
int bgp_global_always_compare_med_modify(struct nb_cb_modify_args *args);
int bgp_global_always_compare_med_destroy(struct nb_cb_destroy_args *args);
int bgp_global_external_compare_router_id_modify(struct nb_cb_modify_args *args);
int bgp_global_external_compare_router_id_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_ignore_as_path_length_modify(struct nb_cb_modify_args *args);
int bgp_global_ignore_as_path_length_destroy(struct nb_cb_destroy_args *args);
int bgp_global_aspath_confed_modify(struct nb_cb_modify_args *args);
int bgp_global_aspath_confed_destroy(struct nb_cb_destroy_args *args);
int bgp_global_confed_med_modify(struct nb_cb_modify_args *args);
int bgp_global_confed_med_destroy(struct nb_cb_destroy_args *args);
int bgp_global_missing_as_worst_med_modify(struct nb_cb_modify_args *args);
int bgp_global_missing_as_worst_med_destroy(struct nb_cb_destroy_args *args);
int bgp_global_log_neighbor_changes_modify(struct nb_cb_modify_args *args);
int bgp_global_log_neighbor_changes_destroy(struct nb_cb_destroy_args *args);
int bgp_global_import_check_modify(struct nb_cb_modify_args *args);
int bgp_global_import_check_destroy(struct nb_cb_destroy_args *args);
int bgp_global_wpkt_quanta_modify(struct nb_cb_modify_args *args);
int bgp_global_wpkt_quanta_destroy(struct nb_cb_destroy_args *args);
int bgp_global_rpkt_quanta_modify(struct nb_cb_modify_args *args);
int bgp_global_rpkt_quanta_destroy(struct nb_cb_destroy_args *args);
int bgp_global_coalesce_time_modify(struct nb_cb_modify_args *args);
int bgp_global_coalesce_time_destroy(struct nb_cb_destroy_args *args);
int bgp_global_subgroup_pkt_queue_size_modify(struct nb_cb_modify_args *args);
int bgp_global_subgroup_pkt_queue_size_destroy(struct nb_cb_destroy_args *args);
int bgp_global_confederation_identifier_modify(struct nb_cb_modify_args *args);
int bgp_global_confederation_identifier_destroy(struct nb_cb_destroy_args *args);
int bgp_global_confederation_member_as_create(struct nb_cb_create_args *args);
int bgp_global_confederation_member_as_destroy(struct nb_cb_destroy_args *args);
int bgp_global_minimum_holdtime_modify(struct nb_cb_modify_args *args);
int bgp_global_minimum_holdtime_destroy(struct nb_cb_destroy_args *args);
int bgp_global_allow_martian_nexthop_modify(struct nb_cb_modify_args *args);
int bgp_global_allow_martian_nexthop_destroy(struct nb_cb_destroy_args *args);
int bgp_global_use_underlays_nexthop_weight_modify(
	struct nb_cb_modify_args *args);
int bgp_global_use_underlays_nexthop_weight_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_route_reflector_allow_outbound_policy_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_reflector_allow_outbound_policy_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_bgp_ls_distribute_create(struct nb_cb_create_args *args);
int bgp_global_bgp_ls_distribute_destroy(struct nb_cb_destroy_args *args);
int bgp_global_bgp_ls_distribute_instance_id_modify(
	struct nb_cb_modify_args *args);
int bgp_global_af_redistribution_list_create(struct nb_cb_create_args *args);
int bgp_global_af_redistribution_list_destroy(struct nb_cb_destroy_args *args);
int bgp_global_af_network_config_create(struct nb_cb_create_args *args);
int bgp_global_af_network_config_destroy(struct nb_cb_destroy_args *args);
int bgp_global_af_network_backdoor_modify(struct nb_cb_modify_args *args);
int bgp_global_af_network_label_modify(struct nb_cb_modify_args *args);
int bgp_global_af_network_label_destroy(struct nb_cb_destroy_args *args);
int bgp_global_af_network_rmap_modify(struct nb_cb_modify_args *args);
int bgp_global_af_network_rmap_destroy(struct nb_cb_destroy_args *args);
int bgp_global_af_network_pl_create(struct nb_cb_create_args *args);
int bgp_global_af_network_pl_destroy(struct nb_cb_destroy_args *args);
int bgp_global_af_network_pl_label_modify(struct nb_cb_modify_args *args);
int bgp_global_af_network_pl_rmap_modify(struct nb_cb_modify_args *args);
int bgp_global_af_network_pl_rmap_destroy(struct nb_cb_destroy_args *args);
int bgp_global_af_redistribution_metric_modify(struct nb_cb_modify_args *args);
int bgp_global_af_redistribution_metric_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_af_redistribution_rmap_modify(struct nb_cb_modify_args *args);
int bgp_global_af_redistribution_rmap_destroy(struct nb_cb_destroy_args *args);
int bgp_global_bestpath_aigp_modify(struct nb_cb_modify_args *args);
int bgp_global_bestpath_aigp_destroy(struct nb_cb_destroy_args *args);
int bgp_global_bestpath_use_imported_attributes_modify(
	struct nb_cb_modify_args *args);
int bgp_global_bestpath_use_imported_attributes_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_dynamic_neighbors_limit_modify(struct nb_cb_modify_args *args);
int bgp_global_dynamic_neighbors_limit_destroy(struct nb_cb_destroy_args *args);
void bgp_global_med_config_apply_finish(struct nb_cb_apply_finish_args *args);
int bgp_global_med_config_destroy(struct nb_cb_destroy_args *args);
int bgp_global_default_software_version_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_global_default_software_version_capability_destroy(
	struct nb_cb_destroy_args *args);
void bgp_global_tcp_keepalive_apply_finish(struct nb_cb_apply_finish_args *args);
int bgp_global_hold_time_modify(struct nb_cb_modify_args *args);
int bgp_global_hold_time_destroy(struct nb_cb_destroy_args *args);
int bgp_global_keepalive_modify(struct nb_cb_modify_args *args);
int bgp_global_keepalive_destroy(struct nb_cb_destroy_args *args);
int bgp_global_reject_as_sets_modify(struct nb_cb_modify_args *args);
int bgp_global_reject_as_sets_destroy(struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_enabled_modify(struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_enabled_destroy(struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_restart_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_restart_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_selection_deferral_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_selection_deferral_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_shutdown_modify(struct nb_cb_modify_args *args);
int bgp_global_shutdown_message_modify(struct nb_cb_modify_args *args);
int bgp_global_shutdown_message_destroy(struct nb_cb_destroy_args *args);
int bgp_global_enforce_first_as_global_modify(struct nb_cb_modify_args *args);
int bgp_global_enforce_first_as_global_destroy(struct nb_cb_destroy_args *args);
int bgp_global_suppress_duplicates_modify(struct nb_cb_modify_args *args);
int bgp_global_suppress_duplicates_destroy(struct nb_cb_destroy_args *args);
int bgp_global_ebgp_requires_policy_modify(struct nb_cb_modify_args *args);
int bgp_global_ebgp_requires_policy_destroy(struct nb_cb_destroy_args *args);
int bgp_global_fast_external_failover_modify(struct nb_cb_modify_args *args);
int bgp_global_fast_external_failover_destroy(struct nb_cb_destroy_args *args);
int bgp_global_deterministic_med_modify(struct nb_cb_modify_args *args);
int bgp_global_deterministic_med_destroy(struct nb_cb_destroy_args *args);
int bgp_global_labeled_unicast_explicit_null_modify(
	struct nb_cb_modify_args *args);
int bgp_global_labeled_unicast_explicit_null_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_ipv6_auto_ra_modify(struct nb_cb_modify_args *args);
int bgp_global_ipv6_auto_ra_destroy(struct nb_cb_destroy_args *args);
int bgp_global_allow_multiple_as_modify(struct nb_cb_modify_args *args);
int bgp_global_allow_multiple_as_destroy(struct nb_cb_destroy_args *args);
int bgp_global_multi_path_as_set_modify(struct nb_cb_modify_args *args);
int bgp_global_multi_path_as_set_destroy(struct nb_cb_destroy_args *args);
int bgp_global_peer_type_multipath_relax_modify(struct nb_cb_modify_args *args);
int bgp_global_peer_type_multipath_relax_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_graceful_shutdown_enable_modify(struct nb_cb_modify_args *args);
int bgp_global_graceful_shutdown_enable_destroy(struct nb_cb_destroy_args *args);
int bgp_global_suppress_fib_pending_modify(struct nb_cb_modify_args *args);
int bgp_global_suppress_fib_pending_delay_modify(
	struct nb_cb_modify_args *args);
int bgp_global_suppress_fib_pending_delay_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_advertisement_delay_global_modify(
	struct nb_cb_modify_args *args);
int bgp_global_advertisement_delay_global_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_update_delay_time_modify(struct nb_cb_modify_args *args);
int bgp_global_update_delay_time_destroy(struct nb_cb_destroy_args *args);
int bgp_global_establish_wait_time_modify(struct nb_cb_modify_args *args);
int bgp_global_establish_wait_time_destroy(struct nb_cb_destroy_args *args);
int bgp_global_connect_retry_interval_modify(struct nb_cb_modify_args *args);
int bgp_global_connect_retry_interval_destroy(struct nb_cb_destroy_args *args);
int bgp_global_conditional_advertisement_period_modify(
	struct nb_cb_modify_args *args);
int bgp_global_conditional_advertisement_period_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_default_originate_timer_modify(struct nb_cb_modify_args *args);
int bgp_global_default_originate_timer_destroy(struct nb_cb_destroy_args *args);
int bgp_global_bestpath_bandwidth_modify(struct nb_cb_modify_args *args);
int bgp_global_bestpath_bandwidth_destroy(struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_notification_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_notification_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_long_lived_graceful_restart_stale_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_long_lived_graceful_restart_stale_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_fast_convergence_modify(struct nb_cb_modify_args *args);
int bgp_global_fast_convergence_destroy(struct nb_cb_destroy_args *args);
int bgp_global_default_link_local_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_global_default_link_local_capability_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_default_dynamic_capability_modify(
	struct nb_cb_modify_args *args);
int bgp_global_default_dynamic_capability_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_route_reflector_cluster_id_modify(
	struct nb_cb_modify_args *args);
int bgp_global_route_reflector_cluster_id_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_no_client_reflect_modify(struct nb_cb_modify_args *args);
int bgp_global_no_client_reflect_destroy(struct nb_cb_destroy_args *args);
int bgp_global_local_pref_modify(struct nb_cb_modify_args *args);
int bgp_global_local_pref_destroy(struct nb_cb_destroy_args *args);
int bgp_global_ebgp_multihop_connected_route_check_modify(
	struct nb_cb_modify_args *args);
int bgp_global_ebgp_multihop_connected_route_check_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_rib_stale_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_rib_stale_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_preserve_fw_entry_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_preserve_fw_entry_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_graceful_restart_stale_routes_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_graceful_restart_stale_routes_time_destroy(
	struct nb_cb_destroy_args *args);

/* neighbor list + per-peer leaves */
int bgp_neighbor_create(struct nb_cb_create_args *args);
int bgp_neighbor_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_remote_as_type_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_remote_as_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_remote_as_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_password_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_password_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_description_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_description_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_passive_mode_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_passive_mode_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_solo_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_solo_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_enforce_first_as_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_enforce_first_as_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_ttl_security_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_ttl_security_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_admin_shutdown_enable_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_admin_shutdown_enable_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_admin_shutdown_message_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_admin_shutdown_message_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_ebgp_multihop_enabled_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_ebgp_multihop_enabled_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_ebgp_multihop_ttl_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_ebgp_multihop_ttl_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_ebgp_multihop_disable_connected_check_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_ebgp_multihop_disable_connected_check_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_update_source_ip_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_update_source_ip_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_update_source_interface_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_update_source_interface_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_timers_connect_time_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_timers_connect_time_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_timers_advertise_interval_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_timers_advertise_interval_destroy(
	struct nb_cb_destroy_args *args);
void bgp_neighbor_local_as_apply_finish(struct nb_cb_apply_finish_args *args);
int bgp_neighbor_local_as_destroy(struct nb_cb_destroy_args *args);
void bgp_neighbor_bfd_options_apply_finish(struct nb_cb_apply_finish_args *args);
int bgp_neighbor_bfd_options_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_capabilities_dynamic_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_capabilities_dynamic_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_capabilities_strict_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_capabilities_strict_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_capabilities_override_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_capabilities_override_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_capabilities_extended_nexthop_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_capabilities_extended_nexthop_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_capabilities_negotiate_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_capabilities_negotiate_destroy(struct nb_cb_destroy_args *args);

/* per-peer boolean leaves driven through peer_flag_toggle_*. */
#define _BGP_NB_PEER_FLAG_DECL(_name)                                          \
	int bgp_neighbor_##_name##_modify(struct nb_cb_modify_args *args);     \
	int bgp_neighbor_##_name##_destroy(struct nb_cb_destroy_args *args)
_BGP_NB_PEER_FLAG_DECL(aigp);
_BGP_NB_PEER_FLAG_DECL(ip_transparent);
_BGP_NB_PEER_FLAG_DECL(extended_link_bandwidth);
_BGP_NB_PEER_FLAG_DECL(disable_link_bw_encoding_ieee);
_BGP_NB_PEER_FLAG_DECL(extended_optional_parameters);
_BGP_NB_PEER_FLAG_DECL(send_nexthop_characteristics);
_BGP_NB_PEER_FLAG_DECL(rpki_strict);
_BGP_NB_PEER_FLAG_DECL(capability_fqdn);
_BGP_NB_PEER_FLAG_DECL(capability_link_local);
_BGP_NB_PEER_FLAG_DECL(as_loop_detection);
_BGP_NB_PEER_FLAG_DECL(capability_software_version);
_BGP_NB_PEER_FLAG_DECL(peer_graceful_shutdown);
#undef _BGP_NB_PEER_FLAG_DECL

int bgp_neighbor_timers_delayopen_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_timers_delayopen_destroy(struct nb_cb_destroy_args *args);
void bgp_neighbor_admin_shutdown_apply_finish(
	struct nb_cb_apply_finish_args *args);
int bgp_neighbor_admin_shutdown_rtt_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_tcp_mss_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_tcp_mss_destroy(struct nb_cb_destroy_args *args);
void bgp_neighbor_local_role_apply_finish(struct nb_cb_apply_finish_args *args);
int bgp_neighbor_local_role_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_gr_enable_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_gr_enable_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_gr_helper_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_gr_helper_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_gr_disable_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_gr_disable_destroy(struct nb_cb_destroy_args *args);
void bgp_neighbor_timers_apply_finish(struct nb_cb_apply_finish_args *args);
int bgp_neighbor_timers_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_oad_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_oad_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_ls_local_link_id_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_ls_local_link_id_destroy(struct nb_cb_destroy_args *args);
int bgp_neighbor_ls_remote_link_id_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_ls_remote_link_id_destroy(struct nb_cb_destroy_args *args);

/* per-AF flag toggles */
#define _BGP_NB_PEER_AF_FLAG_DECL(_name)                                       \
	int bgp_neighbor_af_##_name##_modify(struct nb_cb_modify_args *args);  \
	int bgp_neighbor_af_##_name##_destroy(struct nb_cb_destroy_args *args)
_BGP_NB_PEER_AF_FLAG_DECL(soft_reconfig_in);
_BGP_NB_PEER_AF_FLAG_DECL(as_override);
_BGP_NB_PEER_AF_FLAG_DECL(rr_client);
_BGP_NB_PEER_AF_FLAG_DECL(rs_client);
_BGP_NB_PEER_AF_FLAG_DECL(nexthop_self);
_BGP_NB_PEER_AF_FLAG_DECL(nexthop_self_force);
_BGP_NB_PEER_AF_FLAG_DECL(remove_private_as);
_BGP_NB_PEER_AF_FLAG_DECL(remove_private_as_all);
_BGP_NB_PEER_AF_FLAG_DECL(remove_private_as_replace);
_BGP_NB_PEER_AF_FLAG_DECL(remove_private_as_all_replace);
_BGP_NB_PEER_AF_FLAG_DECL(nexthop_local_unchanged);
_BGP_NB_PEER_AF_FLAG_DECL(send_community);
_BGP_NB_PEER_AF_FLAG_DECL(send_ext_community);
_BGP_NB_PEER_AF_FLAG_DECL(send_large_community);
_BGP_NB_PEER_AF_FLAG_DECL(accept_own);
_BGP_NB_PEER_AF_FLAG_DECL(disable_addpath_rx);
int bgp_neighbor_af_add_paths_path_type_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_af_add_paths_path_type_destroy(
	struct nb_cb_destroy_args *args);
_BGP_NB_PEER_AF_FLAG_DECL(enabled);
int bgp_neighbor_af_encapsulation_type_create(struct nb_cb_create_args *args);
int bgp_neighbor_af_encapsulation_type_destroy(
	struct nb_cb_destroy_args *args);
_BGP_NB_PEER_AF_FLAG_DECL(attr_unchanged_as_path);
_BGP_NB_PEER_AF_FLAG_DECL(attr_unchanged_next_hop);
_BGP_NB_PEER_AF_FLAG_DECL(attr_unchanged_med);
_BGP_NB_PEER_AF_FLAG_DECL(rmap_import);
_BGP_NB_PEER_AF_FLAG_DECL(rmap_export);
_BGP_NB_PEER_AF_FLAG_DECL(upa);
#undef _BGP_NB_PEER_AF_FLAG_DECL

/* prefix-limit (shared across neighbor/unnumbered/peer-group) */
int bgp_peer_af_prefix_limit_create(struct nb_cb_create_args *args);
int bgp_peer_af_prefix_limit_destroy(struct nb_cb_destroy_args *args);
int bgp_peer_af_prefix_limit_max_modify(struct nb_cb_modify_args *args);
int bgp_peer_af_prefix_limit_force_modify(struct nb_cb_modify_args *args);

/* per-AF neighbor fanout (l2vpn-evpn S059; shared across the three
 * neighbor contexts)
 */
int bgp_neighbor_af_addpath_rx_limit_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_addpath_rx_limit_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_addpath_best_selected_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_addpath_best_selected_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_allow_own_as_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_af_allow_own_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_allow_own_origin_as_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_allow_own_origin_as_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_allowas_in_route_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_allowas_in_route_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_cond_adv_advertise_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_cond_adv_advertise_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_cond_adv_exist_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_cond_adv_exist_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_cond_adv_non_exist_map_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_cond_adv_non_exist_map_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_access_list_import_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_access_list_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_access_list_export_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_access_list_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_as_path_filter_import_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_as_path_filter_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_as_path_filter_export_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_as_path_filter_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_plist_import_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_plist_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_plist_export_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_plist_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_unsuppress_map_import_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_unsuppress_map_import_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_unsuppress_map_export_modify(
	struct nb_cb_modify_args *args);
int bgp_neighbor_af_unsuppress_map_export_destroy(
	struct nb_cb_destroy_args *args);
int bgp_neighbor_af_soo_modify(struct nb_cb_modify_args *args);
int bgp_neighbor_af_soo_destroy(struct nb_cb_destroy_args *args);
int bgp_peer_af_prefix_limit_option_modify(
	struct nb_cb_modify_args *args);
int bgp_peer_af_prefix_limit_option_destroy(
	struct nb_cb_destroy_args *args);
const char *bgp_nb_af_yang_name(afi_t afi, safi_t safi);

/* peer-group */
int bgp_peer_group_create(struct nb_cb_create_args *args);
int bgp_peer_group_destroy(struct nb_cb_destroy_args *args);
int bgp_peer_group_ipv4_listen_range_create(struct nb_cb_create_args *args);
int bgp_peer_group_ipv4_listen_range_destroy(struct nb_cb_destroy_args *args);
int bgp_peer_group_ipv6_listen_range_create(struct nb_cb_create_args *args);
int bgp_peer_group_ipv6_listen_range_destroy(struct nb_cb_destroy_args *args);

/* cli_show emitters */
#define _BGP_CLI(_n)                                                           \
	void _n##_cli_show(struct vty *, const struct lyd_node *, bool)

_BGP_CLI(bgp_global_router_id);
_BGP_CLI(bgp_global_default_shutdown);
_BGP_CLI(bgp_global_log_neighbor_changes);
_BGP_CLI(bgp_global_fast_convergence);
_BGP_CLI(bgp_global_allow_martian_nexthop);
_BGP_CLI(bgp_global_deterministic_med);
_BGP_CLI(bgp_global_always_compare_med);
_BGP_CLI(bgp_global_import_check);
_BGP_CLI(bgp_global_suppress_duplicates);
_BGP_CLI(bgp_global_reject_as_sets);
_BGP_CLI(bgp_global_ebgp_requires_policy);
_BGP_CLI(bgp_global_show_hostname);
_BGP_CLI(bgp_global_show_nexthop_hostname);
_BGP_CLI(bgp_global_graceful_shutdown);
_BGP_CLI(bgp_global_no_client_to_client_reflection);
_BGP_CLI(bgp_global_cluster_id_self);
_BGP_CLI(bgp_global_disable_ebgp_connected_route_check);
_BGP_CLI(bgp_global_enforce_first_as_global);
_BGP_CLI(bgp_global_default_link_local_capability);
_BGP_CLI(bgp_global_default_dynamic_capability);
_BGP_CLI(bgp_global_use_underlays_nexthop_weight);
_BGP_CLI(bgp_global_peer_type_multipath_relax);
_BGP_CLI(bgp_global_ipv6_auto_ra);
_BGP_CLI(bgp_global_coalesce_time);
_BGP_CLI(bgp_global_subgroup_pkt_queue_size);
_BGP_CLI(bgp_global_wpkt_quanta);
_BGP_CLI(bgp_global_rpkt_quanta);
_BGP_CLI(bgp_global_minimum_holdtime);
_BGP_CLI(bgp_global_dynamic_neighbors_limit);
_BGP_CLI(bgp_global_advertisement_delay_global);
_BGP_CLI(bgp_global_update_delay_time);
_BGP_CLI(bgp_global_restart_time);
_BGP_CLI(bgp_global_selection_deferral_time);
_BGP_CLI(bgp_global_external_compare_router_id);
_BGP_CLI(bgp_global_ignore_as_path_length);
_BGP_CLI(bgp_global_aspath_confed);
_BGP_CLI(bgp_global_confed_med);
_BGP_CLI(bgp_global_missing_as_worst_med);
_BGP_CLI(bgp_global_bestpath_aigp);
_BGP_CLI(bgp_global_bestpath_use_imported_attributes);
_BGP_CLI(bgp_global_allow_multiple_as);
_BGP_CLI(bgp_global_multi_path_as_set);
_BGP_CLI(bgp_global_confederation_identifier);
_BGP_CLI(bgp_global_confederation_member_as);
_BGP_CLI(bgp_global_fast_external_failover);
_BGP_CLI(bgp_global_labeled_unicast_explicit_null);
_BGP_CLI(bgp_global_allow_outbound_policy);
_BGP_CLI(bgp_global_instance_id);
_BGP_CLI(bgp_global_default_software_version_capability);
_BGP_CLI(bgp_global_establish_wait_time);
_BGP_CLI(bgp_global_connect_retry_interval);
_BGP_CLI(bgp_global_conditional_advertisement_period);
_BGP_CLI(bgp_global_default_originate_timer);
_BGP_CLI(bgp_global_bestpath_bandwidth);
_BGP_CLI(bgp_global_graceful_restart_notification);
_BGP_CLI(bgp_global_long_lived_graceful_restart_stale_time);
_BGP_CLI(bgp_global_route_reflector_cluster_id);
_BGP_CLI(bgp_global_no_client_reflect);
_BGP_CLI(bgp_global_local_pref);
_BGP_CLI(bgp_global_ebgp_multihop_connected_route_check);
_BGP_CLI(bgp_global_rib_stale_time);
_BGP_CLI(bgp_global_preserve_fw_entry);
_BGP_CLI(bgp_global_stale_routes_time);
_BGP_CLI(bgp_global_med_config);
_BGP_CLI(bgp_global_tcp_keepalive);
_BGP_CLI(bgp_global_shutdown);
_BGP_CLI(bgp_global_suppress_fib_pending);
_BGP_CLI(bgp_global_bgp_ls_distribute);
_BGP_CLI(bgp_global_af_redistribution_list);

_BGP_CLI(bgp_neighbor_passive_mode);
_BGP_CLI(bgp_neighbor_solo);
_BGP_CLI(bgp_neighbor_enforce_first_as);
_BGP_CLI(bgp_neighbor_description);
_BGP_CLI(bgp_neighbor_password);
_BGP_CLI(bgp_neighbor_aigp);
_BGP_CLI(bgp_neighbor_ip_transparent);
_BGP_CLI(bgp_neighbor_extended_link_bandwidth);
_BGP_CLI(bgp_neighbor_disable_link_bw_encoding_ieee);
_BGP_CLI(bgp_neighbor_extended_optional_parameters);
_BGP_CLI(bgp_neighbor_send_nexthop_characteristics);
_BGP_CLI(bgp_neighbor_rpki_strict);
_BGP_CLI(bgp_neighbor_capability_fqdn);
_BGP_CLI(bgp_neighbor_capability_link_local);
_BGP_CLI(bgp_neighbor_as_loop_detection);
_BGP_CLI(bgp_neighbor_oad);
_BGP_CLI(bgp_neighbor_peer_graceful_shutdown);
_BGP_CLI(bgp_neighbor_local_as);
_BGP_CLI(bgp_neighbor_timers);
_BGP_CLI(bgp_neighbor_local_role);
_BGP_CLI(bgp_neighbor_admin_shutdown);
_BGP_CLI(bgp_neighbor_ebgp_multihop);
_BGP_CLI(bgp_neighbor_ttl_security);
_BGP_CLI(bgp_neighbor_tcp_mss);
_BGP_CLI(bgp_neighbor_timers_delayopen);
_BGP_CLI(bgp_neighbor_ls_local_link_id);
_BGP_CLI(bgp_neighbor_ls_remote_link_id);
_BGP_CLI(bgp_neighbor_admin_shutdown);
_BGP_CLI(bgp_neighbor_neighbor_remote_as);
_BGP_CLI(bgp_neighbor_update_source);
_BGP_CLI(bgp_neighbor_capabilities_dynamic);
_BGP_CLI(bgp_neighbor_capabilities_strict);
_BGP_CLI(bgp_neighbor_capabilities_override);
_BGP_CLI(bgp_neighbor_capabilities_extended_nexthop);
_BGP_CLI(bgp_neighbor_capabilities_negotiate);
_BGP_CLI(bgp_neighbor_bfd_options);
_BGP_CLI(bgp_neighbor_gr_enable);
_BGP_CLI(bgp_neighbor_gr_helper);
_BGP_CLI(bgp_neighbor_gr_disable);
_BGP_CLI(bgp_neighbor_capability_software_version);

_BGP_CLI(bgp_neighbor_af_soft_reconfig_in);
_BGP_CLI(bgp_neighbor_af_as_override);
_BGP_CLI(bgp_neighbor_af_rr_client);
_BGP_CLI(bgp_neighbor_af_rs_client);
_BGP_CLI(bgp_neighbor_af_nexthop_self);
_BGP_CLI(bgp_neighbor_af_nexthop_self_force);
_BGP_CLI(bgp_neighbor_af_remove_private_as);
_BGP_CLI(bgp_neighbor_af_remove_private_as_all);
_BGP_CLI(bgp_neighbor_af_remove_private_as_replace);
_BGP_CLI(bgp_neighbor_af_remove_private_as_all_replace);
_BGP_CLI(bgp_neighbor_af_nexthop_local_unchanged);
_BGP_CLI(bgp_neighbor_af_send_community);
_BGP_CLI(bgp_neighbor_af_send_ext_community);
_BGP_CLI(bgp_neighbor_af_send_large_community);
_BGP_CLI(bgp_neighbor_af_accept_own);
_BGP_CLI(bgp_neighbor_af_disable_addpath_rx);
_BGP_CLI(bgp_neighbor_af_add_paths_path_type);
_BGP_CLI(bgp_neighbor_af_rmap_import);
_BGP_CLI(bgp_neighbor_af_rmap_export);
_BGP_CLI(bgp_neighbor_af_upa);
_BGP_CLI(bgp_neighbor_af_addpath_rx_limit);
_BGP_CLI(bgp_neighbor_af_addpath_best_selected);
_BGP_CLI(bgp_neighbor_af_allow_own_as);
_BGP_CLI(bgp_neighbor_af_allow_own_origin_as);
_BGP_CLI(bgp_neighbor_af_allowas_in_route_map);
_BGP_CLI(bgp_neighbor_af_cond_adv_advertise_map);
_BGP_CLI(bgp_neighbor_af_cond_adv_exist_map);
_BGP_CLI(bgp_neighbor_af_cond_adv_non_exist_map);
_BGP_CLI(bgp_neighbor_af_access_list_import);
_BGP_CLI(bgp_neighbor_af_access_list_export);
_BGP_CLI(bgp_neighbor_af_as_path_filter_import);
_BGP_CLI(bgp_neighbor_af_as_path_filter_export);
_BGP_CLI(bgp_neighbor_af_plist_import);
_BGP_CLI(bgp_neighbor_af_plist_export);
_BGP_CLI(bgp_neighbor_af_unsuppress_map_import);
_BGP_CLI(bgp_neighbor_af_unsuppress_map_export);
_BGP_CLI(bgp_neighbor_af_soo);
_BGP_CLI(bgp_peer_af_prefix_limit_max);
_BGP_CLI(bgp_global_af_network_config);
_BGP_CLI(bgp_global_af_network_pl);


_BGP_CLI(bgp_peer_group);
_BGP_CLI(bgp_peer_group_ipv4_listen_range);
_BGP_CLI(bgp_peer_group_ipv6_listen_range);

#undef _BGP_CLI

/*
 * No-op cli_show for leaves whose parent container emitter renders the
 * full compound CLI block (e.g. timers, local-as, admin-shutdown).
 * Wired against every child leaf to avoid duplicate emission.
 */
void bgp_nb_handled_by_parent_cli_show(struct vty *, const struct lyd_node *,
				       bool);


/* EVPN global (l2vpn-evpn) — Fase C fatia 1 */
int bgp_global_evpn_advertise_all_vni_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_advertise_default_gw_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_advertise_svi_ip_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_autort_rfc8365_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_default_originate_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_resolve_overlay_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_flooding_modify(struct nb_cb_modify_args *args);
int bgp_global_evpn_soo_modify(struct nb_cb_modify_args *args);
int bgp_global_evpn_soo_destroy(struct nb_cb_destroy_args *args);
int bgp_global_evpn_dad_modify(struct nb_cb_modify_args *args);
int bgp_global_evpn_dad_freeze_time_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_dad_freeze_time_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_evpn_dad_freeze_permanent_create(
	struct nb_cb_create_args *args);
int bgp_global_evpn_dad_freeze_permanent_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_evpn_use_es_l3nhg_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_ead_evi_rx_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_ead_evi_tx_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_ead_es_frag_limit_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_ead_es_frag_limit_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_evpn_ead_es_rt_create(
	struct nb_cb_create_args *args);
int bgp_global_evpn_ead_es_rt_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_evpn_pip_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_pip_ip_modify(struct nb_cb_modify_args *args);
int bgp_global_evpn_pip_ip_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_evpn_pip_mac_modify(struct nb_cb_modify_args *args);
int bgp_global_evpn_pip_mac_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_evpn_vrf_rd_modify(struct nb_cb_modify_args *args);
int bgp_global_evpn_vrf_rd_destroy(struct nb_cb_destroy_args *args);
int bgp_global_evpn_vrf_rt_create(struct nb_cb_create_args *args);
int bgp_global_evpn_vrf_rt_destroy(struct nb_cb_destroy_args *args);
int bgp_global_evpn_vrf_rt_auto_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_t5_enable_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_t5_gateway_ip_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_t5_gateway_ip_destroy(
	struct nb_cb_destroy_args *args);
int bgp_global_evpn_t5_rmap_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_t5_rmap_destroy(struct nb_cb_destroy_args *args);
int bgp_global_evpn_vni_create(struct nb_cb_create_args *args);
int bgp_global_evpn_vni_destroy(struct nb_cb_destroy_args *args);
int bgp_global_evpn_vni_rd_modify(struct nb_cb_modify_args *args);
int bgp_global_evpn_vni_rd_destroy(struct nb_cb_destroy_args *args);
int bgp_global_evpn_vni_rt_create(struct nb_cb_create_args *args);
int bgp_global_evpn_vni_rt_destroy(struct nb_cb_destroy_args *args);
int bgp_global_evpn_vni_adv_gw_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_vni_adv_svi_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_vni_adv_subnet_modify(
	struct nb_cb_modify_args *args);
int bgp_global_evpn_vni_flooding_modify(
	struct nb_cb_modify_args *args);

int bgp_bmp_monitor_pre_policy_modify(struct nb_cb_modify_args *args);
int bgp_bmp_monitor_post_policy_modify(struct nb_cb_modify_args *args);
int bgp_bmp_monitor_loc_rib_modify(struct nb_cb_modify_args *args);

int bgp_bmp_target_list_create(struct nb_cb_create_args *args);
int bgp_bmp_target_list_destroy(struct nb_cb_destroy_args *args);
int bgp_bmp_af_list_create(struct nb_cb_create_args *args);
int bgp_bmp_af_list_destroy(struct nb_cb_destroy_args *args);
int bgp_bmp_mirror_buffer_limit_modify(struct nb_cb_modify_args *args);
int bgp_bmp_mirror_buffer_limit_destroy(struct nb_cb_destroy_args *args);
int bgp_bmp_import_vrf_create(struct nb_cb_create_args *args);
int bgp_bmp_import_vrf_destroy(struct nb_cb_destroy_args *args);
int bgp_bmp_listener_create(struct nb_cb_create_args *args);
int bgp_bmp_listener_destroy(struct nb_cb_destroy_args *args);
int bgp_bmp_connect_create(struct nb_cb_create_args *args);
int bgp_bmp_connect_destroy(struct nb_cb_destroy_args *args);
int bgp_bmp_connect_min_retry_modify(struct nb_cb_modify_args *args);
int bgp_bmp_connect_max_retry_modify(struct nb_cb_modify_args *args);
int bgp_bmp_connect_srcif_modify(struct nb_cb_modify_args *args);
int bgp_bmp_connect_srcif_destroy(struct nb_cb_destroy_args *args);
int bgp_bmp_ipv4_acl_modify(struct nb_cb_modify_args *args);
int bgp_bmp_ipv4_acl_destroy(struct nb_cb_destroy_args *args);
int bgp_bmp_ipv6_acl_modify(struct nb_cb_modify_args *args);
int bgp_bmp_ipv6_acl_destroy(struct nb_cb_destroy_args *args);
int bgp_bmp_mirror_modify(struct nb_cb_modify_args *args);
int bgp_bmp_stats_time_modify(struct nb_cb_modify_args *args);
int bgp_bmp_stats_time_destroy(struct nb_cb_destroy_args *args);
int bgp_bmp_stats_experimental_modify(struct nb_cb_modify_args *args);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_NB_H_ */

