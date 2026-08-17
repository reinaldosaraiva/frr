// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Bridge between the core northbound bmp callbacks
 * (bgp_nb_config.c) and the optional bgpd_bmp module: the module
 * cannot be linked from the core daemon, so it publishes its
 * lookup/apply internals here at load time. The core callbacks fail
 * commits with an explicit error while the module is not loaded.
 */
#ifndef _FRR_BGP_NB_BMP_H
#define _FRR_BGP_NB_BMP_H

#include "bgpd/bgp_bmp.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * FRR never dlclose()s modules at runtime, so the pointers stay
 * valid once published; there is no unload counterpart by design.
 *
 * find_target/monitor_apply cover the bmp monitor leaves. The
 * remaining entries cover the bmp target-list lifecycle and one
 * apply per target-list knob: each apply holds the logic of the
 * matching CLI DEFUN so the datastore path and the dual-write CLI
 * path cannot drift apart. The int entries return 0 on success and
 * a negative code on failure; -1 means the referenced object does
 * not exist, except import_vrf_set, which uses -1..-4 (see its
 * comment: -1 is the own-instance rejection).
 */
/* defined in bgp_nb_config.c; filled by the bgpd_bmp module init */
struct bgp_nb_bmp_ops {
	struct bmp_targets *(*find_target)(struct bgp *bgp,
					   const char *name);
	void (*monitor_apply)(struct bmp_targets *bt, afi_t afi,
			      safi_t safi, uint8_t flag, bool enable);
	struct bmp_targets *(*get_target)(struct bgp *bgp,
					   const char *name);
	void (*put_target)(struct bmp_targets *bt);
	void (*mirror_limit_set)(struct bgp *bgp, unsigned long limit);
	void (*acl_set)(struct bmp_targets *bt, bool ipv6,
			const char *name);
	void (*mirror_set)(struct bmp_targets *bt, bool enable);
	void (*stats_interval_set)(struct bmp_targets *bt, uint32_t msec);
	void (*stats_experimental_set)(struct bmp_targets *bt,
				       bool enable);
	int (*import_vrf_set)(struct bmp_targets *bt, const char *vrfname,
			       bool enable);
	int (*listener_add)(struct bmp_targets *bt, const char *address,
			    uint16_t port);
	int (*listener_del)(struct bmp_targets *bt, const char *address,
			    uint16_t port);
	int (*connect_add)(struct bmp_targets *bt, const char *hostname,
			   uint16_t port);
	int (*connect_del)(struct bmp_targets *bt, const char *hostname,
			   uint16_t port);
	int (*connect_retry_set)(struct bmp_targets *bt,
				 const char *hostname, uint16_t port,
				 bool min_retry, uint32_t msec);
	int (*connect_srcif_set)(struct bmp_targets *bt,
				 const char *hostname, uint16_t port,
				 const char *ifname);
};

extern struct bgp_nb_bmp_ops bgp_nb_bmp_ops;

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_NB_BMP_H */
