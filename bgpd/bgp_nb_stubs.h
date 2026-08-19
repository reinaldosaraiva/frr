// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP northbound stubs — S063: warn path removed, reject-only.
 */
#ifndef _FRR_BGP_NB_STUBS_H
#define _FRR_BGP_NB_STUBS_H

#include "lib/northbound.h"

int bgp_nb_stub_reject_create(struct nb_cb_create_args *args);
int bgp_nb_stub_reject_modify(struct nb_cb_modify_args *args);
int bgp_nb_stub_reject_destroy(struct nb_cb_destroy_args *args);
const void *bgp_nb_stub_get_next(struct nb_cb_get_next_args *args);
int bgp_nb_stub_get_keys(struct nb_cb_get_keys_args *args);
const void *bgp_nb_stub_lookup_entry(struct nb_cb_lookup_entry_args *args);

#endif /* _FRR_BGP_NB_STUBS_H */
