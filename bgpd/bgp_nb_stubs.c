// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Northbound stub callbacks for the frr-bgp YANG tree.
 *
 * S063 (Fase D closeout): the warn class is dead. All stub entries
 * in bgp_nb_stubs_table.inc are reject-strict: programmatic (non-CLI)
 * writes fail commit validation with an explicit error.
 *
 * Classes (see the class column in bgp_nb_stubs_table.inc, assigned
 * by tools/gen-bgp-nb-stubs.py):
 *
 * - reject: Fase D triage decision (REJECT_POLICY in the generator).
 *   Config callbacks bind reject-strict stubs.
 *
 * Oper callbacks (get_next, get_keys, lookup_entry) stay neutral
 * no-ops for all classes.
 *
 * The CLI dual-write path (NB_CLIENT_CLI) is exempt from rejection:
 * the legacy DEFUN has already applied the change, and the NB write
 * only mirrors it into the YANG datastore.
 */
#include <zebra.h>

#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/yang.h"

#include "bgpd/bgp_nb_stubs.h"

static bool bgp_nb_stub_client_is_cli(const struct nb_context *context)
{
	return context && context->client == NB_CLIENT_CLI;
}

static int bgp_nb_stub_reject(const struct nb_context *context,
			      enum nb_event event,
			      const struct lyd_node *dnode, char *errmsg,
			      size_t errmsg_len)
{
	char xpath[XPATH_MAXLEN];

	if (bgp_nb_stub_client_is_cli(context))
		return NB_OK;
	if (event != NB_EV_VALIDATE)
		return NB_OK;

	yang_dnode_get_path(dnode, xpath, sizeof(xpath));
	snprintfrr(errmsg, errmsg_len, "unimplemented in bgpd northbound (reject class): %s",
		   xpath);
	return NB_ERR_VALIDATION;
}

int bgp_nb_stub_reject_create(struct nb_cb_create_args *args)
{
	return bgp_nb_stub_reject(args->context, args->event, args->dnode,
				  args->errmsg, args->errmsg_len);
}

int bgp_nb_stub_reject_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_stub_reject(args->context, args->event, args->dnode,
				  args->errmsg, args->errmsg_len);
}

int bgp_nb_stub_reject_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_nb_stub_reject(args->context, args->event, args->dnode,
				  args->errmsg, args->errmsg_len);
}

const void *bgp_nb_stub_get_next(struct nb_cb_get_next_args *args)
{
	return NULL;
}

int bgp_nb_stub_get_keys(struct nb_cb_get_keys_args *args)
{
	args->keys->num = 0;
	return NB_OK;
}

const void *bgp_nb_stub_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	return NULL;
}
