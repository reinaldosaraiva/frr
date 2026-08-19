#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate bgpd northbound stubs from a missing-callbacks TSV.

Input format (one line per missing callback):
    <op>\\t<xpath>

Where <op> is one of: create, modify, destroy, get_next, get_keys,
lookup_entry.

Output:
    bgpd/bgp_nb_stubs_table.inc -- nodes-table fragment, suitable for
        #include inside the .nodes = { ... } initializer of
        frr_bgp_info in bgpd/bgp_nb.c.

Each xpath is classified into one of two stub classes (the class
column, B3 O3 of NevoaSolutionsLtda/frr issue #17):

    core -- MGC-critical subtrees (EVPN, prefix-limit,
        redistribution-list, network-config). Config callbacks bind
        reject-strict stubs: a programmatic (non-CLI) commit fails
        validation with an explicit error instead of returning a
        false commit-OK.

    reject -- Fase D triage decision (see REJECT_POLICY): same
        reject-strict stubs as core, but the classification is a
        per-family policy decision rather than MGC criticality.

    warn -- everything else. Config callbacks bind no-op stubs that
        return NB_OK and emit an aggregated log warning for
        programmatic writes.

Oper callbacks (get_next, get_keys, lookup_entry) stay neutral no-ops
for both classes. The CLI dual-write path is exempt from rejection and
warning inside the stub implementations (bgpd/bgp_nb_stubs.c).

The stub function symbols themselves live in bgpd/bgp_nb_stubs.c and
are declared in bgpd/bgp_nb_stubs.h; this generator only emits the
table entries.

Idempotent: rerun whenever the YANG tree changes and the diff appears
in the .inc file.
"""
import collections
import os
import re
import sys

# Explicitly rejected subtrees (Fase D of the gRPC-100 track: the
# warn -> wired-ou-reject flip). A family lands here only after the
# triage slice classifies it as reject (no wiring scope); wired
# xpaths leave the table through tools/missing_cbs.tsv instead.
# Every entry records the slice that triaged it and the rationale,
# so the policy is reviewable in the git history of this file.
REJECT_POLICY = [
    # (xpath substring, triaged by, rationale)
    # R1: SRv6 + sem-consumidor (S063 fatia 3)
    ('sid-export/', 'S063', 'SRv6 SID export - sem consumidor no padrao MGC Router'),
    ('sid-vpn-export/', 'S063', 'SRv6 SID VPN export - sem consumidor no padrao MGC Router'),
    ('segment-routing/srv6', 'S063', 'SRv6 global - sem consumidor no padrao MGC Router'),
    ('sid-vpn-per-vrf-export/', 'S063', 'SRv6 per-VRF SID export - sem consumidor no padrao MGC Router'),
    ('snmp-traps/', 'S063', 'SNMP module so existe em build --enable-snmp; binario MGC sem consumidor'),
    ('hard-administrative-reset', 'S063', 'zero codigo em bgpd (grep vazio) - yang-only'),
    ('instance-type-view', 'S063', 'bgp_nb_config.c:109-114: caminho view nao suportado; wiring mentiria'),
]
REJECT_PATTERNS = [pat for pat, _slice, _why in REJECT_POLICY]

# Config ops overridden for the core class; oper ops fall back to the
# neutral stubs above.
CORE_OP_TO_CB = {
    "create": "bgp_nb_stub_reject_create",
    "modify": "bgp_nb_stub_reject_modify",
    "destroy": "bgp_nb_stub_reject_destroy",
}

# Neutral oper stubs: get/iter callbacks stay no-ops for every class.
NEUTRAL_OP_TO_CB = {
    "get_next": "bgp_nb_stub_get_next",
    "get_keys": "bgp_nb_stub_get_keys",
    "lookup_entry": "bgp_nb_stub_lookup_entry",
}

ALL_OPS = set(CORE_OP_TO_CB) | set(NEUTRAL_OP_TO_CB)

# MGC core subtrees (schema-xpath substrings). Verified against the
# current tree: "evpn" only matches l2vpn-evpn nodes, and no stubbed
# core node is an ancestor of a wired xpath (so rejecting create on
# core presence containers/lists cannot break wired leaves).
CORE_RE = re.compile(
    r"evpn|/prefix-limit|/redistribution-list|/network-config")


def classify(xpath: str) -> str:
    if CORE_RE.search(xpath):
        return "core"
    if any(pat in xpath for pat in REJECT_PATTERNS):
        return "reject"
    # warn path removed in S063: untriaged yang fails closed
    return "reject"


def main(tsv_path: str, out_path: str) -> int:
    by_xpath: dict[str, set[str]] = collections.defaultdict(set)
    with open(tsv_path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or not line.startswith(("create\t", "modify\t",
                                                "destroy\t", "get_next\t",
                                                "get_keys\t",
                                                "lookup_entry\t")):
                continue
            op, xpath = line.split("\t", 1)
            if op in ALL_OPS:
                by_xpath[xpath].add(op)

    if not by_xpath:
        print(f"no stub entries parsed from {tsv_path}", file=sys.stderr)
        return 1

    classes = {x: classify(x) for x in by_xpath}
    n_core = sum(1 for c in classes.values() if c == "core")
    n_reject = sum(1 for c in classes.values() if c == "reject")
    n_warn = len(by_xpath) - n_core - n_reject

    lines = []
    lines.append("/* SPDX-License-Identifier: GPL-2.0-or-later */")
    lines.append("/*")
    lines.append(" * Auto-generated by tools/gen-bgp-nb-stubs.py.")
    lines.append(" * Do not edit by hand. Regenerate by running:")
    lines.append(" *   python3 tools/gen-bgp-nb-stubs.py "
                 "tools/missing_cbs.tsv "
                 "bgpd/bgp_nb_stubs_table.inc")
    lines.append(" *")
    lines.append(" * Each entry binds a YANG node to stub callbacks so that")
    lines.append(" * nb_validate_callbacks() passes for the frr-bgp module")
    lines.append(" * tree. The trailing comment is the stub class column:")
    lines.append(" * core = reject-strict for programmatic clients,")
    lines.append(" * reject = reject-strict per the Fase D policy")
    lines.append(" *        (REJECT_POLICY in the generator),")
    lines.append(" * warn = NB_OK no-op with aggregated warning.")
    lines.append(f" * Current population: {n_core} core, "
                 f"{n_reject} reject, {n_warn} warn.")
    lines.append(" *")
    lines.append(" * Real handlers for any of these xpaths should be")
    lines.append(" * added to bgp_nb.c (above the #include of this file)")
    lines.append(" * and the corresponding line removed from this file or")
    lines.append(" * from tools/missing_cbs.tsv before regeneration.")
    lines.append(" */")
    lines.append("")
    for xpath in sorted(by_xpath):
        ops = by_xpath[xpath]
        klass = classify(xpath)
        cb_lines = []
        for op in sorted(ops):
            if op in CORE_OP_TO_CB:
                cb = CORE_OP_TO_CB[op]
            else:
                cb = NEUTRAL_OP_TO_CB[op]
            cb_lines.append(f".{op} = {cb},")
        cb_block = " ".join(cb_lines)
        lines.append(f'{{ .xpath = "{xpath}",')
        lines.append(f'  .cbs = {{ {cb_block} }} }}, /* class: {klass} */')

    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"wrote {out_path}: {len(by_xpath)} xpath stub entries "
          f"({n_core} core, {n_reject} reject, {n_warn} warn)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <missing_cbs.tsv> <out.inc>",
              file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
