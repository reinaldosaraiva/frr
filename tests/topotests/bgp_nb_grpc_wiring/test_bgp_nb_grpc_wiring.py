# SPDX-License-Identifier: ISC
"""
Verifies the Fase B fatia 1 northbound wiring in bgpd: the prefix-limit
subtree (peer_maximum_prefix_* internals) and the network-config
subtree (bgp_static_* internals) become programmable through the mgmtd
gRPC bridge.

RED on the base trunk (S056 head f97d994cc): the commits below hit
reject-strict stubs and fail. GREEN on the s057 head: the commits apply
and the legacy CLI surface (show running-config) renders the exact knob
lines, proving the datastore and the bgpd internals agree.

Fase C fatia 1 wired the l2vpn-evpn prefix-limit fanout (shared
callbacks); the flipped test guards that the commit now applies.
"""
import glob
import json
import os
import re
import sys

import pytest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

GRPCP_MGMTD = 50065
script_path = os.path.realpath(os.path.join(CWD, "../lib/grpc-query.py"))

pytestmark = [pytest.mark.bgpd, pytest.mark.mgmtd]

CPP = (
    "/frr-routing:routing/control-plane-protocols/control-plane-protocol"
    "[type='frr-bgp:bgp'][name='bgp'][vrf='default']/frr-bgp:bgp"
)
PEER = "10.0.0.2"
NB = f"{CPP}/neighbors/neighbor[remote-address='{PEER}']"
AF = (f"{NB}/afi-safis"
      "/afi-safi[afi-safi-name='frr-routing:ipv4-unicast']/ipv4-unicast")
AF_G = (f"{CPP}/global/afi-safis"
        "/afi-safi[afi-safi-name='frr-routing:ipv4-unicast']"
        "/ipv4-unicast")
AF_VPN = (f"{CPP}/global/afi-safis"
          "/afi-safi[afi-safi-name='frr-routing:l3vpn-ipv4-unicast']"
          "/l3vpn-ipv4-unicast")
EVPN_AF = (
    f"{NB}/afi-safis"
    "/afi-safi[afi-safi-name='frr-routing:l2vpn-evpn']/l2vpn-evpn"
)


def _frr_grpc_module_available():
    """True when the FRR northbound gRPC module (grpc.so) is installed."""
    patterns = (
        "/usr/lib/*/frr/modules/grpc.so",
        "/usr/lib/frr/modules/grpc.so",
        "/usr/lib64/*/frr/modules/grpc.so",
        "/usr/lib64/frr/modules/grpc.so",
        "/usr/local/lib/*/frr/modules/grpc.so",
        "/usr/local/lib/frr/modules/grpc.so",
    )
    for pattern in patterns:
        for path in glob.glob(pattern):
            if os.path.isfile(path):
                return True

    frr_root = os.path.realpath(os.path.join(CWD, "../../.."))
    for base in (frr_root, os.environ.get("FRR_BUILD_DIR")):
        if not base:
            continue
        for rel in ("lib/.libs/grpc.so", "lib/grpc.so"):
            if os.path.isfile(os.path.join(base, rel)):
                return True
    return False


try:
    import grpc  # noqa: F401
    import grpc_tools  # noqa: F401
except ImportError:
    pytest.skip("skipping; gRPC modules not installed", allow_module_level=True)

if not _frr_grpc_module_available():
    pytest.skip(
        "skipping; FRR gRPC northbound module not installed "
        "(install frr-grpc or build with --enable-grpc)",
        allow_module_level=True,
    )

try:
    from lib.micronet import commander

    commander.cmd_raises([script_path, "--check"])
except Exception:
    pytest.skip(
        "skipping; cannot create or import gRPC proto modules",
        allow_module_level=True,
    )


def build_topo(tgen):
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    router = tgen.gears["r1"]
    router.load_config("bgpd", os.path.join(CWD, "r1/bgpd.conf"))
    router.load_config(TopoRouter.RD_MGMTD, "", f"-M grpc:{GRPCP_MGMTD}")
    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def run_grpc_client(r, commands):
    if not isinstance(commands, str):
        commands = "\n".join(commands) + "\n"
    if not commands.endswith("\n"):
        commands += "\n"
    return r.cmd_raises(
        [script_path, f"--port={GRPCP_MGMTD}"], stdin=commands
    )


def run_grpc_client_status(r, command):
    if not command.endswith("\n"):
        command += "\n"
    return r.net.cmd_status(
        [script_path, f"--port={GRPCP_MGMTD}"], stdin=command
    )


@pytest.fixture(autouse=True)
def skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def test_prefix_limit_inbound_grpc():
    """G-PL: maximum-prefix + threshold land in the peer internals and
    render back on the legacy CLI."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    step("Create the neighbor context, then the prefix-limit (one shot)")
    run_grpc_client(
        r1,
        [
            f"commit-set,{CPP}/global/local-as=65000",
            # one transaction: remote-as-type is a mandatory leaf and
            # the wired validation demands remote-as in the same txn
            f"commit-result,ALL,"
            f"{NB}/neighbor-remote-as/remote-as-type=as-specified,"
            f"{NB}/neighbor-remote-as/remote-as=65001,"
            f"{AF}/prefix-limit/direction-list"
            "[direction='in']/max-prefixes=2,"
            f"{AF}/prefix-limit/direction-list"
            "[direction='in']/options/shutdown-threshold-pct=80",
        ]
    )

    step("The legacy CLI shows the maximum-prefix line")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "neighbor 10.0.0.2 maximum-prefix 2 80" in output, (
        f"expected maximum-prefix on legacy CLI; got:\n{output}"
    )

    step("The gRPC get-config view agrees (round-trip)")
    out = run_grpc_client(r1, f"get-config,{AF}/prefix-limit")
    assert "2" in out and "80" in out, f"prefix-limit missing: {out}"


def test_prefix_limit_outbound_grpc():
    """G-PL: direction=out maps onto maximum-prefix-out."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    run_grpc_client(
        r1,
        f"commit-set,{AF}/prefix-limit/direction-list[direction='out']"
        "/max-prefixes=5",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "neighbor 10.0.0.2 maximum-prefix-out 5" in output, (
        f"expected maximum-prefix-out on legacy CLI; got:\n{output}"
    )


def test_prefix_limit_destroy_grpc():
    """G-PL: destroying the direction-list unsets the internals."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    run_grpc_client(
        r1,
        f"commit-delete,{AF}/prefix-limit/direction-list[direction='out']",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "maximum-prefix-out" not in output, (
        f"maximum-prefix-out should be gone; got:\n{output}"
    )
    assert "maximum-prefix 2 80" in output, "inbound half must survive"


def test_network_config_grpc():
    """G-NC: network-config lands in bgp static routes and the route is
    originated (the link subnet satisfies import-check)."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    step("Announce the r1-eth0 link subnet")
    # (the grpc-query CLI is path=value only; touching the defaulted
    # backdoor leaf expresses the list-entry CREATE)
    run_grpc_client(
        r1,
        f"commit-set,{AF_G}/network-config[prefix='10.0.0.0/24']"
        "/backdoor=false",
    )

    output = r1.vtysh_cmd("show running-config bgpd")
    assert "network 10.0.0.0/24" in output, (
        f"expected network on legacy CLI; got:\n{output}"
    )

    step("The static route is originated into the BGP table")
    output = r1.vtysh_cmd("show bgp ipv4 unicast 10.0.0.0/24 json")
    assert "10.0.0.0/24" in output, (
        f"expected the network in the BGP table; got:\n{output}"
    )


def test_network_config_backdoor_grpc():
    """G-NC: the backdoor leaf round-trips and the entry is removable."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    run_grpc_client(
        r1,
        f"commit-set,{AF_G}/network-config[prefix='10.0.0.0/24']"
        "/backdoor=true",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "network 10.0.0.0/24 backdoor" in output, (
        f"expected backdoor on legacy CLI; got:\n{output}"
    )

    run_grpc_client(
        r1, f"commit-delete,{AF_G}/network-config[prefix='10.0.0.0/24']"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "network 10.0.0.0/24" not in output, (
        f"network should be gone; got:\n{output}"
    )


def test_prefix_limit_option_destroy_grpc():
    """G-PL: destroying an individual option leaf unsets the knob."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    step("Re-state the base + threshold in one txn (runs after the neighbor test)")
    run_grpc_client(
        r1,
        f"commit-result,ALL,"
        f"{AF}/prefix-limit/direction-list[direction='in']"
        "/max-prefixes=2,"
        f"{AF}/prefix-limit/direction-list[direction='in']"
        "/options/shutdown-threshold-pct=50",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "maximum-prefix 2 50" in output, (
        f"expected explicit threshold; got:\n{output}"
    )

    step("Destroy the option leaf; the explicit threshold is gone")
    run_grpc_client(
        r1,
        f"commit-delete,{AF}/prefix-limit/direction-list[direction='in']"
        "/options/shutdown-threshold-pct",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "maximum-prefix 2 50" not in output, (
        f"explicit threshold should be gone; got:\n{output}"
    )
    assert "maximum-prefix 2" in output, "inbound limit must survive"


def test_network_config_l3vpn_grpc():
    """G-NC l3vpn: rd/prefix-list entries with label-index and
    route-map (the leaf modify/destroy paths under network-config[rd])."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    step("Create the rd + prefix-list entry via gRPC")
    run_grpc_client(
        r1,
        f"commit-set,{AF_VPN}/network-config[rd='65000:100']"
        "/prefix-list[prefix='198.18.9.0/24']/label-index=1000",
    )

    step("label-index modify on the existing entry (depth-4 leaf path)")
    # the legacy internals refuse a label CHANGE (parity); the modify
    # must fail cleanly AND flow through the leaf callback without
    # aborting the daemon -- that is the depth regression under test
    rc, stdout, stderr = run_grpc_client_status(
        r1,
        f"commit-set,{AF_VPN}/network-config[rd='65000:100']"
        "/prefix-list[prefix='198.18.9.0/24']/label-index=1001",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "198.18.9.0/24" in output, (
        f"bgpd lost the vpn network after a leaf modify; got:\n{output}"
    )

    step("rmap-policy-export set and unset on the entry")
    run_grpc_client(
        r1,
        f"commit-set,{AF_VPN}/network-config[rd='65000:100']"
        "/prefix-list[prefix='198.18.9.0/24']/rmap-policy-export=s057rm",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "198.18.9.0/24 rd 65000:100 label 1000 route-map s057rm" in output, (
        f"expected vpn network line; got:\n{output}"
    )
    run_grpc_client(
        r1,
        f"commit-delete,{AF_VPN}/network-config[rd='65000:100']"
        "/prefix-list[prefix='198.18.9.0/24']/rmap-policy-export",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "route-map s057rm" not in output, "rmap should be unset"

    step("destroy the rd entry (children included)")
    run_grpc_client(
        r1,
        f"commit-delete,{AF_VPN}/network-config[rd='65000:100']",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "198.18.9.0/24" not in output, (
        f"vpn network should be gone; got:\n{output}"
    )


def test_prefix_limit_multi_leaf_option_destroy():
    """G-PL: destroying ONE leaf of the tr case keeps the sibling alive
    (review round 2, A1) and half-cases are rejected (A2)."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    step("State the full tr case in one txn")
    run_grpc_client(
        r1,
        f"commit-result,ALL,"
        f"{AF}/prefix-limit/direction-list[direction='in']"
        "/max-prefixes=3,"
        f"{AF}/prefix-limit/direction-list[direction='in']"
        "/options/tr-shutdown-threshold-pct=40,"
        f"{AF}/prefix-limit/direction-list[direction='in']"
        "/options/tr-restart-timer=100",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "maximum-prefix 3 40 restart 100" in output, (
        f"expected full tr case; got:\n{output}"
    )

    step("Destroy only the threshold; the timer must survive")
    run_grpc_client(
        r1,
        f"commit-delete,{AF}/prefix-limit/direction-list[direction='in']"
        "/options/tr-shutdown-threshold-pct",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "restart 100" in output, (
        f"tr-restart-timer must survive its sibling destroy; got:\n{output}"
    )
    assert "3 40" not in output, "threshold should be reset"

    step("A half-case commit is rejected (tr timer without threshold)")
    rc, stdout, stderr = run_grpc_client_status(
        r1,
        f"commit-set,{AF}/prefix-limit/direction-list[direction='in']"
        "/options/tr-restart-timer=77",
    )
    assert rc != 0 or "requires" in (stdout + stderr), (
        f"orphan tr-restart-timer should be refused; got: {stdout+stderr}"
    )
    """G-NC CLI authority: a bare `network X` (no knobs) configures the
    internals, and a re-issue WITHOUT backdoor mirrors the legacy knob
    clear (review rounds 1-2, B2/A3). (The CLI dual mirrors into bgpd's own
    northbound datastore; mgmtd's copy only tracks mgmtd-fronted
    commits -- the NB_CLIENT_CLI exemption design.)"""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    step("Announce a bare network through the legacy CLI")
    r1.vtysh_cmd(
        "configure terminal\nrouter bgp 65000\n"
        "address-family ipv4 unicast\n"
        "network 198.18.77.0/24\n"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "network 198.18.77.0/24" in output, (
        f"legacy CLI missing the bare network; got:\n{output}"
    )

    step("Set backdoor, then re-issue bare: the knob must clear")
    r1.vtysh_cmd(
        "configure terminal\nrouter bgp 65000\n"
        "address-family ipv4 unicast\n"
        "network 198.18.77.0/24 backdoor\n"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "network 198.18.77.0/24 backdoor" in output, (
        f"backdoor should be set; got:\n{output}"
    )
    r1.vtysh_cmd(
        "configure terminal\nrouter bgp 65000\n"
        "address-family ipv4 unicast\n"
        "network 198.18.77.0/24\n"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "network 198.18.77.0/24\n" in output, (
        f"re-issue must render the bare form (knob cleared); got:\n{output}"
    )

    step("Set route-map, then re-issue bare: the rmap must clear")
    r1.vtysh_cmd(
        "configure terminal\nroute-map s057rm permit 1\nexit\n"
        "router bgp 65000\n"
        "address-family ipv4 unicast\n"
        "network 198.18.77.0/24 route-map s057rm\n"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "network 198.18.77.0/24 route-map s057rm" in output, (
        f"rmap should be set; got:\n{output}"
    )
    r1.vtysh_cmd(
        "configure terminal\nrouter bgp 65000\n"
        "address-family ipv4 unicast\n"
        "network 198.18.77.0/24\n"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "network 198.18.77.0/24 route-map" not in output, (
        f"re-issue must clear the network rmap; got:\n{output}"
    )

    step("Destroy removes the entry from the internals")
    r1.vtysh_cmd(
        "configure terminal\nrouter bgp 65000\n"
        "address-family ipv4 unicast\n"
        "no network 198.18.77.0/24\n"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "198.18.77.0/24" not in output, "destroy left the network"


def test_evpn_prefix_limit_wired():
    """Fase C fatia 1 flipped the l2vpn-evpn prefix-limit from the
    reject-strict stub class to the shared wired callbacks from
    Fase B: the gRPC commit now applies and renders on the legacy
    CLI."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    step("l2vpn-evpn prefix-limit commit must apply")
    run_grpc_client(
        r1,
        [
            f"commit-set,{NB}/afi-safis/afi-safi"
            "[afi-safi-name='frr-routing:l2vpn-evpn']/enabled=true",
            f"commit-set,{EVPN_AF}/prefix-limit/direction-list"
            "[direction='in']/max-prefixes=2",
        ],
    )

    output = r1.vtysh_cmd("show running-config bgpd")
    assert "neighbor 10.0.0.2 maximum-prefix 2" in output, (
        f"expected EVPN maximum-prefix on legacy CLI; got:\n{output}"
    )

    step("Destroying the direction-list withdraws it")
    run_grpc_client(
        r1,
        f"commit-delete,{EVPN_AF}/prefix-limit/direction-list"
        "[direction='in']",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "maximum-prefix 2\n" not in output, (
        f"EVPN maximum-prefix must be gone; got:\n{output}"
    )


def test_cli_write_keeps_authority_and_datastore_intact():
    """The CLI keeps legacy authority: a legacy `neighbor maximum-prefix`
    applies to the bgpd internals (legacy show reflects it) without
    corrupting the gRPC-visible datastore view. (The CLI dual-write
    mirrors into the daemon-side datastore -- mgmtd's copy only
    tracks mgmtd-fronted commits, per the NB_CLIENT_CLI exemption
    design in bgp_nb_stubs.c.)"""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    step("Re-configure maximum-prefix through the legacy CLI")
    r1.vtysh_cmd(
        "configure terminal\nrouter bgp 65000\n"
        "address-family ipv4 unicast\n"
        f"neighbor {PEER} maximum-prefix 100\n"
    )

    step("The legacy CLI is still the authority on the internals")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "neighbor 10.0.0.2 maximum-prefix 100" in output, (
        f"expected CLI-configured maximum-prefix; got:\n{output}"
    )

    step("The gRPC datastore view stays queryable (no corruption)")
    out = run_grpc_client(r1, f"get-config,{AF}/prefix-limit")
    assert "prefix-limit" in out or "direction-list" in out, (
        f"datastore view lost the prefix-limit subtree: {out}"
    )


def test_prefix_limit_cli_reemit_clears_stale_options():
    """P003 (Greptile #40): re-issuing `maximum-prefix` WITHOUT a
    previously configured option/force must clear it from both
    planes. The datastore mirror lives in bgpd's own northbound
    copy: without the mirror-clear, the northbound apply of the
    very same batch dragged the stale datastore values back into
    the runtime (peer_maximum_prefix_set() re-applied them), so the
    re-issue was a no-op for the omitted knobs on BOTH planes and
    the runtime render kept `500 80 warning-only force` on base
    221666459f (RED). The gRPC get-config view of the mgmtd DS is
    NOT the oracle for CLI re-issues (NB_CLIENT_CLI: mgmtd only
    tracks mgmtd-fronted commits -- pinned by the sibling
    test_cli_write_keeps_authority_and_datastore_intact)."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    dl = f"{AF}/prefix-limit/direction-list[direction='in']"

    step("State the full tw case + force through one gRPC commit")
    run_grpc_client(
        r1,
        [
            f"commit-set,{dl}/max-prefixes=1000",
            f"commit-result,ALL,"
            # threshold at EXACTLY the yang default (75): the stale
# snapshot cannot tell absent from default in the runtime
# (review MAJOR -- the datastore must answer, not the knobs)
f"{dl}/options/tw-shutdown-threshold-pct=75,"
            f"{dl}/options/tw-warning-only=true,"
            f"{dl}/force-check=true",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    # the legacy render omits a threshold at the default value (75)
    assert "maximum-prefix 1000 warning-only force" in output, (
        f"expected tw case + force on legacy CLI; got:\n{output}"
    )

    step("Re-issue bare through the legacy CLI")
    r1.vtysh_cmd(
        "configure terminal\nrouter bgp 65000\n"
        "address-family ipv4 unicast\n"
        "neighbor 10.0.0.2 maximum-prefix 500\n"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "maximum-prefix 500" in output, (
        f"re-issue must render; got:\n{output}"
    )
    assert "warning-only" not in output and " force" not in output, (
        f"BASE: the stale mirror dragged the omitted knobs back "
        f"(no-op on both planes); got:\n{output}"
    )

    step("Re-affirm through gRPC: the diff apply must not resurrect them")
    run_grpc_client(r1, f"commit-set,{dl}/max-prefixes=500")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "maximum-prefix 500" in output, (
        f"re-affirm must render; got:\n{output}"
    )
    assert "warning-only" not in output and " force" not in output, (
        f"stale mirror resurrected the knobs on the gRPC apply; "
        f"got:\n{output}"
    )

    step("CLI case switch: tr case, then re-emit threshold-only")
    r1.vtysh_cmd(
        "configure terminal\nrouter bgp 65000\n"
        "address-family ipv4 unicast\n"
        "neighbor 10.0.0.2 maximum-prefix 600 restart 5\n"
    )
    r1.vtysh_cmd(
        "configure terminal\nrouter bgp 65000\n"
        "address-family ipv4 unicast\n"
        "neighbor 10.0.0.2 maximum-prefix 700 90\n"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "maximum-prefix 700 90" in output, (
        f"expected bare threshold on legacy CLI; got:\n{output}"
    )
    assert "restart" not in output, f"restart must clear; got:\n{output}"

    step("gRPC re-affirm: the new case only, no stale siblings")
    run_grpc_client(r1, f"commit-set,{dl}/max-prefixes=700")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "maximum-prefix 700 90" in output, (
        f"threshold must survive the gRPC re-affirm; got:\n{output}"
    )
    assert "restart" not in output, (
        f"stale restart-timer resurrected on apply; got:\n{output}"
    )

    step("Destroy the direction-list; nothing survives")
    run_grpc_client(r1, f"commit-delete,{dl}")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "maximum-prefix" not in output, (
        f"destroy must clear the render; got:\n{output}"
    )


def _pgw_maxp_line(output):
    """The `neighbor pgw maximum-prefix ...` render line, or "".

    Anchors the stale-option asserts on the peer-group's own line so
    residue from sibling tests on other neighbors cannot cascade a
    false failure into this test (P004 adversarial review)."""
    match = re.search(r"^\s*neighbor pgw maximum-prefix.*$", output, re.MULTILINE)
    return match.group(0) if match else ""


def test_prefix_limit_pg_cli_reemit_clears_stale_options():
    """P004 (typed finding of P003): the peer-group context of the
    stale-option clear. Seeding the tw case through gRPC and
    re-issuing `maximum-prefix` bare through the legacy CLI must
    clear the stale options from the group runtime, and the gRPC
    re-affirm must not resurrect them. On base 221666459f the group
    render kept `400 warning-only` (and `400 80` for the
    explicit-threshold seed): the re-apply of the very batch dragged
    the group's stale datastore options back into the runtime. The
    P003 v3 DS-truth snapshot covers the group context as a side
    effect (the runtime knobs of a group blend inherited state a
    runtime-flags snapshot cannot trust); this test pins it. The
    seed must come through gRPC: a CLI-only seed never reaches the
    datastore copy the dual-write reads (proven by the P004 repro
    matrix -- a CLI-only seed does not manifest the divergence on
    any head)."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    pg = f"{CPP}/peer-groups/peer-group[peer-group-name='pgw']"
    dl = (
        f"{pg}/afi-safis"
        "/afi-safi[afi-safi-name='frr-routing:ipv4-unicast']"
        "/ipv4-unicast/prefix-limit/direction-list[direction='in']"
    )

    step("Create the peer-group and attach the member")
    r1.vtysh_cmd(
        "configure terminal\nrouter bgp 65000\n"
        "neighbor pgw peer-group\n"
        f"neighbor {PEER} remote-as 65001\n"
        f"neighbor {PEER} peer-group pgw\n"
    )

    step("State the full tw case through one gRPC commit")
    run_grpc_client(
        r1,
        f"commit-result,ALL,"
        f"{dl}/max-prefixes=300,"
        # threshold at EXACTLY the yang default (75): the legacy
        # render omits it -- only warning-only shows
        f"{dl}/options/tw-shutdown-threshold-pct=75,"
        f"{dl}/options/tw-warning-only=true",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "neighbor pgw maximum-prefix 300 warning-only" in output, (
        f"expected the tw case on the group render; got:\n{output}"
    )

    step("Re-issue bare through the legacy CLI")
    r1.vtysh_cmd(
        "configure terminal\nrouter bgp 65000\n"
        "address-family ipv4 unicast\n"
        "neighbor pgw maximum-prefix 400\n"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    line = _pgw_maxp_line(output)
    assert "neighbor pgw maximum-prefix 400" in line, (
        f"re-issue must render on the group; got:\n{output}"
    )
    assert "warning-only" not in line, (
        f"BASE: the group runtime kept the stale tw case; got:\n{output}"
    )

    step("Re-affirm through gRPC: the diff apply must not resurrect them")
    run_grpc_client(r1, f"commit-set,{dl}/max-prefixes=400")
    output = r1.vtysh_cmd("show running-config bgpd")
    line = _pgw_maxp_line(output)
    assert "neighbor pgw maximum-prefix 400" in line, (
        f"re-affirm must render; got:\n{output}"
    )
    assert "warning-only" not in line, (
        f"stale group options resurrected on the gRPC apply; got:\n{output}"
    )

    step("Explicit-threshold seed (tw 80): the bare re-issue drops it too")
    run_grpc_client(
        r1,
        f"commit-result,ALL,{dl}/max-prefixes=300,"
        f"{dl}/options/tw-shutdown-threshold-pct=80,"
        f"{dl}/options/tw-warning-only=true",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "neighbor pgw maximum-prefix 300 80" in _pgw_maxp_line(output), (
        f"expected the explicit threshold on the group render; got:\n{output}"
    )
    r1.vtysh_cmd(
        "configure terminal\nrouter bgp 65000\n"
        "address-family ipv4 unicast\n"
        "neighbor pgw maximum-prefix 400\n"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    line = _pgw_maxp_line(output)
    assert "neighbor pgw maximum-prefix 400" in line, (
        f"re-issue must render on the group; got:\n{output}"
    )
    assert "warning-only" not in line and " 80" not in line, (
        f"BASE: the group runtime kept the explicit stale case; got:\n{output}"
    )

    step("Destroy the direction-list; nothing survives on the group")
    run_grpc_client(r1, f"commit-delete,{dl}")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "neighbor pgw maximum-prefix" not in _pgw_maxp_line(output), (
        f"destroy must clear the group render; got:\n{output}"
    )

    step("Teardown: detach the member and remove the peer-group")
    r1.vtysh_cmd(
        "configure terminal\nrouter bgp 65000\n"
        f"no neighbor {PEER} peer-group pgw\n"
        "no neighbor pgw peer-group\n"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "pgw" not in output, (
        f"the peer-group must be gone so later tests on the shared "
        f"neighbor start clean; got:\n{output}"
    )
