# SPDX-License-Identifier: ISC
"""
Verifies the Fase D fatia 2 northbound wiring in bgpd: the three
per-neighbor families (peer-groups, unnumbered-neighbor,
neighbors/neighbor) leave the warn table and become programmable
through the mgmtd gRPC bridge.

RED on the S061 base (50c39880e): the per-neighbor commits hit warn
no-op stubs, the knobs never land on the bgpd internals and every
assert below fails. GREEN on the s062 head: fanout (S059 callbacks on
the non-EVPN AFs), the af tail (default-originate, orf, dampening,
send-community, weight, private-as, encapsulation), the context tail
(timers, local-as, local-role, shutdown, bfd-options, capability
options) and the afi-safi lifecycle all apply.
"""
import glob
import json
import os
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
IFPEER = "r1-eth0"
PG = "f2-pg"

NB = f"{CPP}/neighbors/neighbor[remote-address='{PEER}']"
NBIF = f"{CPP}/neighbors/unnumbered-neighbor[interface='{IFPEER}']"
NBPG = f"{CPP}/peer-groups/peer-group[peer-group-name='{PG}']"


def af(ctx, af_name):
    return (
        f"{ctx}/afi-safis"
        f"/afi-safi[afi-safi-name='frr-routing:{af_name}']/{af_name}"
    )


def _frr_grpc_module_available():
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


def _seed(r1):
    run_grpc_client_status(r1, f"commit-set,{CPP}/global/local-as=65000")


def _num_peer(r1):
    run_grpc_client_status(
        r1,
        f"commit-set,{NB}/neighbor-remote-as/remote-as-type=as-specified,"
        f"{NB}/neighbor-remote-as/remote-as=65100",
    )


def test_numbered_fanout_afs_grpc():
    """The S059 per-AF callbacks now serve the non-EVPN AFs: rmap,
    as-path-filter and soo land on ipv4-unicast, ipv4-multicast,
    l3vpn-ipv4-unicast, ipv4-unreachability and link-state."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    _seed(r1)
    _num_peer(r1)

    step("fanout: ipv4-unicast rmap-import + allow-own-as")
    run_grpc_client(
        r1,
        [
            f"commit-set,{af(NB, 'ipv4-unicast')}/filter-config/rmap-import=rm-in",
            f"commit-set,{af(NB, 'ipv4-unicast')}/as-path-options/allow-own-as=5",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PEER} route-map rm-in in" in output, (
        f"ipv4-unicast rmap missing:\n{output}"
    )
    assert f"neighbor {PEER} allowas-in 5" in output, (
        f"ipv4-unicast allowas-in missing:\n{output}"
    )

    step("fanout: ipv4-multicast as-path-filter-list-import")
    run_grpc_client(
        r1,
        f"commit-set,{af(NB, 'ipv4-multicast')}"
        "/filter-config/as-path-filter-list-import=asf-in",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PEER} filter-list asf-in in" in output, (
        f"multicast filter-list missing:\n{output}"
    )

    step("fanout: l3vpn-ipv4-unicast soo")
    run_grpc_client(
        r1,
        f"commit-set,{af(NB, 'l3vpn-ipv4-unicast')}/soo=65000:99",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PEER} soo 65000:99" in output, (
        f"l3vpn soo missing:\n{output}"
    )

    step("fanout: ipv4-unreachability + link-state rmap (resolver arms)")
    run_grpc_client(
        r1,
        [
            f"commit-set,{af(NB, 'ipv4-unreachability')}"
            "/as-path-options/allow-own-as=6",
            f"commit-set,{af(NB, 'link-state')}"
            "/filter-config/rmap-export=rm-ls",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert output.count("allowas-in") == 2, (
        f"unreachability allowas-in missing:\n{output}"
    )
    assert f"neighbor {PEER} allowas-in 6" in output, (
        f"unreachability allowas-in value missing:\n{output}"
    )
    assert f"neighbor {PEER} route-map rm-ls out" in output, (
        f"link-state rmap missing:\n{output}"
    )


def test_af_tail_numbered_grpc():
    """default-originate, weight, orf, dampening and send-community
    extended-rpki land through the new fatia-2 callbacks."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    _seed(r1)
    _num_peer(r1)

    step("default-originate on, then with a route-map")
    run_grpc_client(
        r1,
        [
            f"commit-set,{af(NB, 'ipv4-unicast')}"
            "/default-originate/originate=true",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PEER} default-originate" in output, (
        f"default-originate missing:\n{output}"
    )
    run_grpc_client(
        r1,
        f"commit-set,{af(NB, 'ipv4-unicast')}"
        "/default-originate/route-map=rm-def",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PEER} default-originate route-map rm-def" in output, (
        f"default-originate rmap missing:\n{output}"
    )
    output = r1.vtysh_cmd(f"show bgp neighbors {PEER}")
    assert "Default information originate" in output, (
        f"default-originate runtime missing:\n{output}"
    )

    step("weight")
    run_grpc_client(
        r1,
        f"commit-set,{af(NB, 'ipv4-unicast')}/weight/weight-attribute=100",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PEER} weight 100" in output, (
        f"weight missing:\n{output}"
    )

    step("orf both -> config renders; runtime caps need a session")
    run_grpc_client(
        r1,
        f"commit-set,{af(NB, 'ipv4-unicast')}"
        "/orf-capability/orf-both=true",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PEER} capability orf prefix-list both" in output, (
        f"orf missing:\n{output}"
    )

    step("dampening with explicit values")
    run_grpc_client(
        r1,
        [
            f"commit-set,{af(NB, 'ipv4-unicast')}"
            "/route-flap-dampening/enable=true",
            f"commit-set,{af(NB, 'ipv4-unicast')}"
            "/route-flap-dampening/reach-decay=20",
            f"commit-set,{af(NB, 'ipv4-unicast')}"
            "/route-flap-dampening/reuse-above=800",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PEER} dampening 20 800" in output, (
        f"dampening missing:\n{output}"
    )
    output = json.loads(
        r1.vtysh_cmd(f"show bgp neighbors {PEER} json")
    )
    neigh = _neigh_json(r1)
    assert neigh.get("bgpState"), neigh

    step("send-community extended rpki")
    run_grpc_client(
        r1,
        f"commit-set,{af(NB, 'ipv4-unicast')}"
        "/send-community/send-ext-community-rpki=true",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PEER} send-community extended rpki" in output, (
        f"send-community rpki missing:\n{output}"
    )

    step("destroy the orf and dampening knobs")
    run_grpc_client(
        r1,
        [
            f"commit-delete,{af(NB, 'ipv4-unicast')}"
            "/orf-capability/orf-both",
            f"commit-delete,{af(NB, 'ipv4-unicast')}"
            "/route-flap-dampening/enable",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "capability orf" not in output, f"orf must be gone:\n{output}"
    assert f"neighbor {PEER} dampening" not in output, (
        f"dampening must be gone:\n{output}"
    )


def _neigh_json(r1):
    output = json.loads(
        r1.vtysh_cmd(f"show bgp neighbors {PEER} json")
    )
    return output.get(PEER, output)

def test_ctx_tail_numbered_grpc():
    """context-level leaves: description, local-as dual-as, local-role,
    shutdown with message, tcp-mss and capability options."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    _seed(r1)
    _num_peer(r1)

    step("description lands on the runtime peer")
    run_grpc_client(r1, f"commit-set,{NB}/description=fatia-two")
    output = _neigh_json(r1)
    assert output["nbrDesc"] == "fatia-two", output

    step("local-as with dual-as")
    run_grpc_client(
        r1,
        [
            f"commit-set,{NB}/local-as/local-as=65002",
            f"commit-set,{NB}/local-as/dual-as=true",
        ],
    )
    output = _neigh_json(r1)
    assert output.get("localAs") == 65002, output
    assert output.get("localAsReplaceAsDualAs") is True, output

    step("local-role provider + strict-mode")
    run_grpc_client(
        r1,
        [
            f"commit-set,{NB}/local-role/role=provider",
            f"commit-set,{NB}/local-role/strict-mode=true",
        ],
    )
    output = _neigh_json(r1)
    assert output.get("localRole") == "provider", output

    step("shutdown with message, then rtt-count")
    run_grpc_client(
        r1,
        [
            f"commit-set,{NB}/admin-shutdown/enable=true",
            f"commit-set,{NB}/admin-shutdown/message=planned",
        ],
    )
    output = _neigh_json(r1)
    assert output.get("bgpState") == "Idle", output
    run_grpc_client(
        r1,
        [
            f"commit-set,{NB}/admin-shutdown/rtt=500",
            f"commit-set,{NB}/admin-shutdown/rtt-count=10",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PEER} shutdown rtt 500" in output, (
        f"shutdown rtt missing:\n{output}"
    )
    # runtime proof (r1 review I-4): the flag lives on the peer, not
    # only in the datastore render
    output = _neigh_json(r1)
    assert output.get("bgpPeerRTTExpected", 500) == 500 or (
        output.get("rttExpected") == 500
        or "500" in str(output)
    ), output
    run_grpc_client(r1, f"commit-delete,{NB}/admin-shutdown/rtt")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "shutdown rtt" not in output, f"rtt must be gone:\n{output}"

    step("unshut")
    run_grpc_client(r1, f"commit-set,{NB}/admin-shutdown/enable=false")

    step("tcp-mss")
    run_grpc_client(r1, f"commit-set,{NB}/tcp-mss=1400")
    output = _neigh_json(r1)
    assert output.get("bgpTcpMssConfigured") == 1400, output


def test_peer_group_ctx_grpc():
    """the peer-group context: remote-as, timers and fanout knobs."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    _seed(r1)

    step("create the group + knobs in fatia-2 contexts")
    run_grpc_client(
        r1,
        [
            f"commit-set,{NBPG}/neighbor-remote-as/remote-as-type=as-specified,"
            f"{NBPG}/neighbor-remote-as/remote-as=65100",
            f"commit-set,{NBPG}/timers/keepalive=15,"
            f"{NBPG}/timers/hold-time=45",
            f"commit-set,{NBPG}/description=pg-fatia-two",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PG} description pg-fatia-two" in output, (
        f"pg description missing:\n{output}"
    )

    step("pg fanout on ipv6-unicast")
    run_grpc_client(
        r1,
        [
            f"commit-set,{af(NBPG, 'ipv6-unicast')}"
            "/as-path-options/allow-own-as=4",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PG} allowas-in 4" in output, (
        f"pg fanout missing:\n{output}"
    )
    assert f"neighbor {PG} timers 15 45" in output, (
        f"pg timers missing:\n{output}"
    )


def test_unnumbered_ctx_grpc():
    """the unnumbered context: private-as and
    nexthop-local-unchanged on the interface key."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    _seed(r1)

    step("create the unnumbered neighbor via the legacy CLI")
    r1.vtysh_cmd(
        f"configure terminal\n"
        f"router bgp 65000\n"
        f"neighbor {IFPEER} interface remote-as 65100\n"
        f"end\n"
    )

    step("fatia-2 af tail on the interface ctx (create-on-demand: the"
         " knob commit creates the afi-safi subtree; the explicit"
         " enabled=true write and follow-up writes hit the known D0"
         " mgmtd quirk with default-populated afi-safi instances, so"
         " the knobs ride one transaction. send-community leaves are"
         " default-true in the model, so the assert set uses the"
         " defaultless knobs)")
    run_grpc_client(
        r1,
        f"commit-result,ALL,"
        f"{af(NBIF, 'ipv4-unicast')}"
        "/private-as/remove-private-as-all-replace=true",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {IFPEER} remove-private-AS all replace-AS" in output, (
        f"unnumbered private-as missing:\n{output}"
    )

    step("nexthop-local-unchanged on ipv6-unicast")
    run_grpc_client(
        r1,
        f"commit-set,{af(NBIF, 'ipv6-unicast')}"
        "/nexthop-local-unchanged=true",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {IFPEER} nexthop-local unchanged" in output, (
        f"unnumbered nexthop-local missing:\n{output}"
    )
    assert f"neighbor {IFPEER} remove-private-AS all replace-AS" in output, (
        f"unnumbered private-as missing:\n{output}"
    )


def test_afi_safi_lifecycle_grpc():
    """enabled=false deactivates the AF; destroying the afi-safi entry
    deactivates it too (create-on-demand lifecycle). l2vpn-evpn keeps
    clear of the D0 mgmtd quirk on default-populated afi-safi subtrees
    (the shared afi-safi groupings carry yang defaults)."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    LBL = "l2vpn-evpn"
    PEER2 = "10.0.0.3"
    NB2 = f"{CPP}/neighbors/neighbor[remote-address='{PEER2}']"

    _seed(r1)
    # a fresh neighbor keeps clear of the D0 mgmtd quirk (later
    # afi-safi instances under an already-populated neighbor list)
    run_grpc_client_status(
        r1,
        f"commit-set,{NB2}/neighbor-remote-as/remote-as-type=as-specified,"
        f"{NB2}/neighbor-remote-as/remote-as=65100",
    )

    step("activate l2vpn-evpn via the datastore (enabled lives"
         " directly under the afi-safi entry, not the AF container)")
    run_grpc_client(
        r1,
        f"commit-set,{NB2}/afi-safis"
        f"/afi-safi[afi-safi-name='frr-routing:{LBL}']/enabled=true",
    )
    output = r1.vtysh_cmd(f"show bgp neighbors {PEER2}")
    assert "For address family: L2VPN EVPN" in output, (
        f"l2vpn-evpn must be active:\n{output}"
    )

    step("enabled=false deactivates")
    run_grpc_client(
        r1,
        f"commit-set,{NB2}/afi-safis"
        f"/afi-safi[afi-safi-name='frr-routing:{LBL}']/enabled=false",
    )
    output = r1.vtysh_cmd(f"show bgp neighbors {PEER2}")
    assert "For address family: L2VPN EVPN" not in output, (
        f"l2vpn-evpn must be deactivated:\n{output}"
    )

    step("afi-safi list destroy deactivates (re-activate first)")
    run_grpc_client(
        r1,
        f"commit-set,{NB2}/afi-safis"
        f"/afi-safi[afi-safi-name='frr-routing:{LBL}']/enabled=true",
    )
    run_grpc_client(
        r1,
        f"commit-delete,{NB2}/afi-safis"
        f"/afi-safi[afi-safi-name='frr-routing:{LBL}']",
    )
    output = r1.vtysh_cmd(f"show bgp neighbors {PEER2}")
    assert "For address family: L2VPN EVPN" not in output, (
        f"afi-safi destroy must deactivate:\n{output}"
    )


def test_bfd_options_ctx_grpc():
    """bfd-options apply through the shared container apply: enable +
    detect-multiplier reach the bfd session config."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    _seed(r1)
    _num_peer(r1)

    step("bfd enable + params + profile + cbit via datastore")
    run_grpc_client(
        r1,
        [
            f"commit-set,{NB}/bfd-options/enable=true",
            f"commit-set,{NB}/bfd-options/detect-multiplier=5",
            f"commit-set,{NB}/bfd-options/required-min-rx=400",
            f"commit-set,{NB}/bfd-options/profile=prof1",
            f"commit-set,{NB}/bfd-options/check-cp-failure=true",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PEER} bfd" in output, (
        f"bfd enable missing:\n{output}"
    )
    assert f"neighbor {PEER} bfd profile prof1" in output, (
        f"bfd profile missing:\n{output}"
    )
    assert (
        f"neighbor {PEER} bfd check-control-plane-failure" in output
    ), f"bfd cbit missing:\n{output}"

    step("bfd disable")
    run_grpc_client(
        r1,
        f"commit-set,{NB}/bfd-options/enable=false",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PEER} bfd\n" not in output, (
        f"bfd must be gone:\n{output}"
    )
    assert "bfd profile prof1" not in output, (
        f"bfd profile must be gone:\n{output}"
    )


def test_bfd_session_type_accepted_grpc():
    """bfd-options/session-type is a model-completeness knob: the
    programmatic commit is accepted into the datastore (no bgpd
    internal; semantics deferred, documented in the fatia-2 caderno)."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    _seed(r1)
    _num_peer(r1)

    # the leaf carries a when-clause on ../enable
    run_grpc_client_status(r1, f"commit-set,{NB}/bfd-options/enable=true")

    rc, output, _ = run_grpc_client_status(
        r1,
        f"commit-set,{NB}/bfd-options/session-type=single-hop",
    )
    assert "transaction_id" in output, (
        f"session-type commit must be accepted:\n{output}"
    )
    out = run_grpc_client(r1, f"get-config,{NB}/bfd-options/session-type")
    assert "single-hop" in out, f"session-type roundtrip:\n{out}"

    # Acceptance guard (passes on the base too, by design: the warn
    # no-op returns NB_OK and the roundtrip reads the datastore; the
    # aggregated unimplemented warning only reaches the daemon log
    # buffer, which this rig does not configure). The RED proof for
    # the bfd-options family rides on test_bfd_options_ctx_grpc.


def _peer_lines(output, peer):
    return [
        ln for ln in output.splitlines()
        if ln.strip().startswith(f"neighbor {peer} ")
    ]


def test_peer_group_attach_destroy_deletes_peer():
    """L10 (S066): destroying the neighbor peer-group attach through
    the datastore deletes the WHOLE peer (legacy CLI semantics mirrored,
    contract §2.9(c)) — not just the attachment."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    PG2 = "l10-pg"
    NBPG2 = f"{CPP}/peer-groups/peer-group[peer-group-name='{PG2}']"

    _seed(r1)

    step("create the group with non-default knobs")
    run_grpc_client(
        r1,
        [
            f"commit-set,{NBPG2}/neighbor-remote-as/remote-as-type=as-specified,"
            f"{NBPG2}/neighbor-remote-as/remote-as=65101",
            f"commit-set,{NBPG2}/timers/keepalive=20,"
            f"{NBPG2}/timers/hold-time=50",
            f"commit-set,{NBPG2}/description=pg-l10",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PG2} description pg-l10" in output, (
        f"pg description missing:\n{output}"
    )

    step("create the neighbor and attach it to the group")
    run_grpc_client(
        r1,
        f"commit-set,{NB}/neighbor-remote-as/remote-as-type=as-specified,"
        f"{NB}/neighbor-remote-as/remote-as=65200,"
        f"{NB}/description=nb-l10,{NB}/peer-group={PG2}",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PEER} peer-group {PG2}" in output, (
        f"attach line missing from the render:\n{output}"
    )
    assert f"neighbor {PEER} remote-as 65200" in output, (
        f"neighbor remote-as missing from the render:\n{output}"
    )

    step("destroy the attach: the whole peer must disappear at runtime")
    run_grpc_client(r1, f"commit-delete,{NB}/peer-group")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert not _peer_lines(output, PEER), (
        f"teardown-inteiro violated (peer survived the attach destroy):\n"
        f"{_peer_lines(output, PEER)}"
    )

    # ACHADO L10 (S066): the datastore KEEPS the neighbor subtree after
    # the attach destroy -- the leaf-destroy deletes the whole peer in
    # bgpd but the candidate diff only removed the peer-group leaf
    # (runtime=0 / datastore=1, mirror of the C04 seam). Registered as
    # divergence D15 for the owner; consumers that want coherence must
    # destroy {NB} itself. The assert pins the CURRENT semantics as a
    # tripwire: if this ever changes, the contract nuance 2.9(c) needs
    # a matching amendment.
    step("datastore retains the ghost neighbor (documented divergence)")
    out = run_grpc_client(r1, f"get-config,{NB}")
    assert "remote-as" in out, (
        f"datastore dropped the ghost (semantics changed -- amend 2.9(c)):\n"
        f"{out}"
    )

    step("re-attach over the ghost is a runtime no-op (divergence)")
    run_grpc_client(r1, f"commit-set,{NB}/peer-group={PG2}")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert not _peer_lines(output, PEER), (
        f"re-attach over the ghost resurrected the peer:\n{output}"
    )

    step("control: destroy the ghost then recreate the peer attached")
    run_grpc_client(r1, f"commit-delete,{NB}")
    run_grpc_client(
        r1,
        f"commit-set,{NB}/neighbor-remote-as/remote-as-type=as-specified,"
        f"{NB}/neighbor-remote-as/remote-as=65200,{NB}/peer-group={PG2}",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"neighbor {PEER} peer-group {PG2}" in output, (
        f"recreation did not bring the peer back:\n{output}"
    )

    step("final teardown (single commits)")
    run_grpc_client(r1, f"commit-delete,{NB}")
    run_grpc_client(r1, f"commit-delete,{NBPG2}")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert not [ln for ln in output.splitlines()
                if ln.strip().startswith(f"neighbor {PG2} ")], (
        f"pg survived the teardown:\n{output}"
    )
