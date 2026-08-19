# SPDX-License-Identifier: ISC
"""
Verifies the Fase D fatia 3 northbound wiring in bgpd: the
global/afi-safis family and the daemon/interface tail leave the warn
table and become programmable through the mgmtd gRPC bridge.

RED on the S062 base (b433dd2468): the global AF commits hit warn
no-op stubs, the knobs never land on the bgpd internals and every
render assert below fails. GREEN on the s063 head: aggregate-route,
dampening, maxpaths, admin-distance, table-map, retain-route-target,
flowspec local-install, vpn-config (vrf<->vpn leak with
VALIDATE-only mutual exclusion), upa, prefer-global, the daemon tail
(update-delay, graceful-restart, community-alias, default-afi-safi,
mpls bgp-forwarding) and the REJECT_POLICY entries (snmp-traps,
sid-export) all apply or reject explicitly.
"""
import glob
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
CPPRED = (
    "/frr-routing:routing/control-plane-protocols/control-plane-protocol"
    "[type='frr-bgp:bgp'][name='red'][vrf='red']/frr-bgp:bgp"
)
PEER = "10.0.0.2"
IFR1 = "r1-eth0"
NB = f"{CPP}/neighbors/neighbor[remote-address='{PEER}']"
DAEMON = "/frr-bgp:bgp-daemon"


def gaf(ctx, af_name):
    return (
        f"{ctx}/global/afi-safis"
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


def _commit_rejected(r1, command):
    rc, output, _ = run_grpc_client_status(r1, command)
    rejected = (
        rc != 0
        or not output.strip()
        or "error_message" in output
        or "details" in output
    )
    assert rejected, f"commit must be rejected:\n{command}\n{output}"
    return output


def _render(r1):
    return r1.vtysh_cmd("show running-config bgpd")


def test_global_aggregate_route_grpc():
    """G1: aggregate-route entries are created (leaf-on-same-commit),
    modified and destroyed with render parity in both AFs."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    AGG4 = f"{gaf(CPP, 'ipv4-unicast')}/aggregate-route[prefix='10.0.0.0/8']"

    _seed(r1)

    step("create entry with as-set on the same commit")
    run_grpc_client(r1, f"commit-set,{AGG4}/as-set=true")
    output = _render(r1)
    assert "aggregate-address 10.0.0.0/8 as-set" in output, (
        f"aggregate as-set missing:\n{output}"
    )

    step("modify summary-only")
    run_grpc_client(r1, f"commit-set,{AGG4}/summary-only=true")
    output = _render(r1)
    assert "aggregate-address 10.0.0.0/8 as-set summary-only" in output, (
        f"aggregate summary-only missing:\n{output}"
    )

    step("NEG: suppress-map conflicts with summary-only (validate-only)")
    output = _commit_rejected(r1, f"commit-set,{AGG4}/suppress-map=rm-x")
    if output.strip():
        assert "summary-only" in output and "suppress-map" in output, (
            f"expected the mutual-exclusion error:\n{output}"
        )
    out = run_grpc_client(r1, f"get-config,{AGG4}")
    assert "rm-x" not in out, f"rejected leaf left residue:\n{out}"

    step("delete the entry")
    run_grpc_client(r1, f"commit-delete,{AGG4}")
    output = _render(r1)
    assert "aggregate-address 10.0.0.0/8" not in output, (
        f"aggregate survived destroy:\n{output}"
    )

    step("direct leaf deletes on a fresh entry (macro destroy paths)")
    AGG5 = f"{gaf(CPP, 'ipv4-unicast')}/aggregate-route[prefix='10.1.0.0/16']"
    run_grpc_client(r1, f"commit-set,{AGG5}/as-set=true")
    run_grpc_client(r1, f"commit-set,{AGG5}/community=100:20")
    output = _render(r1)
    assert "aggregate-address 10.1.0.0/16 as-set" in output, (
        f"fresh entry missing:\n{output}"
    )
    run_grpc_client(r1, f"commit-delete,{AGG5}/community")
    out = run_grpc_client(r1, f"get-config,{AGG5}")
    assert "100:20" not in out, f"community leaf delete left residue:\n{out}"
    output = _render(r1)
    assert "aggregate-address 10.1.0.0/16 as-set" in output, (
        f"entry must survive a leaf delete:\n{output}"
    )
    run_grpc_client(r1, f"commit-delete,{AGG5}")

    step("ipv6 fanout")
    AGG6 = (
        f"{gaf(CPP, 'ipv6-unicast')}"
        "/aggregate-route[prefix='2001:db8::/32']"
    )
    run_grpc_client(r1, f"commit-set,{AGG6}/summary-only=true")
    output = _render(r1)
    assert "aggregate-address 2001:db8::/32 summary-only" in output, (
        f"ipv6 aggregate missing:\n{output}"
    )


def test_global_dampening_grpc():
    """G2: dampening enable renders the knob and the four parameters
    convert minutes to seconds with the CLI defaults; reuse>=suppress
    is rejected in VALIDATE with no datastore residue."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    DAMP4 = f"{gaf(CPP, 'ipv4-unicast')}/route-flap-dampening"

    _seed(r1)

    step("enable renders bare dampening")
    run_grpc_client(r1, f"commit-set,{DAMP4}/enable=true")
    assert "bgp dampening" in _render(r1)

    step("parameters land (reach-decay maps to HALF)")
    run_grpc_client(
        r1,
        [
            f"commit-set,{DAMP4}/reach-decay=30",
            f"commit-set,{DAMP4}/reuse-above=900",
            f"commit-set,{DAMP4}/suppress-above=3000",
            f"commit-set,{DAMP4}/unreach-decay=90",
        ],
    )
    output = _render(r1)
    assert "bgp dampening 30 900 3000 90" in output, (
        f"dampening parameters missing:\n{output}"
    )

    step("NEG: suppress below reuse is a pure-data violation")
    output = _commit_rejected(r1, f"commit-set,{DAMP4}/suppress-above=700")
    if output.strip():
        assert "reuse-above" in output or "suppress-above" in output, (
            f"expected the reuse/suppress error:\n{output}"
        )
    out = run_grpc_client(r1, f"get-config,{DAMP4}")
    assert "700" not in out, f"rejected value left residue:\n{out}"

    step("disable removes the render")
    run_grpc_client(r1, f"commit-set,{DAMP4}/enable=false")
    assert "bgp dampening" not in _render(r1)


def test_global_maxpaths_grpc():
    """G3: ebgp/ibgp maximum-paths and equal-cluster-length land on
    the unicast AFs; the daemon cap is enforced."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    MP4 = f"{gaf(CPP, 'ipv4-unicast')}/use-multiple-paths"

    _seed(r1)

    step("ebgp + ibgp + equal-cluster-length")
    run_grpc_client(
        r1,
        [
            f"commit-set,{MP4}/ebgp/maximum-paths=4",
            f"commit-set,{MP4}/ibgp/maximum-paths=6",
            f"commit-set,{MP4}/ibgp/cluster-length-list=true",
        ],
    )
    output = _render(r1)
    assert "maximum-paths 4" in output, f"ebgp maxpaths:\n{output}"
    assert "maximum-paths ibgp 6 equal-cluster-length" in output, (
        f"ibgp maxpaths + cll:\n{output}"
    )

    step("NEG: over the multipath cap (VALIDATE-only; zero residue)")
    output = _commit_rejected(
        r1, f"commit-set,{MP4}/ebgp/maximum-paths=60000"
    )
    out = run_grpc_client(r1, f"get-config,{MP4}")
    assert "60000" not in out, f"rejected cap left residue:\n{out}"
    output2 = _render(r1)
    assert "maximum-paths 60000" not in output2, (
        f"rejected cap mutated the daemon:\n{output2}"
    )

    step("labeled-unicast fanout")
    MPL = f"{gaf(CPP, 'ipv4-labeled-unicast')}/use-multiple-paths"
    run_grpc_client(r1, f"commit-set,{MPL}/ebgp/maximum-paths=2")
    output = _render(r1)
    assert "maximum-paths 2" in output, f"labeled fanout:\n{output}"

    step("destroys reset the render")
    run_grpc_client(
        r1,
        [
            f"commit-delete,{MP4}/ebgp/maximum-paths",
            f"commit-delete,{MP4}/ibgp/maximum-paths",
        ],
    )
    output = _render(r1)
    assert "maximum-paths 4" not in output, f"ebgp destroy:\n{output}"
    assert "maximum-paths ibgp 6" not in output, f"ibgp destroy:\n{output}"


def test_global_distance_grpc():
    """G4: distance bgp e/i/l and per-prefix distance entries with
    access-list render and destroy."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    DIST4 = f"{gaf(CPP, 'ipv4-unicast')}/admin-distance"
    DRT4 = f"{gaf(CPP, 'ipv4-unicast')}/admin-distance-route"

    _seed(r1)

    step("global e/i/l distances")
    run_grpc_client(
        r1,
        [
            f"commit-set,{DIST4}/external=30",
            f"commit-set,{DIST4}/internal=210",
            f"commit-set,{DIST4}/local=230",
        ],
    )
    output = _render(r1)
    assert "distance bgp 30 210 230" in output, (
        f"distance bgp missing:\n{output}"
    )

    step("per-prefix distance with access-list, then distance-only modify")
    run_grpc_client(
        r1,
        [
            f"commit-set,{DRT4}[prefix='10.5.0.0/16']/distance=170",
            f"commit-set,{DRT4}[prefix='10.5.0.0/16']/access-list=AL5",
        ],
    )
    output = _render(r1)
    assert "distance 170 10.5.0.0/16 AL5" in output, (
        f"per-prefix distance missing:\n{output}"
    )
    run_grpc_client(r1, f"commit-set,{DRT4}[prefix='10.5.0.0/16']/distance=160")
    output = _render(r1)
    assert "distance 160 10.5.0.0/16 AL5" in output, (
        f"distance-only modify must preserve the access-list:\n{output}"
    )

    step("entry destroy")
    run_grpc_client(r1, f"commit-delete,{DRT4}[prefix='10.5.0.0/16']")
    output = _render(r1)
    assert "distance 170 10.5.0.0/16" not in output, (
        f"distance entry survived destroy:\n{output}"
    )
    assert "distance 160 10.5.0.0/16" not in output, (
        f"distance entry survived destroy:\n{output}"
    )


def test_global_table_map_grpc():
    """G5: filter-config/rmap-export maps to table-map."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    TM4 = f"{gaf(CPP, 'ipv4-unicast')}/filter-config/rmap-export"

    _seed(r1)

    run_grpc_client(r1, f"commit-set,{TM4}=TM")
    output = _render(r1)
    assert "table-map TM" in output, f"table-map missing:\n{output}"

    run_grpc_client(r1, f"commit-delete,{TM4}")
    output = _render(r1)
    assert "table-map" not in output, f"table-map survived destroy:\n{output}"


def test_global_retain_rt_grpc():
    """G6: retain-route-target-all on l3vpn renders inside an active
    vpnv4 AF (the disabled form is the renderable one; the yang default
    is true)."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    RET = f"{gaf(CPP, 'l3vpn-ipv4-unicast')}/retain-route-target-all"
    NBAF = (
        f"{NB}/afi-safis"
        "/afi-safi[afi-safi-name='frr-routing:l3vpn-ipv4-unicast']"
    )

    _seed(r1)

    step("activate vpnv4 on a peer so the AF renders")
    run_grpc_client(
        r1,
        f"commit-set,{NB}/neighbor-remote-as/remote-as-type=as-specified,"
        f"{NB}/neighbor-remote-as/remote-as=65100",
    )
    run_grpc_client(r1, f"commit-set,{NBAF}/enabled=true")
    output = _render(r1)
    assert "address-family ipv4 vpn" in output, f"af vpnv4 missing:\n{output}"

    step("retain=false renders the no-form")
    run_grpc_client(r1, f"commit-set,{RET}=false")
    output = _render(r1)
    assert "no bgp retain route-target all" in output, (
        f"retain no-form missing:\n{output}"
    )

    step("back to default removes the line")
    run_grpc_client(r1, f"commit-set,{RET}=true")
    output = _render(r1)
    assert "retain route-target" not in output, (
        f"retain line survived:\n{output}"
    )


def test_global_flowspec_local_install_grpc():
    """G7: flowspec local-install interface entries round-trip (the
    enable leaf carries a yang default of true and renders nothing by
    itself; the interface leaf-list is the renderable surface)."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    FSLI = f"{gaf(CPP, 'ipv4-flowspec')}/flow-spec-config/local-install"

    _seed(r1)

    step("disable/enable commit through the wired path")
    run_grpc_client(r1, f"commit-set,{FSLI}/enable=false")
    run_grpc_client(r1, f"commit-set,{FSLI}/enable=true")

    step("interface entry renders")
    run_grpc_client(r1, f"commit-set,{FSLI}/interface={IFR1}")
    output = _render(r1)
    assert f"local-install {IFR1}" in output, (
        f"local-install render missing:\n{output}"
    )

    step("interface destroy")
    run_grpc_client(r1, f"commit-delete,{FSLI}/interface[.='{IFR1}']")
    output = _render(r1)
    assert f"local-install {IFR1}" not in output, (
        f"local-install survived destroy:\n{output}"
    )


def test_global_vpn_config_grpc():
    """G8: vpn-config on a second VRF instance wires the vrf<->vpn
    leak surface; mutual exclusion is enforced VALIDATE-only so a
    rejected transaction leaves no running-DS residue."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    VPN4 = f"{gaf(CPPRED, 'ipv4-unicast')}/vpn-config"

    _seed(r1)
    run_grpc_client_status(r1, f"commit-set,{CPPRED}/global/local-as=65001")

    step("rd/label/allocation/nexthop/rt lists land")
    run_grpc_client(
        r1,
        [
            f"commit-set,{VPN4}/rd=100:1",
            f"commit-set,{VPN4}/label=24000",
            f"commit-set,{VPN4}/export-allocation-mode=per-nexthop",
            f"commit-set,{VPN4}/nexthop=10.99.0.1",
            f"commit-set,{VPN4}/import-rt-list=65000:100",
            f"commit-set,{VPN4}/export-rt-list=65000:200",
        ],
    )
    output = _render(r1)
    for line in (
        "rd vpn export 100:1",
        "label vpn export 24000",
        "label vpn export allocation-mode per-nexthop",
        "nexthop vpn export 10.99.0.1",
        "rt vpn import 65000:100",
        "rt vpn export 65000:200",
    ):
        assert line in output, f"vpn-config line missing ({line}):\n{output}"

    step("NEG: malformed rd rejected with zero residue")
    output = _commit_rejected(r1, f"commit-set,{VPN4}/rd=banana")
    if output.strip():
        assert "rd" in output, f"expected malformed-rd error:\n{output}"
    out = run_grpc_client(r1, f"get-config,{VPN4}")
    assert "banana" not in out, f"malformed rd left residue:\n{out}"

    step("redirect-rt lands alongside the vpn family")
    run_grpc_client(r1, f"commit-set,{VPN4}/redirect-rt=65000:300")
    output = _render(r1)
    assert "redirect" in output, f"redirect-rt missing:\n{output}"

    step("NEG: import vrf with the vpn family active (two-way guard)")
    output = _commit_rejected(
        r1, f"commit-set,{VPN4}/import-vrf-list[vrf='default']/vrf=default"
    )
    if output.strip():
        assert "unconfigure vpn commands" in output, (
            f"expected the vpn/v2v exclusion error:\n{output}"
        )
    out = run_grpc_client(r1, f"get-config,{VPN4}")
    assert "import-vrf-list" not in out, f"v2v left residue:\n{out}"

    step("clear the vpn family -> import vrf applies")
    run_grpc_client(r1, f"commit-delete,{VPN4}")
    run_grpc_client(
        r1, f"commit-set,{VPN4}/import-vrf-list[vrf='default']/vrf=default"
    )
    output = _render(r1)
    assert "import vrf" in output, f"import vrf missing:\n{output}"

    step("NEG: rd with v2v active (mirror direction)")
    _commit_rejected(r1, f"commit-set,{VPN4}/rd=100:2")

    step("NEG: self-import rejected on pure candidate data")
    _commit_rejected(
        r1, f"commit-set,{VPN4}/import-vrf-list[vrf='red']/vrf=red"
    )


def test_global_upa_grpc():
    """G9: upa originate-all/drop/max-routes on the unicast AFs."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    UPA4 = f"{gaf(CPP, 'ipv4-unicast')}/upa"

    _seed(r1)

    run_grpc_client(
        r1,
        [
            f"commit-set,{UPA4}/originate-all=true",
            f"commit-set,{UPA4}/drop=true",
            f"commit-set,{UPA4}/max-routes=5000",
        ],
    )
    output = _render(r1)
    assert "upa originate-all" in output, f"upa originate-all:\n{output}"
    assert " upa drop" in output, f"upa drop:\n{output}"
    assert "upa max-routes 5000" in output, f"upa max-routes:\n{output}"


def test_global_prefer_global_grpc():
    """G10: nexthop prefer-global on the ipv6 AFs (ups-fix proof: the
    leaf sits directly under the per-family container)."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    PG6 = f"{gaf(CPP, 'ipv6-unicast')}/prefer-global"
    PGL = f"{gaf(CPP, 'ipv6-labeled-unicast')}/prefer-global"

    _seed(r1)

    step("ipv6-unicast enable renders")
    run_grpc_client(r1, f"commit-set,{PG6}=true")
    output = _render(r1)
    assert "nexthop prefer-global" in output, (
        f"prefer-global missing:\n{output}"
    )

    step("destroy removes the render")
    run_grpc_client(r1, f"commit-delete,{PG6}")
    output = _render(r1)
    assert "nexthop prefer-global" not in output, (
        f"prefer-global survived destroy:\n{output}"
    )

    step("labeled-unicast fanout")
    run_grpc_client(r1, f"commit-set,{PGL}=true")
    output = _render(r1)
    assert "nexthop prefer-global" in output, (
        f"prefer-global labeled fanout:\n{output}"
    )


def test_daemon_config_grpc():
    """R2: the bgp-daemon tail — update-delay/establish-wait pair with
    the cross-leaf guard, graceful-restart, community-alias upsert with
    format guard, default-afi-safi with the unicast/labeled mutex and
    the interface mpls-bgp-forwarding augment."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    _seed(r1)

    step("update-delay + establish-wait pair")
    run_grpc_client(
        r1,
        [
            f"commit-set,{DAEMON}/update-delay-time=60",
            f"commit-set,{DAEMON}/establish-wait-time=30",
        ],
    )
    output = r1.vtysh_cmd("show running-config")
    assert "bgp update-delay 60 30" in output, (
        f"update-delay render missing:\n{output}"
    )

    step("NEG: update-delay below establish-wait")
    _commit_rejected(r1, f"commit-set,{DAEMON}/update-delay-time=10")

    step("graceful-restart")
    run_grpc_client(
        r1,
        [
            f"commit-set,{DAEMON}/graceful-restart/enabled=true",
            f"commit-set,{DAEMON}/graceful-restart/restart-time=150",
        ],
    )
    output = r1.vtysh_cmd("show running-config")
    assert "bgp graceful-restart restart-time 150" in output, (
        f"GR render missing:\n{output}"
    )

    step("graceful-shutdown enable then disable (no wedge)")
    run_grpc_client(r1, f"commit-set,{DAEMON}/graceful-shutdown/enable=true")
    output = r1.vtysh_cmd("show running-config")
    assert "bgp graceful-shutdown" in output, (
        f"graceful-shutdown render missing:\n{output}"
    )
    run_grpc_client(r1, f"commit-set,{DAEMON}/graceful-shutdown/enable=false")
    output = r1.vtysh_cmd("show running-config")
    assert "bgp graceful-shutdown\n" not in output, (
        f"graceful-shutdown disable wedged:\n{output}"
    )

    step("community-alias + malformed NEG")
    run_grpc_client(
        r1,
        f"commit-set,{DAEMON}/community-alias[community='100:10']"
        "/alias=CUSTUM",
    )
    output = r1.vtysh_cmd("show running-config")
    assert "bgp community alias 100:10 CUSTUM" in output, (
        f"community alias missing:\n{output}"
    )
    output = _commit_rejected(
        r1,
        f"commit-set,{DAEMON}/community-alias[community='banana']"
        "/alias=X",
    )
    if output.strip():
        assert "community" in output, (
            f"expected community format error:\n{output}"
        )
    run_grpc_client(
        r1, f"commit-delete,{DAEMON}/community-alias[community='100:10']"
    )
    output = r1.vtysh_cmd("show running-config")
    assert "bgp community alias" not in output, (
        f"community alias survived destroy:\n{output}"
    )

    step("default-afi-safi + unicast/labeled mutex")
    run_grpc_client(r1, f"commit-set,{CPP}/global/default-afi-safi=ipv6-unicast")
    output = r1.vtysh_cmd("show running-config")
    assert "bgp default ipv6-unicast" in output, (
        f"default afi-safi missing:\n{output}"
    )
    output = _commit_rejected(
        r1,
        f"commit-set,{CPP}/global/default-afi-safi=ipv4-labeled-unicast",
    )
    if output.strip():
        assert "mutually exclusive" in output, (
            f"expected the unicast/labeled mutex error:\n{output}"
        )

    step("interface mpls-bgp-forwarding augment")
    run_grpc_client(
        r1,
        f"commit-set,/frr-interface:lib/interface[name='{IFR1}']"
        "/frr-bgp:mpls-bgp-forwarding=true",
    )
    output = r1.vtysh_cmd("show running-config")
    assert "mpls bgp forwarding" in output, (
        f"mpls bgp forwarding missing:\n{output}"
    )


def test_reject_policy_grpc():
    """Fase D closure: REJECT_POLICY entries fail closed with an
    explicit message instead of the silent warn no-op. Inverted on the
    S062 base (warn accepts the commit), which is the RED proof for
    this test."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    _seed(r1)

    step("snmp-traps rfc4273 (set away from the yang default)")
    _commit_rejected(r1, f"commit-set,{DAEMON}/snmp-traps/rfc4273=false")

    step("sid-export route-map")
    _commit_rejected(
        r1,
        f"commit-set,{gaf(CPP, 'ipv4-unicast')}/sid-export/route-map=RM",
    )


def test_global_afi_safi_lifecycle_grpc():
    """G11: the afi-safi list entry lifecycle — leaves under a fresh
    AF create on demand and the entry destroy tears the subtree down
    (children-first destroys). The multicast prefix must sit inside
    224.0.0.0/4 (yang pattern on the list key)."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    AFM = f"{CPP}/global/afi-safis/afi-safi[afi-safi-name='frr-routing:ipv4-multicast']"
    AGGM = f"{AFM}/ipv4-multicast/aggregate-route[prefix='239.77.0.0/16']"

    _seed(r1)

    step("leaf under a fresh AF creates the entry on demand")
    run_grpc_client(r1, f"commit-set,{AGGM}/as-set=true")
    output = _render(r1)
    assert "aggregate-address 239.77.0.0/16 as-set" in output, (
        f"fresh-AF aggregate missing:\n{output}"
    )

    step("entry destroy removes the child render")
    run_grpc_client(r1, f"commit-delete,{AFM}")
    output = _render(r1)
    assert "aggregate-address 239.77.0.0/16" not in output, (
        f"entry destroy left the child render:\n{output}"
    )
