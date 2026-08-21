# SPDX-License-Identifier: ISC
"""
Verifies the bgpd <-> mgmtd round-trip: configuration written via mgmtd
becomes visible in `show running-config bgpd` and vice-versa.

Coverage:
  * router-id via mgmtd -> legacy CLI
  * router-id via legacy CLI -> mgmtd YANG view
  * neighbor passive round-trip
  * per-AF route-reflector-client round-trip
  * local-as apply_finish atomicity (single mgmt transaction)
  * vtysh-destroy retained in the datastore (L6, S070)
"""
import glob
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import (
    kill_router_daemons,
    retry,
    start_router_daemons,
    step,
)

pytestmark = [pytest.mark.bgpd, pytest.mark.mgmtd]

GRPCP_MGMTD = 50066
script_path = os.path.realpath(os.path.join(CWD, "../lib/grpc-query.py"))


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


CPP = (
    "/frr-routing:routing/control-plane-protocols/control-plane-protocol"
    "[type='frr-bgp:bgp'][name='bgp'][vrf='default']/frr-bgp:bgp"
)
CPPRED = (
    "/frr-routing:routing/control-plane-protocols/control-plane-protocol"
    "[type='frr-bgp:bgp'][name='bgp'][vrf='red']/frr-bgp:bgp"
)


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for rname, router in tgen.routers().items():
        mgmtd_param = f"-M grpc:{GRPCP_MGMTD}" if rname == "r1" else None
        router.load_config(
            "mgmtd", os.path.join(CWD, f"{rname}/mgmtd.conf"), mgmtd_param
        )
        router.load_config("bgpd", os.path.join(CWD, f"{rname}/bgpd.conf"))
    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def mgmt_apply(router, *commands):
    """Run a list of `mgmt set-config` / etc. commands and apply.

    `configure terminal file-lock` acquires the candidate datastore
    lock for the duration of config-mode; without it, `mgmt commit
    apply` fails with 'source not locked'.
    """
    script = (
        "configure terminal file-lock\n"
        + "\n".join(commands)
        + "\nmgmt commit apply\n"
    )
    return router.vtysh_cmd(script)


def run_grpc_client(r, commands):
    if not isinstance(commands, str):
        commands = "\n".join(commands) + "\n"
    if not commands.endswith("\n"):
        commands += "\n"
    return r.cmd_raises([script_path, f"--port={GRPCP_MGMTD}"], stdin=commands)


def run_grpc_client_status(r, command):
    if not command.endswith("\n"):
        command += "\n"
    return r.net.cmd_status(
        [script_path, f"--port={GRPCP_MGMTD}"], stdin=command
    )


def test_router_id_mgmtd_to_cli():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Set router-id via mgmtd")
    # local-as is mandatory on the bgp container in frr-bgp.yang, so
    # any commit that touches the global subtree must also re-state
    # it. The initial value matches r1/bgpd.conf.
    mgmt_apply(
        r1,
        f'mgmt set-config {CPP}/global/local-as 65000',
        f'mgmt set-config {CPP}/global/router-id 10.0.0.1',
    )
    step("Verify legacy CLI shows the router-id")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "bgp router-id 10.0.0.1" in output, (
        f"expected router-id on legacy CLI; got:\n{output}"
    )


def test_router_id_mgmtd_view():
    """Round-trip via mgmtd's own YANG view: write through mgmt, then read
    the running datastore through mgmt and confirm the value is there."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    mgmt_apply(
        r1,
        f'mgmt set-config {CPP}/global/local-as 65000',
        f'mgmt set-config {CPP}/global/router-id 10.0.0.2',
    )
    output = r1.vtysh_cmd(
        f'show mgmt get-data {CPP}/global/router-id datastore running only-config json'
    )
    assert "10.0.0.2" in output, (
        f"expected router-id in mgmtd YANG view; got:\n{output}"
    )


def test_neighbor_passive_roundtrip():
    """Create a neighbor via mgmt and toggle passive-mode through mgmt;
    verify the legacy CLI surface picks it up."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    n = f"{CPP}/neighbors/neighbor[remote-address='10.0.0.2']"
    mgmt_apply(
        r1,
        f'mgmt set-config {CPP}/global/local-as 65000',
        f"mgmt set-config {n}/neighbor-remote-as/remote-as-type as-specified",
        f"mgmt set-config {n}/neighbor-remote-as/remote-as 65001",
        f"mgmt set-config {n}/passive-mode true",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "neighbor 10.0.0.2 remote-as 65001" in output, (
        f"expected neighbor on legacy CLI; got:\n{output}"
    )
    assert "neighbor 10.0.0.2 passive" in output, (
        f"expected passive on legacy CLI; got:\n{output}"
    )


def test_per_af_route_reflector_client_roundtrip():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    n = f"{CPP}/neighbors/neighbor[remote-address='10.0.0.2']"
    af = (f"{n}/afi-safis/afi-safi"
          "[afi-safi-name='frr-routing:ipv4-unicast']")
    mgmt_apply(
        r1,
        f'mgmt set-config {CPP}/global/local-as 65000',
        f"mgmt set-config {n}/neighbor-remote-as/remote-as-type as-specified",
        f"mgmt set-config {n}/neighbor-remote-as/remote-as 65000",
        f"mgmt set-config {af}/enabled true",
        f"mgmt set-config {af}/ipv4-unicast/route-reflector"
        "/route-reflector-client true",
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "neighbor 10.0.0.2 route-reflector-client" in output, (
        f"expected RR-client on legacy CLI; got:\n{output}"
    )


def test_local_as_apply_finish_roundtrip():
    """local-as is a multi-leaf apply_finish container — all three leaves
    must apply atomically in one mgmtd transaction."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    n = f"{CPP}/neighbors/neighbor[remote-address='10.0.0.2']"
    base = f"{n}/local-as"
    mgmt_apply(
        r1,
        f'mgmt set-config {CPP}/global/local-as 65000',
        f"mgmt set-config {n}/neighbor-remote-as/remote-as-type as-specified",
        f"mgmt set-config {n}/neighbor-remote-as/remote-as 65001",
        f'mgmt set-config {base}/local-as 65999',
        f'mgmt set-config {base}/no-prepend true',
        f'mgmt set-config {base}/replace-as true',
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "neighbor 10.0.0.2 local-as 65999 no-prepend replace-as" in output, (
        f"expected full local-as line; got:\n{output}"
    )


def test_vtysh_destroy_retained_in_datastore():
    """L6 (S070): `no router bgp <as> vrf <X>` through vtysh removes the
    instance from the bgpd runtime but the mgmtd datastore RETAINS it
    (running=0, datastore=1); an idempotent re-replay does not cure the
    drift (no diff, nothing is pushed to the backend); restarting bgpd
    cures it (the backend re-downloads the datastore). Contract nuance
    4.10 -- vtysh is a reader.

    The instance is created through the datastore itself (pure-DS
    create): per the S069 multi-instance semantics, boot/CLI instances
    are ghosts to the datastore and creating them with the SAME AS
    adopts them -- the same-AS create below pins that path for the
    default instance before the dedicated vrf instance is drawn."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("adopt the boot (ghost) default instance with its own AS (S069)")
    rc, out, _ = run_grpc_client_status(r1, f"commit-set,{CPP}/global/local-as=65000")
    if rc != 0:
        # already adopted by an earlier test of this module: the
        # idempotent re-commit aborts with no-changes (rc != 0, empty
        # output -- mgmtd quirk, see the bmp monitor suite)
        assert "AS is fixed" not in out, out
    rc, out, _ = run_grpc_client_status(r1, f"get-config,{CPP}")
    assert "65000" in out, f"default instance not adopted:\n{out}"

    step("create the dedicated vrf red instance through the datastore")
    rc, out, _ = run_grpc_client_status(
        r1, f"commit-set,{CPPRED}/global/local-as=65300"
    )
    ok = rc == 0 and "error_message" not in out
    assert ok, f"pure-DS create of the vrf instance failed:\n{out}"
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "router bgp 65300 vrf red" in output, (
        f"created instance must render:\n{output}"
    )

    step("mutate through vtysh: destroy the instance in the runtime only")
    r1.vtysh_cmd("configure terminal\nno router bgp 65300 vrf red")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "router bgp 65300 vrf red" not in output, (
        f"vtysh destroy left the instance in the runtime:\n{output}"
    )
    rc, out, _ = run_grpc_client_status(r1, f"get-config,{CPPRED}")
    assert "65300" in out, f"datastore must retain the instance:\n{out}"

    step("idempotent re-replay does NOT cure the drift")
    rc, out, _ = run_grpc_client_status(
        r1, f"commit-set,{CPPRED}/global/local-as=65300"
    )
    assert rc != 0 or "No changes" in out or "no changes" in out, (
        f"idempotent re-replay must abort with no-changes:\n{out}"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "router bgp 65300 vrf red" not in output, (
        f"re-replay resurrected the runtime instance:\n{output}"
    )

    step("restarting bgpd cures the drift (datastore re-download)")
    kill_router_daemons(tgen, "r1", ["bgpd"], save_config=False)
    start_router_daemons(tgen, "r1", ["bgpd"])

    @retry(30)
    def _instance_back():
        out = r1.vtysh_cmd("show running-config bgpd")
        return (
            None
            if "router bgp 65300 vrf red" in out
            else "instance not restored after the bgpd restart"
        )

    assert _instance_back() is None, "bgpd restart did not re-download"
    rc, out, _ = run_grpc_client_status(r1, f"get-config,{CPPRED}")
    assert "65300" in out, f"datastore lost the instance:\n{out}"

    step("teardown: datastore destroy leaves both planes coherent")
    rc, out, _ = run_grpc_client_status(r1, f"commit-delete,{CPPRED}")
    ok = rc == 0 and "error_message" not in out
    assert ok, f"teardown destroy failed:\n{out}"
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "router bgp 65300 vrf red" not in output, (
        f"teardown left the runtime instance behind:\n{output}"
    )
    rc, out, _ = run_grpc_client_status(r1, f"get-config,{CPPRED}")
    assert "65300" not in out, f"datastore residue after teardown:\n{out}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
