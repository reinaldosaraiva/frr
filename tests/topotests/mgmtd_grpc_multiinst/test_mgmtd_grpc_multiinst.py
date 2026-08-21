# SPDX-License-Identifier: ISC
"""
Verifies the multi-instance semantics of the mgmtd gRPC bridge
discovered by the S069 D0 investigation: instances created outside
the datastore (boot frr.conf parse or legacy CLI) are ghosts to the
datastore; adopting them with the SAME AS is tolerated, changing the
AS through the datastore is guarded, and once adopted the instance
lifecycle (destroy/recreate cycles, multi-delete) is stable. The
suite boots r1 with an integrated frr.conf holding TWO bgp instances
(default AS 65000, vrf red AS 65300) that only bgpd parses -- the
mgmtd datastore boots empty (per-daemon config files only).
"""
import os
import sys

import pytest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

GRPCP_MGMTD = 50072
script_path = os.path.realpath(os.path.join(CWD, "../lib/grpc-query.py"))

pytestmark = [pytest.mark.bgpd, pytest.mark.mgmtd]

CPP = (
    "/frr-routing:routing/control-plane-protocols/control-plane-protocol"
    "[type='frr-bgp:bgp'][name='bgp'][vrf='default']/frr-bgp:bgp"
)
CPPRED = (
    "/frr-routing:routing/control-plane-protocols/control-plane-protocol"
    "[type='frr-bgp:bgp'][name='bgp'][vrf='red']/frr-bgp:bgp"
)

topodef = {"s1": ("r1",)}


def build_topo(tgen):
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    router = tgen.gears["r1"]
    router.load_frr_config("frr.conf")
    router.load_config(TopoRouter.RD_MGMTD, "", f"-M grpc:{GRPCP_MGMTD}")
    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


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


def test_ghost_instance_as_guard():
    """A boot-created instance is invisible to the datastore: the
    delete of the never-adopted node fails the EditCandidate (F1b)
    and a create with a DIFFERENT AS is guarded ("instance AS is
    fixed at creation") leaving runtime and datastore untouched."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    step("the boot instance lives in the runtime only")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "router bgp 65300 vrf red" in output, (
        f"boot instance missing from the runtime:\n{output}"
    )
    rc, out, _ = run_grpc_client_status(r1, f"get-config,{CPPRED}")
    assert "65300" not in out, (
        f"datastore must not track the boot instance yet:\n{out}"
    )

    step("NEG: delete of the datastore-absent node fails (F1b)")
    rc, out, _ = run_grpc_client_status(r1, f"commit-delete,{CPPRED}")
    rejected = rc != 0 or "Failed to remove" in out
    assert rejected, f"ghost delete must fail the candidate:\n{out}"
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "router bgp 65300 vrf red" in output, (
        f"rejected delete must not tear the runtime down:\n{output}"
    )

    step("NEG: create with a different AS is guarded")
    rc, out, _ = run_grpc_client_status(
        r1, f"commit-set,{CPPRED}/global/local-as=65400"
    )
    rejected = rc != 0 or "error_message" in out
    assert rejected, f"AS change through the datastore must fail:\n{out}"
    if "error_message" in out:
        assert "AS is fixed" in out, f"expected the AS guard:\n{out}"
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "router bgp 65300 vrf red" in output, (
        f"guarded create must not touch the runtime:\n{output}"
    )
    rc, out, _ = run_grpc_client_status(r1, f"get-config,{CPPRED}")
    assert "65400" not in out, f"guarded create left DS residue:\n{out}"


def test_ghost_instance_adoption_same_as():
    """Creating the boot instance in the datastore with the SAME AS
    is tolerated (get-or-create): the datastore adopts the instance
    and leaves under its afi-safis become programmable."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    step("adopt the boot instance with its own AS")
    rc, out, _ = run_grpc_client_status(
        r1, f"commit-set,{CPPRED}/global/local-as=65300"
    )
    ok = rc == 0 and "error_message" not in out
    assert ok, f"same-AS adoption must be a clean success:\n{out}"
    rc, out, _ = run_grpc_client_status(r1, f"get-config,{CPPRED}")
    assert "65300" in out, f"adopted instance missing from the DS:\n{out}"

    step("leaves under the adopted instance's afi-safis land")
    AGG = (
        f"{CPPRED}/global/afi-safis"
        "/afi-safi[afi-safi-name='frr-routing:ipv4-unicast']"
        "/ipv4-unicast/aggregate-route[prefix='10.5.0.0/16']"
    )
    run_grpc_client(r1, f"commit-set,{AGG}/as-set=true")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "aggregate-address 10.5.0.0/16 as-set" in output, (
        f"adopted instance leaf must render:\n{output}"
    )

    step("the default instance stays unadopted by this test")
    rc, out, _ = run_grpc_client_status(r1, f"get-config,{CPP}")
    assert "65400" not in out, f"unexpected residue:\n{out}"


def test_adopted_instance_destroy_recreate_cycles():
    """Once adopted, teardown/create cycles of the instance through
    the datastore are stable (no wedge): the S069 answer to the
    bench-Run-2 wedge class."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    for i in range(3):
        rc1, o1, _ = run_grpc_client_status(r1, f"commit-delete,{CPPRED}")
        rc2, o2, _ = run_grpc_client_status(
            r1, f"commit-set,{CPPRED}/global/local-as=65300"
        )
        ok = (
            rc1 == 0
            and rc2 == 0
            and "error_message" not in o1
            and "error_message" not in o2
        )
        assert ok, f"cycle {i} must be clean:\n{o1}\n{o2}"

    output = r1.vtysh_cmd("show running-config bgpd")
    assert "router bgp 65300 vrf red" in output, (
        f"instance must be back after the cycles:\n{output}"
    )


def test_multi_delete_two_instances_one_commit():
    """A single commit deleting BOTH instances (default and vrf) then
    re-creating them in a single commit is coherent: the multi-delete
    quirk class of the D0 family is stable on the current head."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    rc1, out1, _ = run_grpc_client_status(
        r1, f"commit-set,{CPP}/global/local-as=65000"
    )
    ok = rc1 == 0 and "error_message" not in out1
    assert ok, f"default adoption must succeed:\n{out1}"

    step("one commit tearing both instances down")
    rc, out, _ = run_grpc_client_status(
        r1, f"commit-delete,{CPPRED},{CPP}"
    )
    ok = rc == 0 and "error_message" not in out
    assert ok, f"multi-delete must be a clean success:\n{out}"
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "router bgp 65300 vrf red" not in output, (
        f"multi-delete left the vrf instance behind:\n{output}"
    )

    step("both instances come back in a single commit")
    rc, out, _ = run_grpc_client_status(
        r1,
        f"commit-set,{CPP}/global/local-as=65000,"
        f"{CPPRED}/global/local-as=65300",
    )
    ok = rc == 0 and "error_message" not in out
    assert ok, f"recreate after multi-delete must succeed:\n{out}"
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "router bgp 65300 vrf red" in output, (
        f"recreate after multi-delete failed:\n{output}"
    )
    rc, out, _ = run_grpc_client_status(r1, f"get-config,{CPPRED}")
    assert "65300" in out, f"datastore lost the recreated instance:\n{out}"
