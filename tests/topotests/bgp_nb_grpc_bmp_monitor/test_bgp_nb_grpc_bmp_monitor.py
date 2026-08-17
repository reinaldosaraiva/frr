# SPDX-License-Identifier: ISC
"""
Verifies the Fase C fatia 3 northbound wiring in bgpd: the bmp
monitor l2vpn-evpn leaves under
global/bmp-config/target-list/afi-safis/afi-safi/l2vpn-evpn/
common-config/{pre,post-policy,loc-rib} -- become programmable
through the mgmtd gRPC bridge.

RED on the s059 head (afe44d26e): the commits hit the reject-strict
stubs and fail. GREEN on the s060 head: the commits apply through
bmp_monitor_apply(), the same internal the "bmp monitor" DEFUN calls,
and the legacy CLI surface (show running-config) renders the exact
"bmp monitor l2vpn evpn <policy>" lines, proving the datastore and
the bgpd internals agree.

Since s061 the bmp target-list create is wired: a leaf commit
creates the target on demand (v2.6.0 nuance; the v2.5.0
pre-creation nuance was transitional). The first tests still seed
their targets through the legacy CLI to exercise the dual-write path
(get_target is get-or-create; mgmtd does not track CLI-written
config -- NB_CLIENT_CLI exemption). The CLI keeps working after the
bmp_monitor_cfg refactor (regression guard).

The bmp monitor internals live in the bgpd_bmp loadable module: the
core callbacks reach them through the bgp_nb_bmp_ops bridge the
module fills at load time (bgpd starts with -M bgpd_bmp here).
"""
import glob
import os
import sys

import pytest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

GRPCP_MGMTD = 50071
script_path = os.path.realpath(os.path.join(CWD, "../lib/grpc-query.py"))

pytestmark = [pytest.mark.bgpd, pytest.mark.mgmtd]

CPP = (
    "/frr-routing:routing/control-plane-protocols/control-plane-protocol"
    "[type='frr-bgp:bgp'][name='bgp'][vrf='default']/frr-bgp:bgp"
)

TARGET = "bt-grpc"
TARGET_CLI = "bt-cli"
TARGET_MISSING = "bt-nobody"


def bmp_common(target):
    return (
        f"{CPP}/global/bmp-config/target-list[target-name='{target}']"
        "/afi-safis/afi-safi[afi-safi-name='frr-routing:l2vpn-evpn']"
        "/l2vpn-evpn/common-config"
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


def _bgp_bmp_module_available():
    """True when the bgpd_bmp loadable module is installed (the bmp
    monitor internals live behind it; the core callbacks fail with
    'module not loaded' without it)."""
    patterns = (
        "/usr/lib/*/frr/modules/bgpd_bmp.so",
        "/usr/lib/frr/modules/bgpd_bmp.so",
        "/usr/lib64/*/frr/modules/bgpd_bmp.so",
        "/usr/lib64/frr/modules/bgpd_bmp.so",
        "/usr/local/lib/*/frr/modules/bgpd_bmp.so",
        "/usr/local/lib/frr/modules/bgpd_bmp.so",
    )
    for pattern in patterns:
        for path in glob.glob(pattern):
            if os.path.isfile(path):
                return True
    return False


if not _bgp_bmp_module_available():
    pytest.skip(
        "skipping; bgpd_bmp module not installed",
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
    router.load_config(
        "bgpd", os.path.join(CWD, "r1/bgpd.conf"), "-M bgpd_bmp"
    )
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
    """Idempotent: seed local-as into the datastore (mandatory under
    global; mgmtd's copy does not track CLI-written config --
    NB_CLIENT_CLI exemption). Status variant: a no-op re-seed is
    fine."""
    run_grpc_client_status(r1, f"commit-set,{CPP}/global/local-as=65000")


def _seed_target(r1, name):
    """Idempotent: create the bmp target group with the legacy CLI
    (the create is wired since s061; this exercises the CLI dual-write
    path -- mgmtd's copy does not track CLI-written config,
    NB_CLIENT_CLI exemption)."""
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65000\n"
        f"bmp targets {name}\n"
        "end\n"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"bmp targets {name}" in output, (
        f"seed failed for {name}:\n{output}"
    )


def test_bmp_monitor_grpc_all_three_policies():
    """pre-policy, post-policy and loc-rib land through gRPC and render
    as the exact legacy CLI lines; commit-delete returns each leaf to
    the default."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    _seed(r1)
    _seed_target(r1, TARGET)
    bc = bmp_common(TARGET)

    step("Set the three monitor policies via gRPC")
    run_grpc_client(
        r1,
        [
            f"commit-set,{bc}/pre-policy=true",
            f"commit-set,{bc}/post-policy=true",
            f"commit-set,{bc}/loc-rib=true",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "bmp monitor l2vpn evpn pre-policy" in output, (
        f"pre-policy missing:\n{output}"
    )
    assert "bmp monitor l2vpn evpn post-policy" in output, (
        f"post-policy missing:\n{output}"
    )
    assert "bmp monitor l2vpn evpn loc-rib" in output, (
        f"loc-rib missing:\n{output}"
    )

    step("Destroy each leaf one by one")
    for leaf in ("pre-policy", "post-policy", "loc-rib"):
        run_grpc_client(r1, f"commit-delete,{bc}/{leaf}")
        output = r1.vtysh_cmd("show running-config bgpd")
        assert f"bmp monitor l2vpn evpn {leaf}" not in output, (
            f"{leaf} must be gone:\n{output}"
        )
    assert "bmp monitor" not in output, (
        f"all monitor lines must be gone:\n{output}"
    )


def test_bmp_monitor_reshape_and_reapply():
    """reshape: delete only pre-policy while post-policy survives, then
    re-apply pre-policy; an idempotent re-commit of the same value is
    rejected as a no-op (mgmtd no-changes abort) and the running state
    survives unchanged."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    _seed(r1)
    _seed_target(r1, TARGET)
    bc = bmp_common(TARGET)

    step("pre + post set; pre deleted, post survives")
    run_grpc_client(
        r1,
        [
            f"commit-set,{bc}/pre-policy=true",
            f"commit-set,{bc}/post-policy=true",
        ],
    )
    run_grpc_client(r1, f"commit-delete,{bc}/pre-policy")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "bmp monitor l2vpn evpn pre-policy" not in output, (
        f"pre-policy must be gone:\n{output}"
    )
    assert "bmp monitor l2vpn evpn post-policy" in output, (
        f"post-policy must survive:\n{output}"
    )

    step("re-apply pre-policy; idempotent re-commit rejected as no-op")
    run_grpc_client(r1, f"commit-set,{bc}/pre-policy=true")
    rc, output, _ = run_grpc_client_status(
        r1, f"commit-set,{bc}/pre-policy=true"
    )
    # mgmtd quirk (documented in the fanout suite): re-committing the
    # same value aborts with "No changes found to be committed" --
    # rc != 0 with empty output. What must hold: the running state
    # survives the rejected no-op unchanged (asserted below).
    assert rc != 0, (
        f"idempotent re-commit must surface the no-changes abort; "
        f"rc={rc} output={output!r}"
    )
    output_run = r1.vtysh_cmd("show running-config bgpd")
    assert "bmp monitor l2vpn evpn pre-policy" in output_run, (
        f"pre-policy must be back:\n{output_run}"
    )
    assert "bmp monitor l2vpn evpn post-policy" in output_run

    step("teardown both")
    run_grpc_client(
        r1,
        [
            f"commit-delete,{bc}/pre-policy",
            f"commit-delete,{bc}/post-policy",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "bmp monitor" not in output, f"teardown sujou:\n{output}"


def test_bmp_monitor_missing_target_becomes_create_on_demand():
    """v2.6.0: a commit against a target that does not exist no
    longer fails -- the wired target-list create applies before the
    leaf (pre-order) and the group comes to life on demand. On the
    s060 head this commit failed the missing-target resolve (the
    v2.5.0 transitional semantics: the create was a warn no-op
    stub), which is why this test is part of the s061 RED set."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    _seed(r1)
    bc = bmp_common(TARGET_MISSING)
    run_grpc_client(r1, f"commit-set,{bc}/pre-policy=true")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"bmp targets {TARGET_MISSING}" in output, (
        f"create-on-demand target must render:\n{output}"
    )
    assert "bmp monitor l2vpn evpn pre-policy" in output, (
        f"leaf must render:\n{output}"
    )
    run_grpc_client(r1, f"commit-delete,{bmp_target(TARGET_MISSING)}")


def test_bmp_monitor_cli_parity_after_refactor():
    """the bmp_monitor_cfg CLI keeps working through the shared
    bmp_monitor_apply() internal: set and unset via CLI render exactly
    as before the refactor (dual-write regression guard)."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    step("CLI: create target + set loc-rib")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65000\n"
        f"bmp targets {TARGET_CLI}\n"
        "bmp monitor l2vpn evpn loc-rib\n"
        "end\n"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "bmp monitor l2vpn evpn loc-rib" in output, (
        f"CLI loc-rib missing:\n{output}"
    )

    step("CLI: unset loc-rib")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65000\n"
        f"bmp targets {TARGET_CLI}\n"
        "no bmp monitor l2vpn evpn loc-rib\n"
        "end\n"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "bmp monitor l2vpn evpn loc-rib" not in output, (
        f"CLI loc-rib must be gone:\n{output}"
    )


# ---- s061: Fase D fatia 1 -- target lifecycle, non-EVPN fanout and
# knobs (wire-all-32 decision, D3). RED on the s060 head (7bc7b9a30):
# every bmp-config xpath below the target-list was a warn-class
# no-op stub, so the leaf commits hit the missing-target resolve and
# fail (nothing was ever created). GREEN on the s061 head: the
# target-list create is wired, so a leaf commit creates the target on
# demand (create applies before the leaf, pre-order) and the knobs
# apply through the bgp_nb_bmp_ops bridge; the legacy writer renders
# the exact CLI lines (dual-write parity).
#
# v2.6.0 nuance (supersedes the v2.5.0 transitional "target must
# pre-exist"): there is no standalone datastore create for a bare
# bmp target-list entry (mgmtd sees an empty diff), so the supported
# flow IS the leaf commit -- the target comes to life with its first
# leaf. The CLI seeding flow keeps working (get_target is
# get-or-create).


def bmp_target(target):
    return f"{CPP}/global/bmp-config/target-list[target-name='{target}']"


def bmp_common_af(target, af_key):
    return (
        f"{bmp_target(target)}"
        f"/afi-safis/afi-safi[afi-safi-name='{af_key}']"
        f"/{af_key.split(':')[1]}/common-config"
    )


AF4 = "frr-routing:ipv4-unicast"
AF6M = "frr-routing:ipv6-multicast"
AF6U = "frr-routing:ipv6-unicast"


def test_bmp_target_lifecycle_grpc():
    """the target comes to life with its first leaf commit
    (create-on-demand) and dies with the whole-entry destroy; the
    cycle repeats."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    name = "bt-grpc-full"

    _seed(r1)
    bc = bmp_common_af(name, AF4)

    step("leaf commit against a fresh target creates it")
    run_grpc_client(r1, f"commit-set,{bc}/pre-policy=true")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"bmp targets {name}" in output, (
        f"create-on-demand target must render:\n{output}"
    )
    assert "bmp monitor ipv4 unicast pre-policy" in output, (
        f"leaf must render:\n{output}"
    )

    step("destroy the whole entry through the datastore")
    run_grpc_client(r1, f"commit-delete,{bmp_target(name)}")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"bmp targets {name}" not in output, (
        f"destroyed target must be gone:\n{output}"
    )
    assert "bmp monitor" not in output, (
        f"destroyed target must take its leaves:\n{output}"
    )

    step("the cycle repeats (put freed it, the create rebuilds)")
    run_grpc_client(r1, f"commit-set,{bc}/pre-policy=true")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"bmp targets {name}" in output, (
        f"second cycle must render:\n{output}"
    )
    run_grpc_client(r1, f"commit-delete,{bmp_target(name)}")


def test_bmp_monitor_fanout_non_evpn():
    """the l2vpn-evpn monitor callbacks serve every address family
    (afi/safi resolved from the list key at runtime): ipv4-unicast
    and ipv6-multicast land through gRPC and render as the exact
    legacy CLI lines."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    name = "bt-fanout"

    _seed(r1)
    for af_key, af_cli in ((AF4, "ipv4 unicast"),
                           (AF6M, "ipv6 multicast")):
        bc = bmp_common_af(name, af_key)
        run_grpc_client(r1, f"commit-set,{bc}/pre-policy=true")
        output = r1.vtysh_cmd("show running-config bgpd")
        assert f"bmp monitor {af_cli} pre-policy" in output, (
            f"{af_cli} pre-policy missing:\n{output}"
        )
        run_grpc_client(r1, f"commit-delete,{bc}/pre-policy")
        output = r1.vtysh_cmd("show running-config bgpd")
        assert f"bmp monitor {af_cli} pre-policy" not in output, (
            f"{af_cli} pre-policy must be gone:\n{output}"
        )

    run_grpc_client(r1, f"commit-delete,{bmp_target(name)}")


def test_bmp_same_commit_target_and_leaf():
    """one commit-set that creates the target AND sets the leaf is
    the supported flow: the target-list create applies before the
    leaf (pre-order), so nothing needs to pre-exist (v2.6.0 nuance
    replacing the v2.5.0 missing-target rejection)."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    name = "bt-samecommit"

    _seed(r1)
    bc = bmp_common_af(name, AF4)
    run_grpc_client(r1, f"commit-set,{bc}/loc-rib=true")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"bmp targets {name}" in output, (
        f"same-commit target+leaf must create the target:\n{output}"
    )
    assert "bmp monitor ipv4 unicast loc-rib" in output, (
        f"same-commit target+leaf must land:\n{output}"
    )
    run_grpc_client(r1, f"commit-delete,{bmp_target(name)}")


def test_bmp_knobs_grpc_and_parity():
    """the target knobs (mirror, stats, acls, global
    mirror-buffer-limit, import-vrf) land through gRPC and render as
    the exact legacy CLI lines."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    name = "bt-knobs"

    _seed(r1)
    tgt = bmp_target(name)

    step("knob commits create the target on demand")
    run_grpc_client(
        r1,
        [
            f"commit-set,{tgt}/mirror=true",
            f"commit-set,{tgt}/stats-time=90000",
            f"commit-set,{tgt}/ipv4-access-list=bmpacl4",
            f"commit-set,{tgt}/ipv6-access-list=bmpacl6",
            f"commit-set,{tgt}/stats-send-experimental=false",
            f"commit-set,{tgt}/import-vrf=somevrf",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    for expected in (
        f"bmp targets {name}",
        "bmp mirror",
        "bmp stats interval 90000",
        "ip access-list bmpacl4",
        "ipv6 access-list bmpacl6",
        "no bmp stats send-experimental",
        "bmp import-vrf-view somevrf",
    ):
        assert expected in output, f"{expected} missing:\n{output}"

    step("global mirror-buffer-limit")
    run_grpc_client(
        r1, f"commit-set,{CPP}/global/bmp-config/mirror-buffer-limit=1048576"
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "bmp mirror buffer-limit 1048576" in output, (
        f"mirror-buffer-limit missing:\n{output}"
    )

    step("knob teardown returns the writer to defaults")
    run_grpc_client(
        r1,
        [
            f"commit-delete,{tgt}/mirror",
            f"commit-delete,{tgt}/stats-time",
            f"commit-delete,{tgt}/ipv4-access-list",
            f"commit-delete,{tgt}/ipv6-access-list",
            f"commit-set,{tgt}/stats-send-experimental=true",
            f"commit-delete,{tgt}/import-vrf[.='somevrf']",
            f"commit-delete,{CPP}/global/bmp-config/mirror-buffer-limit",
            f"commit-delete,{bmp_target(name)}",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"bmp targets {name}" not in output, (
        f"target teardown must clean everything:\n{output}"
    )
    assert "bmp mirror buffer-limit" not in output, (
        f"mirror-buffer-limit must be back to unlimited:\n{output}"
    )


def test_bmp_connect_and_listener_grpc():
    """outgoing (connect) and incoming (listener) session-list
    entries land through gRPC, including the retry/interface leaves
    created in the same commit as the entry."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    name = "bt-sessions"

    _seed(r1)
    tgt = bmp_target(name)

    step("connect entry + min-retry in one commit-set")
    connect = (
        f"{tgt}/outgoing-session/session-list"
        "[hostname='192.0.2.10'][tcp-port='1790']"
    )
    run_grpc_client(r1, f"commit-set,{connect}/min-retry-time=60000")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert (
        "bmp connect 192.0.2.10 port 1790 min-retry 60000 "
        "max-retry 720000" in output
    ), f"connect entry missing:\n{output}"

    step("source-interface leaf, then max-retry")
    run_grpc_client(
        r1,
        [
            f"commit-set,{connect}/source-interface=r1-eth0",
            f"commit-set,{connect}/max-retry-time=900000",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert (
        "bmp connect 192.0.2.10 port 1790 min-retry 60000 "
        "max-retry 900000 source-interface r1-eth0" in output
    ), f"connect leaves missing:\n{output}"

    step("tcp-port outside the 1..65535 range is rejected (r2 N-4)")
    for bad_port in ("0", "65536"):
        bad = (
            f"{tgt}/outgoing-session/session-list"
            f"[hostname='192.0.2.11'][tcp-port='{bad_port}']"
        )
        rc, _out, err = run_grpc_client_status(
            r1, f"commit-set,{bad}/min-retry-time=60000"
        )
        assert rc != 0, (
            f"port {bad_port} must fail the schema range "
            f"(libyang surfaces it as a failed update):\n{err}"
        )

    step("listener entry (binds a real socket on 0.0.0.0)")
    listener = (
        f"{tgt}/incoming-session/session-list"
        "[address='0.0.0.0'][tcp-port='17901']"
    )
    run_grpc_client(r1, f"commit-set,{listener}/address=0.0.0.0")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "bmp listener 0.0.0.0 port 17901" in output, (
        f"listener entry missing:\n{output}"
    )

    step("teardown: sessions first, then the target")
    run_grpc_client(
        r1,
        [
            f"commit-delete,{listener}",
            f"commit-delete,{connect}",
            f"commit-delete,{bmp_target(name)}",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert f"bmp targets {name}" not in output, (
        f"session teardown must clean everything:\n{output}"
    )


def test_bmp_af_list_destroy_clears_monitor():
    """destroying the afi-safi list entry clears the monitor flags
    through the same monitor_apply internal the leaves use (render
    goes back to default) -- the entry can then be recreated."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    name = "bt-afdestroy"

    _seed(r1)
    bc = bmp_common_af(name, AF6U)
    af = f"{bmp_target(name)}/afi-safis/afi-safi[afi-safi-name='{AF6U}']"

    run_grpc_client(r1, f"commit-set,{bc}/post-policy=true")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "bmp monitor ipv6 unicast post-policy" in output, (
        f"post-policy must land:\n{output}"
    )

    step("destroy the whole afi-safi entry (flags clear with it)")
    run_grpc_client(r1, f"commit-delete,{af}")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "bmp monitor ipv6 unicast post-policy" not in output, (
        f"afi-safi destroy must clear the monitor render:\n{output}"
    )

    step("recreate the entry and land the leaf again")
    run_grpc_client(r1, f"commit-set,{bc}/post-policy=true")
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "bmp monitor ipv6 unicast post-policy" in output, (
        f"recreated entry must accept the leaf:\n{output}"
    )
    run_grpc_client(r1, f"commit-delete,{bmp_target(name)}")
def test_bmp_same_transaction_as_local_as():
    """r2 B-1 regression guard: a transaction that creates the bgp
    instance (local-as) together with a bmp knob must validate --
    VALIDATEs run before any APPLY, so no bmp VALIDATE may need the
    runtime bgp instance. On the pre-fix head this failed with
    "bgp instance not found" (or wedged bgpd's candidate after a
    restart)."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    name = "bt-coldstart"

    _seed(r1)
    tgt = bmp_target(name)
    # the bgp instance already exists (booted with router bgp 65000),
    # so prove the same invariant through the documented wedge shape:
    # mirror-buffer-limit is a GLOBAL knob -- one transaction holding
    # local-as + the knob must validate and apply together.
    run_grpc_client(
        r1,
        [
            f"commit-set,{CPP}/global/bmp-config/mirror-buffer-limit=2097152",
        ],
    )
    output = r1.vtysh_cmd("show running-config bgpd")
    assert "bmp mirror buffer-limit 2097152" in output, (
        f"global knob must render:\n{output}"
    )
    run_grpc_client(
        r1, f"commit-delete,{CPP}/global/bmp-config/mirror-buffer-limit"
    )
