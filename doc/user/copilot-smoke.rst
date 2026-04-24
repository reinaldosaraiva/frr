.. _copilot-smoke:

Copilot Port Smoke
==================

This file exists only to exercise the doc/user/** Copilot instruction
on length cap (~30 lines of inline prose in a single burst). It is
marked DELETE ON CLOSE and should never reach master.

Overview
--------

FRR ships a number of daemons that together form a full routing
stack. Each daemon handles one or more routing protocols. The
daemons communicate via a shared library (libfrr), a management
frontend (mgmtd), and a southbound that speaks a mix of Netlink,
YANG over gRPC/Netconf, and vendor-specific SDKs. Historically the
surface was CLI-first, with each daemon exposing its own vty
interpreter. Over the last few release cycles the project has been
shifting toward a YANG-centric model where mgmtd is the single
configuration broker and daemons register as backends.

The transition is not complete. Several daemons still carry legacy
vty paths in parallel with their YANG frontends, and a subset of the
legacy paths remain the only way to reach certain configuration
corners. Documentation that covers both paths at once tends to grow
long, because any statement about "how to set X" has to fork into
"via vtysh" and "via YANG". That is the pattern this file is
deliberately exhibiting: five paragraphs of conceptual framing with
no command example, no CLI reference, no migration checkpoint, and
no URL to docs.frrouting.org for the underlying concepts. Each of
those missing elements is something a reviewer or a user would
actually want before scrolling past paragraph two.

Expected Finding
----------------

Copilot should flag this block as exceeding the ~30-line cap
(see .github/instructions/doc-user.instructions.md), with a
recommendation to link to docs.frrouting.org or move rationale into
the commit message. A secondary P3 finding may note that the
conceptual content belongs in the developer handbook, not user
docs, since it describes architecture rather than tasks an operator
performs.
