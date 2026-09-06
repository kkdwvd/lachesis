#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Write a rust-project.json for rust-analyzer, driven by rules.mk.

There is no Cargo workspace: every crate here is built by bare rustc (see
rules.mk), so rust-project.json is the only way rust-analyzer can see them.
This script only assembles the crate graph and its dependency edges; every
path it is given comes from rules.mk's own variables (RUSTC's sysroot,
LIB_CRATES and its per-crate _DIR, the btf/btf_macros/verus_builtin_macros
locations, PROG and SRC), so there is nothing to keep in sync by hand.

Dependency edges, not otherwise derivable from LIB_CRATES order alone:
each library crate depends on btf, btf_macros and verus_builtin_macros (the
--extern flags rules.mk's erased-compile rule passes to every one of them)
plus every earlier crate in LIB_CRATES; the policy depends on every crate in
LIB_CRATES plus verus_builtin_macros.
"""

import argparse
import json
import sys


def parse_spec(spec, n, what):
    parts = spec.split(":", n - 1)
    if len(parts) != n:
        sys.exit(f"{what}: expected {n} ':'-separated fields, got {spec!r}")
    return parts


class CrateGraph:
    def __init__(self):
        self.crates = []
        self.index_of = {}

    def add(self, name, root_module, edition, deps=(), proc_macro_dylib=None,
            is_workspace_member=True):
        entry = {
            "display_name": name,
            "root_module": root_module,
            "edition": edition,
            "deps": [{"crate": self.index_of[d], "name": d} for d in deps],
            "cfg": [],
        }
        if proc_macro_dylib is not None:
            entry["is_proc_macro"] = True
            entry["proc_macro_dylib_path"] = proc_macro_dylib
        entry["is_workspace_member"] = is_workspace_member
        self.index_of[name] = len(self.crates)
        self.crates.append(entry)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sysroot", required=True)
    p.add_argument("--sysroot-src", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--btf", required=True, metavar="NAME:ROOT_MODULE:EDITION")
    p.add_argument("--btf-macros", required=True,
                    metavar="NAME:ROOT_MODULE:EDITION:DYLIB")
    p.add_argument("--verus-macros", required=True,
                    metavar="NAME:ROOT_MODULE:EDITION:DYLIB")
    p.add_argument("--lib-crate", action="append", default=[],
                    metavar="NAME:ROOT_MODULE:EDITION",
                    help="one per LIB_CRATES entry, in dependency order")
    p.add_argument("--policy", required=True,
                    metavar="NAME:ROOT_MODULE:EDITION")
    args = p.parse_args()

    graph = CrateGraph()

    name, root, edition = parse_spec(args.btf, 3, "--btf")
    graph.add(name, root, edition)
    btf = name

    name, root, edition, dylib = parse_spec(args.btf_macros, 4, "--btf-macros")
    graph.add(name, root, edition, proc_macro_dylib=dylib,
              is_workspace_member=False)
    btf_macros = name

    name, root, edition, dylib = parse_spec(args.verus_macros, 4,
                                             "--verus-macros")
    graph.add(name, root, edition, proc_macro_dylib=dylib,
              is_workspace_member=False)
    verus_builtin_macros = name

    lib_crates = []
    for spec in args.lib_crate:
        name, root, edition = parse_spec(spec, 3, "--lib-crate")
        graph.add(name, root, edition,
                  deps=lib_crates + [btf, btf_macros, verus_builtin_macros])
        lib_crates.append(name)

    name, root, edition = parse_spec(args.policy, 3, "--policy")
    graph.add(name, root, edition, deps=lib_crates + [verus_builtin_macros])

    with open(args.out, "w") as f:
        json.dump({
            "sysroot": args.sysroot,
            "sysroot_src": args.sysroot_src,
            "crates": graph.crates,
        }, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main()
