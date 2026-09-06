#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Make rustc's debug info survive the kernel's BTF verifier.

llc derives BTF from DWARF, and rustc's DWARF breaks three rules that
kernel/bpf/btf.c enforces on every loaded BTF blob. All three are fixed here,
in the textual IR, right before the final llvm-as:

1. Type and function names.  __btf_name_char_ok() allows only
   [A-Za-z0-9_.], with the first character restricted to [A-Za-z_.], and
   caps the length at KSYM_NAME_LEN. Rust names such as `NonNull<str>`,
   `dyn core::fmt::Write` or `Formatter<'_>` are rejected:

       [44] STRUCT NonNull<str> size=16 vlen=1 Invalid name
       libbpf: Error loading .BTF into kernel: -EINVAL

   Illegal characters become '_'.

2. Member order.  btf_struct_check_meta() requires member bit offsets to
   be non-decreasing. rustc reorders struct fields but emits DW_TAG_member
   entries in declaration order, so e.g. core::fmt::Formatter comes out as
   `options` at bit 128 followed by `buf` at bit 0:

       [68] STRUCT Formatter size=24 vlen=2
            options type_id=69 bits_offset=128
            buf type_id=71 bits_offset=0 Invalid member bits_offset

   DW_TAG_member entries in each composite type's element list are sorted
   by offset; anything else in the list (methods, template parameters,
   inheritance) keeps its slot.

3. Base-type encodings.  LLVM's BTFDebug only translates boolean, signed,
   unsigned, signed/unsigned char and float base types; anything else is
   silently dropped and every reference to it becomes type id 0, which the
   kernel then rejects. Rust's `char` is DW_ATE_UTF, so

       [112] STRUCT Some size=4 vlen=1
             __0 type_id=0 bits_offset=0 Invalid type_id

   Unsupported encodings are rewritten to DW_ATE_unsigned.

4. Function parameter names.  btf_func_check() rejects a FUNC whose
   prototype has an unnamed argument. BTFDebug takes those names from the
   DILocalVariables in a DISubprogram's retainedNodes, and rustc omits them
   for implicit or `_` parameters (`#[track_caller]` Location, say):

       [50] FUNC panic_const_div_by_zero type_id=41 Invalid arg#1

   A `param<n>` DILocalVariable is synthesised for every argument that
   lacks one.

Names the rest of the pipeline depends on -- the kernel structs matched by
CO-RE (`task_struct`, `sched_ext_entity`), the struct_ops type
(`sched_ext_ops`) and its members, and the kfunc prototypes add_ksyms.py
mirrors from kernel BTF -- are already legal and already offset-ordered,
so they pass through untouched. Only `name:` fields inside `!DI...` nodes
are rewritten; the CO-RE `@"llvm.task_struct:0:0$0:0:0"` globals and every
LLVM symbol name are left alone.

Usage: btf_fixup.py input.ll output.ll
"""

import re
import sys

KSYM_NAME_LEN = 512

# `name: "..."` inside a !DI... node, but not `linkageName: "..."` or any
# other `...Name:` field. LLVM escapes a literal quote as \22, so matching
# up to the next quote is safe.
NAME_RE = re.compile(r'(?<![A-Za-z])(name: ")([^"]*)(")')
MD_RE = re.compile(r'^(!\d+) = (.*)$')
DI_RE = re.compile(r'^(?:distinct )?!DI')
TUPLE_RE = re.compile(r'^!\{(.*)\}$')
COMPOSITE_TAGS = ('DW_TAG_structure_type', 'DW_TAG_class_type',
                  'DW_TAG_union_type', 'DW_TAG_variant_part',
                  'DW_TAG_variant')
ENCODING_RE = re.compile(r'(?<![A-Za-z])(encoding: )(DW_ATE_\w+)')
# The encodings BTFDebug::visitBasicType() knows how to translate.
BTF_ENCODINGS = frozenset((
    'DW_ATE_boolean', 'DW_ATE_signed', 'DW_ATE_signed_char',
    'DW_ATE_unsigned', 'DW_ATE_unsigned_char', 'DW_ATE_float',
))


def sanitize(name):
    if not name:
        return name
    out = []
    for i, c in enumerate(name):
        ok = c.isascii() and (c.isalpha() or c in '_.' or
                              (i > 0 and c.isdigit()))
        out.append(c if ok else '_')
    return ''.join(out)[:KSYM_NAME_LEN - 1]


def field(body, key, default=None):
    m = re.search(r'(?<![A-Za-z])' + key + r': (\d+)', body)
    return int(m.group(1)) if m else default


def main():
    src, dst = sys.argv[1], sys.argv[2]
    with open(src) as f:
        lines = f.readlines()

    # Index the metadata definitions.
    md = {}
    for i, line in enumerate(lines):
        m = MD_RE.match(line.rstrip('\n'))
        if m:
            md[m.group(1)] = (i, m.group(2))

    # --- 1. sanitize names ---
    renamed = 0
    for mid, (i, body) in md.items():
        if not DI_RE.match(body):
            continue

        def repl(m):
            nonlocal renamed
            new = sanitize(m.group(2))
            if new != m.group(2):
                renamed += 1
            return m.group(1) + new + m.group(3)

        new_body = NAME_RE.sub(repl, body)
        if new_body != body:
            lines[i] = f'{mid} = {new_body}\n'
            md[mid] = (i, new_body)

    # --- 2. remap base-type encodings BTF cannot express ---
    recoded = 0
    for mid, (i, body) in list(md.items()):
        if '!DIBasicType' not in body:
            continue

        def enc(m):
            nonlocal recoded
            if m.group(2) in BTF_ENCODINGS:
                return m.group(0)
            recoded += 1
            return m.group(1) + 'DW_ATE_unsigned'

        new_body = ENCODING_RE.sub(enc, body)
        if new_body != body:
            lines[i] = f'{mid} = {new_body}\n'
            md[mid] = (i, new_body)

    # --- 3. sort DW_TAG_member lists by offset ---
    def member_offset(ref):
        ent = md.get(ref)
        if not ent:
            return None
        body = ent[1]
        if 'DW_TAG_member' not in body or '!DIDerivedType' not in body:
            return None
        return field(body, 'offset', 0)

    sorted_lists = 0
    seen = set()
    for mid, (i, body) in list(md.items()):
        if '!DICompositeType' not in body:
            continue
        if not any(t in body for t in COMPOSITE_TAGS):
            continue
        m = re.search(r'(?<![A-Za-z])elements: (![0-9]+)', body)
        if not m or m.group(1) in seen:
            continue
        lid = m.group(1)
        seen.add(lid)
        ent = md.get(lid)
        if not ent:
            continue
        li, lbody = ent
        tm = TUPLE_RE.match(lbody)
        if not tm or not tm.group(1).strip():
            continue
        items = [x.strip() for x in tm.group(1).split(',')]
        slots = [k for k, x in enumerate(items) if member_offset(x) is not None]
        if len(slots) < 2:
            continue
        members = [items[k] for k in slots]
        ordered = sorted(members, key=lambda x: member_offset(x))
        if ordered == members:
            continue
        for k, x in zip(slots, ordered):
            items[k] = x
        new_lbody = '!{' + ', '.join(items) + '}'
        lines[li] = f'{lid} = {new_lbody}\n'
        md[lid] = (li, new_lbody)
        sorted_lists += 1

    # --- 4. name every function parameter ---
    next_id = max(int(k[1:]) for k in md) + 1
    extra = []
    named = 0
    for mid, (i, body) in list(md.items()):
        if '!DISubprogram(' not in body or 'DISPFlagDefinition' not in body:
            continue
        m = re.search(r'(?<![A-Za-z])type: (![0-9]+)', body)
        if not m:
            continue
        proto = md.get(m.group(1))
        if not proto or '!DISubroutineType' not in proto[1]:
            continue
        tm = re.search(r'(?<![A-Za-z])types: (![0-9]+)', proto[1])
        if not tm:
            continue
        tl = md.get(tm.group(1))
        if not tl:
            continue
        lm = TUPLE_RE.match(tl[1])
        if not lm or not lm.group(1).strip():
            continue
        # types: !{<return>, <arg1>, <arg2>, ...}
        args = [x.strip() for x in lm.group(1).split(',')][1:]
        if not args:
            continue

        rm = re.search(r'(?<![A-Za-z])retainedNodes: (![0-9]+)', body)
        have = set()
        items = []
        if rm and md.get(rm.group(1)):
            rl = TUPLE_RE.match(md[rm.group(1)][1])
            if rl and rl.group(1).strip():
                items = [x.strip() for x in rl.group(1).split(',')]
            for x in items:
                ent = md.get(x)
                if not ent or '!DILocalVariable' not in ent[1]:
                    continue
                a = field(ent[1], 'arg')
                if a and re.search(r'(?<![A-Za-z])name: "[^"]+"', ent[1]):
                    have.add(a)

        fm = re.search(r'(?<![A-Za-z])file: (![0-9]+)', body)
        line_no = field(body, 'line', 0)
        added = []
        for k, ty in enumerate(args, start=1):
            if k in have or ty == 'null':
                continue
            vid = f'!{next_id}'
            next_id += 1
            parts = [f'name: "param{k}"', f'arg: {k}', f'scope: {mid}']
            if fm:
                parts.append(f'file: {fm.group(1)}')
            parts.append(f'line: {line_no}')
            parts.append(f'type: {ty}')
            extra.append(f'{vid} = !DILocalVariable({", ".join(parts)})\n')
            added.append(vid)
            named += 1
        if not added:
            continue

        items += added
        if rm and md.get(rm.group(1)):
            rid = rm.group(1)
            ri = md[rid][0]
            new_rbody = '!{' + ', '.join(items) + '}'
            lines[ri] = f'{rid} = {new_rbody}\n'
            md[rid] = (ri, new_rbody)
        else:
            rid = f'!{next_id}'
            next_id += 1
            extra.append(f'{rid} = !{{{", ".join(items)}}}\n')
            new_body = body.rstrip()
            assert new_body.endswith(')')
            new_body = new_body[:-1] + f', retainedNodes: {rid})'
            lines[i] = f'{mid} = {new_body}\n'
            md[mid] = (i, new_body)

    lines.extend(extra)

    with open(dst, 'w') as f:
        f.writelines(lines)
    print(f'[btf_fixup] renamed {renamed} debug-info names, '
          f'recoded {recoded} base types, '
          f'reordered {sorted_lists} member lists, '
          f'named {named} parameters', file=sys.stderr)


if __name__ == '__main__':
    main()
