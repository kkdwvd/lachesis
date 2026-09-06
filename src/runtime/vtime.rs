// SPDX-License-Identifier: GPL-2.0
//! Virtual-time arithmetic, verified.
//!
//! Ghost code is erased by the macro in the compile pass, so the object is
//! the code you would have written by hand: the
//! `>= 0x8000_0000_0000_0000` test comes back out of LLVM as `if r s< 0`.

use crate::prelude::*;

verus! {

/// Virtual times wrap, so "before" is the top bit of the wrapped
/// difference -- the kernel's `time_before64`, without the signed cast that
/// exec-mode Verus would need a truncation annotation for. Upstream's Rust
/// `scx_simple` compares vtimes as plain `u64`, which pins the global clock
/// just below `u64::MAX` from the first enqueue at zero.
pub open spec fn spec_vtime_before(a: u64, b: u64) -> bool {
    a.wrapping_sub(b) >= 0x8000_0000_0000_0000
}

pub fn vtime_before(a: u64, b: u64) -> (r: bool)
    ensures r == spec_vtime_before(a, b),
{
    a.wrapping_sub(b) >= 0x8000_0000_0000_0000
}

/// Limit the budget an idling task can accumulate: a vtime that has fallen
/// more than `lag` behind `now` is pulled up to the floor `now - lag`.
///
/// The contract is what the phase 3 lag bound will rest on. It says the
/// result is one of the two candidates and nothing more, so weakening the
/// body to "always return `vtime`" or dropping the floor branch fails the
/// second clause rather than silently passing.
pub fn clamp_vtime(vtime: u64, now: u64, lag: u64) -> (r: u64)
    ensures
        r == vtime || r == now.wrapping_sub(lag),
        !spec_vtime_before(r, now.wrapping_sub(lag)),
{
    let floor = now.wrapping_sub(lag);
    if vtime_before(vtime, floor) { floor } else { vtime }
}

/// A vtime is never before itself. Trivial, but it is the fact
/// `clamp_vtime`'s second postcondition turns on when the floor is
/// returned, and the phase 3 lag bound will need it by name.
pub proof fn lemma_vtime_before_irreflexive(a: u64)
    ensures !spec_vtime_before(a, a),
{
}

/// Charge a task for the slice it consumed, scaled by its weight: a
/// heavier task advances its virtual time more slowly and so is picked
/// again sooner.
///
/// Neither the C `scx_simple` nor upstream's Rust port survives a slice
/// larger than the default or a zero weight; here the first is handled by
/// the guard and the second by the precondition, and Verus discharges both.
/// The precondition is enforceable because a policy is inside `verus!`
/// too, and it is satisfiable because `Task::weight()` is specified to
/// return `1 ..= 10000` -- the kernel's own clamp. Passing a literal zero
/// is a verification error at the call site. `wrapping_mul` only differs
/// from `*` for a `slice_dfl` above 1.8e17ns, which is about six years.
pub fn charge_vtime(vtime: u64, slice_left: u64, slice_dfl: u64, weight: u32) -> (r: u64)
    requires
        1 <= weight,
    ensures
        slice_left >= slice_dfl ==> r == vtime,
{
    let used = if slice_left >= slice_dfl { 0 } else { slice_dfl - slice_left };
    vtime.wrapping_add(used.wrapping_mul(100) / (weight as u64))
}

} // verus!
