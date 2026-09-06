// SPDX-License-Identifier: GPL-2.0
//! `scx_lachesis` -- load the policy, hold it, and report on it.
//!
//! This is the loader, and it is deliberately dull: argument parsing,
//! libbpf-rs, `.bss` decoding, signals, printing. None of it is verified.
//! Everything that decides something -- how a counter delta is computed,
//! what an exit kind means -- is in `scx_lachesis_core`, which is verified
//! with `--no-cheating`, and this file calls it.
//!
//! Holding the struct_ops link is the reason the binary exists at all.
//! `bpftool struct_ops register` pins the link and walks away, so nothing
//! detaches the scheduler when the process dies and nothing reads the exit
//! information the kernel reports through `ops.exit`. Here the link is a
//! value on the stack: dropping it unregisters the scheduler, the kernel
//! calls `ops.exit` with `SCX_EXIT_UNREG`, the BPF side records the kind
//! and the code into its `.bss`, and the loop below reads them back out.

use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use libbpf_rs::btf::types::{
    Array, Composite, DataSec, Enum, Enum64, Float, Int, MemberAttr, Ptr, Var,
};
use libbpf_rs::btf::{Btf, BtfType, HasSize, ReferencesType};
use libbpf_rs::{MapCore, MapFlags, MapType, ObjectBuilder, PrintLevel};
use scx_lachesis_core::{
    classify_exit, counter_deltas, exit_kind_name, ExitClass, MAX_COUNTERS,
};

const USAGE: &str = "\
usage: scx_lachesis [options]

Load scx_lachesis.o as this machine's sched_ext scheduler, hold the
struct_ops link, print counter deltas, and report the kernel's exit reason
on the way out.

  --obj PATH        the BPF object to load
                    (default: scx_lachesis.o beside this executable)
  --interval SECS   seconds between stats lines (default: 1)
  --duration SECS   detach and exit after this long (default: 5);
                    0 runs until SIGINT or SIGTERM
  --allow-host      attach even when this is not a QEMU guest
  -h, --help        print this and exit

Without --allow-host the loader refuses to attach unless
/sys/class/dmi/id/sys_vendor reads QEMU, the same guard vm-guest.sh
applies: attaching here displaces whatever sched_ext scheduler the machine
is already running, and the development host runs one. --allow-host is the
escape hatch for the day this is deployed on a real host; nothing in this
repository passes it.
";

/// The struct_ops map the policy's `scheduler!` invocation emits.
const OPS_MAP: &str = "lachesis_ops";
/// `.bss` fields the loader knows by name. Everything else in the policy's
/// static is treated as a counter, so adding one to the policy needs no
/// change here.
const VTIME_FIELD: &str = "vtime_now";
const EXIT_KIND_FIELD: &str = "exit_kind";
const EXIT_CODE_FIELD: &str = "exit_code";

/// A leaf's name without the variable and struct path in front of it, which
/// is what the three names above are matched against: the decoded names are
/// rooted at the `.bss` variable, so the policy's `vtime_now` shows up as
/// `LACHESIS.vtime_now`.
fn tail(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

const SCX_DIR: &str = "/sys/kernel/sched_ext";
/// How long to wait for `ops.exit` to land after the link is dropped.
/// Disabling a scheduler is asynchronous: `bpf_link` destruction kicks off
/// `scx_disable()` and the callback runs from a kthread.
const EXIT_WAIT: Duration = Duration::from_secs(5);
/// Sleep granularity, so a signal is noticed well inside one interval.
const TICK: Duration = Duration::from_millis(100);

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// arguments

struct Args {
    obj: PathBuf,
    interval: Duration,
    duration: Duration,
    allow_host: bool,
}

fn parse_args() -> Result<Args, String> {
    // Four flags do not justify a dependency, and every dependency here is
    // one more crate between a verified core and the kernel.
    let mut obj = None;
    let mut interval = 1u64;
    let mut duration = 5u64;
    let mut allow_host = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| -> Result<String, String> {
            args.next()
                .ok_or_else(|| format!("{name} needs an argument"))
        };
        match arg.as_str() {
            "--obj" => obj = Some(PathBuf::from(value("--obj")?)),
            "--interval" => {
                interval = value("--interval")?
                    .parse()
                    .map_err(|e| format!("--interval: {e}"))?
            }
            "--duration" => {
                duration = value("--duration")?
                    .parse()
                    .map_err(|e| format!("--duration: {e}"))?
            }
            "--allow-host" => allow_host = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                process::exit(0);
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    if interval == 0 {
        return Err("--interval must be at least 1".into());
    }

    let obj = match obj {
        Some(path) => path,
        None => std::env::current_exe()
            .map_err(|e| format!("cannot find my own path: {e}"))?
            .parent()
            .ok_or("my own path has no directory")?
            .join("scx_lachesis.o"),
    };
    Ok(Args {
        obj,
        interval: Duration::from_secs(interval),
        duration: Duration::from_secs(duration),
        allow_host,
    })
}

/// The guard `vm-guest.sh` applies, applied again here so that running the
/// binary by hand is as safe as running it through the VM script.
fn refuse_on_host() -> Result<(), String> {
    let vendor = fs::read_to_string("/sys/class/dmi/id/sys_vendor")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    if vendor == "QEMU" {
        return Ok(());
    }
    Err(format!(
        "refusing to attach a sched_ext scheduler outside a VM \
         (/sys/class/dmi/id/sys_vendor is '{vendor}', expected 'QEMU'); \
         pass --allow-host to override"
    ))
}

// ---------------------------------------------------------------------------
// `.bss` layout, decoded from the object's BTF

/// One integer inside the policy's static, at a byte offset into the map's
/// value.
struct Leaf {
    name: String,
    offset: usize,
    size: usize,
}

impl Leaf {
    fn read(&self, value: &[u8]) -> u64 {
        let mut buf = [0u8; 8];
        buf[..self.size].copy_from_slice(&value[self.offset..self.offset + self.size]);
        u64::from_ne_bytes(buf)
    }
}

fn name_of(t: &BtfType<'_>) -> String {
    t.name()
        .and_then(OsStr::to_str)
        .unwrap_or("(anon)")
        .to_string()
}

fn type_size(btf: &Btf<'_>, t: BtfType<'_>) -> Option<usize> {
    let t = t.skip_mods_and_typedefs();
    if let Ok(i) = Int::try_from(t) {
        return Some(i.size());
    }
    if let Ok(c) = Composite::try_from(t) {
        return Some(c.size());
    }
    if let Ok(e) = Enum::try_from(t) {
        return Some(e.size());
    }
    if let Ok(e) = Enum64::try_from(t) {
        return Some(e.size());
    }
    if let Ok(f) = Float::try_from(t) {
        return Some(f.size());
    }
    if Ptr::try_from(t).is_ok() {
        return btf.ptr_size().ok().map(usize::from);
    }
    if let Ok(a) = Array::try_from(t) {
        let elem = btf.type_by_id::<BtfType<'_>>(a.contained_type().type_id())?;
        return Some(a.capacity() * type_size(btf, elem)?);
    }
    None
}

/// Flatten a BTF type into the integers it is made of.
///
/// The names are dotted paths, as `bpftool map dump` prints them, with one
/// simplification: a struct with a single member contributes no name of its
/// own. Rust's atomics are four nested single-field newtypes
/// (`AtomicU64` / `Atomic<u64>` / `UnsafeCell` / `Align8`), so without that
/// every counter would print as `stats.counters[0].v.value.__0`; with it,
/// the names are the ones the policy source uses.
fn walk(
    btf: &Btf<'_>,
    name: &str,
    t: BtfType<'_>,
    offset: usize,
    out: &mut Vec<Leaf>,
) -> Result<(), String> {
    let t = t.skip_mods_and_typedefs();

    if let Ok(i) = Int::try_from(t) {
        if i.offset != 0 || i.bits % 8 != 0 || i.size() > 8 {
            return Err(format!("{name}: unsupported integer layout"));
        }
        out.push(Leaf {
            name: name.to_string(),
            offset,
            size: i.size(),
        });
        return Ok(());
    }
    if let Ok(e) = Enum::try_from(t) {
        out.push(Leaf {
            name: name.to_string(),
            offset,
            size: e.size(),
        });
        return Ok(());
    }
    if let Ok(a) = Array::try_from(t) {
        let elem = btf
            .type_by_id::<BtfType<'_>>(a.contained_type().type_id())
            .ok_or_else(|| format!("{name}: array element type is missing"))?;
        let stride = type_size(btf, elem)
            .ok_or_else(|| format!("{name}: array element has no size"))?;
        for k in 0..a.capacity() {
            walk(btf, &format!("{name}[{k}]"), elem, offset + k * stride, out)?;
        }
        return Ok(());
    }
    if let Ok(c) = Composite::try_from(t) {
        let unnamed_wrapper = c.len() == 1;
        for m in c.iter() {
            let bit_offset = match m.attr {
                MemberAttr::Normal { offset } => offset,
                MemberAttr::BitField { .. } => {
                    return Err(format!("{name}: bitfields are not decoded"))
                }
            };
            if bit_offset % 8 != 0 {
                return Err(format!("{name}: member is not byte aligned"));
            }
            let member = m.name.and_then(OsStr::to_str).unwrap_or("");
            let child = if unnamed_wrapper || member.is_empty() {
                name.to_string()
            } else {
                format!("{name}.{member}")
            };
            let ty = btf
                .type_by_id::<BtfType<'_>>(m.ty)
                .ok_or_else(|| format!("{child}: member type is missing"))?;
            walk(btf, &child, ty, offset + bit_offset as usize / 8, out)?;
        }
        return Ok(());
    }
    // A pointer, a function, anything else: not something `.bss` carries for
    // a scheduler that has no heap. Skipping keeps the loader working if the
    // policy ever grows one.
    Ok(())
}

/// Every integer in the `.bss` datasec, in offset order.
fn bss_layout(btf: &Btf<'_>) -> Result<Vec<Leaf>, String> {
    let sec = btf
        .type_by_kind::<DataSec<'_>>()
        .find(|d| d.name().and_then(OsStr::to_str) == Some(".bss"))
        .ok_or("the object has no .bss datasec in its BTF")?;

    let mut leaves = Vec::new();
    for var_info in sec.iter() {
        let var = btf
            .type_by_id::<Var<'_>>(var_info.ty)
            .ok_or("a .bss datasec entry is not a variable")?;
        let ty = btf
            .type_by_id::<BtfType<'_>>(var.referenced_type().type_id())
            .ok_or("a .bss variable has no type")?;
        walk(btf, &name_of(&var), ty, var_info.offset as usize, &mut leaves)?;
    }
    leaves.sort_by_key(|l| l.offset);
    Ok(leaves)
}

// ---------------------------------------------------------------------------
// sampling

struct Sample {
    vtime: u64,
    exit_kind: u64,
    exit_code: u64,
    counters: [u64; MAX_COUNTERS],
}

/// Which leaves are counters, in `.bss` order; the rest are named fields the
/// loader reports on their own.
fn counter_names(leaves: &[Leaf]) -> Vec<&str> {
    leaves
        .iter()
        .filter(|l| {
            !matches!(tail(&l.name), VTIME_FIELD | EXIT_KIND_FIELD | EXIT_CODE_FIELD)
        })
        .map(|l| l.name.as_str())
        .collect()
}

fn sample(leaves: &[Leaf], value: &[u8]) -> Sample {
    let mut s = Sample {
        vtime: 0,
        exit_kind: 0,
        exit_code: 0,
        counters: [0; MAX_COUNTERS],
    };
    let mut n = 0;
    for leaf in leaves {
        let v = leaf.read(value);
        match tail(&leaf.name) {
            VTIME_FIELD => s.vtime = v,
            EXIT_KIND_FIELD => s.exit_kind = v,
            EXIT_CODE_FIELD => s.exit_code = v,
            _ => {
                if n < MAX_COUNTERS {
                    s.counters[n] = v;
                    n += 1;
                }
            }
        }
    }
    s
}

fn report_exit(s: &Sample) -> i32 {
    let class = classify_exit(s.exit_kind);
    println!(
        "exit: kind={} ({}) code=0x{:x}",
        s.exit_kind,
        exit_kind_name(s.exit_kind),
        s.exit_code
    );
    match class {
        ExitClass::NotExited => {
            println!("exit: the kernel never called ops.exit");
            1
        }
        ExitClass::Done | ExitClass::Unregistered => 0,
        ExitClass::Error | ExitClass::Stall | ExitClass::Unknown => 1,
    }
}

fn scx_attr(name: &str) -> String {
    fs::read_to_string(format!("{SCX_DIR}/{name}"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "(unreadable)".to_string())
}

// ---------------------------------------------------------------------------

fn run() -> Result<i32, String> {
    let args = parse_args()?;
    if !args.allow_host {
        refuse_on_host()?;
    }

    // libbpf is chatty at Info level about relocation sections it skips;
    // warnings and errors are what a run should show.
    libbpf_rs::set_print(Some((PrintLevel::Warn, |_, msg: String| eprint!("{msg}"))));

    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }

    let open = ObjectBuilder::default()
        .open_file(&args.obj)
        .map_err(|e| format!("cannot open {}: {e}", args.obj.display()))?;
    let mut obj = open
        .load()
        .map_err(|e| format!("cannot load {}: {e}", args.obj.display()))?;

    let link = {
        let mut ops = obj
            .maps_mut()
            .find(|m| m.name() == OPS_MAP)
            .ok_or_else(|| format!("no map named {OPS_MAP} in {}", args.obj.display()))?;
        if ops.map_type() != MapType::StructOps {
            return Err(format!(
                "{OPS_MAP} is a {:?}, not a struct_ops map",
                ops.map_type()
            ));
        }
        ops.attach_struct_ops()
            .map_err(|e| format!("cannot attach {OPS_MAP}: {e}"))?
    };
    println!(
        "attached: {} as struct_ops map {OPS_MAP}, state={} root/ops={}",
        args.obj.display(),
        scx_attr("state"),
        scx_attr("root/ops"),
    );

    let btf = obj
        .btf()
        .map_err(|e| format!("cannot read the object's BTF: {e}"))?
        .ok_or("the object carries no BTF")?;
    let leaves = bss_layout(&btf)?;
    let names = counter_names(&leaves);
    if names.len() > MAX_COUNTERS {
        return Err(format!(
            "the policy has {} counters, more than \
             scx_lachesis_core::MAX_COUNTERS ({MAX_COUNTERS})",
            names.len()
        ));
    }
    let bss = obj
        .maps()
        .find(|m| m.name().to_string_lossy().ends_with(".bss"))
        .ok_or("the object has no .bss map")?;
    println!(
        "stats: map {} with {} counters ({})",
        bss.name().to_string_lossy(),
        names.len(),
        names.join(", ")
    );

    let read = || -> Result<Sample, String> {
        let value = bss
            .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)
            .map_err(|e| format!("cannot read {}: {e}", bss.name().to_string_lossy()))?
            .ok_or("the .bss map has no entry 0")?;
        Ok(sample(&leaves, &value))
    };

    let start = Instant::now();
    let mut prev = read()?;
    let mut next = start + args.interval;
    let mut ejected = None;

    while !STOP.load(Ordering::Relaxed) {
        if !args.duration.is_zero() && start.elapsed() >= args.duration {
            break;
        }
        if Instant::now() < next {
            std::thread::sleep(TICK);
            continue;
        }
        next += args.interval;

        let now = read()?;
        let deltas = counter_deltas(&prev.counters, &now.counters);
        let counters: Vec<String> = names
            .iter()
            .enumerate()
            .map(|(i, name)| format!("{name}=+{}", deltas[i]))
            .collect();
        println!(
            "[{:6.1}s] vtime={} {}",
            start.elapsed().as_secs_f64(),
            now.vtime,
            counters.join(" ")
        );
        if now.exit_kind != 0 {
            ejected = Some(now);
            break;
        }
        prev = now;
    }

    if let Some(s) = ejected {
        println!("ejected while attached; not detaching");
        return Ok(report_exit(&s));
    }

    // Dropping the link unregisters the scheduler. The kernel then calls
    // ops.exit with SCX_EXIT_UNREG from a kthread, so the recorded kind
    // appears a moment later, not immediately.
    println!("detaching after {:.1}s", start.elapsed().as_secs_f64());
    drop(link);
    let deadline = Instant::now() + EXIT_WAIT;
    loop {
        let s = read()?;
        if s.exit_kind != 0 {
            let code = report_exit(&s);
            println!("state={} after detach", scx_attr("state"));
            return Ok(code);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the kernel did not report an exit within {}s",
                EXIT_WAIT.as_secs()
            ));
        }
        std::thread::sleep(TICK);
    }
}

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(e) => {
            eprintln!("scx_lachesis: {e}");
            process::exit(1);
        }
    }
}
