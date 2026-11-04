//! Process-local launch policy and read-only observations of fixture-owned daemons.
use nix::libc;
use std::os::unix::process::CommandExt;
use std::process::Command;

pub fn set_child_umask(command: &mut Command, mask: libc::mode_t) {
    // SAFETY: the child-only hook calls only the async-signal-safe umask syscall.
    unsafe {
        command.pre_exec(move || {
            libc::umask(mask);
            Ok(())
        });
    }
}

#[cfg(target_os = "linux")]
pub fn process_umask(pid: u32) -> u32 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .expect("read fixture-owned daemon status");
    let mut fields = status
        .lines()
        .filter_map(|line| line.strip_prefix("Umask:"));
    let field = fields.next().expect("daemon status has Umask").trim();
    assert!(fields.next().is_none(), "exactly one Umask field");
    assert!(!field.is_empty() && field.bytes().all(|b| (b'0'..=b'7').contains(&b)));
    let mask = u32::from_str_radix(field, 8).expect("octal Umask");
    assert!(mask <= 0o777, "permission mask");
    mask
}
