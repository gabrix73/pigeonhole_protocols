//! A read one byte past a secret's end faults: run in a child process of this test, which must
//! die of SIGSEGV.

#![cfg(target_os = "linux")]

use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use pigeonhole_protocols::secret::Secret;

#[test]
fn reading_past_the_end_faults() {
    if std::env::var("GUARD_CHILD").is_ok() {
        let s = Secret::new(&[7u8; 32]);
        assert!(s.is_guarded());
        // SAFETY: deliberately not: this read must fault on the guard page after the secret.
        let past = unsafe { std::ptr::read_volatile(s.as_ptr().add(s.len())) };
        println!("read {past} past the end");
        return;
    }
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["reading_past_the_end_faults", "--exact", "--nocapture"])
        .env("GUARD_CHILD", "1")
        .output()
        .unwrap();
    assert_eq!(status.status.signal(), Some(libc_sigsegv()), "{status:?}");
}

fn libc_sigsegv() -> i32 {
    11
}
