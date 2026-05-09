//! `lancer-prowler-cli` — CLI-only companion binary (plan.md line 326).
//!
//! Re-execs the main `lancer-prowler` binary with `--cli` injected, so users
//! who want a non-GUI entry point can shell out to this companion without
//! having to remember the flag. Falls back to error if the main binary is
//! not on PATH or alongside this binary.

use std::env;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().skip(1).collect();
    let main_bin = find_main_binary();

    let mut cmd = Command::new(&main_bin);
    cmd.arg("--cli");
    cmd.args(&argv);

    let status = match cmd.status() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("lancer-prowler-cli: failed to launch {}: {e}", main_bin.display());
            return ExitCode::from(127);
        }
    };

    match status.code() {
        Some(code) => ExitCode::from(code.clamp(0, 255) as u8),
        None => ExitCode::from(1),
    }
}

fn find_main_binary() -> PathBuf {
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = if cfg!(windows) {
                dir.join("lancer-prowler.exe")
            } else {
                dir.join("lancer-prowler")
            };
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from(if cfg!(windows) {
        "lancer-prowler.exe"
    } else {
        "lancer-prowler"
    })
}
