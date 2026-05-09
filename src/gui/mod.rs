//! Lancer-standard 3-pane GUI.
//!
//! Default invocation (no `--cli`) opens this GUI. The real implementation uses
//! `eframe` / `egui` and is gated behind the `gui` cargo feature so that builds
//! without it still compile against the rest of the toolchain (eframe pulls in
//! a large dependency tree).
//!
//! When the `gui` feature is *not* enabled, `launch()` falls back to the TUI so
//! the user still gets an interactive surface.

use crate::models::CheckReport;
use crate::lancer_server::Server;

#[cfg(feature = "gui")]
mod app;

pub fn launch(findings: Vec<CheckReport>, server: Option<Server>) -> anyhow::Result<()> {
    #[cfg(feature = "gui")]
    {
        return app::run(findings, server);
    }
    #[cfg(not(feature = "gui"))]
    {
        // Fallback: print banner explaining how to enable the real GUI, then
        // launch the TUI so the user has an interactive surface.
        eprintln!("┌─────────────────────────────────────────────────────────────┐");
        eprintln!("│  lancer-prowler — TUI fallback                              │");
        eprintln!("│                                                             │");
        eprintln!("│  The native eframe/egui GUI is gated behind                 │");
        eprintln!("│  `cargo build --features gui` because eframe pulls in       │");
        eprintln!("│  a large dependency tree that blocks Windows builds         │");
        eprintln!("│  on some toolchains. Running TUI dashboard instead.         │");
        eprintln!("│                                                             │");
        eprintln!("│  Use `--cli` for non-interactive output.                    │");
        eprintln!("└─────────────────────────────────────────────────────────────┘");
        let _ = server;
        crate::tui::TuiApp::run(findings)
    }
}
