//! eframe/egui implementation of the Lancer GUI (3-pane layout).
//!
//! Compiled only when the `gui` feature is enabled. Tracks the Lancer standard:
//! - Top menu bar (File / Tools / Settings / Help)
//! - Left sidebar — inputs / queued jobs / scope
//! - Center — findings table
//! - Right detail pane — full record of the selected finding
//! - Bottom status bar — activity / item counts / action buttons

#![cfg(feature = "gui")]

use crate::lancer_server::Server;
use crate::models::{CheckReport, Severity, Status};

pub fn run(findings: Vec<CheckReport>, server: Option<Server>) -> anyhow::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_title("lancer-prowler"),
        ..Default::default()
    };
    eframe::run_native(
        "lancer-prowler",
        native_options,
        Box::new(move |_cc| Ok(Box::new(LancerApp::new(findings, server)))),
    )
    .map_err(|e| anyhow::anyhow!("eframe: {e}"))?;
    Ok(())
}

struct LancerApp {
    findings: Vec<CheckReport>,
    selected: Option<usize>,
    filter_text: String,
    show_only_failures: bool,
    server: Option<Server>,
}

impl LancerApp {
    fn new(findings: Vec<CheckReport>, server: Option<Server>) -> Self {
        Self {
            findings,
            selected: None,
            filter_text: String::new(),
            show_only_failures: false,
            server,
        }
    }

    fn filtered_indices(&self) -> Vec<usize> {
        self.findings
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                let text_ok = self.filter_text.is_empty()
                    || f.check_id.contains(&self.filter_text)
                    || f.service.contains(&self.filter_text);
                let fail_ok = !self.show_only_failures || f.status == Status::Fail;
                text_ok && fail_ok
            })
            .map(|(i, _)| i)
            .collect()
    }
}

impl eframe::App for LancerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Menu bar
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open scan…").clicked() {
                        // file picker would go here
                        ui.close_menu();
                    }
                    if ui.button("Export CSV…").clicked() {
                        let _ = crate::output::csv_output::write_csv(
                            &self.findings,
                            "findings.csv",
                        );
                        ui.close_menu();
                    }
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
                ui.menu_button("Tools", |ui| {
                    if ui.button("Re-run scan").clicked() {
                        ui.close_menu();
                    }
                });
                ui.menu_button("Settings", |ui| {
                    ui.label("(theme/font settings TBD)");
                });
                ui.menu_button("Help", |ui| {
                    ui.label("lancer-prowler — Lancer ecosystem.");
                });
            });
        });

        // Status bar
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let total = self.findings.len();
                let pass = self.findings.iter().filter(|f| f.status == Status::Pass).count();
                let fail = self.findings.iter().filter(|f| f.status == Status::Fail).count();
                let muted = self.findings.iter().filter(|f| f.status == Status::Muted).count();
                ui.label(format!(
                    "Items: {total}  •  PASS: {pass}  •  FAIL: {fail}  •  MUTED: {muted}"
                ));
                if let Some(s) = self.server.as_ref() {
                    ui.separator();
                    ui.label(format!("lancer-port: {}", s.port));
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Export").clicked() {
                        // placeholder
                    }
                });
            });
        });

        // Left sidebar
        egui::SidePanel::left("inputs").default_width(260.0).show(ctx, |ui| {
            ui.heading("Inputs / jobs");
            ui.separator();
            ui.label("Provider scope:");
            ui.label(" • aws (configured)");
            ui.label(" • azure / gcp / kubernetes (stubs)");
            ui.label(" • m365 / github / oci / alibaba / cloudflare (stubs)");
            ui.separator();
            ui.label("Filters:");
            ui.text_edit_singleline(&mut self.filter_text);
            ui.checkbox(&mut self.show_only_failures, "Show only failures");
        });

        // Right detail pane
        egui::SidePanel::right("detail").default_width(360.0).show(ctx, |ui| {
            ui.heading("Finding detail");
            ui.separator();
            if let Some(idx) = self.selected {
                if let Some(f) = self.findings.get(idx) {
                    ui.label(format!("Check ID  : {}", f.check_id));
                    ui.label(format!("Check name: {}", f.check_name));
                    ui.label(format!("Status    : {}", f.status));
                    ui.label(format!("Severity  : {}", f.severity));
                    ui.label(format!("Service   : {}", f.service));
                    ui.label(format!("Provider  : {}", f.provider));
                    ui.label(format!("Account   : {}", f.account_id));
                    ui.label(format!("Region    : {}", f.region));
                    ui.label(format!("Resource  : {}", f.resource_arn));
                    ui.separator();
                    ui.label("Status extended:");
                    ui.label(&f.status_extended);
                    ui.separator();
                    ui.label("Compliance:");
                    for c in &f.compliance {
                        ui.label(format!("- {} / {}", c.framework, c.control_id));
                    }
                }
            } else {
                ui.label("(select a finding on the left to see the detail)");
            }
        });

        // Center pane — findings table
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Findings");
            ui.separator();
            let indices = self.filtered_indices();
            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("findings_grid")
                    .striped(true)
                    .show(ui, |ui| {
                        ui.label("Check ID");
                        ui.label("Status");
                        ui.label("Sev");
                        ui.label("Service");
                        ui.label("Region");
                        ui.label("Resource");
                        ui.end_row();
                        for i in indices {
                            let f = &self.findings[i];
                            if ui
                                .selectable_label(self.selected == Some(i), &f.check_id)
                                .clicked()
                            {
                                self.selected = Some(i);
                            }
                            ui.colored_label(status_color(&f.status), f.status.to_string());
                            ui.colored_label(severity_color(&f.severity), f.severity.to_string());
                            ui.label(&f.service);
                            ui.label(&f.region);
                            ui.label(&f.resource_id);
                            ui.end_row();
                        }
                    });
            });
        });
    }
}

fn status_color(s: &Status) -> egui::Color32 {
    match s {
        Status::Pass => egui::Color32::from_rgb(60, 200, 80),
        Status::Fail => egui::Color32::from_rgb(220, 70, 70),
        Status::Muted => egui::Color32::from_rgb(200, 180, 60),
        Status::Unknown => egui::Color32::GRAY,
    }
}

fn severity_color(s: &Severity) -> egui::Color32 {
    match s {
        Severity::Critical => egui::Color32::from_rgb(170, 30, 220),
        Severity::High => egui::Color32::from_rgb(220, 70, 70),
        Severity::Medium => egui::Color32::from_rgb(220, 170, 50),
        Severity::Low => egui::Color32::from_rgb(70, 170, 220),
        Severity::Informational => egui::Color32::GRAY,
    }
}
