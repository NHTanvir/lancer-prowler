//! Cross-tool integration HTTP server.
//!
//! Every Lancer-clone GUI exposes a small local HTTP server on a port
//! auto-allocated at launch (`127.0.0.1:<port>`, written to
//! `%TEMP%/lancer-prowler.port`).
//!
//! Endpoints:
//!   GET  /v1/state                         — current jobs / progress
//!   POST /v1/import                        — accept a target / record from
//!                                            another Lancer tool
//!   GET  /v1/export?format=json|csv|sarif|markdown
//!                                          — pull the current result set
//!
//! Uses the std-only TcpListener — no extra dependency. The server runs on a
//! tokio task and shares state via `Arc<RwLock<ServerState>>`.

use crate::models::CheckReport;
use crate::output;
use anyhow::Context;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

#[derive(Default, Clone)]
pub struct ServerState {
    pub findings: Vec<CheckReport>,
    pub running: bool,
    pub progress: f32,
    pub status_message: String,
}

#[derive(Clone)]
pub struct Server {
    pub state: Arc<RwLock<ServerState>>,
    pub port: u16,
}

impl Server {
    pub fn launch() -> anyhow::Result<Self> {
        let state = Arc::new(RwLock::new(ServerState::default()));
        let listener = TcpListener::bind("127.0.0.1:0")
            .context("Failed to bind 127.0.0.1:0 for Lancer HTTP server")?;
        let port = listener.local_addr()?.port();

        let port_file = port_file_path();
        if let Some(parent) = port_file.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&port_file, port.to_string())
            .context("Failed to write port file")?;

        let state_clone = state.clone();
        std::thread::Builder::new()
            .name("lancer-http".to_string())
            .spawn(move || {
                listener.set_nonblocking(false).ok();
                for stream in listener.incoming() {
                    if let Ok(s) = stream {
                        let state_inner = state_clone.clone();
                        std::thread::spawn(move || {
                            if let Err(e) = handle_request(s, state_inner) {
                                tracing::debug!("lancer-http request error: {e:#}");
                            }
                        });
                    }
                }
            })
            .context("failed to spawn lancer-http thread")?;

        tracing::info!("Lancer HTTP server listening on 127.0.0.1:{port}");
        Ok(Self { state, port })
    }

    pub fn update_findings(&self, findings: Vec<CheckReport>) {
        if let Ok(mut s) = self.state.write() {
            s.findings = findings;
            s.running = false;
            s.progress = 1.0;
            s.status_message = "idle".to_string();
        }
    }

    pub fn set_status(&self, msg: &str, progress: f32) {
        if let Ok(mut s) = self.state.write() {
            s.running = progress < 1.0;
            s.progress = progress;
            s.status_message = msg.to_string();
        }
    }
}

pub fn port_file_path() -> PathBuf {
    if let Ok(t) = std::env::var("TEMP") {
        let mut p = PathBuf::from(t);
        p.push("lancer-prowler.port");
        return p;
    }
    if let Ok(t) = std::env::var("TMPDIR") {
        let mut p = PathBuf::from(t);
        p.push("lancer-prowler.port");
        return p;
    }
    let mut p = PathBuf::from(std::env::temp_dir());
    p.push("lancer-prowler.port");
    p
}

fn handle_request(mut stream: TcpStream, state: Arc<RwLock<ServerState>>) -> anyhow::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
    let _peer: SocketAddr = stream.peer_addr()?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse().unwrap_or(0);
            }
            headers.push((key, val));
        }
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return write_response(&mut stream, 400, "Bad Request", "text/plain", b"bad request");
    }
    let method = parts[0];
    let target = parts[1];

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };

    match (method, path) {
        ("GET", "/v1/state") => {
            let snapshot = state.read().unwrap().clone();
            let json = serde_json::json!({
                "running": snapshot.running,
                "progress": snapshot.progress,
                "status": snapshot.status_message,
                "findings_count": snapshot.findings.len(),
            });
            let body = json.to_string();
            write_response(&mut stream, 200, "OK", "application/json", body.as_bytes())
        }
        ("GET", "/v1/export") => {
            let format = query
                .split('&')
                .find_map(|p| p.strip_prefix("format=").map(|s| s.to_string()))
                .unwrap_or_else(|| "json".to_string());
            let findings = state.read().unwrap().findings.clone();
            let (ct, body) = render_export(&format, &findings);
            write_response(&mut stream, 200, "OK", ct, body.as_bytes())
        }
        ("POST", "/v1/import") => {
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                reader.read_exact(&mut body).ok();
            }
            // Best-effort parse as OCSF JSON.
            match crate::ingest::ingest_file_from_bytes(&body, "json-ocsf") {
                Ok(new) => {
                    if let Ok(mut s) = state.write() {
                        s.findings.extend(new);
                    }
                    write_response(
                        &mut stream,
                        200,
                        "OK",
                        "application/json",
                        b"{\"status\":\"ok\"}",
                    )
                }
                Err(e) => write_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    "text/plain",
                    format!("ingest error: {e}").as_bytes(),
                ),
            }
        }
        _ => write_response(&mut stream, 404, "Not Found", "text/plain", b"not found"),
    }
}

fn render_export(format: &str, findings: &[CheckReport]) -> (&'static str, String) {
    match format {
        "csv" => {
            let mut buf = Vec::<u8>::new();
            {
                let mut w = csv::Writer::from_writer(&mut buf);
                w.write_record(&[
                    "check_id",
                    "check_name",
                    "status",
                    "severity",
                    "service",
                    "region",
                    "account_id",
                    "resource_id",
                    "resource_arn",
                    "status_extended",
                ])
                .ok();
                for f in findings {
                    w.write_record(&[
                        &f.check_id,
                        &f.check_name,
                        &f.status.to_string(),
                        &f.severity.to_string(),
                        &f.service,
                        &f.region,
                        &f.account_id,
                        &f.resource_id,
                        &f.resource_arn,
                        &f.status_extended,
                    ])
                    .ok();
                }
                w.flush().ok();
            }
            ("text/csv", String::from_utf8(buf).unwrap_or_default())
        }
        "sarif" => {
            let doc = output::sarif::build_document(findings);
            ("application/json", serde_json::to_string(&doc).unwrap_or_default())
        }
        "markdown" => ("text/markdown", output::markdown::render(findings)),
        _ => (
            "application/json",
            serde_json::to_string(findings).unwrap_or_default(),
        ),
    }
}

fn write_response(
    stream: &mut TcpStream,
    code: u16,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> anyhow::Result<()> {
    let header = format!(
        "HTTP/1.1 {code} {status}\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
        body.len(),
        content_type,
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}
