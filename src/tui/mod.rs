use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState, Tabs},
    Frame, Terminal,
};
use crate::models::{CheckReport, Severity, Status};

pub struct TuiApp {
    pub findings: Vec<CheckReport>,
    pub selected_tab: usize,
    pub table_state: TableState,
    pub scroll_offset: usize,
}

impl TuiApp {
    pub fn new(findings: Vec<CheckReport>) -> Self {
        Self {
            findings,
            selected_tab: 0,
            table_state: TableState::default(),
            scroll_offset: 0,
        }
    }

    pub fn run(findings: Vec<CheckReport>) -> anyhow::Result<()> {
        use crossterm::{
            event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
            execute,
            terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
        };
        use std::io;

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let mut app = TuiApp::new(findings);

        loop {
            terminal.draw(|f| app.render(f))?;
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => app.next_row(),
                    KeyCode::Up | KeyCode::Char('k') => app.prev_row(),
                    KeyCode::Tab => app.next_tab(),
                    KeyCode::BackTab => app.prev_tab(),
                    _ => {}
                }
            }
        }

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
        terminal.show_cursor()?;
        Ok(())
    }

    fn render(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),   // header
                Constraint::Length(5),   // summary stats
                Constraint::Min(0),      // main content
                Constraint::Length(2),   // footer/keybinds
            ])
            .split(f.area());

        self.render_header(f, chunks[0]);
        self.render_summary(f, chunks[1]);
        self.render_findings_table(f, chunks[2]);
        self.render_footer(f, chunks[3]);
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let tabs = vec!["All Findings", "Failed", "Critical/High", "By Service"];
        let tabs_widget = Tabs::new(tabs)
            .select(self.selected_tab)
            .block(Block::default().borders(Borders::ALL).title(" Lancer-Prowler "))
            .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
        f.render_widget(tabs_widget, area);
    }

    fn render_summary(&self, f: &mut Frame, area: Rect) {
        let total = self.findings.len();
        let failed = self.findings.iter().filter(|r| matches!(r.status, Status::Fail)).count();
        let critical = self.findings.iter().filter(|r| matches!(r.severity, Severity::Critical) && matches!(r.status, Status::Fail)).count();
        let high = self.findings.iter().filter(|r| matches!(r.severity, Severity::High) && matches!(r.status, Status::Fail)).count();
        let pass_pct = if total > 0 { ((total - failed) * 100 / total) as u16 } else { 100 };

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(25); 4])
            .split(area);

        let stat = |label: &str, val: usize, color: Color| {
            Paragraph::new(format!(" {}", val))
                .block(Block::default().borders(Borders::ALL).title(format!(" {} ", label)))
                .style(Style::default().fg(color))
        };

        f.render_widget(stat("Total", total, Color::White), chunks[0]);
        f.render_widget(stat("Failed", failed, Color::Red), chunks[1]);
        f.render_widget(stat("Critical", critical, Color::Magenta), chunks[2]);

        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL).title(" Pass Rate "))
            .gauge_style(Style::default().fg(Color::Green))
            .percent(pass_pct)
            .label(format!("{}% ({} high)", pass_pct, high));
        f.render_widget(gauge, chunks[3]);
    }

    fn render_findings_table(&mut self, f: &mut Frame, area: Rect) {
        let tab = self.selected_tab;
        let rows: Vec<Row> = self.findings.iter().filter(|r| match tab {
            1 => matches!(r.status, Status::Fail),
            2 => matches!(r.status, Status::Fail) && matches!(r.severity, Severity::Critical | Severity::High),
            _ => true,
        }).map(|r| {
            let status_color = match r.status {
                Status::Fail => Color::Red,
                Status::Pass => Color::Green,
                _ => Color::Yellow,
            };
            let sev_color = match r.severity {
                Severity::Critical => Color::Magenta,
                Severity::High => Color::Red,
                Severity::Medium => Color::Yellow,
                Severity::Low => Color::Cyan,
                Severity::Informational => Color::White,
            };
            Row::new(vec![
                Cell::from(r.check_id.as_str()).style(Style::default().fg(Color::White)),
                Cell::from(format!("{:?}", r.status)).style(Style::default().fg(status_color)),
                Cell::from(format!("{:?}", r.severity)).style(Style::default().fg(sev_color)),
                Cell::from(r.resource_id.as_str()),
                Cell::from(r.region.as_str()),
                Cell::from(r.status_extended.chars().take(60).collect::<String>()),
            ])
        }).collect();

        let header = Row::new(vec!["Check ID", "Status", "Severity", "Resource", "Region", "Details"])
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .height(1);

        let table = Table::new(rows, [
            Constraint::Percentage(25),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Percentage(20),
            Constraint::Length(12),
            Constraint::Percentage(30),
        ])
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(" Findings "))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        f.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let text = Line::from(vec![
            Span::styled(" ↑/↓ Navigate", Style::default().fg(Color::Gray)),
            Span::raw("  "),
            Span::styled("Tab Next view", Style::default().fg(Color::Gray)),
            Span::raw("  "),
            Span::styled("q Quit", Style::default().fg(Color::Red)),
        ]);
        let para = Paragraph::new(text);
        f.render_widget(para, area);
    }

    fn filtered_findings(&self) -> Vec<&CheckReport> {
        match self.selected_tab {
            0 => self.findings.iter().collect(),
            1 => self.findings.iter().filter(|r| matches!(r.status, Status::Fail)).collect(),
            2 => self.findings.iter().filter(|r| {
                matches!(r.status, Status::Fail) &&
                matches!(r.severity, Severity::Critical | Severity::High)
            }).collect(),
            3 => self.findings.iter().collect(), // by service - same for now
            _ => self.findings.iter().collect(),
        }
    }

    fn next_row(&mut self) {
        let len = self.filtered_findings().len();
        if len == 0 { return; }
        let i = self.table_state.selected().map_or(0, |i| (i + 1).min(len - 1));
        self.table_state.select(Some(i));
    }

    fn prev_row(&mut self) {
        let i = self.table_state.selected().map_or(0, |i| i.saturating_sub(1));
        self.table_state.select(Some(i));
    }

    fn next_tab(&mut self) { self.selected_tab = (self.selected_tab + 1) % 4; }
    fn prev_tab(&mut self) { self.selected_tab = self.selected_tab.saturating_sub(1); }
}
