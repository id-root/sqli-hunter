// src/ui/dashboard.rs
//! TUI Dashboard Implementation
//! 
//! A 3-pane layout showing Targets, Logs, and Statistics
//! with real-time updates via mpsc channels.

use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io;
use std::time::Duration;
use tokio::sync::mpsc;
use chrono::{DateTime, Local};

use crate::models::Finding;

/// Events that can be sent to the dashboard
#[derive(Debug, Clone)]
pub enum DashboardEvent {
    /// A target scan started
    TargetStarted {
        url: String,
        target_id: i64,
    },
    
    /// A target scan completed
    TargetCompleted {
        url: String,
        target_id: i64,
        vulnerable: bool,
    },
    
    /// A log message
    Log {
        level: LogLevel,
        message: String,
    },
    
    /// A new finding
    Finding(Finding),
    
    /// Progress update
    Progress {
        current: u64,
        total: u64,
        message: String,
    },
    
    /// Update statistics
    Stats {
        targets_scanned: u64,
        vulnerabilities_found: u64,
        payloads_tested: u64,
        requests_sent: u64,
    },
    
    /// Request to quit the dashboard
    Quit,
}

/// Log level for dashboard messages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Success,
    Debug,
}

impl LogLevel {
    fn color(&self) -> Color {
        match self {
            LogLevel::Info => Color::Cyan,
            LogLevel::Warn => Color::Yellow,
            LogLevel::Error => Color::Red,
            LogLevel::Success => Color::Green,
            LogLevel::Debug => Color::Gray,
        }
    }
    
    fn prefix(&self) -> &'static str {
        match self {
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Success => "OK",
            LogLevel::Debug => "DEBUG",
        }
    }
}

/// Target status in the dashboard
#[derive(Debug, Clone)]
struct TargetStatus {
    url: String,
    target_id: i64,
    status: TargetState,
    findings_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetState {
    #[allow(dead_code)]
    Pending,
    Scanning,
    Safe,
    Vulnerable,
}

impl TargetState {
    fn color(&self) -> Color {
        match self {
            TargetState::Pending => Color::Gray,
            TargetState::Scanning => Color::Yellow,
            TargetState::Safe => Color::Green,
            TargetState::Vulnerable => Color::Red,
        }
    }
    
    fn symbol(&self) -> &'static str {
        match self {
            TargetState::Pending => "○",
            TargetState::Scanning => "◐",
            TargetState::Safe => "✓",
            TargetState::Vulnerable => "✗",
        }
    }
}

/// Log entry with timestamp
#[derive(Debug, Clone)]
struct LogEntry {
    timestamp: DateTime<Local>,
    level: LogLevel,
    message: String,
}

/// Scan statistics
#[derive(Debug, Clone, Default)]
struct ScanStats {
    targets_scanned: u64,
    vulnerabilities_found: u64,
    payloads_tested: u64,
    requests_sent: u64,
    progress_current: u64,
    progress_total: u64,
    progress_message: String,
}

impl ScanStats {
    fn progress_percent(&self) -> u16 {
        if self.progress_total == 0 {
            0
        } else {
            ((self.progress_current as f64 / self.progress_total as f64) * 100.0) as u16
        }
    }
}

/// TUI Dashboard
pub struct Dashboard {
    /// Event receiver
    rx: mpsc::Receiver<DashboardEvent>,
    
    /// Event sender (for returning to caller)
    tx: mpsc::Sender<DashboardEvent>,
    
    /// Target list
    targets: Vec<TargetStatus>,
    
    /// Log entries
    logs: Vec<LogEntry>,
    
    /// Findings
    findings: Vec<Finding>,
    
    /// Statistics
    stats: ScanStats,
    
    /// Maximum log entries to keep
    max_logs: usize,
    
    /// Selected target index
    selected_target: usize,
    
    /// Log scroll position
    log_scroll: usize,
    
    /// Whether dashboard should quit
    should_quit: bool,
}

impl Dashboard {
    /// Create a new dashboard with default settings
    pub fn new() -> (Self, mpsc::Sender<DashboardEvent>) {
        let (tx, rx) = mpsc::channel(1000);
        
        (
            Self {
                rx,
                tx: tx.clone(),
                targets: Vec::new(),
                logs: Vec::new(),
                findings: Vec::new(),
                stats: ScanStats::default(),
                max_logs: 500,
                selected_target: 0,
                log_scroll: 0,
                should_quit: false,
            },
            tx
        )
    }
    
    /// Get an event sender for this dashboard
    pub fn sender(&self) -> mpsc::Sender<DashboardEvent> {
        self.tx.clone()
    }
    
    /// Add a log entry
    fn add_log(&mut self, level: LogLevel, message: String) {
        self.logs.push(LogEntry {
            timestamp: Local::now(),
            level,
            message,
        });
        
        // Keep log size bounded
        if self.logs.len() > self.max_logs {
            self.logs.remove(0);
        }
        
        // Auto-scroll to bottom
        self.log_scroll = self.logs.len().saturating_sub(1);
    }
    
    /// Process a dashboard event
    fn process_event(&mut self, event: DashboardEvent) {
        match event {
            DashboardEvent::TargetStarted { url, target_id } => {
                // Check if target exists
                if let Some(t) = self.targets.iter_mut().find(|t| t.target_id == target_id) {
                    t.status = TargetState::Scanning;
                } else {
                    self.targets.push(TargetStatus {
                        url: url.clone(),
                        target_id,
                        status: TargetState::Scanning,
                        findings_count: 0,
                    });
                }
                self.add_log(LogLevel::Info, format!("Scanning: {}", url));
            }
            
            DashboardEvent::TargetCompleted { url, target_id, vulnerable } => {
                if let Some(t) = self.targets.iter_mut().find(|t| t.target_id == target_id) {
                    t.status = if vulnerable {
                        TargetState::Vulnerable
                    } else {
                        TargetState::Safe
                    };
                }
                
                if vulnerable {
                    self.add_log(LogLevel::Error, format!("VULNERABLE: {}", url));
                } else {
                    self.add_log(LogLevel::Success, format!("Safe: {}", url));
                }
            }
            
            DashboardEvent::Log { level, message } => {
                self.add_log(level, message);
            }
            
            DashboardEvent::Finding(finding) => {
                // Update target findings count
                if let Some(t) = self.targets.iter_mut().find(|t| t.target_id == finding.target_id) {
                    t.findings_count += 1;
                    t.status = TargetState::Vulnerable;
                }
                
                self.add_log(
                    LogLevel::Error,
                    format!("VULN: {} param={}", finding.target_url, finding.vulnerable_param),
                );
                
                self.findings.push(finding);
                self.stats.vulnerabilities_found += 1;
            }
            
            DashboardEvent::Progress { current, total, message } => {
                self.stats.progress_current = current;
                self.stats.progress_total = total;
                self.stats.progress_message = message;
            }
            
            DashboardEvent::Stats { targets_scanned, vulnerabilities_found, payloads_tested, requests_sent } => {
                self.stats.targets_scanned = targets_scanned;
                self.stats.vulnerabilities_found = vulnerabilities_found;
                self.stats.payloads_tested = payloads_tested;
                self.stats.requests_sent = requests_sent;
            }
            
            DashboardEvent::Quit => {
                self.should_quit = true;
            }
        }
    }
    
    /// Run the dashboard
    pub async fn run(&mut self) -> Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        
        // Initial welcome log
        self.add_log(LogLevel::Info, "Dashboard initialized".to_string());
        self.add_log(LogLevel::Info, "Press 'q' to quit, ↑↓ to navigate".to_string());
        
        // Main loop
        let result = self.run_loop(&mut terminal).await;
        
        // Restore terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;
        
        result
    }
    
    async fn run_loop(&mut self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        loop {
            // Draw UI
            terminal.draw(|f| self.render(f))?;
            
            // Check for quit
            if self.should_quit {
                break;
            }
            
            // Poll for events with timeout
            tokio::select! {
                // Check for dashboard events
                event = self.rx.recv() => {
                    if let Some(e) = event {
                        self.process_event(e);
                    }
                }
                
                // Check for keyboard input
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    if event::poll(Duration::from_millis(0))? {
                        if let Event::Key(key) = event::read()? {
                            if key.kind == KeyEventKind::Press {
                                match key.code {
                                    KeyCode::Char('q') | KeyCode::Esc => {
                                        self.should_quit = true;
                                    }
                                    KeyCode::Up => {
                                        self.selected_target = self.selected_target.saturating_sub(1);
                                    }
                                    KeyCode::Down => {
                                        if self.selected_target < self.targets.len().saturating_sub(1) {
                                            self.selected_target += 1;
                                        }
                                    }
                                    KeyCode::PageUp => {
                                        self.log_scroll = self.log_scroll.saturating_sub(10);
                                    }
                                    KeyCode::PageDown => {
                                        self.log_scroll = (self.log_scroll + 10).min(self.logs.len().saturating_sub(1));
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Render the dashboard
    fn render(&self, f: &mut Frame) {
        // Create main layout: 3 columns
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(25),  // Targets
                Constraint::Percentage(50),  // Logs
                Constraint::Percentage(25),  // Stats
            ])
            .split(f.size());
        
        // Render each pane
        self.render_targets(f, main_chunks[0]);
        self.render_logs(f, main_chunks[1]);
        self.render_stats(f, main_chunks[2]);
    }
    
    /// Render targets pane
    fn render_targets(&self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self.targets
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let status_style = Style::default().fg(t.status.color());
                
                // Truncate URL if too long
                let max_url_len = area.width.saturating_sub(10) as usize;
                let url_display = if t.url.len() > max_url_len {
                    format!("{}...", &t.url[..max_url_len.saturating_sub(3)])
                } else {
                    t.url.clone()
                };
                
                let content = Line::from(vec![
                    Span::styled(t.status.symbol(), status_style),
                    Span::raw(" "),
                    Span::raw(url_display),
                    if t.findings_count > 0 {
                        Span::styled(
                            format!(" ({})", t.findings_count),
                            Style::default().fg(Color::Red),
                        )
                    } else {
                        Span::raw("")
                    },
                ]);
                
                let style = if i == self.selected_target {
                    Style::default().bg(Color::DarkGray)
                } else {
                    Style::default()
                };
                
                ListItem::new(content).style(style)
            })
            .collect();
        
        let targets_list = List::new(items)
            .block(
                Block::default()
                    .title(" Targets ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .highlight_style(Style::default().add_modifier(Modifier::BOLD));
        
        f.render_widget(targets_list, area);
    }
    
    /// Render logs pane
    fn render_logs(&self, f: &mut Frame, area: Rect) {
        let log_area_height = area.height.saturating_sub(2) as usize;
        
        // Get visible logs
        let start = self.log_scroll.saturating_sub(log_area_height / 2);
        let visible_logs: Vec<&LogEntry> = self.logs
            .iter()
            .skip(start)
            .take(log_area_height)
            .collect();
        
        let items: Vec<ListItem> = visible_logs
            .iter()
            .map(|log| {
                let time = log.timestamp.format("%H:%M:%S");
                let line = Line::from(vec![
                    Span::styled(
                        format!("[{}]", time),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(" "),
                    Span::styled(
                        format!("{:5}", log.level.prefix()),
                        Style::default().fg(log.level.color()),
                    ),
                    Span::raw(" "),
                    Span::raw(&log.message),
                ]);
                ListItem::new(line)
            })
            .collect();
        
        let logs_list = List::new(items)
            .block(
                Block::default()
                    .title(format!(" Logs ({}/{}) ", self.log_scroll + 1, self.logs.len()))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            );
        
        f.render_widget(logs_list, area);
    }
    
    /// Render stats pane
    fn render_stats(&self, f: &mut Frame, area: Rect) {
        // Split stats area into sections
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),   // Progress
                Constraint::Length(8),   // Stats
                Constraint::Min(3),      // Findings summary
            ])
            .split(area);
        
        // Progress gauge
        let progress = Gauge::default()
            .block(Block::default().title(" Progress ").borders(Borders::ALL))
            .gauge_style(Style::default().fg(Color::Cyan).bg(Color::DarkGray))
            .percent(self.stats.progress_percent())
            .label(format!("{}%", self.stats.progress_percent()));
        f.render_widget(progress, chunks[0]);
        
        // Stats block
        let stats_text = vec![
            Line::from(vec![
                Span::raw("Targets:  "),
                Span::styled(
                    format!("{}", self.stats.targets_scanned),
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::raw("Vulns:    "),
                Span::styled(
                    format!("{}", self.stats.vulnerabilities_found),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::raw("Payloads: "),
                Span::styled(
                    format!("{}", self.stats.payloads_tested),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::raw("Requests: "),
                Span::styled(
                    format!("{}", self.stats.requests_sent),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
        ];
        
        let stats_paragraph = Paragraph::new(stats_text)
            .block(
                Block::default()
                    .title(" Statistics ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            );
        f.render_widget(stats_paragraph, chunks[1]);
        
        // Findings summary
        let findings_text = if self.findings.is_empty() {
            vec![Line::from(Span::styled(
                "No vulnerabilities found",
                Style::default().fg(Color::Green),
            ))]
        } else {
            self.findings
                .iter()
                .rev()
                .take(5)
                .map(|f| {
                    Line::from(vec![
                        Span::styled("✗ ", Style::default().fg(Color::Red)),
                        Span::raw(format!("{}", f.vulnerable_param)),
                    ])
                })
                .collect()
        };
        
        let findings_paragraph = Paragraph::new(findings_text)
            .block(
                Block::default()
                    .title(" Recent Findings ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: true });
        f.render_widget(findings_paragraph, chunks[2]);
    }
}

impl Default for Dashboard {
    fn default() -> Self {
        Self::new().0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dashboard_creation() {
        let (dashboard, _tx) = Dashboard::new();
        
        assert!(dashboard.targets.is_empty());
        assert!(dashboard.logs.is_empty());
        assert!(!dashboard.should_quit);
    }
    
    #[test]
    fn test_log_level_colors() {
        assert_eq!(LogLevel::Info.color(), Color::Cyan);
        assert_eq!(LogLevel::Error.color(), Color::Red);
        assert_eq!(LogLevel::Success.color(), Color::Green);
    }
    
    #[test]
    fn test_target_state() {
        assert_eq!(TargetState::Scanning.symbol(), "◐");
        assert_eq!(TargetState::Vulnerable.color(), Color::Red);
    }
    
    #[test]
    fn test_progress_percent() {
        let mut stats = ScanStats::default();
        stats.progress_current = 50;
        stats.progress_total = 100;
        
        assert_eq!(stats.progress_percent(), 50);
    }
    
    #[test]
    fn test_progress_percent_zero_total() {
        let stats = ScanStats::default();
        assert_eq!(stats.progress_percent(), 0);
    }
}
