// src/ui/widgets.rs
//! Reusable TUI Widgets
//! 
//! Custom widgets for the scanner dashboard.

use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier, Style},
    symbols,
    widgets::{Block, Borders, Widget},
};

/// A simple sparkline widget for showing trend data
pub struct Sparkline<'a> {
    /// Data points
    data: &'a [u64],
    
    /// Maximum value (auto-calculated if None)
    max: Option<u64>,
    
    /// Style for the sparkline
    style: Style,
    
    /// Block wrapper
    block: Option<Block<'a>>,
}

impl<'a> Sparkline<'a> {
    pub fn new(data: &'a [u64]) -> Self {
        Self {
            data,
            max: None,
            style: Style::default(),
            block: None,
        }
    }
    
    pub fn max(mut self, max: u64) -> Self {
        self.max = Some(max);
        self
    }
    
    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }
    
    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }
}

impl<'a> Widget for Sparkline<'a> {
    fn render(mut self, area: Rect, buf: &mut Buffer) {
        // Render block if present
        let sparkline_area = match self.block.take() {
            Some(b) => {
                let inner = b.inner(area);
                b.render(area, buf);
                inner
            }
            None => area,
        };
        
        if sparkline_area.height < 1 || sparkline_area.width < 1 || self.data.is_empty() {
            return;
        }
        
        let max = self.max.unwrap_or_else(|| *self.data.iter().max().unwrap_or(&1));
        let max = max.max(1); // Prevent division by zero
        
        // Define bar characters from empty to full
        let bar_chars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        
        let values_per_cell = (self.data.len() as f64 / sparkline_area.width as f64).ceil() as usize;
        let values_per_cell = values_per_cell.max(1);
        
        for (i, x) in (sparkline_area.left()..sparkline_area.right()).enumerate() {
            let start = i * values_per_cell;
            let end = ((i + 1) * values_per_cell).min(self.data.len());
            
            if start >= self.data.len() {
                break;
            }
            
            // Average values for this cell
            let sum: u64 = self.data[start..end].iter().sum();
            let avg = sum / (end - start) as u64;
            
            // Calculate bar height
            let height = ((avg as f64 / max as f64) * 7.0).round() as usize;
            let height = height.min(7);
            
            let char = bar_chars[height];
            
            buf.get_mut(x, sparkline_area.top())
                .set_char(char)
                .set_style(self.style);
        }
    }
}

/// Status indicator widget (colored dot with label)
pub struct StatusIndicator<'a> {
    label: &'a str,
    status: IndicatorStatus,
    show_label: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicatorStatus {
    Ok,
    Warning,
    Error,
    Unknown,
    Pending,
}

impl<'a> StatusIndicator<'a> {
    pub fn new(label: &'a str, status: IndicatorStatus) -> Self {
        Self {
            label,
            status,
            show_label: true,
        }
    }
    
    pub fn show_label(mut self, show: bool) -> Self {
        self.show_label = show;
        self
    }
}

impl<'a> Widget for StatusIndicator<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 1 || area.height < 1 {
            return;
        }
        
        let (symbol, color) = match self.status {
            IndicatorStatus::Ok => ("●", Color::Green),
            IndicatorStatus::Warning => ("●", Color::Yellow),
            IndicatorStatus::Error => ("●", Color::Red),
            IndicatorStatus::Unknown => ("○", Color::Gray),
            IndicatorStatus::Pending => ("◐", Color::Cyan),
        };
        
        let style = Style::default().fg(color);
        buf.set_string(area.x, area.y, symbol, style);
        
        if self.show_label && area.width > 2 {
            let max_label_len = (area.width - 2) as usize;
            let label = if self.label.len() > max_label_len {
                &self.label[..max_label_len]
            } else {
                self.label
            };
            
            buf.set_string(area.x + 2, area.y, label, Style::default());
        }
    }
}

/// Simple animated spinner widget
pub struct Spinner {
    frame: usize,
}

impl Spinner {
    const FRAMES: [char; 8] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'];
    
    pub fn new(frame: usize) -> Self {
        Self { frame }
    }
}

impl Widget for Spinner {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 1 || area.height < 1 {
            return;
        }
        
        let char = Self::FRAMES[self.frame % Self::FRAMES.len()];
        buf.set_string(area.x, area.y, char.to_string(), Style::default().fg(Color::Cyan));
    }
}

/// Key hints widget for showing keyboard shortcuts
pub struct KeyHints<'a> {
    hints: Vec<(&'a str, &'a str)>,
    style: Style,
    separator: &'a str,
}

impl<'a> KeyHints<'a> {
    pub fn new(hints: Vec<(&'a str, &'a str)>) -> Self {
        Self {
            hints,
            style: Style::default(),
            separator: " | ",
        }
    }
    
    pub fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }
    
    pub fn separator(mut self, sep: &'a str) -> Self {
        self.separator = sep;
        self
    }
}

impl<'a> Widget for KeyHints<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 1 || area.height < 1 {
            return;
        }
        
        let mut x = area.x;
        let key_style = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        let desc_style = Style::default().fg(Color::Gray);
        let sep_style = Style::default().fg(Color::DarkGray);
        
        for (i, (key, desc)) in self.hints.iter().enumerate() {
            // Add separator if not first
            if i > 0 {
                if x + self.separator.len() as u16 > area.right() {
                    break;
                }
                buf.set_string(x, area.y, self.separator, sep_style);
                x += self.separator.len() as u16;
            }
            
            // Render key
            if x + key.len() as u16 > area.right() {
                break;
            }
            buf.set_string(x, area.y, *key, key_style);
            x += key.len() as u16 + 1;
            
            // Render description
            if x + desc.len() as u16 > area.right() {
                break;
            }
            buf.set_string(x, area.y, *desc, desc_style);
            x += desc.len() as u16;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sparkline_creation() {
        let data = vec![1, 2, 3, 4, 5];
        let sparkline = Sparkline::new(&data)
            .max(10)
            .style(Style::default().fg(Color::Green));
        
        assert_eq!(sparkline.max, Some(10));
    }
    
    #[test]
    fn test_status_indicator() {
        let indicator = StatusIndicator::new("Test", IndicatorStatus::Ok);
        assert_eq!(indicator.status, IndicatorStatus::Ok);
    }
    
    #[test]
    fn test_spinner_frames() {
        for i in 0..10 {
            let spinner = Spinner::new(i);
            // Just verify it doesn't panic
        }
    }
    
    #[test]
    fn test_key_hints() {
        let hints = KeyHints::new(vec![
            ("q", "quit"),
            ("↑↓", "navigate"),
        ]).separator(" • ");
        
        assert_eq!(hints.separator, " • ");
    }
}
