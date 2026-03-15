use crate::drivers::DriverInfo;
use anyhow::Result;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::path::PathBuf;

pub mod formats;

#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    Json,
    Text,
    Html,
    Csv,
}

impl ExportFormat {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(ExportFormat::Json),
            "text" | "txt" => Some(ExportFormat::Text),
            "html" => Some(ExportFormat::Html),
            "csv" => Some(ExportFormat::Csv),
            _ => None,
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Text => "txt",
            ExportFormat::Html => "html",
            ExportFormat::Csv => "csv",
        }
    }
}

#[derive(Debug)]
pub struct ExportOptions {
    pub format: ExportFormat,
    pub output_file: Option<PathBuf>,
    pub open_in_browser: bool,
}

/// Export driver list in the specified format
pub fn export_drivers(drivers: &[DriverInfo], options: &ExportOptions) -> Result<String> {
    let content = match options.format {
        ExportFormat::Json => formats::json::export(drivers)?,
        ExportFormat::Text => formats::text::export(drivers)?,
        ExportFormat::Html => formats::html::export(drivers)?,
        ExportFormat::Csv => formats::csv::export(drivers)?,
    };

    if let Some(output_path) = &options.output_file {
        std::fs::write(output_path, &content)?;
        println!("Exported to: {}", output_path.display());

        if options.open_in_browser && matches!(options.format, ExportFormat::Html) {
            let _ = open_in_browser(output_path);
        }
    }

    Ok(content)
}

fn open_in_browser(path: &PathBuf) -> Result<()> {
    // Use webbrowser crate if available, or xdg-open on Linux, open on macOS, start on Windows
    #[cfg(target_os = "windows")]
    {
        let path_str = path.to_str().unwrap_or("");
        // Use raw_arg to avoid double-quoting paths with special chars like &
        std::process::Command::new("cmd")
            .raw_arg(format!("/C start \"\" \"{}\"", path_str))
            .spawn()?;
    }
    #[cfg(not(target_os = "windows"))]
    {
        webbrowser::open(path.to_str().unwrap_or(""))?;
    }
    Ok(())
}
