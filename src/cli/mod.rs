use crate::drivers;
use crate::export;
use crate::services;
use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "DriverExplorer")]
#[command(about = "Windows Driver Enumeration and Management Tool")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all loaded drivers
    List {
        /// Show signature information
        #[arg(long)]
        signatures: bool,
    },
    /// Get detailed information about a specific driver
    Info { driver_name: String },
    /// Register and start a kernel driver
    Load { driver_path: PathBuf },
    /// Stop and unregister a kernel driver
    Unload { service_name: String },
    /// Start a registered kernel driver
    Start { service_name: String },
    /// Stop a running kernel driver
    Stop { service_name: String },
    /// Register a kernel driver service
    Register {
        service_name: String,
        driver_path: PathBuf,
        #[arg(long)]
        display_name: Option<String>,
    },
    /// Unregister a kernel driver service
    Unregister { service_name: String },
    /// Verify the signature of a driver file
    VerifySignature { driver_path: PathBuf },
    /// Export driver list to a file
    Export {
        /// Export format (json, text, html, csv)
        #[arg(long, default_value = "json")]
        format: String,
        /// Output file path
        #[arg(long)]
        output: Option<PathBuf>,
        /// Open HTML output in browser (only for HTML format)
        #[arg(long)]
        open: bool,
    },
    /// Execute multiple driver/service operations from a JSON config file
    Batch { config: PathBuf },
    /// Save a structured snapshot of the current loaded driver state
    Snapshot {
        /// Output JSON file
        output: PathBuf,
    },
    /// Compare two driver snapshots, or a snapshot against the live system
    Compare {
        /// Baseline snapshot JSON
        baseline: PathBuf,
        /// Optional comparison snapshot JSON. If omitted, compares against the live system
        comparison: Option<PathBuf>,
    },
}

pub fn run() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .try_init()
        .ok();

    let cli = Cli::parse();

    match cli.command {
        Commands::List { signatures } => cmd_list(signatures),
        Commands::Info { driver_name } => cmd_info(&driver_name),
        Commands::Load { driver_path } => cmd_load(&driver_path),
        Commands::Unload { service_name } => cmd_unload(&service_name),
        Commands::Start { service_name } => cmd_start(&service_name),
        Commands::Stop { service_name } => cmd_stop(&service_name),
        Commands::Register {
            service_name,
            driver_path,
            display_name,
        } => cmd_register(&service_name, &driver_path, display_name),
        Commands::Unregister { service_name } => cmd_unregister(&service_name),
        Commands::VerifySignature { driver_path } => cmd_verify_signature(&driver_path),
        Commands::Export {
            format,
            output,
            open,
        } => cmd_export(&format, output, open),
        Commands::Batch { config } => cmd_batch(&config),
        Commands::Snapshot { output } => cmd_snapshot(&output),
        Commands::Compare {
            baseline,
            comparison,
        } => cmd_compare(&baseline, comparison.as_ref()),
    }
}

fn cmd_list(show_signatures: bool) -> Result<()> {
    println!("Enumerating drivers...\n");

    let drivers = drivers::enumerate_all()?;

    if drivers.is_empty() {
        println!("No drivers found.");
        return Ok(());
    }

    // Print header
    println!("{:<40} {:<50} {:<20}", "Name", "File Path", "Load Address");
    println!("{}", "=".repeat(110));

    // Print driver entries
    for driver in drivers {
        println!(
            "{:<40} {:<50} 0x{:X}",
            driver.name, driver.file_path, driver.load_address
        );

        if show_signatures {
            if let Some(signed) = driver.is_signed {
                let status = if signed { "Signed" } else { "Unsigned" };
                println!("  Signed: {}", status);
            }
            if let Some(signer) = driver.signer {
                println!("  Signer: {}", signer);
            }
        }
    }

    Ok(())
}

fn cmd_info(driver_name: &str) -> Result<()> {
    let drivers = drivers::enumerate_all()?;

    let driver = drivers
        .iter()
        .find(|d| d.name.eq_ignore_ascii_case(driver_name))
        .ok_or_else(|| anyhow::anyhow!("Driver '{}' not found", driver_name))?;

    println!("Driver Information: {}\n", driver.name);
    println!("  File Path:        {}", driver.file_path);
    println!("  Load Address:     0x{:X}", driver.load_address);
    println!("  Type:             {}", driver.driver_type);
    println!("  Status:           {}", driver.status);

    if let Some(version) = &driver.file_version {
        println!("  Version:          {}", version);
    }
    if let Some(product) = &driver.product_name {
        println!("  Product:          {}", product);
    }
    if let Some(company) = &driver.company_name {
        println!("  Company:          {}", company);
    }
    if let Some(description) = &driver.file_description {
        println!("  Description:      {}", description);
    }
    if let Some(signed) = driver.is_signed {
        let status = if signed { "Yes" } else { "No" };
        println!("  Signed:           {}", status);
    }
    if let Some(signer) = &driver.signer {
        println!("  Signer:           {}", signer);
    }

    Ok(())
}

fn cmd_load(driver_path: &PathBuf) -> Result<()> {
    let path_str = driver_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid driver path"))?;

    // Get service name from filename (without extension)
    let service_name = driver_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid driver filename"))?;

    println!("Registering driver service '{}'...", service_name);
    services::register_driver(service_name, service_name, path_str)?;

    println!("Starting driver service '{}'...", service_name);
    services::start_driver(service_name)?;

    println!("Driver loaded successfully!");
    Ok(())
}

fn cmd_unload(service_name: &str) -> Result<()> {
    println!("Stopping driver service '{}'...", service_name);
    services::stop_driver(service_name)?;

    println!("Unregistering driver service '{}'...", service_name);
    services::unregister_driver(service_name)?;

    println!("Driver unloaded successfully!");
    Ok(())
}

fn cmd_start(service_name: &str) -> Result<()> {
    println!("Starting driver service '{}'...", service_name);
    services::start_driver(service_name)?;
    println!("Driver started successfully!");
    Ok(())
}

fn cmd_stop(service_name: &str) -> Result<()> {
    println!("Stopping driver service '{}'...", service_name);
    services::stop_driver(service_name)?;
    println!("Driver stopped successfully!");
    Ok(())
}

fn cmd_register(
    service_name: &str,
    driver_path: &PathBuf,
    display_name: Option<String>,
) -> Result<()> {
    let path_str = driver_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid driver path"))?;

    let display = display_name.unwrap_or_else(|| service_name.to_string());

    println!("Registering driver service '{}'...", service_name);
    services::register_driver(service_name, &display, path_str)?;
    println!("Driver registered successfully!");
    Ok(())
}

fn cmd_unregister(service_name: &str) -> Result<()> {
    println!("Unregistering driver service '{}'...", service_name);
    services::unregister_driver(service_name)?;
    println!("Driver unregistered successfully!");
    Ok(())
}

fn cmd_verify_signature(driver_path: &PathBuf) -> Result<()> {
    let path_str = driver_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid driver path"))?;

    println!("Verifying signature for: {}\n", path_str);

    match drivers::verify_signature(path_str) {
        Ok((is_signed, signer)) => {
            let status = if is_signed { "Signed" } else { "Unsigned" };
            println!("  Status: {}", status);
            if let Some(signer_name) = signer {
                println!("  Signer: {}", signer_name);
            }
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("Signature verification failed: {}", e)),
    }
}

fn cmd_export(format_str: &str, output_file: Option<PathBuf>, open_browser: bool) -> Result<()> {
    let format = export::ExportFormat::from_str(format_str)
        .ok_or_else(|| anyhow::anyhow!("Invalid export format: {}", format_str))?;

    println!("Enumerating drivers for export...");
    let drivers = drivers::enumerate_all()?;

    let options = export::ExportOptions {
        format,
        output_file,
        open_in_browser: open_browser,
    };

    let content = export::export_drivers(&drivers, &options)?;

    if options.output_file.is_none() {
        println!("{}", content);
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct BatchConfig {
    #[serde(default)]
    continue_on_error: bool,
    operations: Vec<BatchOperation>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum BatchOperation {
    Load {
        driver_path: PathBuf,
    },
    Unload {
        service_name: String,
    },
    Start {
        service_name: String,
    },
    Stop {
        service_name: String,
    },
    Register {
        service_name: String,
        driver_path: PathBuf,
        #[serde(default)]
        display_name: Option<String>,
    },
    Unregister {
        service_name: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct DriverSnapshot {
    generated_at: chrono::DateTime<chrono::Utc>,
    count: usize,
    drivers: Vec<drivers::DriverInfo>,
}

fn cmd_batch(config_path: &PathBuf) -> Result<()> {
    let config_text = fs::read_to_string(config_path)?;
    let config: BatchConfig = serde_json::from_str(&config_text)?;

    if config.operations.is_empty() {
        println!("No operations found in {}", config_path.display());
        return Ok(());
    }

    let total = config.operations.len();
    let mut failures = 0usize;

    for (idx, operation) in config.operations.iter().enumerate() {
        println!("[{}/{}] {}", idx + 1, total, describe_operation(operation));

        let result = execute_batch_operation(operation);
        match result {
            Ok(()) => println!("  OK"),
            Err(e) => {
                failures += 1;
                println!("  FAILED: {}", e);
                if !config.continue_on_error {
                    return Err(e);
                }
            }
        }
    }

    println!(
        "Batch complete. {} succeeded, {} failed.",
        total - failures,
        failures
    );

    if failures > 0 {
        return Err(anyhow::anyhow!("One or more batch operations failed"));
    }

    Ok(())
}

fn execute_batch_operation(operation: &BatchOperation) -> Result<()> {
    match operation {
        BatchOperation::Load { driver_path } => cmd_load(driver_path),
        BatchOperation::Unload { service_name } => cmd_unload(service_name),
        BatchOperation::Start { service_name } => cmd_start(service_name),
        BatchOperation::Stop { service_name } => cmd_stop(service_name),
        BatchOperation::Register {
            service_name,
            driver_path,
            display_name,
        } => cmd_register(service_name, driver_path, display_name.clone()),
        BatchOperation::Unregister { service_name } => cmd_unregister(service_name),
    }
}

fn describe_operation(operation: &BatchOperation) -> String {
    match operation {
        BatchOperation::Load { driver_path } => format!("load {}", driver_path.display()),
        BatchOperation::Unload { service_name } => format!("unload {}", service_name),
        BatchOperation::Start { service_name } => format!("start {}", service_name),
        BatchOperation::Stop { service_name } => format!("stop {}", service_name),
        BatchOperation::Register {
            service_name,
            driver_path,
            ..
        } => format!("register {} from {}", service_name, driver_path.display()),
        BatchOperation::Unregister { service_name } => format!("unregister {}", service_name),
    }
}

fn cmd_snapshot(output: &PathBuf) -> Result<()> {
    let drivers = drivers::enumerate_all()?;
    let snapshot = DriverSnapshot {
        generated_at: chrono::Utc::now(),
        count: drivers.len(),
        drivers,
    };

    fs::write(output, serde_json::to_string_pretty(&snapshot)?)?;
    println!("Snapshot saved to {}", output.display());
    Ok(())
}

fn cmd_compare(baseline_path: &PathBuf, comparison_path: Option<&PathBuf>) -> Result<()> {
    let baseline = read_snapshot(baseline_path)?;
    let comparison = if let Some(path) = comparison_path {
        read_snapshot(path)?
    } else {
        DriverSnapshot {
            generated_at: chrono::Utc::now(),
            drivers: drivers::enumerate_all()?,
            count: 0,
        }
    };

    let baseline_map = snapshot_map(&baseline.drivers);
    let comparison_map = snapshot_map(&comparison.drivers);

    let baseline_names = baseline_map.keys().cloned().collect::<BTreeSet<_>>();
    let comparison_names = comparison_map.keys().cloned().collect::<BTreeSet<_>>();

    let added = comparison_names
        .difference(&baseline_names)
        .cloned()
        .collect::<Vec<_>>();
    let removed = baseline_names
        .difference(&comparison_names)
        .cloned()
        .collect::<Vec<_>>();
    let changed = baseline_names
        .intersection(&comparison_names)
        .filter_map(|name| {
            let before = baseline_map.get(name)?;
            let after = comparison_map.get(name)?;
            if before != after {
                Some(name.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    println!("Baseline:   {}", baseline_path.display());
    println!(
        "Comparison: {}",
        comparison_path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "live system".to_string())
    );
    println!();
    println!("Added:   {}", added.len());
    for name in &added {
        println!("  + {}", name);
    }
    println!("Removed: {}", removed.len());
    for name in &removed {
        println!("  - {}", name);
    }
    println!("Changed: {}", changed.len());
    for name in &changed {
        println!("  * {}", name);
        if let (Some(before), Some(after)) = (baseline_map.get(name), comparison_map.get(name)) {
            print_driver_diff(before, after);
        }
    }

    Ok(())
}

fn read_snapshot(path: &PathBuf) -> Result<DriverSnapshot> {
    let text = fs::read_to_string(path)?;
    let mut snapshot: DriverSnapshot = serde_json::from_str(&text)?;
    snapshot.count = snapshot.drivers.len();
    Ok(snapshot)
}

fn snapshot_map(drivers: &[drivers::DriverInfo]) -> BTreeMap<String, drivers::DriverInfo> {
    drivers
        .iter()
        .cloned()
        .map(|driver| (driver.name.clone(), driver))
        .collect()
}

fn print_driver_diff(before: &drivers::DriverInfo, after: &drivers::DriverInfo) {
    if before.file_path != after.file_path {
        println!("      path: {} -> {}", before.file_path, after.file_path);
    }
    if before.load_address != after.load_address {
        println!(
            "      load_address: 0x{:X} -> 0x{:X}",
            before.load_address, after.load_address
        );
    }
    if before.driver_type != after.driver_type {
        println!(
            "      type: {} -> {}",
            before.driver_type, after.driver_type
        );
    }
    if before.status != after.status {
        println!("      status: {} -> {}", before.status, after.status);
    }
    if before.file_version != after.file_version {
        println!(
            "      version: {} -> {}",
            before.file_version.as_deref().unwrap_or("-"),
            after.file_version.as_deref().unwrap_or("-")
        );
    }
    if before.company_name != after.company_name {
        println!(
            "      company: {} -> {}",
            before.company_name.as_deref().unwrap_or("-"),
            after.company_name.as_deref().unwrap_or("-")
        );
    }
    if before.is_signed != after.is_signed {
        println!(
            "      signed: {} -> {}",
            format_signed(before.is_signed),
            format_signed(after.is_signed)
        );
    }
}

fn format_signed(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "signed",
        Some(false) => "unsigned",
        None => "unknown",
    }
}
