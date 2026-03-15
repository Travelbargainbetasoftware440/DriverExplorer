use crate::drivers::DriverInfo;
use anyhow::Result;
use serde_json::json;

pub fn export(drivers: &[DriverInfo]) -> Result<String> {
    let output = json!({
        "generatedAt": chrono::Utc::now(),
        "count": drivers.len(),
        "drivers": drivers,
    });

    Ok(serde_json::to_string_pretty(&output)?)
}
