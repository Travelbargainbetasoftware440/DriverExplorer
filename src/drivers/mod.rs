use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

pub mod enumerate;
pub mod info;
pub mod signature;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriverType {
    KernelDriver,
    FileSystemDriver,
    NetworkDriver,
    Unknown,
}

impl fmt::Display for DriverType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DriverType::KernelDriver => write!(f, "Kernel Driver"),
            DriverType::FileSystemDriver => write!(f, "File System Driver"),
            DriverType::NetworkDriver => write!(f, "Network Driver"),
            DriverType::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriverStatus {
    Running,
    Stopped,
    Unknown,
}

impl fmt::Display for DriverStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DriverStatus::Running => write!(f, "Running"),
            DriverStatus::Stopped => write!(f, "Stopped"),
            DriverStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriverInfo {
    pub name: String,
    pub file_path: String,
    pub load_address: u64,
    pub end_address: u64,
    pub size: u64,
    pub load_count: u32,
    pub index: u32,
    pub driver_type: DriverType,
    pub file_type: Option<String>,
    pub status: DriverStatus,
    pub file_version: Option<String>,
    pub product_name: Option<String>,
    pub company_name: Option<String>,
    pub file_description: Option<String>,
    pub modified_date: Option<String>,
    pub created_date: Option<String>,
    pub file_attributes: Option<String>,
    pub service_name: Option<String>,
    pub service_display_name: Option<String>,
    pub is_signed: Option<bool>,
    pub signer: Option<String>,
}

#[derive(Error, Debug)]
pub enum DriverError {
    #[error("Windows API error: {0}")]
    WindowsApi(String),

    #[error("Failed to enumerate drivers: {0}")]
    EnumerationFailed(String),

    #[error("Invalid path: {0}")]
    InvalidPath(String),
}

/// Enumerate all loaded drivers on the system
pub fn enumerate_all() -> Result<Vec<DriverInfo>, DriverError> {
    enumerate::enumerate_all()
}

/// Verify the signature of a driver file
pub fn verify_signature(file_path: &str) -> Result<(bool, Option<String>), DriverError> {
    match signature::verify_signature(file_path) {
        Ok(sig_info) => Ok((sig_info.is_signed, sig_info.signer)),
        Err(e) => Err(e),
    }
}
