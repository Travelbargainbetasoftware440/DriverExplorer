use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

pub mod scm;
pub mod registry; // Registry access module (complex Windows API)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceType {
    KernelDriver,
    FileSystemDriver,
    Win32OwnProcess,
    Win32ShareProcess,
}

impl fmt::Display for ServiceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceType::KernelDriver => write!(f, "Kernel Driver"),
            ServiceType::FileSystemDriver => write!(f, "File System Driver"),
            ServiceType::Win32OwnProcess => write!(f, "Win32 Own Process"),
            ServiceType::Win32ShareProcess => write!(f, "Win32 Share Process"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStartType {
    Boot,
    System,
    Auto,
    Demand,
    Disabled,
}

impl fmt::Display for ServiceStartType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceStartType::Boot => write!(f, "Boot"),
            ServiceStartType::System => write!(f, "System"),
            ServiceStartType::Auto => write!(f, "Auto"),
            ServiceStartType::Demand => write!(f, "Demand"),
            ServiceStartType::Disabled => write!(f, "Disabled"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub display_name: Option<String>,
    pub service_type: Option<ServiceType>,
    pub start_type: Option<ServiceStartType>,
    pub image_path: Option<String>,
}

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Registry error: {0}")]
    RegistryError(String),

    #[error("SCM error: {0}")]
    ScmError(String),

    #[error("Service not found: {0}")]
    ServiceNotFound(String),
}

/// Register a kernel driver
pub fn register_driver(
    service_name: &str,
    display_name: &str,
    driver_path: &str,
) -> Result<(), ServiceError> {
    scm::register_driver(service_name, display_name, driver_path)
}

/// Start a kernel driver
pub fn start_driver(service_name: &str) -> Result<(), ServiceError> {
    scm::start_driver(service_name)
}

/// Stop a kernel driver
pub fn stop_driver(service_name: &str) -> Result<(), ServiceError> {
    scm::stop_driver(service_name)
}

/// Unregister (delete) a kernel driver
pub fn unregister_driver(service_name: &str) -> Result<(), ServiceError> {
    scm::unregister_driver(service_name)
}

/// Register a kernel driver with configurable start type and service type
pub fn register_driver_ex(
    service_name: &str,
    display_name: &str,
    driver_path: &str,
    start_type_index: usize,
    driver_type_index: usize,
) -> Result<(), ServiceError> {
    use windows::Win32::System::Services::{
        ENUM_SERVICE_TYPE, SERVICE_START_TYPE,
        SERVICE_BOOT_START, SERVICE_SYSTEM_START, SERVICE_AUTO_START,
        SERVICE_DEMAND_START, SERVICE_DISABLED,
        SERVICE_KERNEL_DRIVER, SERVICE_FILE_SYSTEM_DRIVER,
    };
    let start_type: SERVICE_START_TYPE = match start_type_index {
        0 => SERVICE_BOOT_START,
        1 => SERVICE_SYSTEM_START,
        2 => SERVICE_AUTO_START,
        3 => SERVICE_DEMAND_START,
        4 => SERVICE_DISABLED,
        _ => SERVICE_DEMAND_START,
    };
    let service_type: ENUM_SERVICE_TYPE = match driver_type_index {
        0 => SERVICE_KERNEL_DRIVER,
        1 => SERVICE_FILE_SYSTEM_DRIVER,
        _ => SERVICE_KERNEL_DRIVER,
    };
    scm::register_driver_ex(service_name, display_name, driver_path, start_type, service_type)
}

/// Query current status of a driver service
pub fn query_driver_status(service_name: &str) -> Result<String, ServiceError> {
    scm::query_driver_status(service_name)
}
