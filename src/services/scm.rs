use super::ServiceError;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::System::Services::*;

/// RAII wrapper for SC_HANDLE (service manager)
pub struct ScmHandle(SC_HANDLE);

impl Drop for ScmHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

/// RAII wrapper for SERVICE_HANDLE (service)
pub struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

/// Register a driver service with default settings (Kernel Driver, Demand Start).
pub fn register_driver(
    service_name: &str,
    display_name: &str,
    driver_path: &str,
) -> Result<(), ServiceError> {
    register_driver_ex(
        service_name,
        display_name,
        driver_path,
        SERVICE_DEMAND_START,
        SERVICE_KERNEL_DRIVER,
    )
}

/// Register a driver service with configurable start type and service type.
///
/// Matches OSR Loader behavior:
/// - Opens SCM with SC_MANAGER_ALL_ACCESS
/// - Creates service with SERVICE_ALL_ACCESS
/// - If service already exists, succeeds silently (idempotent)
pub fn register_driver_ex(
    service_name: &str,
    display_name: &str,
    driver_path: &str,
    start_type: SERVICE_START_TYPE,
    service_type: ENUM_SERVICE_TYPE,
) -> Result<(), ServiceError> {
    let scm = get_scm()?;

    let service_name_wide = to_wide_string(service_name);
    let display_name_wide = to_wide_string(display_name);
    let driver_path_wide = to_wide_string(driver_path);

    unsafe {
        match CreateServiceW(
            scm.0,
            PCWSTR(service_name_wide.as_ptr()),
            PCWSTR(display_name_wide.as_ptr()),
            SERVICE_ALL_ACCESS,
            service_type,
            start_type,
            SERVICE_ERROR_NORMAL,
            PCWSTR(driver_path_wide.as_ptr()),
            None,
            None,
            None,
            None,
            None,
        ) {
            Ok(svc) => {
                let _ = CloseServiceHandle(svc);
                Ok(())
            }
            Err(e) => {
                let code = e.code().0 as u32;
                // ERROR_SERVICE_EXISTS (0x80070431 or win32 1073)
                if code == 0x80070431 || (code & 0xFFFF) == 1073 {
                    Ok(())
                } else {
                    Err(ServiceError::ScmError(format_windows_error(
                        "CreateService",
                        e.code().0 as u32,
                    )))
                }
            }
        }
    }
}

/// Start a driver service.
///
/// Matches OSR Loader: opens service with SERVICE_ALL_ACCESS, calls StartServiceW.
pub fn start_driver(service_name: &str) -> Result<(), ServiceError> {
    let scm = get_scm()?;
    let service_name_wide = to_wide_string(service_name);

    unsafe {
        let svc = OpenServiceW(scm.0, PCWSTR(service_name_wide.as_ptr()), SERVICE_ALL_ACCESS)
            .map_err(|e| {
                ServiceError::ScmError(format_windows_error(
                    "OpenService",
                    e.code().0 as u32,
                ))
            })?;

        let _guard = ServiceHandle(svc);

        StartServiceW(svc, None).map_err(|e| {
            ServiceError::ScmError(format_windows_error("StartService", e.code().0 as u32))
        })?;

        Ok(())
    }
}

/// Stop a driver service via SCM ControlService(SERVICE_CONTROL_STOP).
///
/// Matches OSR Loader: uses only SCM stop, no NtUnloadDriver fallback.
pub fn stop_driver(service_name: &str) -> Result<(), ServiceError> {
    let scm = get_scm()?;
    let service_name_wide = to_wide_string(service_name);

    unsafe {
        let svc = OpenServiceW(scm.0, PCWSTR(service_name_wide.as_ptr()), SERVICE_ALL_ACCESS)
            .map_err(|e| {
                ServiceError::ScmError(format_windows_error(
                    "OpenService",
                    e.code().0 as u32,
                ))
            })?;

        let _guard = ServiceHandle(svc);

        let mut status = SERVICE_STATUS::default();
        ControlService(svc, SERVICE_CONTROL_STOP, &mut status).map_err(|e| {
            ServiceError::ScmError(format_windows_error("ControlService", e.code().0 as u32))
        })?;

        Ok(())
    }
}

/// Unregister (delete) a driver service.
///
/// Matches OSR Loader: opens with SERVICE_ALL_ACCESS, calls DeleteService.
pub fn unregister_driver(service_name: &str) -> Result<(), ServiceError> {
    let scm = get_scm()?;
    let service_name_wide = to_wide_string(service_name);

    unsafe {
        let svc = OpenServiceW(scm.0, PCWSTR(service_name_wide.as_ptr()), SERVICE_ALL_ACCESS)
            .map_err(|e| {
                ServiceError::ScmError(format_windows_error(
                    "OpenService",
                    e.code().0 as u32,
                ))
            })?;

        let _guard = ServiceHandle(svc);

        DeleteService(svc).map_err(|e| {
            ServiceError::ScmError(format_windows_error("DeleteService", e.code().0 as u32))
        })?;

        Ok(())
    }
}

/// Query the current status of a driver service.
pub fn query_driver_status(service_name: &str) -> Result<String, ServiceError> {
    let scm = get_scm()?;
    let service_name_wide = to_wide_string(service_name);

    unsafe {
        let svc = OpenServiceW(
            scm.0,
            PCWSTR(service_name_wide.as_ptr()),
            SERVICE_QUERY_STATUS,
        )
        .map_err(|e| {
            ServiceError::ScmError(format_windows_error("OpenService", e.code().0 as u32))
        })?;

        let _guard = ServiceHandle(svc);

        let mut status = SERVICE_STATUS::default();
        QueryServiceStatus(svc, &mut status).map_err(|e| {
            ServiceError::ScmError(format_windows_error(
                "QueryServiceStatus",
                e.code().0 as u32,
            ))
        })?;

        let state_str = match status.dwCurrentState {
            SERVICE_STOPPED => "Stopped",
            SERVICE_START_PENDING => "Start Pending",
            SERVICE_STOP_PENDING => "Stop Pending",
            SERVICE_RUNNING => "Running",
            SERVICE_CONTINUE_PENDING => "Continue Pending",
            SERVICE_PAUSE_PENDING => "Pause Pending",
            SERVICE_PAUSED => "Paused",
            _ => "Unknown",
        };

        Ok(state_str.to_string())
    }
}

/// Get a handle to the Service Control Manager.
///
/// Uses SC_MANAGER_ALL_ACCESS matching OSR Loader behavior.
fn get_scm() -> Result<ScmHandle, ServiceError> {
    unsafe {
        match OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS) {
            Ok(scm) => {
                if scm.is_invalid() {
                    Err(ServiceError::ScmError(
                        "Can't connect to service control manager".to_string(),
                    ))
                } else {
                    Ok(ScmHandle(scm))
                }
            }
            Err(e) => Err(ServiceError::ScmError(format_windows_error(
                "OpenSCManager",
                e.code().0 as u32,
            ))),
        }
    }
}

/// Convert a string to a wide string (UTF-16 with null terminator)
fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Format a Windows error code into a human-readable message,
/// matching OSR Loader's FormatMessageA + MessageBox pattern.
fn format_windows_error(operation: &str, hresult: u32) -> String {
    // The windows crate error already contains FormatMessage text
    let err = windows::core::Error::from_hresult(windows::core::HRESULT(hresult as i32));
    let msg_str = format!("{}", err);
    if msg_str.is_empty() {
        format!("{}: Error code 0x{:08X}", operation, hresult)
    } else {
        format!("{}: {}", operation, msg_str.trim())
    }
}
