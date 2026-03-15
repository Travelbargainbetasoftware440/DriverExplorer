use super::{info, signature, DriverError, DriverInfo, DriverStatus, DriverType};
use crate::services;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows::core::PCWSTR;
use windows::Win32::System::ProcessStatus::*;

/// Extra module info from NtQuerySystemInformation
struct ModuleExtraInfo {
    image_size: u32,
    load_order_index: u16,
    load_count: u16,
}

/// Key for matching modules: lowercase base filename
fn module_name_key(full_path: &[u8], offset_to_file_name: u16) -> String {
    let end = full_path.iter().position(|&b| b == 0).unwrap_or(full_path.len());
    let start = (offset_to_file_name as usize).min(end);
    let name_bytes = &full_path[start..end];
    String::from_utf8_lossy(name_bytes).to_lowercase()
}

/// Raw struct matching RTL_PROCESS_MODULE_INFORMATION (x64)
#[repr(C)]
#[allow(dead_code)]
struct RtlProcessModuleInformation {
    section: usize,
    mapped_base: usize,
    image_base: usize,
    image_size: u32,
    flags: u32,
    load_order_index: u16,
    init_order_index: u16,
    load_count: u16,
    offset_to_file_name: u16,
    full_path_name: [u8; 256],
}

/// Query NtQuerySystemInformation(SystemModuleInformation=11)
/// Returns a map of lowercase module name -> ModuleExtraInfo
fn query_system_modules() -> HashMap<String, ModuleExtraInfo> {
    let mut result = HashMap::new();

    // Dynamically load NtQuerySystemInformation from ntdll.dll
    type NtQuerySystemInformationFn = unsafe extern "system" fn(
        system_information_class: u32,
        system_information: *mut core::ffi::c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32;

    let ntdll_name = to_wide_string("ntdll.dll");

    unsafe {
        // Use GetModuleHandleW since ntdll.dll is always loaded
        let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(
            PCWSTR(ntdll_name.as_ptr()),
        );
        let ntdll = match ntdll {
            Ok(h) => h,
            Err(_) => return result,
        };

        let proc = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            windows::core::PCSTR(b"NtQuerySystemInformation\0".as_ptr()),
        );
        let nt_query: NtQuerySystemInformationFn = match proc {
            Some(f) => std::mem::transmute(f),
            None => return result,
        };

        // First call to get required buffer size
        let mut return_length = 0u32;
        let status = nt_query(11, ptr::null_mut(), 0, &mut return_length);
        // STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
        if status != -0x3FFFFFFC_i32 && return_length == 0 {
            return result;
        }

        // Allocate buffer with extra room
        let buf_size = (return_length as usize + 0x10000).max(0x20000);
        let mut buffer: Vec<u8> = vec![0u8; buf_size];

        let status = nt_query(
            11,
            buffer.as_mut_ptr().cast(),
            buf_size as u32,
            &mut return_length,
        );

        if status < 0 {
            return result;
        }

        // Parse: first u32 is number_of_modules, followed by array of RtlProcessModuleInformation
        let num_modules = *(buffer.as_ptr() as *const u32);

        // Pointer to first module entry (after the count + padding to align)
        let modules_offset = std::mem::size_of::<usize>(); // align to pointer size
        let module_size = std::mem::size_of::<RtlProcessModuleInformation>();

        for i in 0..num_modules as usize {
            let offset = modules_offset + i * module_size;
            if offset + module_size > buffer.len() {
                break;
            }

            let module = &*(buffer.as_ptr().add(offset) as *const RtlProcessModuleInformation);

            let key = module_name_key(&module.full_path_name, module.offset_to_file_name);
            result.insert(
                key,
                ModuleExtraInfo {
                    image_size: module.image_size,
                    load_order_index: module.load_order_index,
                    load_count: module.load_count,
                },
            );
        }

    }

    result
}

/// Enumerate all loaded drivers using PSAPI + NtQuerySystemInformation
pub fn enumerate_all() -> Result<Vec<DriverInfo>, DriverError> {
    // Get extra module info (size, load count, index)
    let module_map = query_system_modules();

    // Build reverse map: driver filename -> service config
    let service_map = services::registry::build_driver_service_map();

    unsafe {
        let mut drivers = Vec::new();
        let mut addresses: Vec<*mut core::ffi::c_void> = vec![ptr::null_mut(); 1024];
        let mut needed = 0u32;

        // Get all device driver base addresses
        match EnumDeviceDrivers(
            addresses.as_mut_ptr(),
            (addresses.len() * mem::size_of::<*mut core::ffi::c_void>()) as u32,
            &mut needed,
        ) {
            Ok(_) => {}
            Err(_) => {
                return Err(DriverError::EnumerationFailed(
                    "EnumDeviceDrivers failed".to_string(),
                ));
            }
        }

        let count = needed as usize / mem::size_of::<*mut core::ffi::c_void>();

        for i in 0..count.min(addresses.len()) {
            if addresses[i].is_null() {
                continue;
            }

            match get_driver_info(addresses[i], &module_map, &service_map) {
                Ok(info) => drivers.push(info),
                Err(_) => continue,
            }
        }

        drivers.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(drivers)
    }
}

unsafe fn get_driver_info(
    base_address: *mut core::ffi::c_void,
    module_map: &HashMap<String, ModuleExtraInfo>,
    service_map: &HashMap<String, services::ServiceConfig>,
) -> Result<DriverInfo, DriverError> {
    // Get base name (e.g., "ntfs.sys")
    let mut name_buf: [u16; 256] = [0; 256];
    let name_len = GetDeviceDriverBaseNameW(base_address, &mut name_buf);
    if name_len == 0 {
        return Err(DriverError::EnumerationFailed(
            "GetDeviceDriverBaseNameW failed".to_string(),
        ));
    }
    let name = wide_null_to_string(&name_buf);

    // Get file path (NT path format)
    let mut path_buf: [u16; 512] = [0; 512];
    let path_len = GetDeviceDriverFileNameW(base_address, &mut path_buf);
    if path_len == 0 {
        return Err(DriverError::EnumerationFailed(
            "GetDeviceDriverFileNameW failed".to_string(),
        ));
    }
    let nt_path = wide_null_to_string(&path_buf);

    // Convert NT path to Win32 path
    let win32_path = convert_nt_path_to_win32(&nt_path).unwrap_or_else(|_| nt_path.clone());

    // Look up extra info from NtQuerySystemInformation by module name
    let addr = base_address as u64;
    let extra = module_map.get(&name.to_lowercase());
    let size = extra.map(|e| e.image_size as u64).unwrap_or(0);
    let end_address = if size > 0 { addr + size } else { 0 };
    let load_count = extra.map(|e| e.load_count as u32).unwrap_or(0);
    let index = extra.map(|e| e.load_order_index as u32).unwrap_or(0);

    // Look up service config from the pre-built reverse map (driver filename -> service)
    let service_config = service_map.get(&name.to_lowercase());

    let (driver_type, status, service_name, service_display_name) =
        if let Some(config) = service_config {
            let service_type = config
                .service_type
                .map(|st| match st {
                    services::ServiceType::KernelDriver => DriverType::KernelDriver,
                    services::ServiceType::FileSystemDriver => DriverType::FileSystemDriver,
                    _ => DriverType::Unknown,
                })
                .unwrap_or(DriverType::Unknown);
            (
                service_type,
                DriverStatus::Running,
                Some(config.name.clone()),
                config.display_name.clone(),
            )
        } else {
            (DriverType::Unknown, DriverStatus::Running, None, None)
        };

    // Get version info (includes file_type now)
    let version_info = info::get_version_info(&win32_path).unwrap_or_default();

    // Get file metadata (dates, attributes)
    let file_meta = info::get_file_metadata(&win32_path);

    // Get signature info
    let signature_info = signature::verify_signature(&win32_path).ok();

    Ok(DriverInfo {
        name,
        file_path: win32_path,
        load_address: addr,
        end_address,
        size,
        load_count,
        index,
        driver_type,
        file_type: version_info.file_type,
        status,
        file_version: version_info.file_version,
        product_name: version_info.product_name,
        company_name: version_info.company_name,
        file_description: version_info.file_description,
        modified_date: file_meta.modified_date,
        created_date: file_meta.created_date,
        file_attributes: file_meta.file_attributes,
        service_name,
        service_display_name,
        is_signed: signature_info.as_ref().map(|s| s.is_signed),
        signer: signature_info.and_then(|s| s.signer),
    })
}

/// Convert NT path to Win32 path
fn convert_nt_path_to_win32(nt_path: &str) -> Result<String, DriverError> {
    if nt_path.is_empty() {
        return Err(DriverError::InvalidPath("Empty path".to_string()));
    }

    // If it starts with a drive letter, return as-is
    if nt_path.len() >= 2 && nt_path.chars().next().unwrap().is_ascii_alphabetic() {
        if nt_path.chars().nth(1) == Some(':') {
            return Ok(nt_path.to_string());
        }
    }

    // Handle "\Device\HarddiskVolume<N>\" paths
    if nt_path.starts_with("\\Device\\HarddiskVolume") {
        if let Some(result) = try_map_volume_to_drive(nt_path) {
            return Ok(result);
        }
    }

    // Handle "\SystemRoot\" paths (12 chars) - case insensitive
    let upper = nt_path.to_uppercase();
    if upper.starts_with("\\SYSTEMROOT\\") {
        let windows_path = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".to_string());
        let rest = &nt_path[12..]; // "\SystemRoot\" = 12 chars
        return Ok(format!("{}\\{}", windows_path, rest));
    }

    // Handle "\??\" prefix (e.g., "\??\C:\Windows\...")
    if nt_path.starts_with("\\??\\") {
        return Ok(nt_path[4..].to_string());
    }

    // Return original if we can't convert
    Ok(nt_path.to_string())
}

/// Map HarddiskVolume path to a drive letter using QueryDosDeviceW
fn try_map_volume_to_drive(nt_path: &str) -> Option<String> {
    // Extract the volume part (e.g., "\Device\HarddiskVolume3")
    let rest_after_device = &nt_path["\\Device\\HarddiskVolume".len()..];
    let slash_pos = rest_after_device.find('\\')?;
    let volume_path = &nt_path[..("\\Device\\HarddiskVolume".len() + slash_pos)];
    let file_rest = &rest_after_device[slash_pos..]; // includes leading backslash

    // Try each drive letter A-Z
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let drive_wide = to_wide_string(&drive);
        let mut target_buf: [u16; 512] = [0; 512];

        let len = unsafe {
            windows::Win32::Storage::FileSystem::QueryDosDeviceW(
                PCWSTR(drive_wide.as_ptr()),
                Some(&mut target_buf),
            )
        };

        if len == 0 {
            continue;
        }

        let target = wide_null_to_string(&target_buf);
        if target.eq_ignore_ascii_case(volume_path) {
            return Some(format!("{}{}", drive, file_rest));
        }
    }

    None
}

/// Convert a null-terminated wide string to a Rust String
fn wide_null_to_string(wide: &[u16]) -> String {
    let null_pos = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..null_pos]).to_string()
}

fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
