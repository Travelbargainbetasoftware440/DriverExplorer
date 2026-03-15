use super::{ServiceConfig, ServiceError, ServiceStartType, ServiceType};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_ENUMERATE_SUB_KEYS, KEY_READ, REG_DWORD, REG_EXPAND_SZ, REG_SZ,
};

const SERVICES_ROOT: &str = "SYSTEM\\CurrentControlSet\\Services";

pub fn get_service_config(service_name: &str) -> Result<ServiceConfig, ServiceError> {
    let subkey = format!("{SERVICES_ROOT}\\{service_name}");
    let key = open_local_machine_key(&subkey)?;

    let display_name = query_string_value(key, "DisplayName")?;
    let image_path = query_string_value(key, "ImagePath")?;
    let service_type = query_dword_value(key, "Type")?.and_then(map_service_type);
    let start_type = query_dword_value(key, "Start")?.and_then(map_start_type);

    unsafe {
        let _ = RegCloseKey(key);
    }

    Ok(ServiceConfig {
        name: service_name.to_string(),
        display_name,
        service_type,
        start_type,
        image_path,
    })
}

fn open_local_machine_key(path: &str) -> Result<HKEY, ServiceError> {
    let mut key = HKEY::default();
    let path_wide = to_wide_string(path);

    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path_wide.as_ptr()),
            Some(0),
            KEY_READ,
            &mut key,
        )
    };

    if status == ERROR_SUCCESS {
        Ok(key)
    } else if status == ERROR_FILE_NOT_FOUND {
        Err(ServiceError::ServiceNotFound(path.to_string()))
    } else {
        Err(ServiceError::RegistryError(format!(
            "RegOpenKeyExW failed for '{}': {}",
            path, status.0
        )))
    }
}

fn query_string_value(key: HKEY, name: &str) -> Result<Option<String>, ServiceError> {
    let name_wide = to_wide_string(name);
    let mut value_type = REG_SZ;
    let mut size = 0u32;

    let status = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name_wide.as_ptr()),
            None,
            Some(&mut value_type),
            None,
            Some(&mut size),
        )
    };

    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }

    if status != ERROR_SUCCESS {
        return Err(ServiceError::RegistryError(format!(
            "RegQueryValueExW size failed for '{}': {}",
            name, status.0
        )));
    }

    if value_type != REG_SZ && value_type != REG_EXPAND_SZ {
        return Ok(None);
    }

    if size == 0 {
        return Ok(Some(String::new()));
    }

    let mut buffer = vec![0u16; (size as usize + 1) / 2];
    let status = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name_wide.as_ptr()),
            None,
            Some(&mut value_type),
            Some(buffer.as_mut_ptr() as *mut u8),
            Some(&mut size),
        )
    };

    if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
        return Err(ServiceError::RegistryError(format!(
            "RegQueryValueExW read failed for '{}': {}",
            name, status.0
        )));
    }

    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    Ok(Some(String::from_utf16_lossy(&buffer[..len])))
}

fn query_dword_value(key: HKEY, name: &str) -> Result<Option<u32>, ServiceError> {
    let name_wide = to_wide_string(name);
    let mut value_type = REG_DWORD;
    let mut raw = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;

    let status = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR(name_wide.as_ptr()),
            None,
            Some(&mut value_type),
            Some((&mut raw as *mut u32).cast::<u8>()),
            Some(&mut size),
        )
    };

    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }

    if status != ERROR_SUCCESS {
        return Err(ServiceError::RegistryError(format!(
            "RegQueryValueExW DWORD failed for '{}': {}",
            name, status.0
        )));
    }

    if value_type != REG_DWORD {
        return Ok(None);
    }

    Ok(Some(raw))
}

fn map_service_type(raw: u32) -> Option<ServiceType> {
    match raw {
        0x0000_0001 => Some(ServiceType::KernelDriver),
        0x0000_0002 => Some(ServiceType::FileSystemDriver),
        0x0000_0010 => Some(ServiceType::Win32OwnProcess),
        0x0000_0020 => Some(ServiceType::Win32ShareProcess),
        _ => None,
    }
}

fn map_start_type(raw: u32) -> Option<ServiceStartType> {
    match raw {
        0 => Some(ServiceStartType::Boot),
        1 => Some(ServiceStartType::System),
        2 => Some(ServiceStartType::Auto),
        3 => Some(ServiceStartType::Demand),
        4 => Some(ServiceStartType::Disabled),
        _ => None,
    }
}

/// Build a reverse map: lowercase driver filename -> (service_name, ServiceConfig)
/// Scans all entries under HKLM\SYSTEM\CurrentControlSet\Services
pub fn build_driver_service_map() -> HashMap<String, ServiceConfig> {
    let mut map = HashMap::new();

    let root_wide = to_wide_string(SERVICES_ROOT);
    let mut root_key = HKEY::default();

    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(root_wide.as_ptr()),
            Some(0),
            KEY_READ | KEY_ENUMERATE_SUB_KEYS,
            &mut root_key,
        )
    };

    if status != ERROR_SUCCESS {
        return map;
    }

    let mut index = 0u32;
    let mut name_buf = [0u16; 256];

    loop {
        let mut name_len = name_buf.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                root_key,
                index,
                Some(PWSTR(name_buf.as_mut_ptr())),
                &mut name_len,
                None,
                None,
                None,
                None,
            )
        };

        if status == ERROR_NO_MORE_ITEMS {
            break;
        }

        if status != ERROR_SUCCESS {
            index += 1;
            continue;
        }

        let svc_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);

        // Open this service's subkey and read ImagePath + Type
        if let Ok(config) = get_service_config(&svc_name) {
            // Only include kernel/filesystem drivers
            let is_driver = config.service_type.map_or(false, |t| {
                matches!(t, ServiceType::KernelDriver | ServiceType::FileSystemDriver)
            });

            if is_driver {
                if let Some(ref image_path) = config.image_path {
                    // Extract filename from ImagePath
                    let filename = image_path
                        .rsplit('\\')
                        .next()
                        .unwrap_or(image_path)
                        .to_lowercase();
                    if !filename.is_empty() {
                        map.insert(filename, config);
                    }
                }
            }
        }

        index += 1;
    }

    unsafe {
        let _ = RegCloseKey(root_key);
    }

    map
}

fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
