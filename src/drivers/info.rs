use super::DriverError;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    GetFileAttributesExW, GetFileExInfoStandard, GetFileVersionInfoSizeW, GetFileVersionInfoW,
    VerQueryValueW, VS_FIXEDFILEINFO, WIN32_FILE_ATTRIBUTE_DATA,
};
use windows::Win32::System::Time::FileTimeToSystemTime;

pub fn get_version_info(file_path: &str) -> Result<VersionInfo, DriverError> {
    let file_path_wide = to_wide_string(file_path);
    let mut handle = 0u32;
    let size =
        unsafe { GetFileVersionInfoSizeW(PCWSTR(file_path_wide.as_ptr()), Some(&mut handle)) };

    if size == 0 {
        return Ok(VersionInfo::default());
    }

    let mut buffer = vec![0u8; size as usize];
    unsafe {
        GetFileVersionInfoW(
            PCWSTR(file_path_wide.as_ptr()),
            Some(handle),
            size,
            buffer.as_mut_ptr().cast(),
        )
        .map_err(|e| DriverError::WindowsApi(format!("GetFileVersionInfoW failed: {}", e)))?;
    }

    let fixed = query_fixed_file_info(&buffer)?;
    let translation = query_translation(&buffer).unwrap_or((0x0409, 0x04B0));

    Ok(VersionInfo {
        file_version: fixed.as_ref().map(format_file_version),
        company_name: query_string_value(&buffer, translation, "CompanyName"),
        product_name: query_string_value(&buffer, translation, "ProductName"),
        file_description: query_string_value(&buffer, translation, "FileDescription"),
        file_type: fixed.as_ref().map(map_file_type),
    })
}

#[derive(Debug, Default, Clone)]
#[allow(dead_code)]
pub struct VersionInfo {
    pub file_version: Option<String>,
    pub company_name: Option<String>,
    pub product_name: Option<String>,
    pub file_description: Option<String>,
    pub file_type: Option<String>,
}

/// Map VS_FIXEDFILEINFO.dwFileType + dwFileSubtype to a human-readable string
fn map_file_type(info: &VS_FIXEDFILEINFO) -> String {
    match info.dwFileType {
        0x00000001 => "Application".to_string(),          // VFT_APP
        0x00000002 => "Dynamic Link Library".to_string(), // VFT_DLL
        0x00000003 => match info.dwFileSubtype {          // VFT_DRV
            0x00000001 => "Printer Driver".to_string(),
            0x00000002 => "Keyboard Driver".to_string(),
            0x00000003 => "Language Driver".to_string(),
            0x00000004 => "Display Driver".to_string(),
            0x00000005 => "Mouse Driver".to_string(),
            0x00000006 => "Network Driver".to_string(),
            0x00000007 => "System Driver".to_string(),
            0x00000008 => "Installable Driver".to_string(),
            0x0000000A => "Communications Driver".to_string(),
            0x0000000C => "Sound Driver".to_string(),
            _ => "Driver".to_string(),
        },
        0x00000004 => "Font".to_string(),           // VFT_FONT
        0x00000005 => "Virtual Device".to_string(),  // VFT_VXD
        0x00000007 => "Static Library".to_string(),  // VFT_STATIC_LIB
        _ => "Unknown".to_string(),
    }
}

/// File metadata from the filesystem (dates, attributes)
#[derive(Debug, Default, Clone)]
pub struct FileMetadata {
    pub modified_date: Option<String>,
    pub created_date: Option<String>,
    pub file_attributes: Option<String>,
}

/// Get file metadata (dates, attributes) using GetFileAttributesExW
pub fn get_file_metadata(file_path: &str) -> FileMetadata {
    let path_wide = to_wide_string(file_path);
    let mut data = WIN32_FILE_ATTRIBUTE_DATA::default();

    let ok = unsafe {
        GetFileAttributesExW(
            PCWSTR(path_wide.as_ptr()),
            GetFileExInfoStandard,
            (&mut data as *mut WIN32_FILE_ATTRIBUTE_DATA).cast(),
        )
    };

    if ok.is_err() {
        return FileMetadata::default();
    }

    FileMetadata {
        modified_date: filetime_to_string(&data.ftLastWriteTime),
        created_date: filetime_to_string(&data.ftCreationTime),
        file_attributes: Some(format_file_attributes(data.dwFileAttributes)),
    }
}

/// Convert FILETIME to a human-readable date string
fn filetime_to_string(ft: &windows::Win32::Foundation::FILETIME) -> Option<String> {
    if ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0 {
        return None;
    }

    let mut st = windows::Win32::Foundation::SYSTEMTIME::default();
    let ok = unsafe { FileTimeToSystemTime(ft, &mut st) };
    if ok.is_err() {
        return None;
    }

    let am_pm = if st.wHour >= 12 { "PM" } else { "AM" };
    let hour12 = match st.wHour % 12 {
        0 => 12,
        h => h,
    };

    Some(format!(
        "{}/{}/{} {}:{:02}:{:02} {}",
        st.wMonth, st.wDay, st.wYear, hour12, st.wMinute, st.wSecond, am_pm
    ))
}

/// Format file attributes bitmask to string like "A", "RHS", etc.
fn format_file_attributes(attrs: u32) -> String {
    let mut result = String::new();
    if attrs & 0x01 != 0 { result.push('R'); } // READONLY
    if attrs & 0x02 != 0 { result.push('H'); } // HIDDEN
    if attrs & 0x04 != 0 { result.push('S'); } // SYSTEM
    if attrs & 0x20 != 0 { result.push('A'); } // ARCHIVE
    if attrs & 0x800 != 0 { result.push('C'); } // COMPRESSED
    if attrs & 0x100 != 0 { result.push('T'); } // TEMPORARY
    if result.is_empty() {
        result.push('-');
    }
    result
}

fn query_fixed_file_info(buffer: &[u8]) -> Result<Option<VS_FIXEDFILEINFO>, DriverError> {
    let subblock = to_wide_string("\\");
    let mut ptr = std::ptr::null_mut();
    let mut len = 0u32;

    let ok = unsafe {
        VerQueryValueW(
            buffer.as_ptr().cast(),
            PCWSTR(subblock.as_ptr()),
            &mut ptr,
            &mut len,
        )
    };

    if !ok.as_bool() || ptr.is_null() || len < std::mem::size_of::<VS_FIXEDFILEINFO>() as u32 {
        return Ok(None);
    }

    let info = unsafe { *(ptr as *const VS_FIXEDFILEINFO) };
    Ok(Some(info))
}

fn query_translation(buffer: &[u8]) -> Option<(u16, u16)> {
    let subblock = to_wide_string("\\VarFileInfo\\Translation");
    let mut ptr = std::ptr::null_mut();
    let mut len = 0u32;

    let ok = unsafe {
        VerQueryValueW(
            buffer.as_ptr().cast(),
            PCWSTR(subblock.as_ptr()),
            &mut ptr,
            &mut len,
        )
    };

    if !ok.as_bool() || ptr.is_null() || len < 4 {
        return None;
    }

    let words = unsafe { std::slice::from_raw_parts(ptr as *const u16, (len / 2) as usize) };
    if words.len() < 2 {
        return None;
    }

    Some((words[0], words[1]))
}

fn query_string_value(buffer: &[u8], translation: (u16, u16), field: &str) -> Option<String> {
    let subblock = format!(
        "\\StringFileInfo\\{:04x}{:04x}\\{}",
        translation.0, translation.1, field
    );
    let subblock_wide = to_wide_string(&subblock);
    let mut ptr = std::ptr::null_mut();
    let mut len = 0u32;

    let ok = unsafe {
        VerQueryValueW(
            buffer.as_ptr().cast(),
            PCWSTR(subblock_wide.as_ptr()),
            &mut ptr,
            &mut len,
        )
    };

    if !ok.as_bool() || ptr.is_null() || len == 0 {
        return None;
    }

    let chars = unsafe { std::slice::from_raw_parts(ptr as *const u16, len as usize) };
    let end = chars.iter().position(|&c| c == 0).unwrap_or(chars.len());
    let value = String::from_utf16_lossy(&chars[..end]).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn format_file_version(info: &VS_FIXEDFILEINFO) -> String {
    format!(
        "{}.{}.{}.{}",
        hiword(info.dwFileVersionMS),
        loword(info.dwFileVersionMS),
        hiword(info.dwFileVersionLS),
        loword(info.dwFileVersionLS)
    )
}

fn hiword(value: u32) -> u16 {
    (value >> 16) as u16
}

fn loword(value: u32) -> u16 {
    (value & 0xFFFF) as u16
}

fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
