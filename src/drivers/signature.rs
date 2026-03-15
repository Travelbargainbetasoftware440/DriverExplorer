use super::DriverError;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Cryptography::Catalog::*;
use windows::Win32::Security::WinTrust::*;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::Win32::Foundation::HWND;

// Raw FFI for CryptCATAdminAcquireContext2 and CryptCATAdminCalcHashFromFileHandle2
// These are not exposed by the windows crate but needed for SHA256 catalog verification
#[link(name = "wintrust")]
unsafe extern "system" {
    fn CryptCATAdminAcquireContext2(
        phCatAdmin: *mut isize,
        pgSubsystem: *const windows::core::GUID,
        pwszHashAlgorithm: *const u16,
        pStrongHashPolicy: *const std::ffi::c_void,
        dwFlags: u32,
    ) -> i32; // BOOL

    fn CryptCATAdminCalcHashFromFileHandle2(
        hCatAdmin: isize,
        hFile: HANDLE,
        pcbHash: *mut u32,
        pbHash: *mut u8,
        dwFlags: u32,
    ) -> i32; // BOOL
}

/// BCRYPT_SHA256_ALGORITHM = "SHA256"
fn sha256_algorithm_wide() -> Vec<u16> {
    to_wide("SHA256")
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SignatureInfo {
    pub is_signed: bool,
    pub signer: Option<String>,
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// GUID for WINTRUST_ACTION_GENERIC_VERIFY_V2
const WINTRUST_ACTION_GENERIC_VERIFY_V2: windows::core::GUID = windows::core::GUID::from_values(
    0x00AAC56B,
    0xCD44,
    0x11d0,
    [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
);

/// Check if a driver file is signed (Authenticode or catalog)
pub fn verify_signature(file_path: &str) -> Result<SignatureInfo, DriverError> {
    if !Path::new(file_path).exists() {
        return Ok(SignatureInfo {
            is_signed: false,
            signer: None,

        });
    }

    // Stage 1: Check embedded Authenticode signature
    if let Some(info) = check_authenticode_wintrust(file_path) {
        return Ok(info);
    }

    // Stage 2: Check catalog signature
    if let Some(info) = check_catalog_signature(file_path) {
        return Ok(info);
    }

    Ok(SignatureInfo {
        is_signed: false,
        signer: None,
    })
}

/// Check embedded Authenticode signature using WinVerifyTrust
fn check_authenticode_wintrust(file_path: &str) -> Option<SignatureInfo> {
    let file_path_wide = to_wide(file_path);

    unsafe {
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(file_path_wide.as_ptr()),
            hFile: HANDLE::default(),
            pgKnownSubject: ptr::null_mut(),
        };

        let mut trust_data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..std::mem::zeroed()
        };

        let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // INVALID_HANDLE_VALUE cast to HWND for "no UI" verification
        let hwnd = HWND(INVALID_HANDLE_VALUE.0 as *mut _);
        let status = WinVerifyTrust(
            hwnd,
            &mut action_guid,
            (&mut trust_data as *mut WINTRUST_DATA).cast(),
        );

        let signer = if status == 0 {
            extract_signer_from_state(trust_data.hWVTStateData)
        } else {
            None
        };

        let is_signed = status == 0;

        // Close state
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(
            hwnd,
            &mut action_guid,
            (&mut trust_data as *mut WINTRUST_DATA).cast(),
        );

        if is_signed {
            Some(SignatureInfo {
                is_signed: true,
                signer,
    
            })
        } else {
            None
        }
    }
}

/// Extract the leaf certificate signer name from a CRYPT_PROVIDER_SGNR
unsafe fn get_signer_name(signer: &CRYPT_PROVIDER_SGNR) -> Option<String> {
    if signer.pasCertChain.is_null() || signer.csCertChain == 0 {
        return None;
    }
    let cert_element = &*signer.pasCertChain;
    if cert_element.pCert.is_null() {
        return None;
    }
    get_cert_subject_name(cert_element.pCert)
}

/// Extract all signer names from WinVerifyTrust state data
/// Returns all primary signers and their counter-signers, deduplicated
unsafe fn extract_signer_from_state(state_data: HANDLE) -> Option<String> {
    if state_data.is_invalid() || state_data == HANDLE::default() {
        return None;
    }

    let prov_data = WTHelperProvDataFromStateData(state_data);
    if prov_data.is_null() {
        return None;
    }

    let data = &*prov_data;
    let mut names: Vec<String> = Vec::new();

    // Iterate all primary signers
    for signer_idx in 0..data.csSigners {
        let prov_signer =
            WTHelperGetProvSignerFromChain(prov_data, signer_idx, false, 0);
        if prov_signer.is_null() {
            continue;
        }

        let signer_ref = &*prov_signer;

        // Get the primary signer name
        if let Some(name) = get_signer_name(signer_ref) {
            if !names.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                names.push(name);
            }
        }

        // Iterate counter-signers (e.g., WHQL timestamp counter-signature)
        for cs_idx in 0..signer_ref.csCounterSigners {
            let counter_signer =
                WTHelperGetProvSignerFromChain(prov_data, signer_idx, true, cs_idx);
            if counter_signer.is_null() {
                continue;
            }
            let cs_ref = &*counter_signer;
            if let Some(name) = get_signer_name(cs_ref) {
                if !names.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                    names.push(name);
                }
            }
        }
    }

    if names.is_empty() {
        None
    } else {
        Some(names.join(", "))
    }
}

/// Extract the subject name from a certificate context
unsafe fn get_cert_subject_name(
    cert_ctx: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
) -> Option<String> {
    use windows::Win32::Security::Cryptography::*;

    if cert_ctx.is_null() {
        return None;
    }

    let cert = &*cert_ctx;
    let cert_info = cert.pCertInfo.as_ref()?;
    let subject = &cert_info.Subject;

    if subject.cbData == 0 || subject.pbData.is_null() {
        return None;
    }

    // First call to get required buffer size
    let size = CertNameToStrW(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        subject,
        CERT_SIMPLE_NAME_STR,
        None,
    );

    if size <= 1 {
        return None;
    }

    let mut buffer = vec![0u16; size as usize];
    CertNameToStrW(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        subject,
        CERT_SIMPLE_NAME_STR,
        Some(&mut buffer),
    );

    let null_pos = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    let name = String::from_utf16_lossy(&buffer[..null_pos]);

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Check catalog signature using CryptCATAdmin APIs
/// Tries SHA256 first (modern catalogs), then SHA1 fallback
fn check_catalog_signature(file_path: &str) -> Option<SignatureInfo> {
    // Try driver-specific subsystem GUID
    let driver_action_verify = windows::core::GUID::from_values(
        0xF750E6C3,
        0x38EE,
        0x11D1,
        [0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    );

    // Try SHA256 with driver subsystem first
    if let Some(info) = try_catalog_sha256(file_path, Some(&driver_action_verify)) {
        return Some(info);
    }

    // Try SHA256 with default subsystem
    if let Some(info) = try_catalog_sha256(file_path, None) {
        return Some(info);
    }

    // Fallback: SHA1 with driver subsystem
    if let Some(info) = try_catalog_with_subsystem(file_path, Some(&driver_action_verify)) {
        return Some(info);
    }

    // Fallback: SHA1 with default subsystem
    try_catalog_with_subsystem(file_path, None)
}

/// Try catalog verification using SHA256 via CryptCATAdminAcquireContext2
fn try_catalog_sha256(
    file_path: &str,
    subsystem: Option<&windows::core::GUID>,
) -> Option<SignatureInfo> {
    let file_wide = to_wide(file_path);
    let sha256_wide = sha256_algorithm_wide();

    unsafe {
        // Open file for hashing
        let file_handle = CreateFileW(
            PCWSTR(file_wide.as_ptr()),
            0x80000000, // GENERIC_READ
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .ok()?;

        // Acquire catalog admin context with SHA256
        let mut cat_admin: isize = 0;
        let sub_ptr = subsystem
            .map(|g| g as *const _)
            .unwrap_or(ptr::null());
        let result = CryptCATAdminAcquireContext2(
            &mut cat_admin,
            sub_ptr,
            sha256_wide.as_ptr(),
            ptr::null(),
            0,
        );
        if result == 0 {
            let _ = windows::Win32::Foundation::CloseHandle(file_handle);
            return None;
        }

        // Calculate hash using CryptCATAdminCalcHashFromFileHandle2 (SHA256-aware)
        let mut hash_size = 0u32;
        CryptCATAdminCalcHashFromFileHandle2(
            cat_admin,
            file_handle,
            &mut hash_size,
            ptr::null_mut(),
            0,
        );

        if hash_size == 0 {
            let _ = CryptCATAdminReleaseContext(cat_admin, 0);
            let _ = windows::Win32::Foundation::CloseHandle(file_handle);
            return None;
        }

        let mut hash = vec![0u8; hash_size as usize];
        let hash_result = CryptCATAdminCalcHashFromFileHandle2(
            cat_admin,
            file_handle,
            &mut hash_size,
            hash.as_mut_ptr(),
            0,
        );

        let _ = windows::Win32::Foundation::CloseHandle(file_handle);

        if hash_result == 0 {
            let _ = CryptCATAdminReleaseContext(cat_admin, 0);
            return None;
        }

        // Find catalog containing this hash
        let cat_info_handle =
            CryptCATAdminEnumCatalogFromHash(cat_admin, &hash, Some(0), None);

        if cat_info_handle == 0 {
            let _ = CryptCATAdminReleaseContext(cat_admin, 0);
            return None;
        }

        // Verify via WinVerifyTrust (same as SHA1 path)
        let result = verify_catalog_trust(
            cat_admin,
            cat_info_handle,
            &file_wide,
            &hash,
        );

        let _ = CryptCATAdminReleaseCatalogContext(cat_admin, cat_info_handle, 0);
        let _ = CryptCATAdminReleaseContext(cat_admin, 0);

        result
    }
}

/// Shared helper: given a catalog admin context + catalog info handle,
/// run WinVerifyTrust and extract signer info.
/// Caller is responsible for releasing cat_admin and cat_info_handle.
unsafe fn verify_catalog_trust(
    cat_admin: isize,
    cat_info_handle: isize,
    file_wide: &[u16],
    hash: &[u8],
) -> Option<SignatureInfo> {
    let mut catalog_info: CATALOG_INFO = std::mem::zeroed();
    catalog_info.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;

    if CryptCATCatalogInfoFromContext(cat_info_handle, &mut catalog_info, 0).is_err() {
        return None;
    }

    let hash_str: String = hash.iter().map(|b| format!("{:02X}", b)).collect();
    let member_tag_wide = to_wide(&hash_str);

    let mut cat_info_struct: WINTRUST_CATALOG_INFO = std::mem::zeroed();
    cat_info_struct.cbStruct = std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
    cat_info_struct.pcwszCatalogFilePath = PCWSTR(catalog_info.wszCatalogFile.as_ptr());
    cat_info_struct.pcwszMemberTag = PCWSTR(member_tag_wide.as_ptr());
    cat_info_struct.pcwszMemberFilePath = PCWSTR(file_wide.as_ptr());
    cat_info_struct.hMemberFile = HANDLE::default();
    cat_info_struct.hCatAdmin = cat_admin;

    let mut trust_data: WINTRUST_DATA = std::mem::zeroed();
    trust_data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_CATALOG;
    trust_data.Anonymous = WINTRUST_DATA_0 {
        pCatalog: &mut cat_info_struct,
    };
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let hwnd = HWND(INVALID_HANDLE_VALUE.0 as *mut _);

    let status = WinVerifyTrust(
        hwnd,
        &mut action_guid,
        (&mut trust_data as *mut WINTRUST_DATA).cast(),
    );

    let signer = if status == 0 {
        extract_signer_from_state(trust_data.hWVTStateData)
    } else {
        None
    };

    let is_signed = status == 0;

    // Close state
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = WinVerifyTrust(
        hwnd,
        &mut action_guid,
        (&mut trust_data as *mut WINTRUST_DATA).cast(),
    );

    if is_signed {
        Some(SignatureInfo {
            is_signed: true,
            signer,

        })
    } else {
        None
    }
}

/// Try catalog verification with a specific subsystem GUID (SHA1 - legacy)
fn try_catalog_with_subsystem(
    file_path: &str,
    subsystem: Option<&windows::core::GUID>,
) -> Option<SignatureInfo> {
    let file_wide = to_wide(file_path);

    unsafe {
        let file_handle = CreateFileW(
            PCWSTR(file_wide.as_ptr()),
            0x80000000, // GENERIC_READ
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .ok()?;

        let mut cat_admin: isize = 0;
        let result = if let Some(guid) = subsystem {
            CryptCATAdminAcquireContext(&mut cat_admin, Some(guid), Some(0))
        } else {
            CryptCATAdminAcquireContext(&mut cat_admin, None, Some(0))
        };
        if result.is_err() {
            let _ = windows::Win32::Foundation::CloseHandle(file_handle);
            return None;
        }

        let mut hash_size = 0u32;
        let _ = CryptCATAdminCalcHashFromFileHandle(file_handle, &mut hash_size, None, Some(0));

        if hash_size == 0 {
            let _ = CryptCATAdminReleaseContext(cat_admin, 0);
            let _ = windows::Win32::Foundation::CloseHandle(file_handle);
            return None;
        }

        let mut hash = vec![0u8; hash_size as usize];
        let hash_result = CryptCATAdminCalcHashFromFileHandle(
            file_handle,
            &mut hash_size,
            Some(hash.as_mut_ptr()),
            Some(0),
        );

        let _ = windows::Win32::Foundation::CloseHandle(file_handle);

        if !hash_result.as_bool() {
            let _ = CryptCATAdminReleaseContext(cat_admin, 0);
            return None;
        }

        let cat_info_handle =
            CryptCATAdminEnumCatalogFromHash(cat_admin, &hash, Some(0), None);

        if cat_info_handle == 0 {
            let _ = CryptCATAdminReleaseContext(cat_admin, 0);
            return None;
        }

        let result = verify_catalog_trust(cat_admin, cat_info_handle, &file_wide, &hash);

        let _ = CryptCATAdminReleaseCatalogContext(cat_admin, cat_info_handle, 0);
        let _ = CryptCATAdminReleaseContext(cat_admin, 0);

        result
    }
}
