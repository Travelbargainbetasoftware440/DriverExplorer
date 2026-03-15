use crate::drivers::DriverInfo;
use anyhow::Result;

pub fn export(drivers: &[DriverInfo]) -> Result<String> {
    let mut output = String::new();

    // Header
    output.push_str("Driver Name,Address,End Address,Size,Load Count,Index,File Type,Description,Version,Company,Product Name,Modified Date,Created Date,Filename,File Attributes,Service Name,Service Display Name,Driver Type,Status,Signed,Signer\n");

    for driver in drivers {
        let addr = if driver.load_address > 0 {
            format!("{:016X}", driver.load_address)
        } else {
            String::new()
        };
        let end_addr = if driver.end_address > 0 {
            format!("{:016X}", driver.end_address)
        } else {
            String::new()
        };
        let size = if driver.size > 0 {
            format!("0x{:08X}", driver.size)
        } else {
            String::new()
        };
        let signed = match driver.is_signed {
            Some(true) => "Yes",
            Some(false) => "No",
            None => "",
        };

        output.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            csv_escape(&driver.name),
            csv_escape(&addr),
            csv_escape(&end_addr),
            csv_escape(&size),
            driver.load_count,
            driver.index,
            csv_escape(driver.file_type.as_deref().unwrap_or("")),
            csv_escape(driver.file_description.as_deref().unwrap_or("")),
            csv_escape(driver.file_version.as_deref().unwrap_or("")),
            csv_escape(driver.company_name.as_deref().unwrap_or("")),
            csv_escape(driver.product_name.as_deref().unwrap_or("")),
            csv_escape(driver.modified_date.as_deref().unwrap_or("")),
            csv_escape(driver.created_date.as_deref().unwrap_or("")),
            csv_escape(&driver.file_path),
            csv_escape(driver.file_attributes.as_deref().unwrap_or("")),
            csv_escape(driver.service_name.as_deref().unwrap_or("")),
            csv_escape(driver.service_display_name.as_deref().unwrap_or("")),
            csv_escape(&driver.driver_type.to_string()),
            csv_escape(&driver.status.to_string()),
            signed,
            csv_escape(driver.signer.as_deref().unwrap_or("")),
        ));
    }

    Ok(output)
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
