use crate::drivers::DriverInfo;
use anyhow::Result;

pub fn export(drivers: &[DriverInfo]) -> Result<String> {
    let mut output = String::new();

    output.push_str(&"=".repeat(120));
    output.push('\n');
    output.push_str(&format!(
        "{:<30} {:<18} {:<12} {:<6} {:<6} {:<20} {:<20}\n",
        "Driver Name", "Address", "Size", "LdCnt", "Index", "File Type", "Company"
    ));
    output.push_str(&"=".repeat(120));
    output.push('\n');

    for driver in drivers {
        let addr = format!("{:016X}", driver.load_address);
        let size = if driver.size > 0 {
            format!("0x{:08X}", driver.size)
        } else {
            String::from("-")
        };

        output.push_str(&format!(
            "{:<30} {:<18} {:<12} {:<6} {:<6} {:<20} {:<20}\n",
            driver.name,
            addr,
            size,
            driver.load_count,
            driver.index,
            driver.file_type.as_deref().unwrap_or("-"),
            driver.company_name.as_deref().unwrap_or("-"),
        ));

        // Detail lines
        output.push_str(&format!("  Path:         {}\n", driver.file_path));
        output.push_str(&format!("  Type:         {}\n", driver.driver_type));
        output.push_str(&format!("  Status:       {}\n", driver.status));

        if driver.end_address > 0 {
            output.push_str(&format!(
                "  Address:      0x{:X} - 0x{:X}\n",
                driver.load_address, driver.end_address
            ));
        }

        if let Some(version) = &driver.file_version {
            output.push_str(&format!("  Version:      {}\n", version));
        }
        if let Some(desc) = &driver.file_description {
            output.push_str(&format!("  Description:  {}\n", desc));
        }
        if let Some(product) = &driver.product_name {
            output.push_str(&format!("  Product:      {}\n", product));
        }
        if let Some(modified) = &driver.modified_date {
            output.push_str(&format!("  Modified:     {}\n", modified));
        }
        if let Some(created) = &driver.created_date {
            output.push_str(&format!("  Created:      {}\n", created));
        }
        if let Some(attrs) = &driver.file_attributes {
            output.push_str(&format!("  Attributes:   {}\n", attrs));
        }
        if let Some(svc) = &driver.service_name {
            output.push_str(&format!("  Service:      {}\n", svc));
        }
        if let Some(svc_disp) = &driver.service_display_name {
            output.push_str(&format!("  Svc Display:  {}\n", svc_disp));
        }
        if let Some(signed) = driver.is_signed {
            output.push_str(&format!(
                "  Signed:       {}\n",
                if signed { "Yes" } else { "No" }
            ));
        }
        output.push('\n');
    }

    output.push_str(&format!("Total drivers: {}\n", drivers.len()));

    Ok(output)
}
