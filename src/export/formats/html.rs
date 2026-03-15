use crate::drivers::DriverInfo;
use anyhow::Result;

pub fn export(drivers: &[DriverInfo]) -> Result<String> {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n");
    html.push_str("<html lang=\"en\">\n");
    html.push_str("<head>\n");
    html.push_str("    <meta charset=\"UTF-8\">\n");
    html.push_str(
        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n",
    );
    html.push_str("    <title>DriverExplorer - Windows Drivers Report</title>\n");
    html.push_str("    <style>\n");
    html.push_str("        * { margin: 0; padding: 0; box-sizing: border-box; }\n");
    html.push_str("        body {\n");
    html.push_str("            font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif;\n");
    html.push_str("            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\n");
    html.push_str("            min-height: 100vh;\n");
    html.push_str("            padding: 20px;\n");
    html.push_str("        }\n");
    html.push_str("        .container {\n");
    html.push_str("            max-width: 100%;\n");
    html.push_str("            margin: 0 auto;\n");
    html.push_str("            background: white;\n");
    html.push_str("            border-radius: 8px;\n");
    html.push_str("            box-shadow: 0 10px 40px rgba(0,0,0,0.3);\n");
    html.push_str("            padding: 30px;\n");
    html.push_str("            overflow-x: auto;\n");
    html.push_str("        }\n");
    html.push_str("        h1 { color: #333; margin-bottom: 10px; }\n");
    html.push_str("        .info { color: #666; margin-bottom: 30px; font-size: 14px; }\n");
    html.push_str("        table { width: 100%; border-collapse: collapse; margin-bottom: 30px; font-size: 12px; }\n");
    html.push_str("        th { background: #f5f5f5; padding: 8px 6px; text-align: left; border-bottom: 2px solid #ddd; font-weight: 600; color: #333; white-space: nowrap; }\n");
    html.push_str("        td { padding: 6px; border-bottom: 1px solid #eee; white-space: nowrap; }\n");
    html.push_str("        tr:hover { background: #f9f9f9; }\n");
    html.push_str("        .status-running { color: #28a745; font-weight: 600; }\n");
    html.push_str("        .status-stopped { color: #dc3545; font-weight: 600; }\n");
    html.push_str("        .signed { color: #28a745; }\n");
    html.push_str("        .unsigned { color: #ffc107; }\n");
    html.push_str("        .footer { text-align: center; color: #999; font-size: 12px; margin-top: 30px; }\n");
    html.push_str("        code { font-size: 11px; }\n");
    html.push_str("    </style>\n");
    html.push_str("</head>\n");
    html.push_str("<body>\n");
    html.push_str("    <div class=\"container\">\n");
    html.push_str("        <h1>DriverExplorer - Windows Driver Report</h1>\n");
    html.push_str(&format!(
        "        <p class=\"info\">Total Drivers: {} | Generated: {}</p>\n",
        drivers.len(),
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    ));

    html.push_str("        <table>\n");
    html.push_str("            <thead>\n");
    html.push_str("                <tr>\n");
    html.push_str("                    <th>Driver Name</th>\n");
    html.push_str("                    <th>Address</th>\n");
    html.push_str("                    <th>End Address</th>\n");
    html.push_str("                    <th>Size</th>\n");
    html.push_str("                    <th>Load Count</th>\n");
    html.push_str("                    <th>Index</th>\n");
    html.push_str("                    <th>File Type</th>\n");
    html.push_str("                    <th>Description</th>\n");
    html.push_str("                    <th>Version</th>\n");
    html.push_str("                    <th>Company</th>\n");
    html.push_str("                    <th>Product Name</th>\n");
    html.push_str("                    <th>Modified Date</th>\n");
    html.push_str("                    <th>Created Date</th>\n");
    html.push_str("                    <th>Filename</th>\n");
    html.push_str("                    <th>File Attributes</th>\n");
    html.push_str("                    <th>Service Name</th>\n");
    html.push_str("                    <th>Service Display Name</th>\n");
    html.push_str("                    <th>Signed</th>\n");
    html.push_str("                </tr>\n");
    html.push_str("            </thead>\n");
    html.push_str("            <tbody>\n");

    for driver in drivers {
        let status_class = match driver.status.to_string().as_str() {
            "Running" => "status-running",
            _ => "status-stopped",
        };

        let signed_text = match driver.is_signed {
            Some(true) => "Yes",
            Some(false) => "No",
            None => "",
        };
        let signed_class = match driver.is_signed {
            Some(true) => "signed",
            _ => "unsigned",
        };

        let addr = format_address(driver.load_address);
        let end_addr = if driver.end_address > 0 {
            format_address(driver.end_address)
        } else {
            String::new()
        };
        let size = if driver.size > 0 {
            format!("0x{:08X}", driver.size)
        } else {
            String::new()
        };

        html.push_str("                <tr>\n");
        html.push_str(&format!(
            "                    <td class=\"{}\">{}</td>\n",
            status_class,
            escape_html(&driver.name)
        ));
        html.push_str(&format!("                    <td><code>{}</code></td>\n", addr));
        html.push_str(&format!("                    <td><code>{}</code></td>\n", end_addr));
        html.push_str(&format!("                    <td>{}</td>\n", size));
        html.push_str(&format!("                    <td>{}</td>\n", driver.load_count));
        html.push_str(&format!("                    <td>{}</td>\n", driver.index));
        html.push_str(&format!(
            "                    <td>{}</td>\n",
            escape_html(driver.file_type.as_deref().unwrap_or(""))
        ));
        html.push_str(&format!(
            "                    <td>{}</td>\n",
            escape_html(driver.file_description.as_deref().unwrap_or(""))
        ));
        html.push_str(&format!(
            "                    <td>{}</td>\n",
            escape_html(driver.file_version.as_deref().unwrap_or(""))
        ));
        html.push_str(&format!(
            "                    <td>{}</td>\n",
            escape_html(driver.company_name.as_deref().unwrap_or(""))
        ));
        html.push_str(&format!(
            "                    <td>{}</td>\n",
            escape_html(driver.product_name.as_deref().unwrap_or(""))
        ));
        html.push_str(&format!(
            "                    <td>{}</td>\n",
            escape_html(driver.modified_date.as_deref().unwrap_or(""))
        ));
        html.push_str(&format!(
            "                    <td>{}</td>\n",
            escape_html(driver.created_date.as_deref().unwrap_or(""))
        ));
        html.push_str(&format!(
            "                    <td><code>{}</code></td>\n",
            escape_html(&driver.file_path)
        ));
        html.push_str(&format!(
            "                    <td>{}</td>\n",
            escape_html(driver.file_attributes.as_deref().unwrap_or(""))
        ));
        html.push_str(&format!(
            "                    <td>{}</td>\n",
            escape_html(driver.service_name.as_deref().unwrap_or(""))
        ));
        html.push_str(&format!(
            "                    <td>{}</td>\n",
            escape_html(driver.service_display_name.as_deref().unwrap_or(""))
        ));
        html.push_str(&format!(
            "                    <td class=\"{}\">{}</td>\n",
            signed_class, signed_text
        ));
        html.push_str("                </tr>\n");
    }

    html.push_str("            </tbody>\n");
    html.push_str("        </table>\n");
    html.push_str("        <div class=\"footer\">\n");
    html.push_str(
        "            <p>Generated by DriverExplorer | Windows Driver Analysis Tool</p>\n",
    );
    html.push_str("        </div>\n");
    html.push_str("    </div>\n");
    html.push_str("</body>\n");
    html.push_str("</html>\n");

    Ok(html)
}

/// Format a 64-bit address as FFFFF802`D5400000 style
fn format_address(addr: u64) -> String {
    let high = (addr >> 32) as u32;
    let low = addr as u32;
    format!("{:08X}`{:08X}", high, low)
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
