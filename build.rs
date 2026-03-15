fn main() {
    // Embed Windows manifest for console window suppression and admin requirement
    let manifest = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    version="1.0.0.0"
    processorArchitecture="x86_64"
    name="DriverExplorer"
    type="win32"
  />
  <description>DriverExplorer - Windows Driver Analysis Tool</description>

  <!-- Hide console window for GUI mode -->
  <asmv3:application xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
    <asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
      <dpiAware>true</dpiAware>
    </asmv3:windowsSettings>
  </asmv3:application>

  <!-- Request admin privileges -->
  <trustInfo xmlns="urn:schemas-microsoft-com:trustInfo.v1">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>

  <!-- Compatibility with Windows 10+ -->
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/> <!-- Windows 10 -->
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/> <!-- Windows 7 -->
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/> <!-- Windows 8 -->
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/> <!-- Windows 8.1 -->
    </application>
  </compatibility>
</assembly>"#;

    std::fs::write("driverexplorer.exe.manifest", manifest)
        .expect("Failed to write manifest file");

    // Generate icon and embed it in the exe
    let icon_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("icon.ico");
    let rgba = generate_icon_rgba(64);
    write_ico(&icon_path, &rgba, 64);

    let mut res = winres::WindowsResource::new();
    res.set_icon(icon_path.to_str().unwrap());
    res.compile().expect("Failed to compile Windows resources");

    println!("cargo:rerun-if-changed=build.rs");
}

/// Generate cyber-styled icon matching the runtime version
fn generate_icon_rgba(size: u32) -> Vec<u8> {
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let c = size as f32 / 2.0;
    let s = size as f32;

    let cyan: [u8; 3] = [0, 230, 255];
    let cyan_dim: [u8; 3] = [0, 140, 180];
    let magenta: [u8; 3] = [180, 0, 255];

    let set_px = |rgba: &mut Vec<u8>, x: u32, y: u32, r: u8, g: u8, b: u8, a: f32| {
        if x >= size || y >= size { return; }
        let idx = ((y * size + x) * 4) as usize;
        let a = a.clamp(0.0, 1.0);
        let oa = rgba[idx + 3] as f32 / 255.0;
        let na = a + oa * (1.0 - a);
        if na > 0.0 {
            rgba[idx]     = ((r as f32 * a + rgba[idx]     as f32 * oa * (1.0 - a)) / na) as u8;
            rgba[idx + 1] = ((g as f32 * a + rgba[idx + 1] as f32 * oa * (1.0 - a)) / na) as u8;
            rgba[idx + 2] = ((b as f32 * a + rgba[idx + 2] as f32 * oa * (1.0 - a)) / na) as u8;
            rgba[idx + 3] = (na * 255.0) as u8;
        }
    };

    // Rounded rect background
    let corner_r = s * 0.18;
    for y in 0..size {
        for x in 0..size {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let dx = (fx - c).abs() - (c - corner_r);
            let dy = (fy - c).abs() - (c - corner_r);
            let qx = dx.max(0.0);
            let qy = dy.max(0.0);
            let sdf = (qx * qx + qy * qy).sqrt() + dx.max(dy).min(0.0) - corner_r;
            if sdf < 1.0 {
                let alpha = if sdf > 0.0 { 1.0 - sdf } else { 1.0 };
                let t = fy / s;
                let r = (8.0 + t * 8.0) as u8;
                let g = (10.0 + t * 12.0) as u8;
                let b = (20.0 + t * 20.0) as u8;
                set_px(&mut rgba, x, y, r, g, b, alpha);
            }
        }
    }

    // Grid pattern
    let grid_spacing = s / 8.0;
    for y in 0..size {
        for x in 0..size {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let gx = (fx % grid_spacing - grid_spacing / 2.0).abs();
            let gy = (fy % grid_spacing - grid_spacing / 2.0).abs();
            if gx < 0.4 || gy < 0.4 {
                let dx = (fx - c).abs() - (c - corner_r);
                let dy = (fy - c).abs() - (c - corner_r);
                let qx = dx.max(0.0);
                let qy = dy.max(0.0);
                let sdf = (qx * qx + qy * qy).sqrt() + dx.max(dy).min(0.0) - corner_r;
                if sdf < -2.0 {
                    set_px(&mut rgba, x, y, 20, 40, 50, 0.25);
                }
            }
        }
    }

    // Shield SDF
    let shield_cx = c;
    let shield_cy = c - s * 0.02;
    let shield_w = s * 0.34;
    let shield_top = shield_cy - s * 0.34;
    let shield_bot = shield_cy + s * 0.38;
    let shield_mid = shield_cy + s * 0.08;

    let shield_sdf = |fx: f32, fy: f32| -> f32 {
        let rx = (fx - shield_cx).abs();
        let ry = fy;
        if ry < shield_top {
            let dy = shield_top - ry;
            let dx = (rx - shield_w).max(0.0);
            (dx * dx + dy * dy).sqrt()
        } else if ry <= shield_mid {
            rx - shield_w
        } else if ry <= shield_bot {
            let t = (ry - shield_mid) / (shield_bot - shield_mid);
            let w_at_y = shield_w * (1.0 - t);
            if w_at_y < 0.5 { let dy = ry - (shield_bot - 0.5); (rx * rx + dy.max(0.0).powi(2)).sqrt() } else { rx - w_at_y }
        } else {
            ((fx - shield_cx).powi(2) + (fy - shield_bot).powi(2)).sqrt()
        }
    };

    // Shield glow
    for y in 0..size {
        for x in 0..size {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let d = shield_sdf(fx, fy);
            if d > 0.0 && d < s * 0.08 {
                let glow = (1.0 - d / (s * 0.08)).powi(2) * 0.3;
                let t = (fy - shield_top) / (shield_bot - shield_top);
                let r = (cyan[0] as f32 * (1.0 - t) + magenta[0] as f32 * t) as u8;
                let g = (cyan[1] as f32 * (1.0 - t) + magenta[1] as f32 * t) as u8;
                let b = (cyan[2] as f32 * (1.0 - t) + magenta[2] as f32 * t) as u8;
                set_px(&mut rgba, x, y, r, g, b, glow);
            }
        }
    }

    // Shield outline
    let stroke_w = s * 0.028;
    for y in 0..size {
        for x in 0..size {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let d = shield_sdf(fx, fy);
            let edge_dist = (d.abs() - stroke_w / 2.0).abs();
            if d.abs() < stroke_w + 1.0 {
                let alpha = (1.0 - edge_dist / 1.0).max(0.0);
                let t = ((fy - shield_top) / (shield_bot - shield_top)).clamp(0.0, 1.0);
                let r = (cyan[0] as f32 * (1.0 - t) + magenta[0] as f32 * t) as u8;
                let g = (cyan[1] as f32 * (1.0 - t) + magenta[1] as f32 * t) as u8;
                let b = (cyan[2] as f32 * (1.0 - t) + magenta[2] as f32 * t) as u8;
                set_px(&mut rgba, x, y, r, g, b, alpha * 0.9);
            }
        }
    }

    // Shield fill
    for y in 0..size {
        for x in 0..size {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let d = shield_sdf(fx, fy);
            if d < -stroke_w / 2.0 {
                let inner = (-d - stroke_w / 2.0).min(1.5) / 1.5;
                set_px(&mut rgba, x, y, 5, 15, 25, inner * 0.6);
            }
        }
    }

    // Chip body
    let chip_cx = c;
    let chip_cy = c - s * 0.02;
    let chip_half = s * 0.12;
    let chip_r = s * 0.03;
    let pin_len = s * 0.06;
    let pin_w = s * 0.025;
    let pin_count = 3;

    for y in 0..size {
        for x in 0..size {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let dx = (fx - chip_cx).abs() - chip_half;
            let dy = (fy - chip_cy).abs() - chip_half;
            let qx = dx.max(0.0);
            let qy = dy.max(0.0);
            let sdf = (qx * qx + qy * qy).sqrt() + dx.max(dy).min(0.0) - chip_r;
            if sdf < 1.0 {
                let alpha = if sdf > 0.0 { 1.0 - sdf } else { 1.0 };
                set_px(&mut rgba, x, y, cyan_dim[0], cyan_dim[1], cyan_dim[2], alpha * 0.5);
            }
            if sdf.abs() < 1.2 {
                let edge_a = (1.0 - sdf.abs() / 1.2).max(0.0);
                set_px(&mut rgba, x, y, cyan[0], cyan[1], cyan[2], edge_a * 0.7);
            }
        }
    }

    // Chip pins
    let pin_spacing = chip_half * 2.0 / (pin_count as f32 + 1.0);
    for i in 1..=pin_count {
        let offset = -chip_half + pin_spacing * i as f32;
        let pins: [(f32, f32, bool); 4] = [
            (chip_cx + offset, chip_cy - chip_half - pin_len / 2.0, false),
            (chip_cx + offset, chip_cy + chip_half + pin_len / 2.0, false),
            (chip_cx - chip_half - pin_len / 2.0, chip_cy + offset, true),
            (chip_cx + chip_half + pin_len / 2.0, chip_cy + offset, true),
        ];
        for (pcx, pcy, horizontal) in &pins {
            for y in 0..size {
                for x in 0..size {
                    let fx = x as f32 + 0.5;
                    let fy = y as f32 + 0.5;
                    let (hw, hh) = if *horizontal { (pin_len / 2.0, pin_w / 2.0) } else { (pin_w / 2.0, pin_len / 2.0) };
                    let sdf = ((fx - pcx).abs() - hw).max((fy - pcy).abs() - hh);
                    if sdf < 0.8 {
                        let alpha = (0.8 - sdf).min(1.0);
                        set_px(&mut rgba, x, y, cyan[0], cyan[1], cyan[2], alpha * 0.8);
                    }
                }
            }
        }
    }

    // Glowing nodes
    let node_r = s * 0.022;
    let node_positions: &[(f32, f32)] = &[
        (c - s * 0.25, c - s * 0.22),
        (c + s * 0.25, c - s * 0.22),
        (c - s * 0.22, c + s * 0.12),
        (c + s * 0.22, c + s * 0.12),
        (c, c + s * 0.28),
    ];
    for &(nx, ny) in node_positions {
        if shield_sdf(nx, ny) > 0.0 { continue; }
        for y in 0..size {
            for x in 0..size {
                let fx = x as f32 + 0.5;
                let fy = y as f32 + 0.5;
                let d = ((fx - nx).powi(2) + (fy - ny).powi(2)).sqrt();
                if d < node_r * 3.0 {
                    let glow = (1.0 - d / (node_r * 3.0)).powi(2) * 0.4;
                    set_px(&mut rgba, x, y, cyan[0], cyan[1], cyan[2], glow);
                }
                if d < node_r + 0.5 {
                    let alpha = (node_r + 0.5 - d).min(1.0);
                    set_px(&mut rgba, x, y, 200, 255, 255, alpha);
                }
            }
        }
    }

    // Circuit traces
    let trace_w = 0.6f32;
    let trace_paths: &[(f32, f32, f32, f32)] = &[
        (c - s * 0.25, c - s * 0.22, chip_cx - chip_half, chip_cy - chip_half),
        (c + s * 0.25, c - s * 0.22, chip_cx + chip_half, chip_cy - chip_half),
        (c - s * 0.22, c + s * 0.12, chip_cx - chip_half, chip_cy + chip_half),
        (c + s * 0.22, c + s * 0.12, chip_cx + chip_half, chip_cy + chip_half),
    ];
    for &(x1, y1, x2, y2) in trace_paths {
        let mx = x1;
        let my = y2;
        for y in 0..size {
            for x in 0..size {
                let fx = x as f32 + 0.5;
                let fy = y as f32 + 0.5;
                let min_y = y1.min(my);
                let max_y = y1.max(my);
                let d1 = if fy >= min_y && fy <= max_y { (fx - mx).abs() } else { let dy = if fy < min_y { min_y - fy } else { fy - max_y }; ((fx - mx).powi(2) + dy.powi(2)).sqrt() };
                let min_x = mx.min(x2);
                let max_x = mx.max(x2);
                let d2 = if fx >= min_x && fx <= max_x { (fy - my).abs() } else { let dx = if fx < min_x { min_x - fx } else { fx - max_x }; (dx.powi(2) + (fy - my).powi(2)).sqrt() };
                let d = d1.min(d2);
                if d < trace_w + 0.5 && shield_sdf(fx, fy) < -1.0 {
                    let alpha = (trace_w + 0.5 - d).min(1.0) * 0.6;
                    set_px(&mut rgba, x, y, cyan_dim[0], cyan_dim[1], cyan_dim[2], alpha);
                }
            }
        }
    }

    rgba
}

/// Write RGBA pixel data as a .ico file (single 64x64 32-bit BMP entry)
fn write_ico(path: &std::path::Path, rgba: &[u8], size: u32) {
    use std::io::Write;

    let pixel_count = (size * size) as usize;
    // ICO BMP: rows are bottom-to-top, BGRA
    let bmp_data_size = pixel_count * 4;
    let and_mask_row = ((size + 31) / 32) * 4;
    let and_mask_size = (and_mask_row * size) as usize;

    // BITMAPINFOHEADER (40 bytes)
    let bih_size: u32 = 40;
    let bmp_total = bih_size as usize + bmp_data_size + and_mask_size;

    let mut ico = Vec::new();

    // ICONDIR header (6 bytes)
    ico.write_all(&0u16.to_le_bytes()).unwrap(); // reserved
    ico.write_all(&1u16.to_le_bytes()).unwrap(); // type = ICO
    ico.write_all(&1u16.to_le_bytes()).unwrap(); // count = 1

    // ICONDIRENTRY (16 bytes)
    ico.push(size as u8); // width (0 means 256)
    ico.push(size as u8); // height
    ico.push(0);          // color palette
    ico.push(0);          // reserved
    ico.write_all(&1u16.to_le_bytes()).unwrap();  // color planes
    ico.write_all(&32u16.to_le_bytes()).unwrap(); // bits per pixel
    ico.write_all(&(bmp_total as u32).to_le_bytes()).unwrap(); // size of image data
    ico.write_all(&22u32.to_le_bytes()).unwrap(); // offset (6 + 16 = 22)

    // BITMAPINFOHEADER
    ico.write_all(&bih_size.to_le_bytes()).unwrap();
    ico.write_all(&size.to_le_bytes()).unwrap();          // width
    ico.write_all(&(size * 2).to_le_bytes()).unwrap();    // height (doubled for AND mask)
    ico.write_all(&1u16.to_le_bytes()).unwrap();          // planes
    ico.write_all(&32u16.to_le_bytes()).unwrap();         // bpp
    ico.write_all(&0u32.to_le_bytes()).unwrap();          // compression
    ico.write_all(&(bmp_data_size as u32 + and_mask_size as u32).to_le_bytes()).unwrap();
    ico.write_all(&0u32.to_le_bytes()).unwrap();          // x ppm
    ico.write_all(&0u32.to_le_bytes()).unwrap();          // y ppm
    ico.write_all(&0u32.to_le_bytes()).unwrap();          // colors used
    ico.write_all(&0u32.to_le_bytes()).unwrap();          // important colors

    // Pixel data: bottom-to-top, BGRA
    for y in (0..size).rev() {
        for x in 0..size {
            let idx = ((y * size + x) * 4) as usize;
            let r = rgba[idx];
            let g = rgba[idx + 1];
            let b = rgba[idx + 2];
            let a = rgba[idx + 3];
            ico.push(b);
            ico.push(g);
            ico.push(r);
            ico.push(a);
        }
    }

    // AND mask (all zeros = fully visible, alpha channel handles transparency)
    ico.extend(std::iter::repeat(0u8).take(and_mask_size));

    std::fs::write(path, &ico).expect("Failed to write icon file");
}
