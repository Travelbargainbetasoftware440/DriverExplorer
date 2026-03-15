use anyhow::Result;

pub mod app;
pub mod state;
pub mod ui;
pub mod theme;
/// Generate a 64x64 cyber-styled app icon
fn generate_icon() -> egui::IconData {
    generate_icon_shared(64, |rgba, w, h| egui::IconData { rgba: rgba.to_vec(), width: w, height: h })
}

/// Shared icon generator used by both runtime and build.rs
/// Cyber theme: dark bg, neon shield with chip/circuit inside, glowing nodes
fn generate_icon_shared<T>(
    size: u32,
    make: impl FnOnce(&[u8], u32, u32) -> T,
) -> T {
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let c = size as f32 / 2.0;
    let s = size as f32;

    // Neon colors
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

    // --- Rounded rect background: near-black with subtle blue ---
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

    // --- Subtle grid pattern (circuit board feel) ---
    let grid_spacing = s / 8.0;
    for y in 0..size {
        for x in 0..size {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let gx = (fx % grid_spacing - grid_spacing / 2.0).abs();
            let gy = (fy % grid_spacing - grid_spacing / 2.0).abs();
            let on_grid = gx < 0.4 || gy < 0.4;
            if on_grid {
                // Check we're inside the background
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

    // --- Shield shape (SDF) ---
    // Shield: top is a semicircle, bottom tapers to a point
    let shield_cx = c;
    let shield_cy = c - s * 0.02;
    let shield_w = s * 0.34;  // half-width
    let shield_top = shield_cy - s * 0.34;
    let shield_bot = shield_cy + s * 0.38;
    let shield_mid = shield_cy + s * 0.08; // where taper starts

    let shield_sdf = |fx: f32, fy: f32| -> f32 {
        let rx = (fx - shield_cx).abs();
        let ry = fy;

        if ry < shield_top {
            // Above shield
            let dy = shield_top - ry;
            let dx = (rx - shield_w).max(0.0);
            (dx * dx + dy * dy).sqrt()
        } else if ry <= shield_mid {
            // Rectangular part
            rx - shield_w
        } else if ry <= shield_bot {
            // Tapered bottom
            let t = (ry - shield_mid) / (shield_bot - shield_mid);
            let w_at_y = shield_w * (1.0 - t);
            if w_at_y < 0.5 {
                let dy = ry - (shield_bot - 0.5);
                (rx * rx + dy.max(0.0).powi(2)).sqrt()
            } else {
                rx - w_at_y
            }
        } else {
            // Below shield
            let dist_to_tip = ((fx - shield_cx).powi(2) + (fy - shield_bot).powi(2)).sqrt();
            dist_to_tip
        }
    };

    // Shield glow (outer neon bloom)
    for y in 0..size {
        for x in 0..size {
            let fx = x as f32 + 0.5;
            let fy = y as f32 + 0.5;
            let d = shield_sdf(fx, fy);
            if d > 0.0 && d < s * 0.08 {
                let glow = (1.0 - d / (s * 0.08)).powi(2) * 0.3;
                // Mix cyan and magenta based on vertical position
                let t = (fy - shield_top) / (shield_bot - shield_top);
                let r = (cyan[0] as f32 * (1.0 - t) + magenta[0] as f32 * t) as u8;
                let g = (cyan[1] as f32 * (1.0 - t) + magenta[1] as f32 * t) as u8;
                let b = (cyan[2] as f32 * (1.0 - t) + magenta[2] as f32 * t) as u8;
                set_px(&mut rgba, x, y, r, g, b, glow);
            }
        }
    }

    // Shield outline (bright neon edge)
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

    // Shield fill (very dark, slightly translucent)
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

    // --- Chip/CPU inside shield ---
    let chip_cx = c;
    let chip_cy = c - s * 0.02;
    let chip_half = s * 0.12;
    let chip_r = s * 0.03; // corner radius
    let pin_len = s * 0.06;
    let pin_w = s * 0.025;
    let pin_count = 3;

    // Chip body (rounded rect)
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
            // Bright edge
            if sdf.abs() < 1.2 {
                let edge_a = (1.0 - sdf.abs() / 1.2).max(0.0);
                set_px(&mut rgba, x, y, cyan[0], cyan[1], cyan[2], edge_a * 0.7);
            }
        }
    }

    // Chip pins (on all 4 sides)
    let pin_spacing = chip_half * 2.0 / (pin_count as f32 + 1.0);
    for i in 1..=pin_count {
        let offset = -chip_half + pin_spacing * i as f32;

        // Each side: top, bottom, left, right
        let pins: [(f32, f32, bool); 4] = [
            (chip_cx + offset, chip_cy - chip_half - pin_len / 2.0, false), // top
            (chip_cx + offset, chip_cy + chip_half + pin_len / 2.0, false), // bottom
            (chip_cx - chip_half - pin_len / 2.0, chip_cy + offset, true),  // left
            (chip_cx + chip_half + pin_len / 2.0, chip_cy + offset, true),  // right
        ];

        for (pcx, pcy, horizontal) in &pins {
            for y in 0..size {
                for x in 0..size {
                    let fx = x as f32 + 0.5;
                    let fy = y as f32 + 0.5;
                    let (hw, hh) = if *horizontal {
                        (pin_len / 2.0, pin_w / 2.0)
                    } else {
                        (pin_w / 2.0, pin_len / 2.0)
                    };
                    let dx = (fx - pcx).abs() - hw;
                    let dy = (fy - pcy).abs() - hh;
                    let sdf = dx.max(dy);
                    if sdf < 0.8 {
                        let alpha = (0.8 - sdf).min(1.0);
                        set_px(&mut rgba, x, y, cyan[0], cyan[1], cyan[2], alpha * 0.8);
                    }
                }
            }
        }
    }

    // --- Glowing circuit nodes at grid intersections inside shield ---
    let node_r = s * 0.022;
    let node_positions: &[(f32, f32)] = &[
        (c - s * 0.25, c - s * 0.22),
        (c + s * 0.25, c - s * 0.22),
        (c - s * 0.22, c + s * 0.12),
        (c + s * 0.22, c + s * 0.12),
        (c, c + s * 0.28),
    ];

    for &(nx, ny) in node_positions {
        // Only draw if inside shield
        if shield_sdf(nx, ny) > 0.0 { continue; }
        for y in 0..size {
            for x in 0..size {
                let fx = x as f32 + 0.5;
                let fy = y as f32 + 0.5;
                let d = ((fx - nx).powi(2) + (fy - ny).powi(2)).sqrt();

                // Glow
                if d < node_r * 3.0 {
                    let glow = (1.0 - d / (node_r * 3.0)).powi(2) * 0.4;
                    set_px(&mut rgba, x, y, cyan[0], cyan[1], cyan[2], glow);
                }
                // Core
                if d < node_r + 0.5 {
                    let alpha = (node_r + 0.5 - d).min(1.0);
                    set_px(&mut rgba, x, y, 200, 255, 255, alpha);
                }
            }
        }
    }

    // --- Circuit traces connecting nodes to chip ---
    let trace_w = 0.6f32;
    let trace_paths: &[(f32, f32, f32, f32)] = &[
        (c - s * 0.25, c - s * 0.22, chip_cx - chip_half, chip_cy - chip_half),
        (c + s * 0.25, c - s * 0.22, chip_cx + chip_half, chip_cy - chip_half),
        (c - s * 0.22, c + s * 0.12, chip_cx - chip_half, chip_cy + chip_half),
        (c + s * 0.22, c + s * 0.12, chip_cx + chip_half, chip_cy + chip_half),
    ];

    for &(x1, y1, x2, y2) in trace_paths {
        let mx = x1; // L-shaped: go vertical first, then horizontal
        let my = y2;
        // Segment 1: (x1,y1) -> (x1,y2)
        // Segment 2: (x1,y2) -> (x2,y2)
        for y in 0..size {
            for x in 0..size {
                let fx = x as f32 + 0.5;
                let fy = y as f32 + 0.5;

                // Distance to vertical segment
                let min_y = y1.min(my);
                let max_y = y1.max(my);
                let d1 = if fy >= min_y && fy <= max_y {
                    (fx - mx).abs()
                } else {
                    let dy = if fy < min_y { min_y - fy } else { fy - max_y };
                    ((fx - mx).powi(2) + dy.powi(2)).sqrt()
                };

                // Distance to horizontal segment
                let min_x = mx.min(x2);
                let max_x = mx.max(x2);
                let d2 = if fx >= min_x && fx <= max_x {
                    (fy - my).abs()
                } else {
                    let dx = if fx < min_x { min_x - fx } else { fx - max_x };
                    (dx.powi(2) + (fy - my).powi(2)).sqrt()
                };

                let d = d1.min(d2);
                if d < trace_w + 0.5 {
                    // Only inside shield
                    if shield_sdf(fx, fy) < -1.0 {
                        let alpha = (trace_w + 0.5 - d).min(1.0) * 0.6;
                        set_px(&mut rgba, x, y, cyan_dim[0], cyan_dim[1], cyan_dim[2], alpha);
                    }
                }
            }
        }
    }

    make(&rgba, size, size)
}

pub fn run() -> Result<()> {
    // Initialize logging
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_millis()
        .try_init()
        .ok();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_maximized(true)
            .with_icon(generate_icon()),
        ..Default::default()
    };

    eframe::run_native(
        "DriverExplorer",
        options,
        Box::new(|cc| {
            // Apply custom theme
            theme::apply_theme(&cc.egui_ctx);
            Ok(Box::new(app::DriverExplorerApp::new(cc)))
        }),
    )
    .map_err(|e| anyhow::anyhow!("GUI error: {}", e))
}
