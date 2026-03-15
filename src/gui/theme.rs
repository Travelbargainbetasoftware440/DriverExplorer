use egui::{Color32, Visuals};

pub fn apply_theme(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();

    // Modern dark theme colors
    visuals.override_text_color = Some(Color32::from_rgb(230, 230, 230));
    visuals.panel_fill = Color32::from_rgb(20, 20, 30); // Dark blue-ish
    visuals.window_fill = Color32::from_rgb(25, 25, 35);
    visuals.extreme_bg_color = Color32::from_rgb(15, 15, 25);

    // Button styling
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(50, 50, 70);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(70, 70, 100);
    visuals.widgets.active.bg_fill = Color32::from_rgb(80, 120, 180);

    // Text field styling
    visuals.widgets.inactive.bg_stroke.color = Color32::from_rgb(60, 60, 80);
    visuals.widgets.hovered.bg_stroke.color = Color32::from_rgb(100, 100, 140);

    // Selection colors
    visuals.selection.bg_fill = Color32::from_rgb(80, 120, 180);
    visuals.selection.stroke.color = Color32::from_rgb(120, 160, 220);

    // Hyperlink color (modern blue)
    visuals.hyperlink_color = Color32::from_rgb(100, 180, 255);

    // Apply visuals
    ctx.set_visuals(visuals);

    // Set font
    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(13.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(16.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        egui::FontId::new(11.0, egui::FontFamily::Monospace),
    );

    ctx.set_style(style);
}

pub struct Colors;

impl Colors {
    pub fn accent() -> Color32 {
        Color32::from_rgb(100, 180, 255)
    }

    pub fn success() -> Color32 {
        Color32::from_rgb(100, 200, 100)
    }

    pub fn warning() -> Color32 {
        Color32::from_rgb(255, 180, 100)
    }

    pub fn error() -> Color32 {
        Color32::from_rgb(255, 100, 100)
    }

    pub fn running() -> Color32 {
        Self::success()
    }

    pub fn stopped() -> Color32 {
        Self::warning()
    }

    pub fn signed() -> Color32 {
        Self::success()
    }

    pub fn unsigned() -> Color32 {
        Self::warning()
    }
}
