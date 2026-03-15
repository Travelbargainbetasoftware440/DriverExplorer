use super::state::{AppState, GuiAction, SortColumn, SortOrder};
use super::theme::Colors;
use egui::{Button, Color32, RichText};

/// Create text with mnemonic character underlined for Alt+key menu access
fn mnemonic_text(text: &str, mnemonic: char) -> egui::WidgetText {
    let lower = text.to_lowercase();
    let m_lower = mnemonic.to_ascii_lowercase();
    if let Some(pos) = lower.find(m_lower) {
        let mut job = egui::text::LayoutJob::default();
        let font = egui::FontId::default();
        let base = egui::TextFormat {
            font_id: font.clone(),
            ..Default::default()
        };
        let underlined = egui::TextFormat {
            font_id: font,
            underline: egui::Stroke::new(1.0, Color32::from_rgb(180, 180, 200)),
            ..Default::default()
        };
        let end = pos + text[pos..].chars().next().map_or(1, |c| c.len_utf8());
        if pos > 0 {
            job.append(&text[..pos], 0.0, base.clone());
        }
        job.append(&text[pos..end], 0.0, underlined);
        if end < text.len() {
            job.append(&text[end..], 0.0, base);
        }
        job.into()
    } else {
        text.into()
    }
}

pub fn draw_toolbar(
    ctx: &egui::Context,
    state: &mut AppState,
    is_elevated: bool,
) -> Vec<GuiAction> {
    let mut actions = Vec::new();

    // --- Detect Alt+key for menu mnemonics ---
    let mut pending_menu = state.pending_menu.take();
    ctx.input(|i| {
        if i.modifiers.alt {
            let keys = [
                (egui::Key::F, 'f'),
                (egui::Key::E, 'e'),
                (egui::Key::V, 'v'),
                (egui::Key::X, 'x'),
                (egui::Key::T, 't'),
                (egui::Key::H, 'h'),
            ];
            for (key, ch) in keys {
                if i.key_pressed(key) {
                    pending_menu = Some(ch);
                }
            }
        }
    });

    // Menu popup IDs
    let menu_ids = [
        egui::Id::new("_dv_menu_file"),
        egui::Id::new("_dv_menu_edit"),
        egui::Id::new("_dv_menu_view"),
        egui::Id::new("_dv_menu_export"),
        egui::Id::new("_dv_menu_tools"),
        egui::Id::new("_dv_menu_help"),
    ];

    // --- Menu bar ---
    egui::TopBottomPanel::top("menubar").show(ctx, |ui| {
        ui.horizontal(|ui| {
            let any_open = menu_ids
                .iter()
                .any(|&id| ui.memory(|mem| mem.is_popup_open(id)));

            // Macro: open menu at index, closing others
            macro_rules! open_menu {
                ($ui:expr, $idx:expr) => {{
                    for (i, &id) in menu_ids.iter().enumerate() {
                        if i != $idx && $ui.memory(|mem| mem.is_popup_open(id)) {
                            $ui.memory_mut(|mem| mem.toggle_popup(id));
                        }
                    }
                    if !$ui.memory(|mem| mem.is_popup_open(menu_ids[$idx])) {
                        $ui.memory_mut(|mem| mem.toggle_popup(menu_ids[$idx]));
                    }
                }};
            }

            // Macro: create menu button with mnemonic and hover-to-switch
            macro_rules! menu_btn {
                ($ui:expr, $idx:expr, $label:expr, $mnemonic:expr) => {{
                    let popup_id = menu_ids[$idx];
                    let is_open = $ui.memory(|mem| mem.is_popup_open(popup_id));
                    let response =
                        $ui.selectable_label(is_open, mnemonic_text($label, $mnemonic));

                    if response.clicked() {
                        if is_open {
                            $ui.memory_mut(|mem| mem.toggle_popup(popup_id));
                        } else {
                            open_menu!($ui, $idx);
                        }
                    } else if pending_menu == Some($mnemonic) {
                        pending_menu = None;
                        if is_open {
                            $ui.memory_mut(|mem| mem.toggle_popup(popup_id));
                        } else {
                            open_menu!($ui, $idx);
                        }
                    } else if response.hovered() && any_open && !is_open {
                        open_menu!($ui, $idx);
                    }

                    (popup_id, response)
                }};
            }

            // FILE MENU
            {
                let (popup_id, response) = menu_btn!(ui, 0, "File", 'f');
                egui::popup::popup_below_widget(
                    ui,
                    popup_id,
                    &response,
                    egui::popup::PopupCloseBehavior::CloseOnClick,
                    |ui| {
                        ui.set_min_width(200.0);
                        if ui
                            .add(
                                egui::Button::new("Save Selected Items")
                                    .shortcut_text("Ctrl+S"),
                            )
                            .clicked()
                        {
                            actions.push(GuiAction::SaveSelectedItems);
                        }
                        ui.separator();
                        if ui
                            .add(egui::Button::new("Properties").shortcut_text("F8"))
                            .clicked()
                        {
                            actions.push(GuiAction::FileProperties);
                        }
                        ui.separator();
                        if ui.button("Google Search").clicked() {
                            actions.push(GuiAction::GoogleSearch);
                        }
                        ui.separator();
                        if ui.button("Exit").clicked() {
                            actions.push(GuiAction::Exit);
                        }
                    },
                );
            }

            // EDIT MENU
            {
                let (popup_id, response) = menu_btn!(ui, 1, "Edit", 'e');
                egui::popup::popup_below_widget(
                    ui,
                    popup_id,
                    &response,
                    egui::popup::PopupCloseBehavior::CloseOnClick,
                    |ui| {
                        ui.set_min_width(200.0);
                        if ui
                            .add(egui::Button::new("Find").shortcut_text("Ctrl+F"))
                            .clicked()
                        {
                            actions.push(GuiAction::FocusFind);
                        }
                        ui.separator();
                        if ui
                            .add(
                                egui::Button::new("Copy Selected Items")
                                    .shortcut_text("Ctrl+C"),
                            )
                            .clicked()
                        {
                            actions.push(GuiAction::CopySelectedItems);
                        }
                        ui.separator();
                        if ui
                            .add(egui::Button::new("Select All").shortcut_text("Ctrl+A"))
                            .clicked()
                        {
                            actions.push(GuiAction::SelectAll);
                        }
                        if ui
                            .add(
                                egui::Button::new("Deselect All")
                                    .shortcut_text("Ctrl+D"),
                            )
                            .clicked()
                        {
                            actions.push(GuiAction::DeselectAll);
                        }
                    },
                );
            }

            // VIEW MENU (includes Options items, no HTML Report)
            {
                let (popup_id, response) = menu_btn!(ui, 2, "View", 'v');
                egui::popup::popup_below_widget(
                    ui,
                    popup_id,
                    &response,
                    egui::popup::PopupCloseBehavior::CloseOnClickOutside,
                    |ui| {
                        ui.set_min_width(220.0);
                        ui.checkbox(
                            &mut state.mark_non_microsoft,
                            "Mark Non-Microsoft Drivers",
                        );
                        let mut hide_ms = !state.show_microsoft;
                        if ui
                            .checkbox(&mut hide_ms, "Hide Microsoft Drivers")
                            .changed()
                        {
                            state.show_microsoft = !hide_ms;
                            state.validate_selection();
                        }
                        let mut hide_non_ms = !state.show_non_microsoft;
                        if ui
                            .checkbox(&mut hide_non_ms, "Hide Non-Microsoft Drivers")
                            .changed()
                        {
                            state.show_non_microsoft = !hide_non_ms;
                            state.validate_selection();
                        }
                        ui.checkbox(&mut state.show_grid_lines, "Show Grid Lines");
                        ui.checkbox(
                            &mut state.read_signatures,
                            "Read Digital Signatures",
                        );
                        ui.separator();
                        if ui
                            .checkbox(&mut state.auto_refresh, "Automatic Refresh")
                            .changed()
                        {
                            if state.auto_refresh {
                                state.auto_refresh_interval =
                                    Some(std::time::Instant::now());
                            } else {
                                state.auto_refresh_interval = None;
                            }
                        }
                        if ui
                            .add(egui::Button::new("Refresh").shortcut_text("F5"))
                            .clicked()
                        {
                            actions.push(GuiAction::Refresh);
                            ui.memory_mut(|mem| mem.toggle_popup(popup_id));
                        }
                    },
                );
            }

            // EXPORT MENU (flattened - no submenus)
            {
                let has_selection = !state.selected_names.is_empty();
                let sel_count = state.selection_count();
                let (popup_id, response) = menu_btn!(ui, 3, "Export", 'x');
                egui::popup::popup_below_widget(
                    ui,
                    popup_id,
                    &response,
                    egui::popup::PopupCloseBehavior::CloseOnClick,
                    |ui| {
                        ui.set_min_width(220.0);
                        if ui.button("CSV - All Items").clicked() {
                            actions.push(GuiAction::ExportCsvAll);
                        }
                        if ui
                            .add_enabled(
                                has_selection,
                                egui::Button::new(format!(
                                    "CSV - Selected ({})",
                                    sel_count
                                )),
                            )
                            .clicked()
                        {
                            actions.push(GuiAction::ExportCsvSelected);
                        }
                        ui.separator();
                        if ui.button("JSON - All Items").clicked() {
                            actions.push(GuiAction::ExportJsonAll);
                        }
                        if ui
                            .add_enabled(
                                has_selection,
                                egui::Button::new(format!(
                                    "JSON - Selected ({})",
                                    sel_count
                                )),
                            )
                            .clicked()
                        {
                            actions.push(GuiAction::ExportJsonSelected);
                        }
                        ui.separator();
                        if ui.button("HTML - All Items").clicked() {
                            actions.push(GuiAction::ExportHtmlAll);
                        }
                        if ui
                            .add_enabled(
                                has_selection,
                                egui::Button::new(format!(
                                    "HTML - Selected ({})",
                                    sel_count
                                )),
                            )
                            .clicked()
                        {
                            actions.push(GuiAction::ExportHtmlSelected);
                        }
                        ui.separator();
                        if ui.button("Text - All Items").clicked() {
                            actions.push(GuiAction::ExportTextAll);
                        }
                        if ui
                            .add_enabled(
                                has_selection,
                                egui::Button::new(format!(
                                    "Text - Selected ({})",
                                    sel_count
                                )),
                            )
                            .clicked()
                        {
                            actions.push(GuiAction::ExportTextSelected);
                        }
                    },
                );
            }

            // TOOLS MENU
            {
                let (popup_id, response) = menu_btn!(ui, 4, "Tools", 't');
                egui::popup::popup_below_widget(
                    ui,
                    popup_id,
                    &response,
                    egui::popup::PopupCloseBehavior::CloseOnClick,
                    |ui| {
                        ui.set_min_width(200.0);
                        if ui.button("Driver Manager...").clicked() {
                            actions.push(GuiAction::OpenDriverManager);
                        }
                        ui.separator();
                        if ui.button("Save Snapshot...").clicked() {
                            actions.push(GuiAction::SaveSnapshot);
                        }
                        if ui.button("Compare Snapshot...").clicked() {
                            actions.push(GuiAction::CompareSnapshot);
                        }
                        ui.separator();
                        if ui.button("Verify Signature").clicked() {
                            actions.push(GuiAction::VerifySignature);
                        }
                    },
                );
            }

            // HELP MENU
            {
                let (popup_id, response) = menu_btn!(ui, 5, "Help", 'h');
                egui::popup::popup_below_widget(
                    ui,
                    popup_id,
                    &response,
                    egui::popup::PopupCloseBehavior::CloseOnClick,
                    |ui| {
                        ui.set_min_width(200.0);
                        if is_elevated {
                            ui.add_enabled(
                                false,
                                egui::Button::new("Run As Administrator"),
                            );
                        } else if ui
                            .add(
                                egui::Button::new("Run As Administrator")
                                    .shortcut_text("Ctrl+F11"),
                            )
                            .clicked()
                        {
                            actions.push(GuiAction::ElevateToAdmin);
                        }
                        ui.separator();
                        if ui.button("About").clicked() {
                            actions.push(GuiAction::ShowAbout);
                        }
                    },
                );
            }
        });
    });

    // --- Toolbar ---
    egui::TopBottomPanel::top("toolbar")
        .frame(egui::Frame::NONE.fill(Color32::from_rgb(18, 18, 28)).inner_margin(egui::Margin::symmetric(8, 6)))
        .show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(6.0, 0.0);

            if ui
                .button(RichText::new("\u{21BB}").size(14.0))
                .on_hover_text("Refresh (F5)")
                .clicked()
            {
                actions.push(GuiAction::Refresh);
            }

            if ui
                .button(RichText::new("\u{1F4BE}").size(14.0))
                .on_hover_text("Save Selected Items (Ctrl+S)")
                .clicked()
            {
                actions.push(GuiAction::SaveSelectedItems);
            }

            if ui
                .button(RichText::new("\u{1F4CB}").size(14.0))
                .on_hover_text("Copy Selected Items (Ctrl+C)")
                .clicked()
            {
                actions.push(GuiAction::CopySelectedItems);
            }

            if ui
                .button(RichText::new("\u{1F50D}").size(14.0))
                .on_hover_text("Find (Ctrl+F)")
                .clicked()
            {
                actions.push(GuiAction::FocusFind);
            }

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(8.0);

            // Prominent action buttons — large, bold, high-contrast fills
            let btn_min_size = egui::vec2(130.0, 28.0);

            let load_btn = Button::new(
                RichText::new("\u{25B6}  LOAD DRIVER").size(14.0).strong().color(Color32::WHITE),
            ).fill(Color32::from_rgb(20, 140, 55)).min_size(btn_min_size).corner_radius(4.0);
            if ui.add(load_btn)
                .on_hover_text("Register and start a new driver")
                .clicked()
            {
                actions.push(GuiAction::LoadDriver);
            }

            ui.add_space(6.0);

            let can_unload = !state.selected_names.is_empty();
            let unload_fill = if can_unload { Color32::from_rgb(180, 30, 30) } else { Color32::from_rgb(60, 30, 30) };
            let unload_btn = Button::new(
                RichText::new("\u{25A0}  UNLOAD").size(14.0).strong().color(if can_unload { Color32::WHITE } else { Color32::from_rgb(100, 70, 70) }),
            ).fill(unload_fill).min_size(egui::vec2(110.0, 28.0)).corner_radius(4.0);
            if ui.add_enabled(can_unload, unload_btn)
                .on_hover_text("Stop and unregister the selected driver")
                .clicked()
            {
                actions.push(GuiAction::UnloadDriver);
            }

            ui.add_space(6.0);

            let manager_btn = Button::new(
                RichText::new("\u{2699}  MANAGER").size(14.0).strong().color(Color32::WHITE),
            ).fill(Color32::from_rgb(40, 80, 170)).min_size(egui::vec2(110.0, 28.0)).corner_radius(4.0);
            if ui.add(manager_btn)
                .on_hover_text("Open Driver Manager panel")
                .clicked()
            {
                actions.push(GuiAction::OpenDriverManager);
            }

            ui.add_space(8.0);
            ui.separator();

            match &state.loading_state {
                super::state::LoadingState::Loading => {
                    ui.label(RichText::new("Loading...").color(Colors::accent()).size(11.0));
                }
                super::state::LoadingState::Loaded => {
                    ui.label(
                        RichText::new(format!("{} drivers", state.drivers.len()))
                            .color(Colors::success())
                            .size(11.0),
                    );
                }
                super::state::LoadingState::Error(e) => {
                    ui.label(
                        RichText::new(format!("Error: {}", e))
                            .color(Colors::error())
                            .size(11.0),
                    );
                }
                super::state::LoadingState::Idle => {}
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if is_elevated {
                    ui.label(
                        RichText::new("\u{1F6E1} Administrator")
                            .size(11.0)
                            .color(Colors::success())
                            .strong(),
                    );
                } else {
                    if ui
                        .button(
                            RichText::new("Run as Administrator")
                                .size(11.0)
                                .color(Colors::warning()),
                        )
                        .on_hover_text("Restart with administrator privileges (Ctrl+F11)")
                        .clicked()
                    {
                        actions.push(GuiAction::ElevateToAdmin);
                    }
                }
            });
        });

        // Search bar
        ui.horizontal(|ui| {
            ui.label(RichText::new("Search:").size(11.0));
            let search_response = ui.add(
                egui::TextEdit::singleline(&mut state.search_filter)
                    .desired_width(200.0)
                    .font(egui::FontId::new(11.0, egui::FontFamily::Proportional)),
            );

            // Focus search box when requested
            if state.focus_search {
                search_response.request_focus();
                state.focus_search = false;
            }

            ui.separator();

            let prev_show_microsoft = state.show_microsoft;
            let prev_show_non_microsoft = state.show_non_microsoft;
            ui.checkbox(&mut state.show_microsoft, RichText::new("Show Microsoft Drivers").size(11.0));
            ui.checkbox(&mut state.show_non_microsoft, RichText::new("Show Non-Microsoft Drivers").size(11.0));

            if search_response.changed() || state.show_microsoft != prev_show_microsoft || state.show_non_microsoft != prev_show_non_microsoft {
                state.validate_selection();
            }

            ui.label(
                RichText::new(format!(
                    "{}/{}",
                    state.filtered_drivers().len(),
                    state.drivers.len()
                ))
                .size(11.0)
                .color(Color32::from_rgb(150, 150, 170)),
            );
        });
    });

    // --- Status bar (bottom) ---
    egui::TopBottomPanel::bottom("statusbar").show(ctx, |ui| {
        ui.horizontal(|ui| {
            state.tick_status();
            if let Some(ref msg) = state.status_message {
                let color = match msg.kind {
                    super::state::StatusKind::Info => Colors::accent(),
                    super::state::StatusKind::Success => Colors::success(),
                    super::state::StatusKind::Error => Colors::error(),
                };
                ui.label(RichText::new(&msg.text).size(11.0).color(color));
            } else {
                let count = state.selection_count();
                if count > 1 {
                    ui.label(
                        RichText::new(format!("{} items selected", count))
                            .size(11.0)
                            .color(Color32::from_rgb(150, 150, 170)),
                    );
                } else if let Some(driver) = state.selected() {
                    ui.label(
                        RichText::new(&driver.file_path)
                            .size(11.0)
                            .color(Color32::from_rgb(150, 150, 170)),
                    );
                }
            }
        });
    });

    // --- Keyboard shortcuts ---
    ctx.input(|i| {
        if i.key_pressed(egui::Key::F5) {
            actions.push(GuiAction::Refresh);
        }
        if i.key_pressed(egui::Key::F8) {
            actions.push(GuiAction::FileProperties);
        }
        if i.modifiers.ctrl && i.key_pressed(egui::Key::F) {
            actions.push(GuiAction::FocusFind);
        }
        if i.modifiers.ctrl && i.key_pressed(egui::Key::C) {
            actions.push(GuiAction::CopySelectedItems);
        }
        if i.modifiers.ctrl && i.key_pressed(egui::Key::S) {
            actions.push(GuiAction::SaveSelectedItems);
        }
        if i.modifiers.ctrl && i.key_pressed(egui::Key::A) {
            actions.push(GuiAction::SelectAll);
        }
        if i.modifiers.ctrl && i.key_pressed(egui::Key::D) {
            actions.push(GuiAction::DeselectAll);
        }
        if i.modifiers.alt && i.key_pressed(egui::Key::Enter) {
            actions.push(GuiAction::FileProperties);
        }
    });

    // --- Driver Manager window ---
    actions.extend(draw_driver_manager(ctx, state));

    // --- About window ---
    if state.show_about {
        egui::Window::new("About DriverExplorer")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("DriverExplorer").size(18.0).strong());
                    ui.label(RichText::new("v0.1.0").size(13.0));
                    ui.add_space(8.0);
                    ui.label("Windows kernel driver analysis and management tool");
                    ui.label("Built for IT professionals, researchers, and developers");
                    ui.add_space(12.0);
                    if ui.button("OK").clicked() {
                        state.show_about = false;
                    }
                });
            });
    }

    // Store unconsumed pending menu back to state
    state.pending_menu = pending_menu;

    actions
}

fn draw_driver_manager(ctx: &egui::Context, state: &mut AppState) -> Vec<GuiAction> {
    use super::state::{START_TYPES, DRIVER_TYPES};
    let mut actions = Vec::new();
    if !state.show_driver_manager {
        return actions;
    }

    let mut open = state.show_driver_manager;
    egui::Window::new("Driver Manager")
        .collapsible(false)
        .resizable(true)
        .default_size([500.0, 540.0])
        .open(&mut open)
        .show(ctx, |ui| {
            let dm = &mut state.driver_manager;

            // --- Driver Path ---
            ui.horizontal(|ui| {
                ui.label(RichText::new("Driver Path:").size(12.0).strong());
            });
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut dm.driver_path)
                        .desired_width(ui.available_width() - 80.0)
                        .hint_text("C:\\path\\to\\driver.sys"),
                );
                if ui.button("Browse...").clicked() {
                    actions.push(GuiAction::DmBrowseDriver);
                }
            });

            ui.add_space(4.0);

            // --- Service Name ---
            ui.horizontal(|ui| {
                ui.label(RichText::new("Service Name:").size(12.0).strong());
                ui.add(
                    egui::TextEdit::singleline(&mut dm.service_name)
                        .desired_width(200.0)
                        .hint_text("mydriver"),
                );
            });

            ui.add_space(4.0);

            // --- Configuration Row ---
            ui.horizontal(|ui| {
                ui.label(RichText::new("Start Type:").size(12.0));
                egui::ComboBox::from_id_salt("dm_start_type")
                    .selected_text(START_TYPES[dm.start_type])
                    .width(110.0)
                    .show_ui(ui, |ui| {
                        for (i, label) in START_TYPES.iter().enumerate() {
                            ui.selectable_value(&mut dm.start_type, i, *label);
                        }
                    });

                ui.add_space(12.0);

                ui.label(RichText::new("Type:").size(12.0));
                egui::ComboBox::from_id_salt("dm_driver_type")
                    .selected_text(DRIVER_TYPES[dm.driver_type])
                    .width(140.0)
                    .show_ui(ui, |ui| {
                        for (i, label) in DRIVER_TYPES.iter().enumerate() {
                            ui.selectable_value(&mut dm.driver_type, i, *label);
                        }
                    });
            });

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(4.0);

            // --- Quick Actions ---
            ui.horizontal(|ui| {
                ui.label(RichText::new("Quick:").size(12.0).strong());
                let has_path = !dm.driver_path.is_empty() && !dm.service_name.is_empty();
                let has_name = !dm.service_name.is_empty();

                if ui
                    .add_enabled(
                        has_path,
                        Button::new(
                            RichText::new("Load (Register + Start)")
                                .size(12.0)
                                .color(if has_path { Colors::success() } else { Color32::GRAY }),
                        ),
                    )
                    .on_hover_text("Register the service and immediately start it")
                    .clicked()
                {
                    actions.push(GuiAction::DmQuickLoad);
                }

                if ui
                    .add_enabled(
                        has_name,
                        Button::new(
                            RichText::new("Unload (Stop + Unregister)")
                                .size(12.0)
                                .color(if has_name { Colors::error() } else { Color32::GRAY }),
                        ),
                    )
                    .on_hover_text("Stop the service and delete it")
                    .clicked()
                {
                    actions.push(GuiAction::DmQuickUnload);
                }
            });

            ui.add_space(4.0);

            // --- Individual Actions ---
            ui.horizontal(|ui| {
                ui.label(RichText::new("Individual:").size(12.0).strong());
                let has_path = !dm.driver_path.is_empty() && !dm.service_name.is_empty();
                let has_name = !dm.service_name.is_empty();

                if ui.add_enabled(has_path, Button::new("Register")).clicked() {
                    actions.push(GuiAction::DmRegister);
                }
                if ui.add_enabled(has_name, Button::new("Start")).clicked() {
                    actions.push(GuiAction::DmStart);
                }
                if ui.add_enabled(has_name, Button::new("Stop")).clicked() {
                    actions.push(GuiAction::DmStop);
                }
                if ui.add_enabled(has_name, Button::new("Unregister")).clicked() {
                    actions.push(GuiAction::DmUnregister);
                }

                ui.add_space(8.0);

                if ui.add_enabled(has_name, Button::new("Query Status")).clicked() {
                    actions.push(GuiAction::DmQueryStatus);
                }
            });

            // --- Status display ---
            if let Some(ref status) = dm.service_status {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Status:").size(12.0).strong());
                    let color = match status.as_str() {
                        "Running" => Colors::success(),
                        "Stopped" => Colors::error(),
                        _ => Colors::warning(),
                    };
                    ui.label(RichText::new(status).size(12.0).strong().color(color));
                });
            }

            ui.add_space(4.0);
            ui.separator();

            // --- Operation Log ---
            ui.horizontal(|ui| {
                ui.label(RichText::new("Log").size(12.0).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Clear").clicked() {
                        dm.log.clear();
                    }
                });
            });

            let log_height = ui.available_height().max(100.0);
            egui::ScrollArea::vertical()
                .max_height(log_height)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    if dm.log.is_empty() {
                        ui.label(
                            RichText::new("No operations yet.")
                                .size(11.0)
                                .color(Color32::from_rgb(100, 100, 120)),
                        );
                    } else {
                        for entry in &dm.log {
                            let color = match entry.kind {
                                super::state::StatusKind::Info => Color32::from_rgb(150, 150, 180),
                                super::state::StatusKind::Success => Colors::success(),
                                super::state::StatusKind::Error => Colors::error(),
                            };
                            let elapsed = entry.timestamp.elapsed().as_secs();
                            let time_str = if elapsed < 60 {
                                format!("{}s ago", elapsed)
                            } else {
                                format!("{}m ago", elapsed / 60)
                            };
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(&time_str)
                                        .size(10.0)
                                        .color(Color32::from_rgb(80, 80, 100)),
                                );
                                ui.label(RichText::new(&entry.text).size(11.0).color(color));
                            });
                        }
                    }
                });
        });

    state.show_driver_manager = open;
    actions
}

pub fn draw_main_area(ctx: &egui::Context, state: &mut AppState) -> Vec<GuiAction> {
    let mut actions = Vec::new();

    // Keyboard navigation - use cursor_index (last navigated position) not selected_index
    let filtered_count = state.filtered_drivers().len();
    let page_size = (ctx.screen_rect().height() / 20.0).max(1.0) as usize;
    if filtered_count > 0 {
        ctx.input(|i| {
            let shift = i.modifiers.shift;
            if i.key_pressed(egui::Key::ArrowDown) {
                let current = state.cursor_index();
                let next = (current + 1).min(filtered_count - 1);
                actions.push(GuiAction::SelectDriver(next, false, shift));
            }
            if i.key_pressed(egui::Key::ArrowUp) {
                let current = state.cursor_index();
                let next = current.saturating_sub(1);
                actions.push(GuiAction::SelectDriver(next, false, shift));
            }
            if i.key_pressed(egui::Key::PageDown) {
                let current = state.cursor_index();
                let next = (current + page_size).min(filtered_count - 1);
                actions.push(GuiAction::SelectDriver(next, false, shift));
            }
            if i.key_pressed(egui::Key::PageUp) {
                let current = state.cursor_index();
                let next = current.saturating_sub(page_size);
                actions.push(GuiAction::SelectDriver(next, false, shift));
            }
            if i.key_pressed(egui::Key::Home) {
                actions.push(GuiAction::SelectDriver(0, false, shift));
            }
            if i.key_pressed(egui::Key::End) {
                actions.push(GuiAction::SelectDriver(filtered_count - 1, false, shift));
            }
        });
    }

    egui::SidePanel::right("detail_panel")
        .default_width(400.0)
        .min_width(100.0)
        .max_width(900.0)
        .resizable(true)
        .show(ctx, |ui| {
            ui.label(RichText::new("Details").size(14.0).strong());
            ui.separator();
            draw_detail_panel(ui, state, &mut actions);
        });

    egui::CentralPanel::default().show(ctx, |ui| {
        draw_driver_table(ui, state, &mut actions);
    });

    actions
}

/// All table columns for the driver list
const TABLE_COLUMNS: &[(&str, SortColumn)] = &[
    ("Driver Name", SortColumn::Name),
    ("Address", SortColumn::Address),
    ("End Address", SortColumn::EndAddress),
    ("Size", SortColumn::Size),
    ("Load Count", SortColumn::LoadCount),
    ("Index", SortColumn::Index),
    ("File Type", SortColumn::Type),
    ("Description", SortColumn::Description),
    ("Version", SortColumn::Version),
    ("Company", SortColumn::Company),
    ("Product Name", SortColumn::ProductName),
    ("Modified Date", SortColumn::ModifiedDate),
    ("Created Date", SortColumn::CreatedDate),
    ("Filename", SortColumn::Path),
    ("File Attributes", SortColumn::FileAttributes),
    ("Service Name", SortColumn::ServiceName),
];

fn sort_indicator(state: &AppState, column: SortColumn) -> &'static str {
    if state.sort_column == column {
        match state.sort_order {
            SortOrder::Ascending => " \u{2191}",
            SortOrder::Descending => " \u{2193}",
        }
    } else {
        ""
    }
}

/// Format address as FFFFF802`D5400000
fn format_address(addr: u64) -> String {
    if addr == 0 {
        return String::new();
    }
    let high = (addr >> 32) as u32;
    let low = addr as u32;
    format!("{:08X}`{:08X}", high, low)
}

fn draw_driver_table(ui: &mut egui::Ui, state: &mut AppState, actions: &mut Vec<GuiAction>) {
    ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
    let available_height = ui.available_height();

    let row_height = 20.0;
    let font_size = 10.0;
    let header_font_size = 10.0;

    let show_grid = state.show_grid_lines;
    let mark_non_ms = state.mark_non_microsoft;

    let grid_color = if show_grid {
        Color32::from_rgb(40, 40, 55)
    } else {
        Color32::TRANSPARENT
    };

    // Column widths
    let col_widths: &[f32] = &[
        140.0,  // Driver Name
        145.0,  // Address
        145.0,  // End Address
        90.0,   // Size
        55.0,   // Load Count
        45.0,   // Index
        150.0,  // File Type
        250.0,  // Description
        120.0,  // Version
        170.0,  // Company
        200.0,  // Product Name
        155.0,  // Modified Date
        155.0,  // Created Date
        350.0,  // Filename
        50.0,   // File Attributes
        120.0,  // Service Name
    ];

    let total_width: f32 = col_widths.iter().sum();

    // Full table with horizontal and vertical scroll
    let mut new_right_click_cell: Option<String> = None;

    egui::ScrollArea::both()
        .auto_shrink([false; 2])
        .max_height(available_height)
        .show(ui, |ui| {
            ui.set_min_width(total_width);

            // --- Header row ---
            ui.horizontal(|ui| {
                ui.set_min_width(total_width);
                ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
                for (i, &(label, column)) in TABLE_COLUMNS.iter().enumerate() {
                    let w = col_widths.get(i).copied().unwrap_or(100.0);
                    let indicator = sort_indicator(state, column);
                    let text = format!("{}{}", label, indicator);
                    let color = if state.sort_column == column {
                        Colors::accent()
                    } else {
                        Color32::from_rgb(200, 200, 220)
                    };

                    let (rect, response) = ui.allocate_exact_size(
                        egui::vec2(w, row_height + 2.0),
                        egui::Sense::click(),
                    );

                    // Header background
                    ui.painter()
                        .rect_filled(rect, 0.0, Color32::from_rgb(35, 35, 55));

                    // Header text
                    let text_pos = egui::pos2(rect.left() + 4.0, rect.center().y);
                    ui.painter().text(
                        text_pos,
                        egui::Align2::LEFT_CENTER,
                        &text,
                        egui::FontId::new(header_font_size, egui::FontFamily::Proportional),
                        color,
                    );

                    // Right border
                    ui.painter().line_segment(
                        [rect.right_top(), rect.right_bottom()],
                        egui::Stroke::new(1.0, Color32::from_rgb(55, 55, 75)),
                    );

                    if response.clicked() {
                        state.toggle_sort(column);
                    }
                }
            });

            // Separator
            ui.painter().line_segment(
                [
                    ui.cursor().left_top(),
                    egui::pos2(ui.cursor().left_top().x + 2200.0, ui.cursor().left_top().y),
                ],
                egui::Stroke::new(1.0, Color32::from_rgb(60, 60, 90)),
            );

            // --- Data rows ---
            let filtered = state.filtered_drivers();

            for (idx, driver) in filtered.iter().enumerate() {
                let is_selected = state.is_selected(&driver.name);

                let driver_name = driver.name.clone();
                let _driver_path = driver.file_path.clone();

                // Check if non-Microsoft
                let is_microsoft = driver
                    .company_name
                    .as_ref()
                    .map(|c| c.to_lowercase().contains("microsoft"))
                    .unwrap_or(false);

                // Build cell values
                let cells: Vec<String> = vec![
                    driver.name.clone(),
                    format_address(driver.load_address),
                    format_address(driver.end_address),
                    if driver.size > 0 {
                        format!("0x{:08X}", driver.size)
                    } else {
                        String::new()
                    },
                    driver.load_count.to_string(),
                    driver.index.to_string(),
                    driver.file_type.as_deref().unwrap_or("").to_string(),
                    driver.file_description.as_deref().unwrap_or("").to_string(),
                    driver.file_version.as_deref().unwrap_or("").to_string(),
                    driver.company_name.as_deref().unwrap_or("").to_string(),
                    driver.product_name.as_deref().unwrap_or("").to_string(),
                    driver.modified_date.as_deref().unwrap_or("").to_string(),
                    driver.created_date.as_deref().unwrap_or("").to_string(),
                    driver.file_path.clone(),
                    driver.file_attributes.as_deref().unwrap_or("").to_string(),
                    driver.service_name.as_deref().unwrap_or("").to_string(),
                ];

                let row_bg = if is_selected {
                    Color32::from_rgb(50, 80, 130)
                } else if mark_non_ms && !is_microsoft {
                    // Subtle warm tint for non-Microsoft drivers
                    if idx % 2 == 0 {
                        Color32::from_rgb(32, 28, 22)
                    } else {
                        Color32::from_rgb(36, 32, 26)
                    }
                } else if idx % 2 == 0 {
                    Color32::from_rgb(22, 22, 32)
                } else {
                    Color32::from_rgb(26, 26, 38)
                };

                let row_response = ui
                    .horizontal(|ui| {
                        ui.set_min_width(total_width);
                        ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);

                        let mut row_response: Option<egui::Response> = None;

                        for (col_idx, cell_text) in cells.iter().enumerate() {
                            let w = col_widths.get(col_idx).copied().unwrap_or(100.0);

                            let (rect, response) = ui.allocate_exact_size(
                                egui::vec2(w, row_height),
                                egui::Sense::click(),
                            );

                            // Row background
                            ui.painter().rect_filled(rect, 0.0, row_bg);

                            // Cell text color
                            let text_color = if col_idx == 0 {
                                if mark_non_ms && !is_microsoft {
                                    Color32::from_rgb(220, 200, 150)
                                } else {
                                    Color32::from_rgb(240, 240, 240)
                                }
                            } else if col_idx == 1 || col_idx == 2 || col_idx == 13 {
                                Color32::from_rgb(160, 180, 210)
                            } else {
                                Color32::from_rgb(190, 190, 200)
                            };

                            // Clip text to cell width
                            let clip_rect = rect.shrink2(egui::vec2(4.0, 0.0));
                            ui.painter().with_clip_rect(clip_rect).text(
                                egui::pos2(rect.left() + 4.0, rect.center().y),
                                egui::Align2::LEFT_CENTER,
                                cell_text,
                                egui::FontId::new(font_size, egui::FontFamily::Proportional),
                                text_color,
                            );

                            // Right border (grid line)
                            ui.painter().line_segment(
                                [rect.right_top(), rect.right_bottom()],
                                egui::Stroke::new(1.0, grid_color),
                            );

                            // Track which cell was right-clicked
                            if response.secondary_clicked() {
                                new_right_click_cell = Some(cell_text.clone());
                            }

                            // Union all cell responses
                            row_response = Some(match row_response {
                                Some(prev) => prev | response,
                                None => response,
                            });
                        }

                        row_response.unwrap()
                    })
                    .inner;

                // Scroll to cursor row when triggered by keyboard navigation
                if state.scroll_to_cursor && state.cursor_pos == Some(idx) {
                    row_response.scroll_to_me(None);
                }

                if row_response.clicked() {
                    let modifiers = ui.input(|i| i.modifiers);
                    actions.push(GuiAction::SelectDriver(idx, modifiers.ctrl, modifiers.shift));
                }

                // Right-click context menu - select the row first if not already selected
                if row_response.secondary_clicked() && !is_selected {
                    actions.push(GuiAction::SelectDriver(idx, false, false));
                }
                row_response.context_menu(|ui| {
                    if ui.button("Start").clicked() {
                        actions.push(GuiAction::StartDriver(driver_name.clone()));
                        ui.close_menu();
                    }
                    if ui.button("Stop").clicked() {
                        actions.push(GuiAction::StopDriver(driver_name.clone()));
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Unload").clicked() {
                        actions.push(GuiAction::SelectDriver(idx, false, false));
                        actions.push(GuiAction::UnloadDriver);
                        ui.close_menu();
                    }
                    if ui.button("Unregister").clicked() {
                        actions.push(GuiAction::UnregisterDriver(driver_name.clone()));
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Properties").clicked() {
                        actions.push(GuiAction::SelectDriver(idx, false, false));
                        actions.push(GuiAction::FileProperties);
                        ui.close_menu();
                    }
                    ui.separator();
                    if let Some(ref cell_val) = state.right_click_cell {
                        let label = if cell_val.len() > 40 {
                            format!("Copy \"{}...\"", &cell_val[..37])
                        } else {
                            format!("Copy \"{}\"", cell_val)
                        };
                        if ui.button(label).clicked() {
                            ui.ctx().copy_text(cell_val.clone());
                            ui.close_menu();
                        }
                        ui.separator();
                    }
                    if ui.button("Copy Selected Items").clicked() {
                        actions.push(GuiAction::SelectDriver(idx, false, false));
                        actions.push(GuiAction::CopySelectedItems);
                        ui.close_menu();
                    }
                    if ui.button("Google Search").clicked() {
                        actions.push(GuiAction::SelectDriver(idx, false, false));
                        actions.push(GuiAction::GoogleSearch);
                        ui.close_menu();
                    }
                });

                // Bottom border for row (horizontal grid line)
                if show_grid {
                    let cursor = ui.cursor();
                    ui.painter().line_segment(
                        [
                            egui::pos2(cursor.left(), cursor.top()),
                            egui::pos2(cursor.left() + 2200.0, cursor.top()),
                        ],
                        egui::Stroke::new(0.5, Color32::from_rgb(35, 35, 50)),
                    );
                }
            }
        });

    // Update right-click cell after the borrow of filtered_drivers ends
    if new_right_click_cell.is_some() {
        state.right_click_cell = new_right_click_cell;
    }

    // Reset scroll flag after table is drawn
    state.scroll_to_cursor = false;
}

fn detail_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).strong().size(11.0));
        ui.monospace(RichText::new(value).size(11.0));
    });
}

fn detail_row_colored(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).strong().size(11.0));
        ui.label(RichText::new(value).size(11.0).color(color));
    });
}

fn draw_detail_panel(ui: &mut egui::Ui, state: &AppState, actions: &mut Vec<GuiAction>) {
    if let Some(driver) = state.selected() {
        let driver_name = driver.name.clone();
        let available_height = ui.available_height();

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .max_height(available_height)
            .show(ui, |ui| {
                ui.monospace(RichText::new(&driver_name).size(14.0).strong());
                ui.separator();

                if let Some(d) = state.selected() {
                    // Addresses & Size
                    detail_row(ui, "Address:", &format_address(d.load_address));
                    if d.end_address > 0 {
                        detail_row(ui, "End Address:", &format_address(d.end_address));
                    }
                    if d.size > 0 {
                        detail_row(
                            ui,
                            "Size:",
                            &format!("0x{:08X} ({} KB)", d.size, d.size / 1024),
                        );
                    }
                    detail_row(ui, "Load Count:", &d.load_count.to_string());
                    detail_row(ui, "Index:", &d.index.to_string());

                    ui.separator();

                    // File Type & Driver Type
                    if let Some(ft) = &d.file_type {
                        detail_row(ui, "File Type:", ft);
                    }
                    detail_row(ui, "Driver Type:", &d.driver_type.to_string());

                    // Status
                    let status_color = match d.status.to_string().as_str() {
                        "Running" => Colors::running(),
                        _ => Colors::stopped(),
                    };
                    detail_row_colored(ui, "Status:", &d.status.to_string(), status_color);

                    ui.separator();

                    // Description & Version Info
                    if let Some(desc) = &d.file_description {
                        detail_row(ui, "Description:", desc);
                    }
                    if let Some(version) = &d.file_version {
                        detail_row(ui, "Version:", version);
                    }
                    if let Some(company) = &d.company_name {
                        detail_row(ui, "Company:", company);
                    }
                    if let Some(product) = &d.product_name {
                        detail_row(ui, "Product Name:", product);
                    }

                    ui.separator();

                    // File Info
                    detail_row(ui, "Filename:", &d.file_path);
                    if let Some(modified) = &d.modified_date {
                        detail_row(ui, "Modified Date:", modified);
                    }
                    if let Some(created) = &d.created_date {
                        detail_row(ui, "Created Date:", created);
                    }
                    if let Some(attrs) = &d.file_attributes {
                        detail_row(ui, "File Attributes:", attrs);
                    }

                    ui.separator();

                    // Service Info
                    if let Some(svc) = &d.service_name {
                        detail_row(ui, "Service Name:", svc);
                    }
                    if let Some(svc_disp) = &d.service_display_name {
                        detail_row(ui, "Service Display:", svc_disp);
                    }

                    // Signature
                    if let Some(signed) = d.is_signed {
                        let (text, color) = if signed {
                            ("Yes", Colors::signed())
                        } else {
                            ("No", Colors::unsigned())
                        };
                        detail_row_colored(ui, "Signed:", text, color);
                    }
                    if let Some(signer) = &d.signer {
                        detail_row(ui, "Signer:", signer);
                    }
                }

                ui.separator();

                ui.horizontal(|ui| {
                    if ui
                        .button(RichText::new("Start").size(12.0).color(Colors::success()))
                        .clicked()
                    {
                        actions.push(GuiAction::StartDriver(driver_name.clone()));
                    }
                    if ui
                        .button(RichText::new("Stop").size(12.0).color(Colors::warning()))
                        .clicked()
                    {
                        actions.push(GuiAction::StopDriver(driver_name.clone()));
                    }
                });

                ui.horizontal(|ui| {
                    if ui
                        .button(RichText::new("Register").size(12.0))
                        .clicked()
                    {
                        actions.push(GuiAction::RegisterDriver(driver_name.clone()));
                    }
                    if ui
                        .button(
                            RichText::new("Unregister")
                                .size(12.0)
                                .color(Colors::error()),
                        )
                        .clicked()
                    {
                        actions.push(GuiAction::UnregisterDriver(driver_name.clone()));
                    }
                });
            });
    } else {
        ui.label(
            RichText::new("Select a driver to view details")
                .size(11.0)
                .color(Color32::from_rgb(120, 120, 120)),
        );
    }
}
