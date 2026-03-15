use crate::drivers::DriverInfo;
use std::collections::BTreeSet;
use std::sync::mpsc::Receiver;
use std::time::Instant;

#[derive(Clone, PartialEq, Eq)]
pub enum LoadingState {
    Idle,
    Loading,
    Loaded,
    #[allow(dead_code)]
    Error(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SortColumn {
    Name,
    Address,
    EndAddress,
    Size,
    LoadCount,
    Index,
    Type,
    Description,
    Version,
    Company,
    ProductName,
    ModifiedDate,
    CreatedDate,
    Path,
    FileAttributes,
    ServiceName,
    #[allow(dead_code)]
    Status,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SortOrder {
    Ascending,
    Descending,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StatusKind {
    Info,
    Success,
    Error,
}

// --- Driver Manager State ---

pub const START_TYPES: &[&str] = &["Boot", "System", "Automatic", "Demand", "Disabled"];
pub const DRIVER_TYPES: &[&str] = &["Kernel Driver", "File System Driver"];

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub text: String,
    pub kind: StatusKind,
    pub timestamp: Instant,
}

#[derive(Clone, Debug)]
pub struct DriverManagerState {
    pub driver_path: String,
    pub service_name: String,
    pub start_type: usize,
    pub driver_type: usize,
    pub log: Vec<LogEntry>,
    pub service_status: Option<String>,
}

impl Default for DriverManagerState {
    fn default() -> Self {
        Self {
            driver_path: String::new(),
            service_name: String::new(),
            start_type: 3, // Demand
            driver_type: 0, // Kernel Driver
            log: Vec::new(),
            service_status: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StatusMessage {
    pub text: String,
    pub kind: StatusKind,
    pub timestamp: Instant,
}

#[derive(Clone, Debug)]
pub enum GuiAction {
    Refresh,
    LoadDriver,
    UnloadDriver,
    ElevateToAdmin,
    StartDriver(String),
    StopDriver(String),
    RegisterDriver(String),
    UnregisterDriver(String),
    // Selection (index, ctrl_held, shift_held)
    SelectDriver(usize, bool, bool),
    // File menu
    SaveSelectedItems,
    FileProperties,
    GoogleSearch,
    Exit,
    // Edit menu
    FocusFind,
    CopySelectedItems,
    SelectAll,
    DeselectAll,
    // Export menu
    ExportJsonAll,
    ExportJsonSelected,
    ExportCsvAll,
    ExportCsvSelected,
    ExportTextAll,
    ExportTextSelected,
    ExportHtmlAll,
    ExportHtmlSelected,
    // Tools menu
    SaveSnapshot,
    CompareSnapshot,
    VerifySignature,
    // Help menu
    ShowAbout,
    // Driver Manager
    OpenDriverManager,
    DmBrowseDriver,
    DmRegister,
    DmStart,
    DmStop,
    DmUnregister,
    DmQuickLoad,
    DmQuickUnload,
    DmQueryStatus,
}

pub struct AppState {
    pub drivers: Vec<DriverInfo>,
    pub selected_names: BTreeSet<String>,
    /// Anchor index for shift-click range selection (set on non-shift click)
    pub anchor_index: Option<usize>,
    /// Current cursor position (moves with every selection action)
    pub cursor_pos: Option<usize>,
    pub search_filter: String,
    pub loading_state: LoadingState,
    pub show_microsoft: bool,
    pub show_non_microsoft: bool,
    pub mark_non_microsoft: bool,
    pub show_grid_lines: bool,
    pub auto_refresh: bool,
    pub read_signatures: bool,
    pub show_about: bool,
    pub focus_search: bool,
    pub receiver: Option<Receiver<Vec<DriverInfo>>>,
    pub sort_column: SortColumn,
    pub sort_order: SortOrder,
    pub status_message: Option<StatusMessage>,
    pub auto_refresh_interval: Option<Instant>,
    /// Which menu to open via Alt+letter mnemonic
    pub pending_menu: Option<char>,
    /// Scroll table to cursor position on next frame
    pub scroll_to_cursor: bool,
    /// Show the Driver Manager window
    pub show_driver_manager: bool,
    /// Driver Manager dialog state
    pub driver_manager: DriverManagerState,
    /// Cell value under the most recent right-click (for "Copy Cell")
    pub right_click_cell: Option<String>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            drivers: Vec::new(),
            selected_names: BTreeSet::new(),
            anchor_index: None,
            cursor_pos: None,
            search_filter: String::new(),
            loading_state: LoadingState::Idle,
            show_microsoft: true,
            show_non_microsoft: true,
            mark_non_microsoft: true,
            show_grid_lines: true,
            auto_refresh: false,
            read_signatures: true,
            show_about: false,
            focus_search: false,
            receiver: None,
            sort_column: SortColumn::Name,
            sort_order: SortOrder::Ascending,
            status_message: None,
            auto_refresh_interval: None,
            pending_menu: None,
            scroll_to_cursor: false,
            show_driver_manager: false,
            driver_manager: DriverManagerState::default(),
            right_click_cell: None,
        }
    }

    /// Set a status bar message
    pub fn set_status(&mut self, text: impl Into<String>, kind: StatusKind) {
        self.status_message = Some(StatusMessage {
            text: text.into(),
            kind,
            timestamp: Instant::now(),
        });
    }

    /// Auto-clear status after 8 seconds
    pub fn tick_status(&mut self) {
        if let Some(ref msg) = self.status_message {
            if msg.timestamp.elapsed().as_secs() >= 8 {
                self.status_message = None;
            }
        }
    }

    /// Clear selection if selected drivers are not in filtered list
    pub fn validate_selection(&mut self) {
        let filtered_names: BTreeSet<String> = self.filtered_drivers()
            .iter()
            .map(|d| d.name.clone())
            .collect();
        self.selected_names.retain(|name| filtered_names.contains(name));
    }

    /// Get filtered and sorted drivers
    pub fn filtered_drivers(&self) -> Vec<&DriverInfo> {
        let mut filtered: Vec<&DriverInfo> = self.drivers
            .iter()
            .filter(|d| {
                let matches_search = self.search_filter.is_empty()
                    || d.name.to_lowercase().contains(&self.search_filter.to_lowercase())
                    || d.file_path
                        .to_lowercase()
                        .contains(&self.search_filter.to_lowercase());

                let is_microsoft =
                    d.company_name
                        .as_ref()
                        .map(|c| c.to_lowercase().contains("microsoft"))
                        .unwrap_or(false);

                let matches_vendor = if is_microsoft {
                    self.show_microsoft
                } else {
                    self.show_non_microsoft
                };

                matches_search && matches_vendor
            })
            .collect();

        filtered.sort_by(|a, b| {
            let ci_cmp = |a: &str, b: &str| {
                a.to_lowercase().cmp(&b.to_lowercase())
            };
            let opt_ci_cmp = |a: Option<&str>, b: Option<&str>| {
                ci_cmp(a.unwrap_or(""), b.unwrap_or(""))
            };
            let cmp_result = match self.sort_column {
                SortColumn::Name => ci_cmp(&a.name, &b.name),
                SortColumn::Address => a.load_address.cmp(&b.load_address),
                SortColumn::EndAddress => a.end_address.cmp(&b.end_address),
                SortColumn::Size => a.size.cmp(&b.size),
                SortColumn::LoadCount => a.load_count.cmp(&b.load_count),
                SortColumn::Index => a.index.cmp(&b.index),
                SortColumn::Type => opt_ci_cmp(a.file_type.as_deref(), b.file_type.as_deref()),
                SortColumn::Description => opt_ci_cmp(a.file_description.as_deref(), b.file_description.as_deref()),
                SortColumn::Version => opt_ci_cmp(a.file_version.as_deref(), b.file_version.as_deref()),
                SortColumn::Company => opt_ci_cmp(a.company_name.as_deref(), b.company_name.as_deref()),
                SortColumn::ProductName => opt_ci_cmp(a.product_name.as_deref(), b.product_name.as_deref()),
                SortColumn::ModifiedDate => opt_ci_cmp(a.modified_date.as_deref(), b.modified_date.as_deref()),
                SortColumn::CreatedDate => opt_ci_cmp(a.created_date.as_deref(), b.created_date.as_deref()),
                SortColumn::Path => ci_cmp(&a.file_path, &b.file_path),
                SortColumn::FileAttributes => opt_ci_cmp(a.file_attributes.as_deref(), b.file_attributes.as_deref()),
                SortColumn::ServiceName => opt_ci_cmp(a.service_name.as_deref(), b.service_name.as_deref()),
                SortColumn::Status => ci_cmp(&a.status.to_string(), &b.status.to_string()),
            };

            match self.sort_order {
                SortOrder::Ascending => cmp_result,
                SortOrder::Descending => cmp_result.reverse(),
            }
        });

        filtered
    }

    /// Toggle sort column and direction
    pub fn toggle_sort(&mut self, column: SortColumn) {
        if self.sort_column == column {
            self.sort_order = match self.sort_order {
                SortOrder::Ascending => SortOrder::Descending,
                SortOrder::Descending => SortOrder::Ascending,
            };
        } else {
            self.sort_column = column;
            self.sort_order = SortOrder::Ascending;
        }
    }

    /// Select a single driver (clear others)
    pub fn select_driver(&mut self, index: usize) {
        let name = self.filtered_drivers().get(index).map(|d| d.name.clone());
        if let Some(name) = name {
            self.selected_names.clear();
            self.selected_names.insert(name);
            self.anchor_index = Some(index);
            self.cursor_pos = Some(index);
        }
    }

    /// Toggle selection of a single driver (Ctrl+click)
    pub fn toggle_select_driver(&mut self, index: usize) {
        let name = self.filtered_drivers().get(index).map(|d| d.name.clone());
        if let Some(name) = name {
            if self.selected_names.contains(&name) {
                self.selected_names.remove(&name);
            } else {
                self.selected_names.insert(name);
            }
            self.anchor_index = Some(index);
            self.cursor_pos = Some(index);
        }
    }

    /// Range select from anchor to index (Shift+click/arrow)
    pub fn range_select_driver(&mut self, index: usize) {
        let names: Vec<String> = {
            let filtered = self.filtered_drivers();
            let anchor = self.anchor_index.unwrap_or(0);
            let start = anchor.min(index);
            let end = anchor.max(index).min(filtered.len().saturating_sub(1));
            (start..=end).map(|i| filtered[i].name.clone()).collect()
        };
        self.selected_names.clear();
        for name in names {
            self.selected_names.insert(name);
        }
        // Move cursor but keep anchor fixed
        self.cursor_pos = Some(index);
    }

    /// Get current cursor position (for keyboard navigation)
    pub fn cursor_index(&self) -> usize {
        self.cursor_pos.unwrap_or(0)
    }

    /// Check if a driver name is selected
    pub fn is_selected(&self, name: &str) -> bool {
        self.selected_names.contains(name)
    }

    /// Get the first selected driver (for detail panel, etc.)
    pub fn selected(&self) -> Option<&DriverInfo> {
        // Return the first selected by filtered order
        let filtered = self.filtered_drivers();
        filtered.iter().find(|d| self.selected_names.contains(&d.name)).copied()
    }

    /// Get all selected drivers
    pub fn selected_drivers(&self) -> Vec<&DriverInfo> {
        self.drivers.iter()
            .filter(|d| self.selected_names.contains(&d.name))
            .collect()
    }

    /// Get selected drivers as owned clones (for export)
    pub fn selected_drivers_cloned(&self) -> Vec<DriverInfo> {
        self.drivers.iter()
            .filter(|d| self.selected_names.contains(&d.name))
            .cloned()
            .collect()
    }

    /// Number of selected items
    pub fn selection_count(&self) -> usize {
        self.selected_names.len()
    }

    /// Clear and reload drivers
    pub fn set_receiver(&mut self, rx: Receiver<Vec<DriverInfo>>) {
        self.receiver = Some(rx);
        self.loading_state = LoadingState::Loading;
    }

    /// Format a single driver as tab-separated text
    fn format_driver_line(driver: &DriverInfo) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            driver.name,
            format!("{:016X}", driver.load_address),
            format!("{:016X}", driver.end_address),
            if driver.size > 0 { format!("0x{:08X}", driver.size) } else { String::new() },
            driver.load_count,
            driver.index,
            driver.file_type.as_deref().unwrap_or(""),
            driver.file_description.as_deref().unwrap_or(""),
            driver.file_version.as_deref().unwrap_or(""),
            driver.company_name.as_deref().unwrap_or(""),
            driver.product_name.as_deref().unwrap_or(""),
            driver.modified_date.as_deref().unwrap_or(""),
            driver.created_date.as_deref().unwrap_or(""),
            driver.file_path,
            driver.file_attributes.as_deref().unwrap_or(""),
            driver.service_name.as_deref().unwrap_or(""),
        )
    }

    /// Format selected drivers as tab-separated text for clipboard
    pub fn format_selected_for_clipboard(&self) -> Option<String> {
        let selected = self.selected_drivers();
        if selected.is_empty() {
            return None;
        }
        let lines: Vec<String> = selected.iter().map(|d| Self::format_driver_line(d)).collect();
        Some(lines.join("\n"))
    }

    /// Check receiver for new driver data
    pub fn check_receiver(&mut self) {
        if let Some(ref receiver) = self.receiver {
            if let Ok(drivers) = receiver.try_recv() {
                self.drivers = drivers;
                self.selected_names.clear();
                self.anchor_index = None;
                self.cursor_pos = None;
                self.loading_state = LoadingState::Loaded;
                self.receiver = None;
            }
        }
    }
}
