#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{
    self,
    Color32,
    FontId,
    Pos2,
    Rect,
    RichText,
    ScrollArea,
    Sense,
    Shape,
    Stroke,
    Ui,
    Vec2,
};

use plotters::element::Pie;
use plotters::prelude::*;
use rfd::FileDialog;

use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use zip::ZipArchive;

#[cfg(windows)]
use windows::core::PCWSTR;

#[cfg(windows)]
use windows::Win32::Foundation::HWND;

#[cfg(windows)]
use windows::Win32::Security::{
    GetTokenInformation,
    TokenElevation,
    TOKEN_ELEVATION,
    TOKEN_QUERY,
};

#[cfg(windows)]
use windows::Win32::System::Threading::{
    GetCurrentProcess,
    OpenProcessToken,
};

#[cfg(windows)]
use windows::Win32::UI::Shell::ShellExecuteW;

#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

// ============================================================
// GENERAL
// ============================================================

const APP_NAME: &str = "Extension Scanner";

type AppResult<T> =
    Result<T, Box<dyn std::error::Error + Send + Sync>>;

const PROGRESS_EVERY: u64 = 500;

const MAX_PIE_SLICES: usize = 14;

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe",
    "scr",
    "com",
    "bat",
    "cmd",
    "ps1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "ws",
    "wsf",
    "wsh",
    "msi",
    "msp",
    "cpl",
];

const COLORS: [[u8; 3]; 20] = [
    [46, 204, 113],
    [52, 152, 219],
    [231, 76, 60],
    [155, 89, 182],
    [241, 196, 15],
    [230, 126, 34],
    [26, 188, 156],
    [52, 73, 94],
    [243, 156, 18],
    [192, 57, 43],
    [41, 128, 185],
    [142, 68, 173],
    [39, 174, 96],
    [211, 84, 0],
    [127, 140, 141],
    [22, 160, 133],
    [44, 62, 80],
    [255, 99, 132],
    [54, 162, 235],
    [255, 206, 86],
];

// ============================================================
// SCAN SOURCE
// ============================================================

#[derive(Clone, Debug)]
enum ScanSource {
    Folder(PathBuf),
    Zip(PathBuf),
}

impl ScanSource {
    fn name(&self) -> String {
        match self {
            ScanSource::Folder(path) => path
                .file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("folder")
                .to_string(),

            ScanSource::Zip(path) => path
                .file_stem()
                .and_then(|x| x.to_str())
                .unwrap_or("archive")
                .to_string(),
        }
    }

    fn display_path(&self) -> String {
        match self {
            ScanSource::Folder(path) => {
                path.display().to_string()
            }

            ScanSource::Zip(path) => {
                path.display().to_string()
            }
        }
    }
}

// ============================================================
// FILE RECORD
// ============================================================

#[derive(Clone)]
struct FileRecord {
    name: String,
    path: String,
    extension: String,
    size: u64,
    filesystem_path: Option<PathBuf>,
    suspicious: bool,
}

// ============================================================
// EXTENSION STATISTICS
// ============================================================

#[derive(Clone)]
struct ExtensionStat {
    extension: String,
    count: u64,
    bytes: u64,
    percentage: f64,
}

// ============================================================
// COMPLETE SCAN RESULT
// ============================================================

struct ScanResult {
    source: ScanSource,
    files: Vec<FileRecord>,
    extensions: Vec<ExtensionStat>,
    total_bytes: u64,
    errors: Vec<String>,
}

// ============================================================
// BACKGROUND MESSAGES
// ============================================================

enum ScanMessage {
    Progress {
        files: u64,
        directories: u64,
        current: String,
    },

    Finished(ScanResult),

    Failed(String),
}

// ============================================================
// SORTING
// ============================================================

#[derive(Clone, Copy, PartialEq)]
enum SortMode {
    Name,
    Extension,
    Largest,
    Smallest,
}

// ============================================================
// APPLICATION
// ============================================================

struct ScannerApp {
    source: Option<ScanSource>,

    files: Vec<FileRecord>,
    extensions: Vec<ExtensionStat>,

    search: String,

    sort_mode: SortMode,

    only_suspicious: bool,
    only_no_extension: bool,

    // NEW:
    generate_pie_chart: bool,
    generate_report: bool,

    selected_file: Option<usize>,

    scanning: bool,

    scanned_files: u64,
    scanned_directories: u64,

    current_file: String,

    scan_started: Option<Instant>,

    receiver: Option<Receiver<ScanMessage>>,

    total_bytes: u64,

    errors: Vec<String>,

    png_path: Option<PathBuf>,
    json_path: Option<PathBuf>,

    about_open: bool,
}

impl Default for ScannerApp {
    fn default() -> Self {
        Self {
            source: None,

            files: Vec::new(),
            extensions: Vec::new(),

            search: String::new(),

            sort_mode: SortMode::Name,

            only_suspicious: false,
            only_no_extension: false,

            generate_pie_chart: true,
            generate_report: true,

            selected_file: None,

            scanning: false,

            scanned_files: 0,
            scanned_directories: 0,

            current_file: String::new(),

            scan_started: None,

            receiver: None,

            total_bytes: 0,

            errors: Vec::new(),

            png_path: None,
            json_path: None,

            about_open: false,
        }
    }
}

// ============================================================
// MAIN
// ============================================================

fn main() -> eframe::Result<()> {
    #[cfg(windows)]
    {
        match ensure_admin() {
            Ok(true) => {}

            Ok(false) => {
                return Ok(());
            }

            Err(error) => {
                let _ = rfd::MessageDialog::new()
                    .set_title(APP_NAME)
                    .set_description(format!(
                        "Could not request administrator privileges.\n\n{}",
                        error
                    ))
                    .show();

                return Ok(());
            }
        }
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(APP_NAME)
            .with_inner_size([1500.0, 900.0])
            .with_min_inner_size([1050.0, 650.0]),

        ..Default::default()
    };

    eframe::run_native(
        APP_NAME,
        options,
        Box::new(|_cc| {
            Ok(Box::new(ScannerApp::default()))
        }),
    )
}

// ============================================================
// EFRAME APP
// ============================================================

impl eframe::App for ScannerApp {
    fn ui(
        &mut self,
        ui: &mut Ui,
        _frame: &mut eframe::Frame,
    ) {
        self.receive_messages();

        if self.scanning {
            ui.ctx().request_repaint_after(
                Duration::from_millis(50),
            );
        }

        self.draw_toolbar(ui);

        ui.separator();

        if self.scanning {
            self.draw_scanning_screen(ui);
        } else if self.files.is_empty() {
            self.draw_start_screen(ui);
        } else {
            self.draw_dashboard(ui);
        }

        if self.about_open {
            self.draw_about_window(ui);
        }
    }
}

// ============================================================
// TOOLBAR
// ============================================================

impl ScannerApp {
    fn draw_toolbar(
        &mut self,
        ui: &mut Ui,
    ) {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(APP_NAME)
                    .strong()
                    .size(21.0),
            );

            ui.separator();

            if ui.button("Scan Folder").clicked()
                && !self.scanning
            {
                if let Some(folder) =
                    FileDialog::new()
                        .set_title(
                            "Choose a folder to scan",
                        )
                        .pick_folder()
                {
                    self.start_scan(
                        ScanSource::Folder(folder),
                    );
                }
            }

            if ui.button("Scan ZIP").clicked()
                && !self.scanning
            {
                if let Some(zip_path) =
                    FileDialog::new()
                        .set_title(
                            "Choose a ZIP archive",
                        )
                        .add_filter(
                            "ZIP archive",
                            &["zip"],
                        )
                        .pick_file()
                {
                    self.start_scan(
                        ScanSource::Zip(zip_path),
                    );
                }
            }

            if ui
                .add_enabled(
                    self.source.is_some()
                        && !self.scanning,
                    egui::Button::new("Rescan"),
                )
                .clicked()
            {
                if let Some(source) =
                    self.source.clone()
                {
                    self.start_scan(source);
                }
            }

            if ui.button("Output").clicked() {
                if let Ok(path) =
                    executable_directory()
                {
                    let _ =
                        open_default(&path);
                }
            }

            if ui.button("About").clicked() {
                self.about_open = true;
            }
        });

        ui.add_space(5.0);

        ui.horizontal_wrapped(|ui| {
            ui.label("Search:");

            ui.add(
                egui::TextEdit::singleline(
                    &mut self.search,
                )
                .desired_width(430.0)
                .hint_text(
                    "filename, full path, extension...",
                ),
            );

            if ui
                .add_enabled(
                    !self.search.is_empty(),
                    egui::Button::new("Clear"),
                )
                .clicked()
            {
                self.search.clear();
            }

            ui.checkbox(
                &mut self.only_suspicious,
                "Suspicious",
            );

            ui.checkbox(
                &mut self.only_no_extension,
                "No Extension",
            );

            ui.separator();

            // NEW:
            ui.checkbox(
                &mut self.generate_pie_chart,
                "Gen pie-chart",
            );

            ui.checkbox(
                &mut self.generate_report,
                "Gen report",
            );

            ui.separator();

            egui::ComboBox::from_id_salt(
                "sort_mode",
            )
            .selected_text(
                match self.sort_mode {
                    SortMode::Name => "Name",
                    SortMode::Extension => {
                        "Extension"
                    }
                    SortMode::Largest => {
                        "Size ↓"
                    }
                    SortMode::Smallest => {
                        "Size ↑"
                    }
                },
            )
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut self.sort_mode,
                    SortMode::Name,
                    "Name",
                );

                ui.selectable_value(
                    &mut self.sort_mode,
                    SortMode::Extension,
                    "Extension",
                );

                ui.selectable_value(
                    &mut self.sort_mode,
                    SortMode::Largest,
                    "Size ↓",
                );

                ui.selectable_value(
                    &mut self.sort_mode,
                    SortMode::Smallest,
                    "Size ↑",
                );
            });
        });
    }
}

// ============================================================
// START SCREEN
// ============================================================

impl ScannerApp {
    fn draw_start_screen(
        &mut self,
        ui: &mut Ui,
    ) {
        ui.vertical_centered(|ui| {
            ui.add_space(95.0);

            ui.label(
                RichText::new(
                    "Extension Scanner",
                )
                .strong()
                .size(40.0),
            );

            ui.add_space(12.0);

            ui.label(
                RichText::new(
                    "Search and analyze files with Everything-style filtering and WizTree-style statistics.",
                )
                .size(18.0)
                .color(
                    Color32::from_gray(
                        160,
                    ),
                ),
            );

            ui.add_space(30.0);

            ui.horizontal(|ui| {
                if ui
                    .add_sized(
                        [190.0, 45.0],
                        egui::Button::new(
                            "Scan Folder",
                        ),
                    )
                    .clicked()
                {
                    if let Some(folder) =
                        FileDialog::new()
                            .set_title(
                                "Choose a folder",
                            )
                            .pick_folder()
                    {
                        self.start_scan(
                            ScanSource::Folder(
                                folder,
                            ),
                        );
                    }
                }

                if ui
                    .add_sized(
                        [190.0, 45.0],
                        egui::Button::new(
                            "Scan ZIP",
                        ),
                    )
                    .clicked()
                {
                    if let Some(zip_path) =
                        FileDialog::new()
                            .set_title(
                                "Choose ZIP archive",
                            )
                            .add_filter(
                                "ZIP archive",
                                &["zip"],
                            )
                            .pick_file()
                    {
                        self.start_scan(
                            ScanSource::Zip(
                                zip_path,
                            ),
                        );
                    }
                }
            });

            ui.add_space(25.0);

            ui.label(
                RichText::new(
                    "Hidden files and directories are scanned.",
                )
                .color(
                    Color32::from_gray(
                        130,
                    ),
                ),
            );

            ui.label(
                RichText::new(
                    "Names such as malware.png.exe are flagged as suspicious.",
                )
                .color(
                    Color32::from_gray(
                        130,
                    ),
            ));

            ui.add_space(18.0);

            ui.horizontal(|ui| {
                ui.checkbox(
                    &mut self.generate_pie_chart,
                    "Gen pie-chart",
                );

                ui.checkbox(
                    &mut self.generate_report,
                    "Gen report",
                );
            });
        });
    }
}

// ============================================================
// SCANNING SCREEN
// ============================================================

impl ScannerApp {
    fn draw_scanning_screen(
        &mut self,
        ui: &mut Ui,
    ) {
        ui.vertical_centered(|ui| {
            ui.add_space(100.0);

            ui.heading("Scanning...");

            ui.add_space(20.0);

            ui.spinner();

            ui.add_space(15.0);

            ui.label(
                RichText::new(format!(
                    "{} files",
                    format_number(
                        self.scanned_files,
                    ),
                ))
                .size(26.0),
            );

            ui.label(format!(
                "{} directories",
                format_number(
                    self.scanned_directories,
                ),
            ));

            if let Some(start) =
                self.scan_started
            {
                ui.add_space(10.0);

                ui.label(format!(
                    "Elapsed: {}",
                    format_duration(
                        start.elapsed(),
                    ),
                ));
            }

            ui.add_space(15.0);

            ui.label(
                RichText::new(
                    truncate_middle(
                        &self.current_file,
                        120,
                    ),
                )
                .monospace()
                .color(
                    Color32::from_gray(
                        145,
                    ),
                ),
            );
        });
    }
}

// ============================================================
// DASHBOARD
// ============================================================

impl ScannerApp {
    fn draw_dashboard(
        &mut self,
        ui: &mut Ui,
    ) {
        let available_width =
            ui.available_width();

        let available_height =
            ui.available_height();

        let top_height =
            (available_height * 0.42)
                .clamp(
                    300.0,
                    450.0,
                );

        ui.horizontal(|ui| {
            let left_width =
                available_width * 0.64;

            ui.allocate_ui(
                Vec2::new(
                    left_width,
                    top_height,
                ),
                |ui| {
                    self.draw_chart(ui);
                },
            );

            ui.add_space(8.0);

            ui.allocate_ui(
                Vec2::new(
                    (available_width
                        - left_width
                        - 8.0)
                        .max(250.0),
                    top_height,
                ),
                |ui| {
                    self.draw_summary(ui);
                },
            );
        });

        ui.separator();

        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Files")
                    .strong()
                    .size(19.0),
            );

            ui.label(format!(
                "{} matching",
                format_number(
                    self.filtered_count()
                        as u64,
                ),
            ));

            if let Some(source) =
                &self.source
            {
                ui.separator();

                ui.label(
                    RichText::new(
                        source.name(),
                    )
                    .color(
                        Color32::from_rgb(
                            100,
                            190,
                            255,
                        ),
                    ),
                );
            }
        });

        ui.add_space(5.0);

        self.draw_file_table(ui);
    }
}

// ============================================================
// IN-APP CHART
// ============================================================

impl ScannerApp {
    fn draw_chart(
        &mut self,
        ui: &mut Ui,
    ) {
        egui::Frame::group(
            ui.style(),
        )
        .show(ui, |ui| {
            ui.label(
                RichText::new(
                    "Extension Distribution",
                )
                .strong()
                .size(18.0),
            );

            ui.add_space(5.0);

            let width =
                ui.available_width();

            let height =
                ui.available_height()
                    .min(345.0);

            let (
                response,
                painter,
            ) =
                ui.allocate_painter(
                    Vec2::new(
                        width,
                        height,
                    ),
                    Sense::hover(),
                );

            draw_in_app_pie(
                &painter,
                response.rect,
                &self.extensions,
            );
        });
    }
}

fn draw_in_app_pie(
    painter: &egui::Painter,
    rect: Rect,
    stats: &[ExtensionStat],
) {
    if stats.is_empty() {
        return;
    }

    let mut data:
        Vec<(String, f64, [u8; 3])> =
        Vec::new();

    let visible_count =
        stats
            .len()
            .min(MAX_PIE_SLICES);

    for (
        index,
        stat,
    ) in stats
        .iter()
        .take(visible_count)
        .enumerate()
    {
        data.push((
            stat.extension.clone(),
            stat.count as f64,
            COLORS[
                index % COLORS.len()
            ],
        ));
    }

    if stats.len()
        > visible_count
    {
        let other =
            stats
                .iter()
                .skip(visible_count)
                .map(|x| x.count)
                .sum::<u64>();

        if other > 0 {
            data.push((
                "Other".to_string(),
                other as f64,
                [110, 110, 120],
            ));
        }
    }

    let total =
        data.iter()
            .map(|x| x.1)
            .sum::<f64>();

    if total <= 0.0 {
        return;
    }

    let center =
        Pos2::new(
            rect.left()
                + rect.width() * 0.27,
            rect.center().y,
        );

    let radius =
        rect.height()
            .min(280.0)
            * 0.38;

    let legend_x =
        rect.left()
            + rect.width() * 0.55;

    let mut legend_y =
        rect.top() + 7.0;

    let mut angle =
        -std::f32::consts::FRAC_PI_2;

    for (
        extension,
        count,
        color,
    ) in data
    {
        let fraction =
            (count / total)
                as f32;

        let next_angle =
            angle
                + fraction
                    * std::f32::consts::TAU;

        let mut points =
            Vec::new();

        points.push(center);

        let steps =
            ((next_angle
                - angle)
                .abs()
                * 24.0)
                .max(2.0)
                as usize;

        for step
            in 0..=steps
        {
            let factor =
                step as f32
                    / steps as f32;

            let current =
                angle
                    + (next_angle
                        - angle)
                        * factor;

            points.push(
                Pos2::new(
                    center.x
                        + radius
                            * current.cos(),
                    center.y
                        + radius
                            * current.sin(),
                ),
            );
        }

        let color32 =
            Color32::from_rgb(
                color[0],
                color[1],
                color[2],
            );

        painter.add(
            Shape::convex_polygon(
                points,
                color32,
                Stroke::new(
                    1.0,
                    Color32::from_gray(25),
                ),
            ),
        );

        if fraction >= 0.04 {
            let middle =
                (angle + next_angle)
                    / 2.0;

            let text_radius =
                radius * 0.68;

            painter.text(
                Pos2::new(
                    center.x
                        + text_radius
                            * middle.cos(),
                    center.y
                        + text_radius
                            * middle.sin(),
                ),
                egui::Align2::CENTER_CENTER,
                format!(
                    "{:.1}%",
                    fraction * 100.0,
                ),
                FontId::proportional(13.0),
                Color32::WHITE,
            );
        }

        painter.rect_filled(
            Rect::from_min_size(
                Pos2::new(
                    legend_x,
                    legend_y,
                ),
                Vec2::splat(14.0),
            ),
            2.0,
            color32,
        );

        painter.text(
            Pos2::new(
                legend_x + 20.0,
                legend_y + 7.0,
            ),
            egui::Align2::LEFT_CENTER,
            format!(
                "{}  {:.2}%  ({})",
                extension,
                fraction * 100.0,
                format_number(
                    count as u64,
                ),
            ),
            FontId::proportional(12.0),
            Color32::from_gray(220),
        );

        legend_y += 21.0;

        angle = next_angle;
    }
}

// ============================================================
// SUMMARY
// ============================================================

impl ScannerApp {
    fn draw_summary(
        &mut self,
        ui: &mut Ui,
    ) {
        egui::Frame::group(
            ui.style(),
        )
        .show(ui, |ui| {
            ui.label(
                RichText::new("Summary")
                    .strong()
                    .size(18.0),
            );

            ui.add_space(10.0);

            // IMPORTANT:
            // Each item is now its own line.
            summary_item(
                ui,
                "Files:",
                &format_number(
                    self.files.len()
                        as u64,
                ),
            );

            summary_item(
                ui,
                "Size:",
                &format_bytes(
                    self.total_bytes,
                ),
            );

            summary_item(
                ui,
                "Extensions:",
                &format_number(
                    self.extensions.len()
                        as u64,
                ),
            );

            let suspicious =
                self.files
                    .iter()
                    .filter(
                        |file| file.suspicious,
                    )
                    .count();

            summary_item(
                ui,
                "Suspicious:",
                &format_number(
                    suspicious as u64,
                ),
            );

            summary_item(
                ui,
                "Errors:",
                &format_number(
                    self.errors.len()
                        as u64,
                ),
            );

            ui.separator();

            ui.label(
                RichText::new("Reports")
                    .strong(),
            );

            ui.add_space(4.0);

            if let Some(path) =
                &self.png_path
            {
                if ui
                    .link(
                        path.file_name()
                            .and_then(
                                |x| x.to_str(),
                            )
                            .unwrap_or(
                                "pie.png",
                            ),
                    )
                    .clicked()
                {
                    let _ =
                        open_default(path);
                }
            } else if !self.generate_pie_chart {
                ui.label(
                    RichText::new(
                        "Pie chart disabled",
                    )
                    .color(
                        Color32::from_gray(
                            130,
                        ),
                    ),
                );
            }

            if let Some(path) =
                &self.json_path
            {
                if ui
                    .link(
                        path.file_name()
                            .and_then(
                                |x| x.to_str(),
                            )
                            .unwrap_or(
                                "report.json",
                            ),
                    )
                    .clicked()
                {
                    let _ =
                        open_default(path);
                }
            } else if !self.generate_report {
                ui.label(
                    RichText::new(
                        "Report disabled",
                    )
                    .color(
                        Color32::from_gray(
                            130,
                        ),
                    ),
                );
            }

            ui.separator();

            if let Some(source) =
                &self.source
            {
                ui.label(
                    RichText::new(
                        source.name(),
                    )
                    .strong(),
                );

                ui.label(
                    RichText::new(
                        truncate_middle(
                            &source
                                .display_path(),
                            85,
                        ),
                    )
                    .monospace()
                    .color(
                        Color32::from_gray(
                            145,
                        ),
                    ),
                );
            }
        });
    }
}

fn summary_item(
    ui: &mut Ui,
    label: &str,
    value: &str,
) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(label)
                .strong(),
        );

        ui.label(value);
    });

    ui.add_space(4.0);
}

// ============================================================
// FILE TABLE
// ============================================================

impl ScannerApp {
    fn draw_file_table(
        &mut self,
        ui: &mut Ui,
    ) {
        let indices =
            self.filtered_indices();

        egui::Frame::group(
            ui.style(),
        )
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add_sized(
                    [25.0, 20.0],
                    egui::Label::new(""),
                );

                ui.add_sized(
                    [250.0, 20.0],
                    egui::Label::new(
                        RichText::new("Name")
                            .strong(),
                    ),
                );

                ui.add_sized(
                    [135.0, 20.0],
                    egui::Label::new(
                        RichText::new(
                            "Extension",
                        )
                        .strong(),
                    ),
                );

                ui.add_sized(
                    [100.0, 20.0],
                    egui::Label::new(
                        RichText::new("Size")
                            .strong(),
                    ),
                );

                ui.label(
                    RichText::new("Path")
                        .strong(),
                );
            });

            ui.separator();

            ScrollArea::vertical()
                .auto_shrink([
                    false,
                    false,
                ])
                .show_rows(
                    ui,
                    24.0,
                    indices.len(),
                    |ui, rows| {
                        for row in rows {
                            if let Some(index) =
                                indices.get(row)
                            {
                                self.draw_file_row(
                                    ui,
                                    *index,
                                );
                            }
                        }
                    },
                );
        });
    }

    fn draw_file_row(
        &mut self,
        ui: &mut Ui,
        index: usize,
    ) {
        let Some(file) =
            self.files
                .get(index)
                .cloned()
        else {
            return;
        };

        let selected =
            self.selected_file
                == Some(index);

        let background =
            if selected {
                Color32::from_rgb(
                    35,
                    70,
                    105,
                )
            } else {
                Color32::TRANSPARENT
            };

        egui::Frame::new()
            .fill(background)
            .show(ui, |ui| {
                let response =
                    ui.horizontal(|ui| {
                        let icon =
                            if file.suspicious {
                                "!"
                            } else {
                                "•"
                            };

                        let icon_color =
                            if file.suspicious {
                                Color32::from_rgb(
                                    255,
                                    175,
                                    55,
                                )
                            } else {
                                Color32::from_gray(
                                    130,
                                )
                            };

                        ui.add_sized(
                            [25.0, 20.0],
                            egui::Label::new(
                                RichText::new(
                                    icon,
                                )
                                .color(
                                    icon_color,
                                ),
                            ),
                        );

                        ui.add_sized(
                            [250.0, 20.0],
                            egui::Label::new(
                                RichText::new(
                                    truncate_middle(
                                        &file.name,
                                        40,
                                    ),
                                ),
                            ),
                        );

                        ui.add_sized(
                            [135.0, 20.0],
                            egui::Label::new(
                                RichText::new(
                                    &file.extension,
                                )
                                .color(
                                    Color32::from_rgb(
                                        100,
                                        190,
                                        255,
                                    ),
                                ),
                            ),
                        );

                        ui.add_sized(
                            [100.0, 20.0],
                            egui::Label::new(
                                format_bytes(
                                    file.size,
                                ),
                            ),
                        );

                        ui.label(
                            RichText::new(
                                truncate_middle(
                                    &file.path,
                                    115,
                                ),
                            )
                            .monospace()
                            .color(
                                Color32::from_gray(
                                    145,
                                ),
                            ),
                        );
                    })
                    .response;

                if response.clicked() {
                    self.selected_file =
                        Some(index);
                }

                if response.double_clicked() {
                    self.locate_file(&file);
                }
            });
    }
}

// ============================================================
// ABOUT
// ============================================================

impl ScannerApp {
    fn draw_about_window(
        &mut self,
        ui: &mut Ui,
    ) {
        egui::Window::new(
            "About Extension Scanner",
        )
        .collapsible(false)
        .resizable(false)
        .default_width(500.0)
        .show(
            ui.ctx(),
            |ui| {
                ui.label(
                    RichText::new(
                        APP_NAME,
                    )
                    .strong()
                    .size(25.0),
                );

                ui.add_space(10.0);

                ui.label(
                    "Recursive extension scanner with searchable results, ZIP scanning, statistics, and optional report generation.",
                );

                ui.add_space(10.0);

                ui.label(
                    "The suspicious check identifies executable filenames containing another extension-like component, for example malware.png.exe.",
                );

                ui.add_space(10.0);

                ui.label(
                    "This is a filename heuristic, not an antivirus engine.",
                );

                ui.add_space(15.0);

                if ui.button("Close").clicked() {
                    self.about_open = false;
                }
            },
        );
    }
}

// ============================================================
// START SCAN
// ============================================================

impl ScannerApp {
    fn start_scan(
        &mut self,
        source: ScanSource,
    ) {
        if self.scanning {
            return;
        }

        self.source =
            Some(source.clone());

        self.files.clear();
        self.extensions.clear();

        self.search.clear();

        self.selected_file =
            None;

        self.scanned_files = 0;
        self.scanned_directories = 0;

        self.current_file.clear();

        self.total_bytes = 0;

        self.errors.clear();

        self.png_path = None;
        self.json_path = None;

        self.scan_started =
            Some(Instant::now());

        self.scanning = true;

        let (
            sender,
            receiver,
        ) =
            mpsc::channel();

        self.receiver =
            Some(receiver);

        thread::spawn(
            move || {
                match perform_scan(
                    source,
                    sender.clone(),
                ) {
                    Ok(result) => {
                        let _ =
                            sender.send(
                                ScanMessage::Finished(
                                    result,
                                ),
                            );
                    }

                    Err(error) => {
                        let _ =
                            sender.send(
                                ScanMessage::Failed(
                                    error.to_string(),
                                ),
                            );
                    }
                }
            },
        );
    }
}

// ============================================================
// RECEIVE SCAN MESSAGES
// ============================================================

impl ScannerApp {
    fn receive_messages(
        &mut self,
    ) {
        let mut finished = None;
        let mut failed = None;

        if let Some(receiver) =
            &self.receiver
        {
            while let Ok(message) =
                receiver.try_recv()
            {
                match message {
                    ScanMessage::Progress {
                        files,
                        directories,
                        current,
                    } => {
                        self.scanned_files =
                            files;

                        self.scanned_directories =
                            directories;

                        self.current_file =
                            current;
                    }

                    ScanMessage::Finished(
                        result,
                    ) => {
                        finished =
                            Some(result);
                    }

                    ScanMessage::Failed(
                        error,
                    ) => {
                        failed =
                            Some(error);
                    }
                }
            }
        }

        if let Some(result) =
            finished
        {
            self.finish_scan(
                result,
            );
        }

        if let Some(error) =
            failed
        {
            self.scanning =
                false;

            let _ =
                rfd::MessageDialog::new()
                    .set_title(
                        APP_NAME,
                    )
                    .set_description(
                        error,
                    )
                    .show();
        }
    }

    fn finish_scan(
        &mut self,
        result: ScanResult,
    ) {
        self.files =
            result.files;

        self.extensions =
            result.extensions;

        self.total_bytes =
            result.total_bytes;

        self.errors =
            result.errors;

        self.scanning =
            false;

        self.scan_started =
            None;

        // ----------------------------------------------------
        // Optional PNG
        // ----------------------------------------------------

        if self.generate_pie_chart {
            match create_png(
                &result.source,
                &self.extensions,
            ) {
                Ok(path) => {
                    self.png_path =
                        Some(path);
                }

                Err(error) => {
                    let _ =
                        rfd::MessageDialog::new()
                            .set_title(
                                APP_NAME,
                            )
                            .set_description(
                                format!(
                                    "The scan completed, but the pie chart could not be generated.\n\n{}",
                                    error,
                                ),
                            )
                            .show();
                }
            }
        }

        // ----------------------------------------------------
        // Optional JSON
        // ----------------------------------------------------

        if self.generate_report {
            match create_json(
                &result.source,
                &self.extensions,
                self.total_bytes,
                self.files.len()
                    as u64,
            ) {
                Ok(path) => {
                    self.json_path =
                        Some(path);
                }

                Err(error) => {
                    let _ =
                        rfd::MessageDialog::new()
                            .set_title(
                                APP_NAME,
                            )
                            .set_description(
                                format!(
                                    "The scan completed, but the report could not be generated.\n\n{}",
                                    error,
                                ),
                            )
                            .show();
                }
            }
        }

        // IMPORTANT:
        //
        // The PNG is deliberately NOT opened anymore.
    }
}

// ============================================================
// FILTERING
// ============================================================

impl ScannerApp {
    fn filtered_indices(
        &self,
    ) -> Vec<usize> {
        let search =
            self.search
                .trim()
                .to_lowercase();

        let mut indices =
            self.files
                .iter()
                .enumerate()
                .filter(
                    |(_, file)| {
                        if self.only_suspicious
                            && !file.suspicious
                        {
                            return false;
                        }

                        if self.only_no_extension
                            && file.extension
                                != "File / No Extension"
                        {
                            return false;
                        }

                        search.is_empty()
                            || file.name
                                .to_lowercase()
                                .contains(
                                    &search,
                                )
                            || file.path
                                .to_lowercase()
                                .contains(
                                    &search,
                                )
                            || file.extension
                                .to_lowercase()
                                .contains(
                                    &search,
                                )
                    },
                )
                .map(
                    |(index, _)| index,
                )
                .collect::<Vec<_>>();

        match self.sort_mode {
            SortMode::Name => {
                indices.sort_by(
                    |a, b| {
                        self.files[*a]
                            .name
                            .to_lowercase()
                            .cmp(
                                &self.files[*b]
                                    .name
                                    .to_lowercase(),
                            )
                    },
                );
            }

            SortMode::Extension => {
                indices.sort_by(
                    |a, b| {
                        self.files[*a]
                            .extension
                            .cmp(
                                &self.files[*b]
                                    .extension,
                            )
                    },
                );
            }

            SortMode::Largest => {
                indices.sort_by(
                    |a, b| {
                        self.files[*b]
                            .size
                            .cmp(
                                &self.files[*a]
                                    .size,
                            )
                    },
                );
            }

            SortMode::Smallest => {
                indices.sort_by(
                    |a, b| {
                        self.files[*a]
                            .size
                            .cmp(
                                &self.files[*b]
                                    .size,
                            )
                    },
                );
            }
        }

        indices
    }

    fn filtered_count(
        &self,
    ) -> usize {
        let search =
            self.search
                .trim()
                .to_lowercase();

        self.files
            .iter()
            .filter(
                |file| {
                    if self.only_suspicious
                        && !file.suspicious
                    {
                        return false;
                    }

                    if self.only_no_extension
                        && file.extension
                            != "File / No Extension"
                    {
                        return false;
                    }

                    search.is_empty()
                        || file.name
                            .to_lowercase()
                            .contains(
                                &search,
                            )
                        || file.path
                            .to_lowercase()
                            .contains(
                                &search,
                            )
                        || file.extension
                            .to_lowercase()
                            .contains(
                                &search,
                            )
                },
            )
            .count()
    }

    fn locate_file(
        &self,
        file: &FileRecord,
    ) {
        if let Some(path) =
            &file.filesystem_path
        {
            let _ =
                reveal_in_explorer(
                    path,
                );
        }
    }
}

// ============================================================
// SCAN ENGINE
// ============================================================

fn perform_scan(
    source: ScanSource,
    sender: Sender<ScanMessage>,
) -> AppResult<ScanResult> {
    let mut files =
        Vec::new();

    let mut statistics:
        HashMap<String, (u64, u64)> =
        HashMap::new();

    let mut directories = 0u64;
    let mut scanned = 0u64;

    let mut errors =
        Vec::new();

    match &source {
        ScanSource::Folder(folder) => {
            scan_directory(
                folder,
                &mut files,
                &mut statistics,
                &mut directories,
                &mut scanned,
                &sender,
                &mut errors,
            )?;
        }

        ScanSource::Zip(zip_path) => {
            scan_zip_archive(
                zip_path,
                &mut files,
                &mut statistics,
                &mut scanned,
                &sender,
                &mut errors,
            )?;
        }
    }

    let total_files =
        files.len() as u64;

    let total_bytes =
        files
            .iter()
            .map(|file| file.size)
            .sum::<u64>();

    let mut extensions =
        statistics
            .into_iter()
            .map(
                |(
                    extension,
                    (count, bytes),
                )| {
                    let percentage =
                        if total_files == 0 {
                            0.0
                        } else {
                            count as f64
                                / total_files
                                    as f64
                                * 100.0
                        };

                    ExtensionStat {
                        extension,
                        count,
                        bytes,
                        percentage,
                    }
                },
            )
            .collect::<Vec<_>>();

    extensions.sort_by(
        |a, b| {
            b.count
                .cmp(&a.count)
                .then_with(
                    || {
                        a.extension
                            .cmp(
                                &b.extension,
                            )
                    },
                )
        },
    );

    let _ =
        sender.send(
            ScanMessage::Progress {
                files: total_files,
                directories,
                current:
                    "Finished".to_string(),
            },
        );

    Ok(ScanResult {
        source,
        files,
        extensions,
        total_bytes,
        errors,
    })
}

// ============================================================
// FOLDER SCANNER
// ============================================================

fn scan_directory(
    directory: &Path,
    files: &mut Vec<FileRecord>,
    statistics: &mut HashMap<String, (u64, u64)>,
    directories: &mut u64,
    scanned: &mut u64,
    sender: &Sender<ScanMessage>,
    errors: &mut Vec<String>,
) -> AppResult<()> {
    *directories += 1;

    let entries =
        match fs::read_dir(directory) {
            Ok(entries) =>
                entries,

            Err(error) => {
                errors.push(
                    format!(
                        "{}: {}",
                        directory.display(),
                        error,
                    ),
                );

                return Ok(());
            }
        };

    // Hidden files/folders are intentionally included.
    for entry_result in entries {
        let entry =
            match entry_result {
                Ok(entry) =>
                    entry,

                Err(error) => {
                    errors.push(
                        error.to_string(),
                    );

                    continue;
                }
            };

        let path =
            entry.path();

        let file_type =
            match entry.file_type() {
                Ok(value) =>
                    value,

                Err(error) => {
                    errors.push(
                        format!(
                            "{}: {}",
                            path.display(),
                            error,
                        ),
                    );

                    continue;
                }
            };

        // Prevent symlink loops.
        if file_type.is_symlink() {
            continue;
        }

        if file_type.is_dir() {
            scan_directory(
                &path,
                files,
                statistics,
                directories,
                scanned,
                sender,
                errors,
            )?;

            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        let metadata =
            match entry.metadata() {
                Ok(metadata) =>
                    metadata,

                Err(error) => {
                    errors.push(
                        format!(
                            "{}: {}",
                            path.display(),
                            error,
                        ),
                    );

                    continue;
                }
            };

        let name =
            path.file_name()
                .and_then(
                    |x| x.to_str(),
                )
                .unwrap_or("")
                .to_string();

        let extension =
            extension_for_path(
                &path,
            );

        let suspicious =
            suspicious_name(
                &name,
            );

        let size =
            metadata.len();

        files.push(
            FileRecord {
                name,
                path: path
                    .display()
                    .to_string(),
                extension:
                    extension.clone(),
                size,
                filesystem_path:
                    Some(
                        path.clone(),
                    ),
                suspicious,
            },
        );

        let stat =
            statistics
                .entry(extension)
                .or_insert(
                    (0, 0),
                );

        stat.0 += 1;
        stat.1 += size;

        *scanned += 1;

        if *scanned
            % PROGRESS_EVERY
            == 0
        {
            let _ =
                sender.send(
                    ScanMessage::Progress {
                        files: *scanned,
                        directories:
                            *directories,
                        current:
                            path.display()
                                .to_string(),
                    },
                );
        }
    }

    Ok(())
}

// ============================================================
// ZIP SCANNER
// ============================================================

fn scan_zip_archive(
    zip_path: &Path,
    files: &mut Vec<FileRecord>,
    statistics: &mut HashMap<String, (u64, u64)>,
    scanned: &mut u64,
    sender: &Sender<ScanMessage>,
    errors: &mut Vec<String>,
) -> AppResult<()> {
    let file =
        File::open(zip_path)?;

    let mut archive =
        ZipArchive::new(file)?;

    for index in 0..archive.len() {
        let entry =
            match archive.by_index(index) {
                Ok(entry) =>
                    entry,

                Err(error) => {
                    errors.push(
                        format!(
                            "ZIP entry {}: {}",
                            index,
                            error,
                        ),
                    );

                    continue;
                }
            };

        if entry.is_dir() {
            continue;
        }

        let entry_name =
            entry.name()
                .to_string();

        let filename =
            Path::new(
                &entry_name,
            )
            .file_name()
            .and_then(
                |x| x.to_str(),
            )
            .unwrap_or(
                &entry_name,
            )
            .to_string();

        let extension =
            extension_for_name(
                &entry_name,
            );

        let size =
            entry.size();

        let suspicious =
            suspicious_name(
                &filename,
            );

        files.push(
            FileRecord {
                name: filename,
                path: format!(
                    "{} :: {}",
                    zip_path.display(),
                    entry_name,
                ),
                extension:
                    extension.clone(),
                size,
                filesystem_path:
                    None,
                suspicious,
            },
        );

        let stat =
            statistics
                .entry(extension)
                .or_insert(
                    (0, 0),
                );

        stat.0 += 1;
        stat.1 += size;

        *scanned += 1;

        if *scanned
            % PROGRESS_EVERY
            == 0
        {
            let _ =
                sender.send(
                    ScanMessage::Progress {
                        files: *scanned,
                        directories: 0,
                        current:
                            format!(
                                "{} :: {}",
                                zip_path
                                    .display(),
                                entry_name,
                            ),
                    },
                );
        }
    }

    Ok(())
}

// ============================================================
// EXTENSIONS
// ============================================================

fn extension_for_path(
    path: &Path,
) -> String {
    match path
        .extension()
        .and_then(
            |x| x.to_str(),
        )
    {
        Some(extension)
            if !extension.is_empty() =>
        {
            format!(
                ".{}",
                extension.to_lowercase(),
            )
        }

        _ =>
            "File / No Extension"
                .to_string(),
    }
}

fn extension_for_name(
    name: &str,
) -> String {
    extension_for_path(
        Path::new(name),
    )
}

// ============================================================
// SUSPICIOUS NAME
// ============================================================

fn suspicious_name(
    filename: &str,
) -> bool {
    let path =
        Path::new(filename);

    let Some(final_extension) =
        path.extension()
    else {
        return false;
    };

    let final_extension =
        final_extension
            .to_string_lossy()
            .to_lowercase();

    if !EXECUTABLE_EXTENSIONS
        .contains(
            &final_extension.as_str(),
        )
    {
        return false;
    }

    let Some(stem) =
        path.file_stem()
    else {
        return false;
    };

    let stem_string =
        stem.to_string_lossy();

    Path::new(
        stem_string.as_ref(),
    )
    .extension()
    .is_some()
}

// ============================================================
// PNG EXPORT
// ============================================================

fn create_png(
    source: &ScanSource,
    extensions: &[ExtensionStat],
) -> AppResult<PathBuf> {
    let directory =
        executable_directory()?;

    let name =
        sanitize_filename(
            &source.name(),
        );

    let path =
        directory.join(
            format!(
                "pie_{}.png",
                name,
            ),
        );

    let total_files =
        extensions
            .iter()
            .map(|x| x.count)
            .sum::<u64>();

    {
        let root =
            BitMapBackend::new(
                &path,
                (1500, 900),
            )
            .into_drawing_area();

        root.fill(
            &RGBColor(
                20,
                23,
                28,
            ),
        )?;

        root.titled(
            &format!(
                "File Extension Distribution - {}",
                name,
            ),
            (
                "sans-serif",
                40,
            )
            .into_font()
            .color(&WHITE),
        )?;

        let mut values:
            Vec<(
                f64,
                [u8; 3],
                String,
            )> =
            Vec::new();

        for (
            index,
            stat,
        ) in extensions
            .iter()
            .take(MAX_PIE_SLICES)
            .enumerate()
        {
            values.push(
                (
                    stat.count as f64,
                    COLORS[
                        index % COLORS.len()
                    ],
                    stat.extension
                        .clone(),
                ),
            );
        }

        if extensions.len()
            > MAX_PIE_SLICES
        {
            let other =
                extensions
                    .iter()
                    .skip(
                        MAX_PIE_SLICES,
                    )
                    .map(
                        |x| x.count,
                    )
                    .sum::<u64>();

            if other > 0 {
                values.push(
                    (
                        other as f64,
                        [110, 110, 120],
                        "Other"
                            .to_string(),
                    ),
                );
            }
        }

        let sizes =
            values
                .iter()
                .map(
                    |x| x.0,
                )
                .collect::<Vec<_>>();

        let labels =
            values
                .iter()
                .map(
                    |x| x.2.clone(),
                )
                .collect::<Vec<_>>();

        let colors =
            values
                .iter()
                .map(
                    |x| {
                        RGBColor(
                            x.1[0],
                            x.1[1],
                            x.1[2],
                        )
                    },
                )
                .collect::<Vec<_>>();

        let center =
            (430i32, 460i32);

        let radius =
            305.0f64;

        let mut pie =
            Pie::new(
                &center,
                &radius,
                &sizes,
                &colors,
                &labels,
            );

        pie.start_angle(-90.0);

        pie.percentages(
            (
                "sans-serif",
                20,
            )
            .into_font()
            .color(&WHITE),
        );

        root.draw(&pie)?;

        let mut y =
            125i32;

        for (
            count,
            color,
            extension,
        ) in &values
        {
            let percentage =
                if total_files == 0 {
                    0.0
                } else {
                    *count
                        / total_files
                            as f64
                        * 100.0
                };

            let rgb =
                RGBColor(
                    color[0],
                    color[1],
                    color[2],
                );

            root.draw(
                &Rectangle::new(
                    [
                        (850, y),
                        (875, y + 25),
                    ],
                    ShapeStyle::from(
                        &rgb,
                    )
                    .filled(),
                ),
            )?;

            root.draw(
                &Text::new(
                    format!(
                        "{}   {:.2}%",
                        extension,
                        percentage,
                    ),
                    (890, y + 20),
                    (
                        "sans-serif",
                        21,
                    )
                    .into_font()
                    .color(&WHITE),
                ),
            )?;

            y += 35;

            if y > 820 {
                break;
            }
        }

        root.draw(
            &Text::new(
                format!(
                    "Total files: {}",
                    format_number(
                        total_files,
                    ),
                ),
                (850, 80),
                (
                    "sans-serif",
                    25,
                )
                .into_font()
                .color(
                    &RGBColor(
                        190,
                        190,
                        190,
                    ),
                ),
            ),
        )?;

        root.present()?;
    }

    Ok(path)
}

// ============================================================
// JSON EXPORT
// ============================================================

fn create_json(
    source: &ScanSource,
    extensions: &[ExtensionStat],
    total_bytes: u64,
    total_files: u64,
) -> AppResult<PathBuf> {
    let directory =
        executable_directory()?;

    let name =
        sanitize_filename(
            &source.name(),
        );

    let path =
        directory.join(
            format!(
                "extensions_{}.json",
                name,
            ),
        );

    let mut output =
        String::new();

    output.push_str("{\n");

    output.push_str(
        "  \"application\": \"Extension Scanner\",\n",
    );

    output.push_str(
        &format!(
            "  \"source\": {},\n",
            json_string(
                &source.display_path(),
            ),
        ),
    );

    output.push_str(
        &format!(
            "  \"total_files\": {},\n",
            total_files,
        ),
    );

    output.push_str(
        &format!(
            "  \"total_bytes\": {},\n",
            total_bytes,
        ),
    );

    output.push_str(
        "  \"extensions\": [\n",
    );

    for (
        index,
        stat,
    ) in extensions.iter().enumerate()
    {
        output.push_str(
            "    {\n",
        );

        output.push_str(
            &format!(
                "      \"extension\": {},\n",
                json_string(
                    &stat.extension,
                ),
            ),
        );

        output.push_str(
            &format!(
                "      \"count\": {},\n",
                stat.count,
            ),
        );

        output.push_str(
            &format!(
                "      \"bytes\": {},\n",
                stat.bytes,
            ),
        );

        output.push_str(
            &format!(
                "      \"percentage\": {:.6}\n",
                stat.percentage,
            ),
        );

        output.push_str(
            "    }",
        );

        if index + 1
            < extensions.len()
        {
            output.push(',');
        }

        output.push('\n');
    }

    output.push_str(
        "  ]\n",
    );

    output.push_str(
        "}\n",
    );

    fs::write(
        &path,
        output,
    )?;

    Ok(path)
}

// ============================================================
// UAC
// ============================================================

#[cfg(windows)]
fn ensure_admin() -> AppResult<bool> {
    if is_admin()? {
        return Ok(true);
    }

    let executable =
        env::current_exe()?;

    let executable_wide =
        wide(
            &executable
                .to_string_lossy(),
        );

    let args =
        env::args()
            .skip(1)
            .collect::<Vec<String>>();

    let argument_string =
        quote_windows_arguments(
            &args,
        );

    let arguments_wide =
        wide(
            &argument_string,
        );

    let operation =
        wide("runas");

    let result =
        unsafe {
            ShellExecuteW(
                None,
                PCWSTR(
                    operation.as_ptr(),
                ),
                PCWSTR(
                    executable_wide
                        .as_ptr(),
                ),
                PCWSTR(
                    arguments_wide
                        .as_ptr(),
                ),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };

    if result.0 as isize <= 32 {
        return Err(
            format!(
                "Windows UAC elevation failed. Return code: {}",
                result.0 as isize,
            )
            .into(),
        );
    }

    Ok(false)
}

#[cfg(windows)]
fn is_admin() -> AppResult<bool> {
    unsafe {
        let process =
            GetCurrentProcess();

        let mut token =
            windows::Win32::Foundation::HANDLE::default();

        OpenProcessToken(
            process,
            TOKEN_QUERY,
            &mut token,
        )?;

        let mut elevation =
            TOKEN_ELEVATION::default();

        let mut returned_length =
            0u32;

        GetTokenInformation(
            token,
            TokenElevation,
            Some(
                &mut elevation
                    as *mut TOKEN_ELEVATION
                    as *mut _,
            ),
            std::mem::size_of::<
                TOKEN_ELEVATION,
            >() as u32,
            &mut returned_length,
        )?;

        Ok(
            elevation.TokenIsElevated != 0
        )
    }
}

#[cfg(windows)]
fn wide(
    value: &str,
) -> Vec<u16> {
    value
        .encode_utf16()
        .chain(
            std::iter::once(0),
        )
        .collect()
}

#[cfg(windows)]
fn quote_windows_arguments(
    args: &[String],
) -> String {
    args.iter()
        .map(
            |argument| {
                if argument
                    .contains(
                        [' ', '\t', '"'],
                    )
                {
                    format!(
                        "\"{}\"",
                        argument.replace(
                            '"',
                            "\\\"",
                        ),
                    )
                } else {
                    argument.clone()
                }
            },
        )
        .collect::<Vec<_>>()
        .join(" ")
}

// ============================================================
// PATH HELPERS
// ============================================================

fn executable_directory()
    -> AppResult<PathBuf>
{
    let executable =
        env::current_exe()?;

    Ok(
        executable
            .parent()
            .map(
                Path::to_path_buf,
            )
            .unwrap_or_else(
                || PathBuf::from("."),
            ),
    )
}

fn sanitize_filename(
    value: &str,
) -> String {
    let invalid = [
        '<', '>', ':', '"',
        '/', '\\', '|',
        '?', '*',
    ];

    let mut output =
        String::new();

    for character
        in value.chars()
    {
        if invalid
            .contains(&character)
        {
            output.push('_');
        } else {
            output.push(character);
        }
    }

    let output =
        output
            .trim()
            .trim_matches('.')
            .to_string();

    if output.is_empty() {
        "scan".to_string()
    } else {
        output
    }
}

// ============================================================
// OPEN FILE / FOLDER
// ============================================================

fn open_default(
    path: &Path,
) -> AppResult<()> {
    #[cfg(windows)]
    {
        Command::new("cmd")
            .args([
                "/C",
                "start",
                "",
                &path.to_string_lossy(),
            ])
            .spawn()?;
    }

    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(path)
            .spawn()?;
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(path)
            .spawn()?;
    }

    Ok(())
}

fn reveal_in_explorer(
    path: &Path,
) -> AppResult<()> {
    #[cfg(windows)]
    {
        let absolute =
            path.canonicalize()
                .unwrap_or_else(
                    |_| path.to_path_buf(),
                );

        Command::new(
            "explorer.exe",
        )
        .args([
            "/select,",
            &format!(
                "\"{}\"",
                absolute.display(),
            ),
        ])
        .spawn()?;
    }

    #[cfg(not(windows))]
    {
        open_default(path)?;
    }

    Ok(())
}

// ============================================================
// FORMATTING
// ============================================================

fn format_number(
    number: u64,
) -> String {
    let input =
        number.to_string();

    let mut output =
        String::new();

    for (
        index,
        character,
    ) in input
        .chars()
        .rev()
        .enumerate()
    {
        if index > 0
            && index % 3 == 0
        {
            output.push(',');
        }

        output.push(
            character,
        );
    }

    output
        .chars()
        .rev()
        .collect()
}

fn format_bytes(
    bytes: u64,
) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    let value =
        bytes as f64;

    if value >= TB {
        format!(
            "{:.2} TB",
            value / TB,
        )
    } else if value >= GB {
        format!(
            "{:.2} GB",
            value / GB,
        )
    } else if value >= MB {
        format!(
            "{:.2} MB",
            value / MB,
        )
    } else if value >= KB {
        format!(
            "{:.2} KB",
            value / KB,
        )
    } else {
        format!(
            "{} B",
            bytes,
        )
    }
}

fn format_duration(
    duration: Duration,
) -> String {
    let seconds =
        duration.as_secs();

    if seconds < 60 {
        format!(
            "{}s",
            seconds,
        )
    } else if seconds < 3600 {
        format!(
            "{}m {:02}s",
            seconds / 60,
            seconds % 60,
        )
    } else {
        format!(
            "{}h {:02}m",
            seconds / 3600,
            (seconds / 60) % 60,
        )
    }
}

fn truncate_middle(
    value: &str,
    maximum: usize,
) -> String {
    if value.chars().count()
        <= maximum
    {
        return value.to_string();
    }

    let side =
        maximum
            .saturating_sub(3)
            / 2;

    let start =
        value
            .chars()
            .take(side)
            .collect::<String>();

    let end =
        value
            .chars()
            .rev()
            .take(side)
            .collect::<String>();

    format!(
        "{}...{}",
        start,
        end.chars()
            .rev()
            .collect::<String>(),
    )
}

// ============================================================
// JSON ESCAPING
// ============================================================

fn json_string(
    value: &str,
) -> String {
    let mut output =
        String::from("\"");

    for character
        in value.chars()
    {
        match character {
            '"' =>
                output.push_str(
                    "\\\"",
                ),

            '\\' =>
                output.push_str(
                    "\\\\",
                ),

            '\n' =>
                output.push_str(
                    "\\n",
                ),

            '\r' =>
                output.push_str(
                    "\\r",
                ),

            '\t' =>
                output.push_str(
                    "\\t",
                ),

            c if c.is_control() =>
                output.push_str(
                    &format!(
                        "\\u{:04x}",
                        c as u32,
                    ),
                ),

            c =>
                output.push(c),
        }
    }

    output.push('"');

    output
}