#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod state;
mod views;

use app::Chrome2RustApp;
use chrome2rust_core::logging::init_logging;
use eframe::egui;
use state::{AppState, LaunchArgs};
use std::path::PathBuf;

fn parse_launch_args() -> LaunchArgs {
    let mut out = LaunchArgs::default();
    let mut pick = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--decrypt" => out.decrypt = true,
            "--pick" | "--browse" => pick = true,
            "--key" => {
                if let Some(k) = args.next() {
                    out.keys.push(k);
                }
            }
            "--help" | "-h" => {
                println!(
                    "chrome2rust-gui [PATH] [--pick] [--decrypt] [--key <PASSPHRASE_OR_HEX>]\n\
                     Launch the native Chrome2Rust Management Console desktop GUI."
                );
                std::process::exit(0);
            }
            other if !other.starts_with('-') && out.path.is_none() => {
                out.path = Some(PathBuf::from(other));
            }
            _ => {}
        }
    }
    if pick && out.path.is_none() {
        out.path = rfd::FileDialog::new()
            .set_title("Select Chrome User Data, Profile, or Cache Folder")
            .pick_folder();
    }
    out
}

fn main() -> eframe::Result<()> {
    let _ = init_logging("warn", None);
    let launch_args = parse_launch_args();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1380.0, 840.0])
            .with_min_inner_size([920.0, 560.0])
            .with_title("Chrome2Rust Management Console - Chrome Cache & User Data Forensics"),
        ..Default::default()
    };

    eframe::run_native(
        "Chrome2Rust Management Console",
        native_options,
        Box::new(|cc| {
            egui_extras::install_image_loaders(&cc.egui_ctx);

            let mut visuals = egui::Visuals::light();

            // Classic Win32 / MMC / Windows 2000 & XP Neutral Palette
            let bg_face = egui::Color32::from_rgb(238, 238, 238);
            let border_color = egui::Color32::from_rgb(160, 160, 160);
            let highlight_blue = egui::Color32::from_rgb(49, 106, 197);

            visuals.panel_fill = bg_face;
            visuals.window_fill = bg_face;
            visuals.window_stroke = egui::Stroke::new(1.0_f32, border_color);
            visuals.window_corner_radius = egui::CornerRadius::same(2);

            visuals.widgets.noninteractive.bg_fill = bg_face;
            visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);
            visuals.widgets.noninteractive.corner_radius = egui::CornerRadius::same(1);

            visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(244, 244, 244);
            visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);
            visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(172, 172, 172));
            visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(2);

            visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(229, 241, 251);
            visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);
            visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(0, 120, 215));
            visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(2);

            visuals.widgets.active.bg_fill = egui::Color32::from_rgb(204, 228, 247);
            visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::BLACK);
            visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(0, 84, 153));
            visuals.widgets.active.corner_radius = egui::CornerRadius::same(2);

            visuals.selection.bg_fill = highlight_blue;
            visuals.selection.stroke = egui::Stroke::new(1.0_f32, highlight_blue);

            let mut style = (*cc.egui_ctx.style()).clone();
            style.spacing.item_spacing = egui::vec2(4.0, 3.0);
            style.spacing.button_padding = egui::vec2(6.0, 3.0);
            style.spacing.window_margin = egui::Margin::same(6);
            style.visuals = visuals;

            cc.egui_ctx.set_style(style);

            Ok(Box::new(Chrome2RustApp::new(AppState::new(launch_args))))
        }),
    )
}
