#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod app;
mod message;
mod views;

use app::App;
use chrome2rust_core::logging::init_logging;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchArgs {
    pub path: Option<PathBuf>,
    pub decrypt: bool,
    pub keys: Vec<String>,
    pub pick: bool,
}

pub fn parse_launch_args_from<I>(args: I) -> LaunchArgs
where
    I: IntoIterator<Item = String>,
{
    let mut out = LaunchArgs::default();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--decrypt" => out.decrypt = true,
            "--pick" | "--browse" => out.pick = true,
            "--key" => {
                if let Some(k) = iter.next() {
                    out.keys.push(k);
                }
            }
            "--help" | "-h" => {
                println!(
                    "chrome2rust-iced [PATH] [--pick] [--decrypt] [--key <PASSPHRASE_OR_HEX>]\n\
                     Launch the cross-platform Iced desktop forensic console for chrome2rust (Linux, macOS, Windows)."
                );
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other if !other.starts_with('-') && out.path.is_none() => {
                out.path = Some(PathBuf::from(other));
            }
            _ => {}
        }
    }
    out
}

const APP_ICON_RGBA: &[u8] = include_bytes!("../assets/icon_32x32.rgba");

fn main() -> iced::Result {
    let _ = init_logging("warn", None);
    let mut launch = parse_launch_args_from(std::env::args().skip(1));
    if launch.pick && launch.path.is_none() {
        launch.path = rfd::FileDialog::new()
            .set_title("Select Chrome User Data, Profile, or Cache Folder")
            .pick_folder();
    }
    let icon = iced::window::icon::from_rgba(APP_ICON_RGBA.to_vec(), 32, 32).ok();

    iced::application(move || App::new(launch.clone()), App::update, App::view)
        .title(App::title)
        .theme(App::theme)
        .subscription(App::subscription)
        .window(iced::window::Settings {
            size: iced::Size::new(1380.0, 840.0),
            min_size: Some(iced::Size::new(920.0, 560.0)),
            position: iced::window::Position::Centered,
            icon,
            ..Default::default()
        })
        .run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_launch_args_with_path_decrypt_keys_and_pick() {
        let parsed = parse_launch_args_from(
            ["/tmp/chrome_profile", "--decrypt", "--key", "peanuts", "--pick"]
                .into_iter()
                .map(str::to_string),
        );
        assert_eq!(parsed.path, Some(PathBuf::from("/tmp/chrome_profile")));
        assert!(parsed.decrypt);
        assert!(parsed.pick);
        assert_eq!(parsed.keys, vec!["peanuts"]);
    }
}
