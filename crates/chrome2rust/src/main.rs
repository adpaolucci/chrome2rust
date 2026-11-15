mod cli;
#[cfg(feature = "gui")]
mod gui;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, GuiArgs, run_subcommand};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Gui(args)) => launch_gui_or_error(args),
        None => launch_gui_or_error(GuiArgs::default()),
        Some(other) => run_subcommand(other),
    }
}

#[cfg(feature = "gui")]
fn launch_gui_or_error(args: GuiArgs) -> Result<()> {
    gui::run_gui(args)
}

#[cfg(not(feature = "gui"))]
fn launch_gui_or_error(_args: GuiArgs) -> Result<()> {
    anyhow::bail!(
        "chrome2rust was built without the `gui` feature.\n\
         Run a CLI subcommand (`chrome2rust --help`), or rebuild with `--features gui`."
    );
}
