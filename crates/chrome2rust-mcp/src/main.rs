#![forbid(unsafe_code)]

use chrome2rust_mcp::{PolicyMode, SERVER_NAME, SERVER_VERSION, get_tools_manifest, run_stdio_server_with_policy};
use clap::Parser;
use std::process;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = SERVER_NAME,
    version = SERVER_VERSION,
    about = "Model Context Protocol (MCP) server for chrome2rust Chrome cache inspection and User Data forensics"
)]
struct Args {
    /// Print available tools in JSON schema format and exit
    #[arg(long)]
    tools: bool,

    /// Permit disk-writing tools (cache_extract, report, custody output_manifest, carve extract_dir) with confirm_destructive=true
    #[arg(long)]
    allow_mutating: bool,

    /// Log level filter (sent to stderr)
    #[arg(long, default_value = "warn")]
    log_level: String,
}

fn main() {
    let args = Args::parse();

    if args.tools {
        let manifest = get_tools_manifest();
        println!("{}", serde_json::to_string_pretty(&manifest).unwrap());
        process::exit(0);
    }

    let filter = EnvFilter::try_new(&args.log_level).unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();

    let policy = if args.allow_mutating {
        PolicyMode::AllowMutating
    } else {
        PolicyMode::ReadOnlyOnly
    };
    if let Err(e) = run_stdio_server_with_policy(policy) {
        eprintln!("[chrome2rust-mcp error] Server exited: {e}");
        process::exit(1);
    }
}
