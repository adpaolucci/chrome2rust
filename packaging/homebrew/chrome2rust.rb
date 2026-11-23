class Chrome2rust < Formula
  desc "Pure-Rust Iced GUI, CLI, and MCP server for Chrome cache inspection and User Data forensics"
  homepage "https://chrome2rust.guap.ca"
  version "0.2.2"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/adpaolucci/chrome2rust/releases/download/v0.2.2/chrome2rust-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/adpaolucci/chrome2rust/releases/download/v0.2.2/chrome2rust-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/adpaolucci/chrome2rust/releases/download/v0.2.2/chrome2rust-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "chrome2rust"
    bin.install "chrome2rust-iced"
    bin.install "chrome2rust-mcp"
    doc.install "README.md", "CHANGELOG.md"
    doc.install "SBOM-crates.txt" if File.exist?("SBOM-crates.txt")
    prefix.install "LICENSE", "NOTICE"
  end

  test do
    assert_match "chrome2rust", shell_output("#{bin}/chrome2rust --help")
    assert_match "chrome2rust_profiles", shell_output("#{bin}/chrome2rust mcp --tools")
    assert_match "chrome2rust-iced", shell_output("#{bin}/chrome2rust-iced --help")
  end
end
