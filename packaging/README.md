# Packaging Manifests (`WinGet` & `Homebrew`)

This directory stores ready-to-submit package manager manifests matching published GitHub Releases for **`chrome2rust`**.

## 1. Windows Package Manager (`winget`)

Validate and submit the YAML manifests in `packaging/winget/manifests/a/adpaolucci/chrome2rust/<version>/`:

```powershell
# Local validation using winget CLI
winget validate --manifest .\packaging\winget\manifests\a\adpaolucci\chrome2rust\0.2.2

# Or submit an automated PR to microsoft/winget-pkgs using wingetcreate
wingetcreate submit .\packaging\winget\manifests\a\adpaolucci\chrome2rust\0.2.2
```

Installed portable command aliases: `chrome2rust`, `chrome2rust-win32`, `chrome2rust-iced`, `chrome2rust-mcp`.

## 2. Homebrew (`macOS` & `Linux`)

Copy `packaging/homebrew/chrome2rust.rb` into `Formula/chrome2rust.rb` of a tap repository (e.g., `adpaolucci/homebrew-tap`):

```bash
brew install adpaolucci/tap/chrome2rust
# Or test locally directly from file:
brew install --formula ./packaging/homebrew/chrome2rust.rb
brew test chrome2rust
```
