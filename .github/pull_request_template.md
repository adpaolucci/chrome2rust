## Summary
<!-- Briefly describe what this PR changes and why. -->

## Verification Checklist
- [ ] `cargo check --workspace --all-targets` passes cleanly
- [ ] `cargo fmt --all -- --check` passes cleanly
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes with zero warnings
- [ ] `cargo test --workspace` passes cleanly
- [ ] Forensic invariants preserved: read-only snapshots used for live SQLite/LevelDB inspection and no mutation outside explicit `cache delete`
