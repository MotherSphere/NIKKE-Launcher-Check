# Building and releases

## Requirements

You need a Rust toolchain new enough for sysinfo 0.39, which is Rust 1.95 or later. CI and the release builds use Rust 1.99.1, set as `RUST_VERSION` in `.github/workflows/build.yml`.

On Linux, the folder picker uses the XDG desktop portal, so the build does not need GTK. The Ubuntu CI job installs `libxkbcommon-dev` and `pkg-config` before it builds.

## Build

```
cargo build --release
```

The binary is `target/release/nikke-check` (`nikke-check.exe` on Windows). The release profile uses thin LTO, one codegen unit and strips the binary.

At run time on Linux, "Scan a folder..." needs a portal FileChooser backend (`xdg-desktop-portal-gtk`, `-gnome` or `-kde`) or `zenity`. Without one no dialog opens; `nikke-check --cli <folder>` runs the same scan.

For development, `cargo build --profile fast` builds without LTO, with 16 codegen units and incremental builds. Its binary is in `target/fast/`.

On Windows, `.cargo/config.toml` links the C runtime statically (`-C target-feature=+crt-static` for `x86_64-pc-windows-msvc`), so the binary runs without the Visual C++ runtime installed.

## Tests

```
cargo test
```

The tests build small fake installs and prefixes in the system temp folder and delete them afterwards. The three tests that create symbolic links run only on Unix.

## CI

`.github/workflows/build.yml` runs on every push to any branch, on pull requests, when started by hand, and when `release.yml` calls it with a release tag. It builds and tests on three runners:

| Runner | Artifact |
|---|---|
| `ubuntu-22.04` | `nikke-check-linux-x86_64` |
| `windows-latest` | `nikke-check-windows-x86_64` |
| `macos-latest` | `nikke-check-macos-arm64` |

The Linux job runs on Ubuntu 22.04 so that the binary needs glibc 2.35 or later and also runs on older distributions and SteamOS. Each job installs the pinned toolchain, then runs `cargo build --release --locked` and `cargo test --release --locked`. On Linux and macOS a smoke test follows: `nikke-check --help` must run, and `nikke-check --cli` on an empty folder must exit with code 3 (NIKKE not found). The Windows job skips the smoke test. Each job uploads its binary as a workflow artifact. The actions are pinned to commit SHAs.

## Releases

Releases go through Release Please and are not tagged by hand. Conventional commits on `main` update a release pull request with the next version and `CHANGELOG.md`. The changelog has sections for `feat` (Features), `fix` (Fixes), `perf` (Performance), `refactor` (Internals) and `docs` (Documentation); `chore`, `test` and `ci` commits are left out. The settings are in `release-please-config.json`, and `.release-please-manifest.json` holds the current version.

Release Please opens the pull request with `GITHUB_TOKEN`, so the repository setting "Allow GitHub Actions to create and approve pull requests" (Settings > Actions > General) must be on.

Merging the release pull request creates the tag, such as `v0.1.0`, and the GitHub release. `.github/workflows/release.yml` runs on every push to `main` and then does the rest in the same run:

1. The `release-please` job creates the tag and the release, and sets the release back to draft so that it never shows without downloads.
2. The `build` job calls `build.yml` with the tag.
3. The `publish` job names the binaries `nikke-check-linux-x86_64`, `nikke-check-macos-arm64` and `nikke-check-windows-x86_64.exe`, marks the Linux and macOS files as executable, and writes `SHA256SUMS.txt` with `sha256sum`. It uploads the four files to the release, then publishes the release and marks it as the latest.

The build runs inside `release.yml` because a release created with `GITHUB_TOKEN` fires no event another workflow could start from.
