# NIKKE Launcher Check

A desktop tool that looks for traces of the November 2026 compromise of the NIKKE PC launcher. It runs on Windows, Linux and macOS, in a window or from a terminal.

The tool only reads files. It does not change, move or delete anything, and it makes no network connections. It does not edit the hosts file either: it only reports whether the malicious domains are blocked there.

Full write-up of the incident: https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5

## What happened

On 2026-09-27, three files on Level Infinite's CDN were modified to load `https://insightjs.com/l.js?f=aegis`, `?f=images` and `?f=feedlist`:

- `https://sg-gpts.playerinfinite.com/comm/assets/lib/aegis-fix.min.js`
- `https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/images.7fec4c32.js`
- `https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/FeedList.feb647c9.js`

Level Infinite replaced `aegis-fix.min.js` on 2026-11-03 at 17:04 GMT and `images.7fec4c32.js` at 17:21 GMT. `FeedList.feb647c9.js` was cleaned at the origin on 2026-10-28, but two CDN servers (43.175.144.148 and 43.175.145.181) still delivered the modified copy on 2026-11-03 at 18:59 GMT, so the launcher can still load the script depending on the server it reaches. The script also names a fallback domain, `insightjs.org`. A third party registered it on 2026-11-03 at 17:55 GMT, and it now shows a warning page in four languages. 89.127.233.127, the server that sent the agent, did not answer at 18:31 GMT (the connection timed out). It is not known how the attacker got write access to the CDN, or whether they still have it.

The launcher shows its pages in an embedded Chromium (CEF), so it runs `l.js`. From November 1, 2026 at the latest, and only on some launches, `l.js` used the launcher's JavaScript bridge to download `https://analytics.insightjs.com/comm/assets/insight.bundle` from 89.127.233.127. That file is LuaJIT bytecode (205,135 bytes, SHA-256 `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec`) and is a remote-access agent. Its commands include `exec`, `download`, `screens`, `creds`, `keyscan`, `browserscan`, `chrome_scan`, `wallet_files` and `chrome_install`.

On Windows the agent can install persistence in Google Chrome (a real Chrome install, not the launcher's CEF): a DLL at `%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\<sha256>\platform_experience_helper.dll`, registered under `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32`.

## What it checks

In each NIKKE install (the folder that holds `Launcher/nikke_launcher.exe`):

- `Launcher/intl_service/debug.log`. A line with `k2f_chan` means the agent ran (critical). The report quotes the `k2f_chan registered`, `adopted <id>`, `agent started as <hostname>` and `lua downloaded to ...` lines. A line with `insightjs` is also critical.
- Every file under `Launcher/log/`, including the `tinyget` logs (one file per launch). `insight.bundle` or `insightjs` in a file means the launcher downloaded the agent (critical); the report names the file and gives the time from the log line. A file there that starts with LuaJIT bytecode is the downloaded agent itself (critical).

Times taken from log lines are the local time of the computer that ran the launcher, and `debug.log` lines carry no year. File times in the report are in UTC, so on a computer in UTC+1 the marker file below shows an hour earlier than the download it came one second before.

In each launcher data folder (`AppData/Roaming/nikke_launcher` or `nikke_launcher_hmt`), every file up to 64 MiB:

- `insightjs` in a file under `Code Cache` or `Cache` means the launcher loaded the malicious script (warning).
- `insightjs` in `Network Persistent State`, `TransportSecurity` or `Reporting and NEL` means the launcher connected to insightjs.com (warning).
- `insightjs` in any other file is a warning.
- `k2f_chan` or `k2f.agent` in any file is critical. `k2f.agent.state` is the ID the agent saves in the launcher's Local Storage (`tbs_cache/Local Storage/leveldb`), and it stays there after `debug.log` is rewritten. The report quotes only the key name, never the saved password that follows it.

A launcher data folder that is a symbolic link or a junction is read through its target, unless the target is a drive root or a folder above the link. When launcher data is found but no install folder, the report says that `debug.log` and the download logs were not checked.

In each user profile: the Windows user running the tool, every user of a Wine prefix except `Public`, and any other folder that holds `AppData/Local` or `AppData/Roaming`, such as `Users/<name>` on a Windows partition mounted under Linux (`Public`, `Default`, `Default User` and `All Users` are left out):

- `AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper` that holds `platform_experience_helper.dll` at any depth, or a subfolder named with 64 hex characters (a SHA-256): Chrome persistence (critical). Per-user Chrome installs keep Chrome's own Platform Experience Helper (`platform_experience_helper.exe`, `LoadFeatures`) in the same folder, so a folder with neither sign is listed as info. The report lists what the folder holds.
- Files in `AppData/Local/Temp` (and `%TEMP%` on Windows) whose name starts with `k2f`, such as `k2f-bcreds-*` and `k2f_screen_*.jpg` (critical).
- A `.tmp` file in that Temp folder of exactly 22 bytes that holds 22 lowercase hex characters (info, at most 5 listed). On the infected computer, a file like this (`onominan.tmp`) was written one second before the agent download. Delta Force prefixes hold an `onominan.tmp` of the same kind dated 2026-09-20, a week before the CDN files were changed, so other Tencent software writes it too and it does not change the verdict.
- On Windows, the default value of `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32`, read through the registry API in the 64-bit view and in the 32-bit view (`WOW6432Node`). If the key exists, the report shows its value (critical).

In each Wine prefix, `user.reg` (the HKCU hive) that contains the key `[Software\\Classes\\CLSID\\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` is critical. The same key in `system.reg` (HKLM) points to `C:\windows\system32\wpc.dll`, the normal Windows Parental Controls entry, and is not reported.

A running launcher is critical: close it now. That is a process named `nikke_launcher.exe` (Linux shows `nikke_launcher.`), a process whose first command-line argument is a path to `nikke_launcher.exe` (Wine sets it to the Windows path), or a `wine`, `wine64`, `wine-preloader` or `wine64-preloader` process started on `nikke_launcher.exe`. Programs that only name the file, such as `sha256sum` or an editor, do not count.

The hosts file (`C:\Windows\System32\drivers\etc\hosts`, or `/etc/hosts` elsewhere) is checked for `insightjs.com`, `analytics.insightjs.com` and `insightjs.org` mapped to `0.0.0.0`, `127.0.0.1`, `::1` or `::`. This is protection, not a sign of infection, and it does not change the verdict. The report gives the lines to add for the domains that are not blocked. If the file exists but cannot be read, each domain is shown as unknown and all three lines are given. Editing the hosts file needs administrator rights.

## Verdicts

| Verdict | Meaning | `--cli` exit code |
|---|---|---|
| No traces found | An install or launcher data was found, with info lines only. When only launcher data was found, the report says that `debug.log` and the download logs were not checked. | 0 |
| Exposed | Warnings only: the launcher loaded the script or contacted insightjs.com. No sign that the agent ran. | 1 |
| Infected | At least one critical finding: the agent was downloaded or ran, persistence exists, or the launcher is running now. | 2 |
| NIKKE not found | No install and no launcher data in the places searched. | 3 |

Exit code 4 means invalid arguments: an unknown option, a path that is not a folder, or a folder that cannot be read.

For each verdict the window and the report list what to do next, from blocking the domains to changing passwords from a clean device. An Exposed result also lists the account steps of an infected computer, for the case where the launcher was open on or after November 1, 2026.

## Running it

Each [release](https://github.com/MotherSphere/NIKKE-Launcher-Check/releases) has three binaries, `nikke-check-linux-x86_64`, `nikke-check-windows-x86_64.exe` and `nikke-check-macos-arm64` (Apple silicon), and a `SHA256SUMS.txt` to check them with `sha256sum -c SHA256SUMS.txt --ignore-missing`. The Linux binary is built on Ubuntu 22.04 and needs glibc 2.35 or later. The Windows binary does not need the Visual C++ runtime. The commands below call the program `nikke-check`; use the name of the file you downloaded, or rename it. You can also build it yourself (see Building).

- Linux: a browser download loses the executable bit. Run `chmod +x nikke-check-linux-x86_64`, then `./nikke-check-linux-x86_64`.
- macOS: the binary is not signed, so Gatekeeper blocks it. Run `chmod +x nikke-check-macos-arm64` and `xattr -d com.apple.quarantine nikke-check-macos-arm64`, then start it from Terminal with `./nikke-check-macos-arm64`.
- Windows: SmartScreen can warn about an unknown publisher. Click "More info", then "Run anyway".

Start `nikke-check` (`nikke-check.exe` on Windows) with no arguments to open the window. "Scan this computer" searches the places listed below. "Scan a folder..." scans one folder and everything under it, 12 levels deep, including any Wine prefix inside. You can also drop a folder on the window (Windows, macOS and X11; winit has no file drop on native Wayland), or start `nikke-check <folder>` to open the window and scan that folder at once. On Windows, dropping a folder on `nikke-check-windows-x86_64.exe` in Explorer does the same.

During a scan the window shows the elapsed time, the current step, the number of items and locations found so far, and the folder being read. "Stop scan" goes back to the start screen and discards the partial result. The result screen gives the verdict, the number of critical, warning and info findings, and for an Infected or Exposed verdict the steps to follow before the findings. "Copy report" puts the text report on the clipboard.

From a terminal:

```
nikke-check --cli                          # scan this computer
nikke-check --cli /mnt/Games/NIKKE ~/.wine # scan only these folders
nikke-check /mnt/Games/NIKKE               # open the window and scan this folder
nikke-check --help
```

The report goes to standard output and the exit code follows the table above.

The Windows build is a GUI program that attaches to the console it was started from. Command Prompt and PowerShell do not wait for GUI programs to exit, so the prompt can come back before the report is printed. In Command Prompt, use `start /wait nikke-check.exe --cli` to get the exit code in `%ERRORLEVEL%`. In PowerShell, pipe the output so that it waits: `.\nikke-check-windows-x86_64.exe --cli | Out-Host; $LASTEXITCODE`.

## Where it looks

Windows: every fixed and removable drive from `A:\` to `Z:\`, 5 folder levels deep (enough for `C:\Program Files\Level Infinite\NIKKE\Launcher\nikke_launcher.exe`), skipping `\Windows`. Mapped network drives and CD drives are not walked, and the report lists the network drives it skipped. Also `%APPDATA%\nikke_launcher`, `%APPDATA%\nikke_launcher_hmt` and the `%USERPROFILE%` profile. The tool also reads the install path the launcher records, which finds installs deeper than 5 levels: `url_protocol.reg` in the launcher data folder, `HKCU\Software\Classes\nikkelauncher\DefaultIcon`, and `GameInstallPath` under `Software\Microsoft\Windows\CurrentVersion\Uninstall\nikke_launcher` in HKCU and HKLM.

Linux: `$HOME` (7 levels), then `/mnt`, `/media`, `/run/media/$USER`, `/opt` and `/games` (6 levels each). Where `/media` is a link to `/run/media` (Fedora Silverblue, Bazzite), only `/run/media/$USER` is walked. Under `sudo` or `pkexec`, the home folder and user name come from `/etc/passwd` for the user who ran the command (`SUDO_USER` or `PKEXEC_UID`), not from root. It also opens these Wine prefixes directly:

- `~/.wine`
- Steam compatdata, `<library>/steamapps/compatdata/*/pfx`, for every library listed in `libraryfolders.vdf` under `~/.local/share/Steam`, `~/.steam/steam`, Flatpak Steam (`~/.var/app/com.valvesoftware.Steam/.local/share/Steam`) and Snap Steam (`~/snap/steam/common/.local/share/Steam`)
- `~/Games/*` (Lutris and others) and `~/Games/umu/*`
- Heroic, `~/Games/Heroic/Prefixes/*` and `~/Games/Heroic/Prefixes/default/*`
- Bottles, `~/.local/share/bottles/bottles/*` and `~/.var/app/com.usebottles.bottles/data/bottles/bottles/*`
- Faugus, `~/Faugus/*`

On Linux, "Scan this computer" skips the network and remote mounts listed in `/proc/self/mountinfo`: NFS, CIFS/SMB, 9p, davfs, sshfs, rclone and the other FUSE types, except local ones such as `fuseblk` (ntfs-3g), mergerfs, bindfs and gocryptfs. It also skips automount points that are not mounted yet, unless `/etc/fstab` gives them a local filesystem type. A network home folder is still scanned. Reading a large share is slow, and a disconnected one can block the scan with no way to cancel it. The report lists the mounts it skipped; scan one with "Scan a folder..." if NIKKE is on it.

macOS: NIKKE has no native Mac client, so on a Mac it runs only through Wine-based tools. The tool searches `$HOME` (6 levels), `/Applications` (4 levels) and each local volume in `/Volumes` (5 levels; network volumes are skipped and listed in the report). It opens the prefixes of Wine (`~/.wine`), CrossOver (`~/Library/Application Support/CrossOver/Bottles/*`), Whisky (`~/Library/Containers/com.isaacmarovitz.Whisky/Bottles/*`), Wineskin, Kegworks and Sikarugir wrappers (`*.app/Contents/SharedSupport/prefix` in `/Applications` and `~/Applications`, and one folder down, such as `~/Applications/Wineskin/NIKKE.app`, where their Winery saves new wrappers) and Heroic (`~/Games/Heroic/Prefixes/*`).

Any `drive_c` folder found along the way also counts as a Wine prefix. In each prefix the tool checks every user in `drive_c/users`, searches `drive_c` for an install (5 levels deep in a computer scan, 12 in a folder scan, skipping `drive_c/windows`), and checks whether the folder that holds the prefix is an install, since installs often keep their prefix inside. It also reads the install path the launcher writes into `user.reg` (App Paths, Uninstall and the `nikkelauncher` URL protocol) and into `url_protocol.reg` in the launcher data, and follows its drive letter through the prefix's `dosdevices` link. A recorded path counts only if it still holds `Launcher/nikke_launcher.exe` or `Launcher/intl_service/debug.log`, since an install can be moved after it was recorded.

Walks never follow symbolic links: Wine links `dosdevices/z:` to `/`, which would loop. They skip `node_modules`, `.git`, `.cache`, `.Trash*`, `$Recycle.Bin`, `System Volume Information`, `dosdevices`, `/proc`, `/sys`, `/dev` and `/run/user`. A scan stops after 3,000,000 entries and the report says so. Folders it may not read are counted and skipped. When a search root, a Steam or bottle folder, or a prefix folder cannot be read, the report names it; on macOS this usually means Terminal needs Full Disk Access. On the Linux machine used for testing, a full scan visited about 597,000 entries in 2.0 seconds with a warm file cache.

## Limits

- `debug.log` and the `tinyget` logs are in the NIKKE folder, so deleting or reinstalling NIKKE removes them. On the infected test install, `debug.log` held all 9 launches from 2026-10-29 to 2026-11-03. The `k2f.agent.state` check in the launcher data does not depend on these logs.
- Finding nothing does not prove that the computer is clean.
- The commands the agent ran leave no logs, so the tool cannot tell what the attacker did.
- On a Mac the tool only finds NIKKE inside the Wine-based setups and folders listed above.
- The checks were tested against a real infected install under Proton on Linux. The Windows and macOS code has not been run against a real infection.

## Building

You need a Rust toolchain new enough for sysinfo 0.39 (Rust 1.95 or later).

```
cargo build --release
```

The binary is `target/release/nikke-check` (`nikke-check.exe` on Windows). On Linux the folder picker uses the XDG desktop portal, so the build does not need GTK. At run time, "Scan a folder..." needs a portal FileChooser backend (`xdg-desktop-portal-gtk`, `-gnome` or `-kde`) or `zenity`. Without one no dialog opens; `nikke-check --cli <folder>` runs the same scan.

For development, `cargo build --profile fast` builds without LTO, and `cargo test` runs the tests. The tests build small fake installs and prefixes in the system temp folder and delete them afterwards.

Releases go through Release Please. Conventional commits on `main` update a release pull request with the next version and `CHANGELOG.md`. Merging it creates the tag and the GitHub release, and `.github/workflows/release.yml` then builds the three binaries from that tag, attaches them with `SHA256SUMS.txt` and publishes the release.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
