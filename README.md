# NIKKE Launcher Check

A desktop tool that looks for traces of the November 2026 compromise of the NIKKE PC launcher. It runs on Windows, Linux and macOS, in a window or from a terminal.

The tool only reads files. It does not change, move or delete anything, and it makes no network connections. It does not edit the hosts file either: it only reports whether the malicious domains are blocked there.

Full write-up of the incident: https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5

## What happened

On 2026-09-27, two files on Level Infinite's CDN were modified to load `https://insightjs.com/l.js?f=aegis` and `https://insightjs.com/l.js?f=images`:

- `https://sg-gpts.playerinfinite.com/comm/assets/lib/aegis-fix.min.js`
- `https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/images.7fec4c32.js`

Both were still modified on 2026-11-03 at 16:56 GMT. The script also names a fallback domain, `insightjs.org`, which is not registered.

The launcher shows its pages in an embedded Chromium (CEF), so it runs `l.js`. From about November 2, 2026, `l.js` used the launcher's JavaScript bridge to download `https://analytics.insightjs.com/comm/assets/insight.bundle` from 89.127.233.127. That file is LuaJIT bytecode (205,135 bytes, SHA-256 `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec`) and is a remote-access agent. Its commands include `exec`, `download`, `screens`, `creds`, `keyscan`, `browserscan`, `chrome_scan`, `wallet_files` and `chrome_install`.

On Windows the agent can install persistence in Google Chrome (a real Chrome install, not the launcher's CEF): a DLL at `%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\<sha256>\platform_experience_helper.dll`, registered under `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32`.

## What it checks

In each NIKKE install (the folder that holds `Launcher/nikke_launcher.exe`):

- `Launcher/intl_service/debug.log`. A line with `k2f_chan` means the agent ran (critical). The report quotes the `k2f_chan registered`, `adopted <id>`, `agent started as <hostname>` and `lua downloaded to ...` lines. A line with `insightjs` is also critical.
- Every file under `Launcher/log/`, including the `tinyget` logs (one file per launch). `insight.bundle` or `insightjs` in a file means the launcher downloaded the agent (critical); the report names the file and gives the time from the log line. A file there that starts with LuaJIT bytecode is the downloaded agent itself (critical).

In each launcher data folder (`AppData/Roaming/nikke_launcher` or `nikke_launcher_hmt`), every file up to 64 MiB:

- `insightjs` in a file under `Code Cache` or `Cache` means the launcher loaded the malicious script (warning).
- `insightjs` in `Network Persistent State`, `TransportSecurity` or `Reporting and NEL` means the launcher connected to insightjs.com (warning).
- `insightjs` in any other file is a warning. `k2f_chan` in any file is critical.

In each user profile (the Windows user running the tool, and every user of a Wine prefix except `Public`):

- `AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper` exists: Chrome persistence (critical). The report lists what the folder holds.
- Files in `AppData/Local/Temp` (and `%TEMP%` on Windows) whose name starts with `k2f`, such as `k2f-bcreds-*` and `k2f_screen_*.jpg` (critical).
- A `.tmp` file in that Temp folder of exactly 22 bytes that holds 22 lowercase hex characters. The agent writes a marker like this one second before the download. On its own it is a weak sign (warning, at most 5 listed).
- On Windows, `reg query HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32 /ve`. If the key exists, the report shows its value (critical).

In each Wine prefix, `user.reg` (the HKCU hive) that contains the key `[Software\\Classes\\CLSID\\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` is critical. The same key in `system.reg` (HKLM) points to `C:\windows\system32\wpc.dll`, the normal Windows Parental Controls entry, and is not reported.

A running process named `nikke_launcher.exe` or `nikke_launcher`, or a Wine process whose command line contains `nikke_launcher.exe`, is critical: close it now.

The hosts file (`C:\Windows\System32\drivers\etc\hosts`, or `/etc/hosts` elsewhere) is checked for `insightjs.com`, `analytics.insightjs.com` and `insightjs.org` mapped to `0.0.0.0`, `127.0.0.1`, `::1` or `::`. This is protection, not a sign of infection, and it does not change the verdict. The report gives the lines to add. Editing the hosts file needs administrator rights.

## Verdicts

| Verdict | Meaning | `--cli` exit code |
|---|---|---|
| No traces found | An install or launcher data was found and checked, with info lines only. | 0 |
| Exposed | Warnings only: the launcher loaded the script or contacted insightjs.com, or a possible marker file exists. No sign that the agent ran. | 1 |
| Infected | At least one critical finding: the agent was downloaded or ran, persistence exists, or the launcher is running now. | 2 |
| NIKKE not found | No install and no launcher data in the places searched. | 3 |

Exit code 4 means invalid arguments: an unknown option, or a path that is not a folder.

For each verdict the window and the report list what to do next, from blocking the domains to changing passwords from a clean device.

## Running it

The CI workflow attaches builds for Linux (x86_64), Windows (x86_64) and macOS (Apple silicon) to each tagged release. You can also build it yourself (see Building).

Start `nikke-check` (`nikke-check.exe` on Windows) with no arguments to open the window. "Scan this computer" searches the places listed below. "Scan a folder..." scans one folder and everything under it, 12 levels deep, including any Wine prefix inside. "Copy report" puts the text report on the clipboard.

From a terminal:

```
nikke-check --cli                          # scan this computer
nikke-check --cli /mnt/Games/NIKKE ~/.wine # scan only these folders
nikke-check --help
```

The report goes to standard output and the exit code follows the table above.

The Windows build is a GUI program that attaches to the console it was started from. Command Prompt does not wait for GUI programs to exit, so use `start /wait nikke-check.exe --cli` if you need the exit code in `%ERRORLEVEL%`.

## Where it looks

Windows: every drive from `A:\` to `Z:\`, 5 folder levels deep (enough for `C:\Program Files\Level Infinite\NIKKE\Launcher\nikke_launcher.exe`), skipping `\Windows`. Also `%APPDATA%\nikke_launcher`, `%APPDATA%\nikke_launcher_hmt` and the `%USERPROFILE%` profile.

Linux: `$HOME` (7 levels), then `/mnt`, `/media`, `/run/media/$USER`, `/opt` and `/games` (6 levels each). It also opens these Wine prefixes directly:

- `~/.wine`
- Steam compatdata, `<library>/steamapps/compatdata/*/pfx`, for every library listed in `libraryfolders.vdf` under `~/.local/share/Steam`, `~/.steam/steam` and Flatpak Steam (`~/.var/app/com.valvesoftware.Steam/.local/share/Steam`)
- `~/Games/*` (Lutris and others) and `~/Games/umu/*`
- Heroic, `~/Games/Heroic/Prefixes/*` and `~/Games/Heroic/Prefixes/default/*`
- Bottles, `~/.local/share/bottles/bottles/*` and `~/.var/app/com.usebottles.bottles/data/bottles/bottles/*`
- Faugus, `~/Faugus/*`

macOS: NIKKE has no native Mac client, so on a Mac it runs only through Wine-based tools. The tool searches `$HOME` (6 levels), `/Applications` (4 levels) and each volume in `/Volumes` (5 levels), and opens the prefixes of Wine (`~/.wine`), CrossOver (`~/Library/Application Support/CrossOver/Bottles/*`), Whisky (`~/Library/Containers/com.isaacmarovitz.Whisky/Bottles/*`), Wineskin and Kegworks wrappers (`*.app/Contents/SharedSupport/prefix` in `/Applications` and `~/Applications`) and Heroic (`~/Games/Heroic/Prefixes/*`).

Any `drive_c` folder found along the way also counts as a Wine prefix. In each prefix the tool checks every user in `drive_c/users`, searches `drive_c` 5 levels deep for an install (skipping `drive_c/windows`), and checks whether the folder that holds the prefix is an install, since installs often keep their prefix inside.

Walks never follow symbolic links: Wine links `dosdevices/z:` to `/`, which would loop. They skip `node_modules`, `.git`, `.cache`, `.Trash*`, `$Recycle.Bin`, `System Volume Information`, `dosdevices`, `/proc`, `/sys`, `/dev` and `/run/user`. A scan stops after 3,000,000 entries and the report says so. Folders it may not read are counted and skipped. On the Linux machine used for testing, a full scan visited about 596,000 entries in 4.6 seconds.

## Limits

- The launcher rewrites `debug.log` at each start, so an infection from an earlier launch may no longer show there. The `tinyget` logs keep one file per launch.
- Finding nothing does not prove that the computer is clean.
- The commands the agent ran leave no logs, so the tool cannot tell what the attacker did.
- The 22-byte marker check can match files written by other programs.
- On a Mac the tool only finds NIKKE inside the Wine-based setups and folders listed above.
- The checks were tested against a real infected install under Proton on Linux. The Windows and macOS code has not been run against a real infection.

## Building

You need a Rust toolchain new enough for sysinfo 0.39 (Rust 1.95 or later).

```
cargo build --release
```

The binary is `target/release/nikke-check` (`nikke-check.exe` on Windows). On Linux the folder picker uses the XDG desktop portal, so the build does not need GTK.

For development, `cargo build --profile fast` builds without LTO, and `cargo test` runs the tests. The tests build small fake installs and prefixes in the system temp folder and delete them afterwards.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
