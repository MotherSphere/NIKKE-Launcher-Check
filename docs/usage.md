# Using the tool

## Download

Each release on the [releases page](https://github.com/MotherSphere/NIKKE-Launcher-Check/releases) has three programs and a checksum file.

| File | System |
|---|---|
| `nikke-check-windows-x86_64.exe` | Windows, 64-bit. It does not need the Visual C++ runtime. |
| `nikke-check-linux-x86_64` | Linux and Steam Deck, 64-bit. It is built on Ubuntu 22.04 and needs glibc 2.35 or later. |
| `nikke-check-macos-arm64` | macOS on Apple silicon. |
| `SHA256SUMS.txt` | The SHA-256 of the three programs. |

The commands on this page call the program `nikke-check`. Use the name of the file you downloaded, or rename the file. To build the program yourself, see [Building and releases](building.md).

## Check the download

`SHA256SUMS.txt` lets you check that your file is the one the release build attached. Download it into the same folder as the program. Open a terminal and go to that folder, for example with `cd ~/Downloads` on Linux and macOS or `cd $HOME\Downloads` in PowerShell, then run the command for your system. If the check fails, do not run the program: download it again from the releases page.

Linux and Steam Deck:

```
sha256sum -c SHA256SUMS.txt --ignore-missing
```

The line for your file must end in `OK`. `--ignore-missing` skips the two programs you did not download.

macOS:

```
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
```

The line must end in `OK`. If your `shasum` does not know `--ignore-missing`, run `shasum -a 256 nikke-check-macos-arm64` and compare the hex string it prints with the line for `nikke-check-macos-arm64` in `SHA256SUMS.txt`.

Windows, in PowerShell:

```
Get-FileHash .\nikke-check-windows-x86_64.exe -Algorithm SHA256
```

Open `SHA256SUMS.txt` in Notepad and compare the `Hash` value with the line for `nikke-check-windows-x86_64.exe`. PowerShell prints the hash in capital letters and the file uses lowercase. Ignore the case. Every letter and digit must match.

## First start

### Windows

Double-click `nikke-check-windows-x86_64.exe`. The program is not signed, so SmartScreen can warn that it comes from an unknown publisher. Click "More info", then "Run anyway".

The window draws with DirectX 12 or Vulkan, and with a software renderer when neither works. It does not use OpenGL, because AMD's OpenGL driver (`atio6axx.dll`) crashed versions 0.2.1 and earlier at start. To pick the backend yourself, set `WGPU_BACKEND` before starting it, for example `$env:WGPU_BACKEND="vulkan"; .\nikke-check-windows-x86_64.exe` in PowerShell. If the window still does not open, `--cli` runs the same scan without it (see [Windows console](#windows-console)).

### Linux and Steam Deck

On a Steam Deck, switch to Desktop Mode and open Konsole. A browser download loses the executable bit, the permission that lets a file run. Open a terminal and run these commands. The first one goes to the Downloads folder; if you saved the file somewhere else, use that folder.

```
cd ~/Downloads
chmod +x nikke-check-linux-x86_64
./nikke-check-linux-x86_64
```

The window needs a desktop session. Without one, for example over SSH, use `--cli` (see [Command line](#command-line)).

### macOS

The program is not signed, so Gatekeeper blocks it. Open Terminal and run these commands. The first one goes to the Downloads folder; if you saved the file somewhere else, use that folder.

```
cd ~/Downloads
chmod +x nikke-check-macos-arm64
xattr -d com.apple.quarantine nikke-check-macos-arm64
./nikke-check-macos-arm64
```

If `xattr` answers `No such xattr`, the file was not quarantined and you can go on to the last command.

macOS keeps some folders private until you allow access. When the report says that some folders could not be read, give Terminal (or the app you started the tool from) Full Disk Access in System Settings > Privacy & Security, then scan again.

## The window

Start `nikke-check` with no arguments to open the window. The bar at the top shows the version and "Read-only. No network access."

### Start screen

The start screen describes the incident in a few lines and has two parts, "Full scan" and "Folder scan", each with its button.

- "Scan this computer" searches the places listed in [Where it looks](locations.md). A full scan can take a few minutes.
- "Scan a folder..." opens a folder dialog, then scans that folder and everything under it, including any Wine prefix inside. Use it when NIKKE is installed somewhere unusual, or on a network drive, which "Scan this computer" skips.

There are three other ways to start a folder scan:

- Drop a folder on the window. This works on Windows, on macOS and in an X11 session on Linux. It does not work in a Wayland session, because the window library (winit) has no file drop there, so the window does not show the drop hint. Use "Scan a folder..." instead. If you drop a file, the window says "Only folders can be scanned. Drop the folder that holds the file."
- Start `nikke-check <folder>`. The window opens and scans that folder at once.
- On Windows, drop a folder on `nikke-check-windows-x86_64.exe` in Explorer. This starts it the same way as `nikke-check <folder>`.

On Linux the folder dialog goes through the XDG desktop portal. It needs a portal FileChooser backend (`xdg-desktop-portal-gtk`, `-gnome` or `-kde`) or `zenity`. Without one no dialog opens; `nikke-check --cli <folder>` runs the same scan in a terminal. The Linux start screen shows this hint too.

### Scan screen

While a scan runs, the window shows:

- the elapsed time
- the steps, in the order they run: "Looking for NIKKE installs and Wine prefixes", "Checking running programs", "Checking N locations" with the number done so far, and "Checking the hosts file"
- counters for the items scanned, the folders, the locations found and the findings so far (critical and warning findings)
- the folder being read

"Stop scan" goes back to the start screen at once, shows "Scan stopped." and discards the partial result.

### Result screen

The result screen starts with the verdict and its summary, then counts the critical, warning and info findings, and shows the number of items scanned and the duration.

- "Copy report" puts the text report on the clipboard. "Scan again" runs the same scan again. "New scan" goes back to the start screen.
- For an Infected or Exposed verdict, the steps under "What to do" come before the findings. For the other verdicts they come after the findings.
- Findings are grouped by location. Each one has a severity (CRITICAL, WARNING or INFO), a title, an explanation, the path, the time when it is known, and up to 5 lines of evidence quoted from the file.
- "Protection" shows whether the hosts file blocks each malicious domain. "Copy these lines" copies the lines to add for the domains that are not blocked.
- "Limits of this check" ends the page, with the link to the full write-up ("Copy link") and the scan statistics.

If the scan stops with an internal error, the window says so and offers "Scan again". If the error comes back, run `nikke-check --cli` in a terminal to get the report as text.

## The report

"Copy report" and `--cli` give the same text report. Its parts, in order:

1. The tool name and version, `Scan of:` (what was scanned) and `Started:` (the start time in UTC).
2. `VERDICT:` and the summary of the verdict.
3. `Locations checked:`, with each location found tagged `[NIKKE install]`, `[Launcher data]`, `[Wine prefix]` or `[User profile]`.
4. `FINDINGS`, grouped by location. Each finding is tagged `[CRITICAL]`, `[WARNING]` or `[INFO]` and can have a `Path:` line, a `Time:` line and evidence lines that start with `|`.
5. `PROTECTION`: which domains the hosts file blocks, and the lines to add for the others.
6. `WHAT TO DO`: the steps for the verdict, the same as in [What to do](what-to-do.md).
7. `LIMITS OF THIS CHECK` and the link to the write-up.
8. `Scan stats:`: entries visited, folders, permission errors, network drives skipped and the time taken. When the entry limit was reached, this line says that some folders were not visited.

Save the report before you clean anything, because deleting `tbs_cache` also deletes the `k2f.agent.state` trace. The report holds paths on your computer, which often include your user name, and an Infected report can quote the computer name the agent logged. Read it before you post it in public.

## Command line

```
nikke-check                  Open the window
nikke-check PATH             Open the window and scan this folder
nikke-check --cli            Scan this computer and print a report
nikke-check --cli PATH...    Scan only these folders and print a report
nikke-check --help           Show this help
```

`-h` is the same as `--help`. Examples:

```
nikke-check --cli                          # scan this computer
nikke-check --cli /mnt/Games/NIKKE ~/.wine # scan only these folders
nikke-check /mnt/Games/NIKKE               # open the window and scan this folder
```

The report goes to standard output. On Linux and macOS, `nikke-check --cli > nikke-report.txt` saves it to a file.

Exit codes with `--cli`:

| Code | Meaning |
|---|---|
| 0 | No traces found |
| 1 | Exposed (warnings only) |
| 2 | Infected (critical traces) |
| 3 | No NIKKE install or launcher data found |
| 4 | Invalid arguments: an unknown option, or with `--cli` a path that is not a folder or a folder that cannot be read |

An unknown option such as `--foo` also exits with code 4 without `--cli`. `nikke-check PATH` does not check the path before the window opens. If PATH is not a folder, the window opens and says "Only folders can be scanned. Drop the folder that holds the file." If the window cannot open, the program prints `Could not open the window:` with the reason and exits with code 1.

### Windows console

The Windows build is a GUI program that attaches to the console it was started from. Command Prompt and PowerShell do not wait for GUI programs to exit, so the prompt can come back before the report is printed.

In Command Prompt, `start /wait` makes it wait, and the exit code is then in `%ERRORLEVEL%`:

```
start /wait nikke-check-windows-x86_64.exe --cli
echo %ERRORLEVEL%
```

In PowerShell, pipe the output so that PowerShell waits:

```
.\nikke-check-windows-x86_64.exe --cli | Out-Host; $LASTEXITCODE
```
