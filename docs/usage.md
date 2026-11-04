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

Start `nikke-check` with no arguments to open the window. The bar at the top shows the version and "Read-only. No network access." The menu at the bottom left sets the language (see [Language](#language)).

### Language

The window and the report are available in 16 languages. Each start uses the language of the system, so in most cases there is nothing to set. The codes are the ones `--lang` takes, and the menu shows each language under its own name:

| Language | Name in the menu | Code |
|---|---|---|
| English | English | `en` |
| Japanese | 日本語 | `ja` |
| Korean | 한국어 | `ko` |
| Simplified Chinese | 简体中文 | `zh-Hans` |
| Traditional Chinese | 繁體中文 | `zh-Hant` |
| Thai | ไทย | `th` |
| Vietnamese | Tiếng Việt | `vi` |
| Indonesian | Bahasa Indonesia | `id` |
| French | Français | `fr` |
| German | Deutsch | `de` |
| Spanish | Español | `es` |
| Portuguese (Brazil) | Português (Brasil) | `pt-BR` |
| Russian | Русский | `ru` |
| Polish | Polski | `pl` |
| Turkish | Türkçe | `tr` |
| Italian | Italiano | `it` |

A text that has no translation yet shows in English.

#### How the system language is chosen

At start, the tool reads the system's list of preferred languages, top first, and takes the first one in the table above. If none of them is in the table, it uses English. The list comes from:

- Windows: the Windows display language, then the other languages in Settings > Time & language > Language & region, top first.
- macOS: Preferred languages in System Settings > General > Language & Region, top first.
- Linux and Steam Deck: the `LANGUAGE`, `LC_ALL`, `LC_MESSAGES` and `LANG` environment variables, in that order. `LANGUAGE` can hold several languages separated by colons, such as `fr:de`.

The tool looks at the language part and ignores the country, the encoding and letter case, so `fr-CA`, `fr_BE.UTF-8` and `FR` all give French, and `es-419` gives Spanish. A few cases need a rule:

- Chinese: a script in the name decides first, so `zh-Hans` gives Simplified Chinese and `zh-Hant` gives Traditional Chinese. Without a script, `zh-TW`, `zh-HK` and `zh-MO` give Traditional Chinese, and `zh`, `zh-CN`, `zh-SG` or any other Chinese gives Simplified Chinese.
- Portuguese: `pt-PT` and plain `pt` give Portuguese (Brazil), the only Portuguese translation.
- Indonesian: the old code `in` gives Indonesian, like `id`.
- A language that is not in the table, such as Norwegian (`nb-NO`), is skipped and the next one in the list is tried. On Linux, `LANGUAGE=nb_NO:de` gives German.
- The `C` and `POSIX` locales are skipped too. With `LANG=C` and nothing else set, the tool uses English.

#### Changing the language

The menu at the bottom left of every screen shows the current language. Pick another one and the window changes at once, including a result already on screen and the report that "Copy report" and "Save report..." give. It does not scan again, the open tab stays, and the "Done" marks stay.

The choice is not saved, since the tool writes no file except a report you save. The next start uses the system language again. To start in a given language every time, add `--lang` and a code to the command (see [Command line](#command-line)):

- Windows: right-click the `.exe` and pick "Show more options" > "Create shortcut" (on Windows 10, "Create shortcut"). Open the shortcut's Properties and, in "Target", add a space and `--lang fr` at the end, after the path and its closing quote if it has one: `C:\Users\you\Downloads\nikke-check-windows-x86_64.exe --lang fr`. Start the tool from that shortcut.
- Linux, Steam Deck and macOS: start it from the terminal with `--lang`, such as `./nikke-check-linux-x86_64 --lang fr`.

#### Fonts

The window draws Japanese, Korean, Chinese and Thai with the fonts installed on the system: it has none of its own. Windows and macOS include fonts for these scripts. On Linux, any installed font that has the characters is used. If none has them, they show as empty boxes; install Noto Sans CJK (`noto-fonts-cjk` on Arch, `fonts-noto-cjk` on Debian and Ubuntu, `google-noto-sans-cjk-fonts` on Fedora) and Noto Sans Thai (`noto-fonts` on Arch, `fonts-noto-core` on Debian and Ubuntu, `google-noto-sans-thai-fonts` on Fedora). The `--cli` report is plain UTF-8 text, so the terminal's own fonts show it.

### Start screen

The start screen describes the incident in a few lines and has two parts, "Computer scan" and "Folder scan".

- "Scan this computer" runs the quick scan of the places listed in [Where it looks](locations.md): the install paths the launcher records, the usual Wine prefix folders, and every folder up to 5 levels deep. It usually takes seconds.
- "Full scan" opens every folder on every local drive. Use it when the quick scan finds no install and you do not know where NIKKE is. It can take a long time on large drives. After a quick scan that finds no proof of the agent, "What to do" offers the same button.
- "Scan a folder..." opens a folder dialog, then scans that folder and everything under it, including any Wine prefix inside. Use it when NIKKE is installed somewhere unusual, or on a network drive, which both computer scans skip.

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

Above the result are "Copy report", "Save report...", the "Hide my info" switch, "Scan again" (the same scan once more) and "New scan" (back to the start screen). The result itself has three tabs. It opens on "What happened", or on "What to do" when the launcher is running and the scan found a sign of the agent, or when a program has the malware's DLL loaded. The "What to do" tab shows the number of steps, such as "What to do (7)".

If the result is Infected or Exposed and the "What to do" tab was never opened, closing the window first shows "You have not looked at the steps yet". "See what to do" opens the tab, and "Close anyway" closes the window.

#### What happened

The verdict and its summary come first. Right under them, a wide button in the color of the verdict, such as "See what to do (7 steps)", opens the next tab. Then come four answers, each with a colored reply and the reasons behind it:

- "Did the malware run on this computer?" Yes, No or Cannot tell. With Yes, the agent runs found in the logs follow, one line each: the time, whether the agent was downloaded, started for the first time or started again with its saved ID, the computer name it sent, and the log the line comes from. A "No" turns orange when part of the scan could not be done, such as a `debug.log` that could not be read, and after a quick scan, which does not open folders more than 5 levels deep.
- "Is anything still active?" The running launcher when the scan also found a sign of the agent, a program that has the DLL loaded, the registry key, or the DLL files.
- "Is there something to clean up?" The DLL folders, the registry key or its empty leftover, the older DLL files, the `k2f` files in Temp, and the launcher cache when it holds traces. With nothing found, it still says to delete `tbs_cache` before the launcher is opened again.
- "Are you protected for next time?" Each domain in the hosts file, and the two IP addresses, which only a firewall or router can block.

When the download logs keep the headers of the agent download, a "Payload build" card gives the ETag, the upload time it encodes, the size and whether it is one of the 7 known builds.

#### What to do

The steps that match what the scan found, numbered in the order to do them. Each has a "Done" box to tick; the marks are not saved. Depending on the result, the steps are:

- Scan the folder where NIKKE is installed: first when NIKKE was not found, and right after "Save the report" when launcher data was found but not the install, because `debug.log` in the install can change the result. After a quick scan this step also has the "Full scan" button.
- Run the full scan: after a quick scan that found the install but no proof of the agent (No traces found or Exposed), since an older copy more than 5 levels deep can still hold the agent's log lines.
- Close the launcher, when the scan also found a sign of the agent, or the programs that have the DLL loaded. A running launcher with no such sign is listed under Information in Details, with no step. On Windows, "Open Task Manager" starts Task Manager. On Linux and macOS, the step gives a `pkill` command.
- Save the report before you delete anything ("Save report..." and "Copy report").
- Remove the DLL, or delete the registry key when no DLL was found: "Copy key path", "Open Registry Editor", the restart when Windows needs one, and "Open folder" for the 64-hex folder. In a Wine prefix it gives a `wine regedit` command for the prefix, and a `protontricks` command for a Steam prefix.
- Clear the launcher cache, with "Open folder" at each `tbs_cache`, and at the launcher's login browser profile when it holds traces.
- Change your passwords from another device. The list names the browsers with saved logins, the wallet extensions and the secret files found, and "Copy this list" copies it.
- Block the domains: on Windows "Copy hosts path" and "Copy these lines" for Notepad, on Linux and macOS a command that adds the lines to `/etc/hosts`. Then a firewall command for the two IP addresses. On Windows it is a PowerShell command. On Linux the tool looks for `firewall-cmd`, `ufw` and `nft` in `PATH`, `/usr/sbin` and `/sbin`, without running them, and gives the command for the first one found in that order: a firewalld policy, `ufw` rules, or an nftables table that lasts until the next restart. With none of them, it says to block the addresses in the router. On macOS it says to use the router.
- Before you open the launcher again: Level Infinite confirmed a fix on November 4, 2026. Delete `tbs_cache` first, since it can still hold the modified files. To keep the evidence, scan first or copy the folder. Keep the domains and the IP addresses blocked: it is still unknown how the attacker got write access to the CDN.

"Open folder" opens the file manager with the file or folder selected: Explorer on Windows, Finder on macOS, and on Linux the file manager that answers the freedesktop `FileManager1` D-Bus call, or `xdg-open` on the parent folder. If the file was deleted since the scan, the nearest folder that still exists opens. These buttons only open windows and change nothing.

[What to do](what-to-do.md) explains each step.

#### Details

- Counts of critical, warning and info findings, the items scanned and the duration, then the "Checked:" line.
- "Your data the malware could reach": the browser profiles with saved logins, the wallet extensions and the secret files found in the checked home folders and profiles, each with "Open folder". The scan only checks that these files exist and never opens them.
- The findings, grouped: "Proof the malware ran", "Things to clean up", "Signs of exposure", "Information" (closed until you click "Show") and "What this scan could not check". Each finding has a severity (CRITICAL, WARNING or INFO), a title, an explanation, what it means, where it was found, the path and the time when they are known, and the buttons "Open folder", "Copy path" or "Copy key path". "Show technical details" shows up to 5 lines of evidence quoted from the file.
- "Protection": whether the hosts file blocks each domain, with "Copy these lines" for the ones that are not blocked.
- "Limits of this check", the write-up link ("Copy link" and "Open link"), the locations checked and the scan statistics.

If the scan stops with an internal error, the window says so and offers "Scan again". If the error comes back, run `nikke-check --cli` in a terminal to get the report as text (on Windows, see [Windows console](#windows-console)).

## The report

"Copy report", "Save report..." and `--cli` give the same text report, in the language of the window or of `--lang`. The headings below are the English ones. Its parts, in order:

1. The tool name and version, `Scan of:` (what was scanned) and `Started:` (the start time in UTC).
2. `VERDICT:` and the summary of the verdict.
3. `WHAT HAPPENED`: the four answers with their reasons, the agent runs and the payload builds.
4. `WHAT TO DO`: the numbered steps, with the paths, registry keys and commands the window shows, and an `Open:` line for each folder to open.
5. `DETAILS`: `Locations checked:` with each location tagged `[NIKKE install]`, `[Launcher data]`, `[Wine prefix]`, `[User profile]` or `[Launcher's login browser profile]`, the data the malware could reach, and the findings in the same groups as the window. Each finding is tagged `[CRITICAL]`, `[WARNING]` or `[INFO]` and can have `Path:`, `Open:`, `Time:` and `Registry key:` lines and evidence lines that start with `|`.
6. `PROTECTION`: which domains the hosts file blocks, the lines to add for the others, and the two IP addresses.
7. `LIMITS OF THIS CHECK` and the link to the write-up.
8. `Scan stats:`: entries visited, folders, permission errors, network drives skipped and the time taken. When the entry limit was reached, this line says that some folders were not visited.

Save the report before you clean anything, because deleting `tbs_cache` also deletes the `k2f.agent.state` trace.

### Save and share the report

"Save report..." opens a save dialog with the name `nikke-check-report-<date>.txt`. That file is the only one the tool writes, and only where you choose. "Copy report" puts the same text on the clipboard.

The report holds paths on your computer, which often include your user name, and an Infected report can quote the computer name and the agent ID the agent logged. Turn on "Hide my info" before you copy or save a report you plan to share, or add `--redact` on the command line. It replaces, in the report only:

- your home folder with `<home>`,
- your user names, and the user folder names of the profiles found, with `<user>` when they appear as a folder name in a path,
- this computer's name and the name each agent run sent with `<computer>`,
- the agent IDs from the logs with `<agent-id>`, and any other UUID except the CLSID with `<id>`.

The window keeps showing everything, so a screenshot of the window is not redacted. Read the report before you post it in public.

## Command line

```
nikke-check                  Open the window
nikke-check PATH             Open the window and scan this folder
nikke-check --cli            Quick scan of this computer, printed as a report
nikke-check --cli --full     Full scan: open every folder on every local drive
nikke-check --cli PATH...    Scan only these folders, in full, and print a report
nikke-check --cli --redact   Replace the computer name, user names, agent IDs
                             and home folder in the report (any --cli form)
nikke-check --help           Show this help

Language:
  --lang CODE    Add to any form above to set the language of the window and
                 the report. Without it, the language of the system is used.
                 CODE: en ja ko zh-Hans zh-Hant th vi id fr de es pt-BR ru pl tr it
```

`-h` is the same as `--help`. `--lang` can go anywhere on the command line and the code can use any letter case, so `--lang PT-br` works. The help itself is printed in that language. Examples:

```
nikke-check --cli                          # quick scan of this computer
nikke-check --cli --full                   # open every folder on every local drive
nikke-check --cli /mnt/Games/NIKKE ~/.wine # scan only these folders
nikke-check --cli --redact > report.txt    # scan this computer, save a report to share
nikke-check /mnt/Games/NIKKE               # open the window and scan this folder
nikke-check --lang ja                      # open the window in Japanese
nikke-check --cli --lang de > bericht.txt  # report in German
```

`--redact` and `--full` go after `--cli`, before or after the folders. A folder scan always opens every folder, so `--full` changes nothing there.

The report goes to standard output. On Linux and macOS, `nikke-check --cli > nikke-report.txt` saves it to a file.

Exit codes with `--cli`:

| Code | Meaning |
|---|---|
| 0 | No traces found |
| 1 | Exposed (warnings only) |
| 2 | Infected (critical traces) |
| 3 | No NIKKE install or launcher data found |
| 4 | Invalid arguments: an unknown option, an unknown or missing `--lang` code, or with `--cli` a path that is not a folder or a folder that cannot be read |

An unknown option such as `--foo` also exits with code 4 without `--cli`, and so does `--lang` with an unknown code, which prints the valid codes. `nikke-check PATH` does not check the path before the window opens. If PATH is not a folder, the window opens and says "Only folders can be scanned. Drop the folder that holds the file." If the window cannot open, the program prints `Could not open the window:` with the reason and exits with code 1. On Windows, where there is no console to print to, an error box shows the reason and the PowerShell command that gives the report without the window (see [Windows console](#windows-console)).

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

If the browser saved the file as `nikke-check-windows-x86_64 (1).exe`, because an older copy was already in the folder, put the name in quotes after `&`. The Windows error box and the window give the command in this form:

```
& '.\nikke-check-windows-x86_64 (1).exe' --cli | Out-Host
```
