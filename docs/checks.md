# What it checks

The tool checks four kinds of locations: NIKKE installs, launcher data folders, user profiles and Wine prefixes. [Where it looks](locations.md) explains how it finds them. Every scan, a folder scan included, also checks the running programs and the hosts file.

Each finding has one of three severities:

- `CRITICAL`: the agent was downloaded or ran, it left persistence, or the launcher is running now.
- `WARNING`: the launcher loaded the malicious script or contacted insightjs.com.
- `INFO`: context, such as an install that was found, a location that could not be checked, or a file that looks related but does not change the verdict.

A finding quotes at most 5 evidence lines, each cut to 240 characters. Folder and file names along the paths below are matched without regard to letter case, except the three network-state file names, which must match exactly.

## NIKKE install

An install is a folder that holds `Launcher/nikke_launcher.exe` or `Launcher/intl_service/debug.log`.

`Launcher/intl_service/debug.log` is read if it is 64 MiB or smaller:

- A line with `k2f_chan` means the agent ran (critical). The report quotes the `k2f_chan registered`, `adopted <id>`, `agent started as <hostname>` and `lua downloaded to ...` lines.
- A line with `insightjs` is also critical.
- The install is listed as info, with the time `debug.log` was last written, or a note that the file is missing or could not be read. The launcher appends to `debug.log` at each launch, so the file holds every launch since it was created.

Every file under `Launcher/log/`, up to 8 levels down and 64 MiB, is read too. This includes the `tinyget` logs, one file per launch.

- A file that starts with LuaJIT bytecode (the bytes `1B 4C 4A`) is the downloaded agent itself (critical). The launcher saves the agent under a `tinyget` log name. The report gives the file size; the known agent is 205,135 bytes.
- `insight.bundle` in a file means the launcher downloaded the agent (critical). The report names the file and gives the time from the log line.
- `insightjs` in a file is critical as well.

## Launcher data

A launcher data folder is `AppData/Roaming/nikke_launcher` or `AppData/Roaming/nikke_launcher_hmt`. Every file in it up to 12 levels down and 64 MiB is read.

- `k2f_chan` or `k2f.agent` in any file is critical. `k2f_chan` is the agent's bridge channel name. `k2f.agent.state` is the ID the agent saves in the launcher's Local Storage (`tbs_cache/Local Storage/leveldb`). Deleting the NIKKE folder removes `debug.log` but not `k2f.agent.state`. The report cuts the quoted line before `agent_pass`, so it never shows the saved password that follows the key.
- `insightjs` in a file under a folder named `Code Cache` or `Cache` means the launcher loaded the malicious script (warning). The script ran; this alone does not show that the agent was downloaded.
- `insightjs` in `Network Persistent State`, `TransportSecurity` or `Reporting and NEL` means the launcher connected to insightjs.com (warning).
- `insightjs` in any other file is a warning.
- With no match, the folder is listed as info with the number of files checked.

A launcher data folder that is a symbolic link or a junction is read through its target, unless the target is missing, a drive root or a folder above the link. Such a link is listed as info and not read.

When launcher data is found but no install folder, an info finding says that `debug.log` and the download logs were not checked, and suggests scanning the install folder with "Scan a folder..." or `nikke-check --cli <folder>`.

## User profiles

The user profiles are the Windows user running the tool, every user of a Wine prefix except `Public`, and any other folder that holds `AppData/Local` or `AppData/Roaming`, such as `Users/<name>` on a Windows partition mounted under Linux. `Public`, `Default`, `Default User` and `All Users` are left out.

In each profile:

- `AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper` is Chrome persistence (critical) when it holds `platform_experience_helper.dll` at any depth, or a subfolder named with 64 hex characters (a SHA-256). A hash-named subfolder without the DLL is still critical, and the finding says the DLL may already have been removed. Per-user Chrome installs keep Chrome's own Platform Experience Helper (`platform_experience_helper.exe`, `LoadFeatures`) in the same folder, so a folder with neither sign is listed as info. The report lists what the folder holds.
- Files in `AppData/Local/Temp` whose name starts with `k2f` are critical. The agent names its temporary files `k2f-bcreds-*` (collected browser credentials) and `k2f_screen_*.jpg` (screenshots).
- A `.tmp` file in that Temp folder of exactly 22 bytes that holds 22 lowercase hex characters is info, with at most 5 listed. On the infected computer, a file like this (`onominan.tmp`) was written one second before the agent download. Delta Force prefixes hold an `onominan.tmp` of the same kind dated 2026-09-20, a week before the CDN files were changed, so other Tencent software writes it too and it does not change the verdict.

For the Windows user running the tool, two more checks run:

- The same Temp checks in `%TEMP%`.
- The default value of `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32`, read through the registry API in the 64-bit view and in the 32-bit view (`WOW6432Node`). If the key exists, the report shows its value (critical). The HKLM copy that points to `wpc.dll` is part of Windows and is not read.

A Windows folder scan runs these two checks as well when the scanned folder is your own profile or a folder above it.

## Wine prefix registry

In each Wine prefix, a `user.reg` (the HKCU hive) that contains the key `[Software\\Classes\\CLSID\\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` is critical. The report quotes the key and its default value. The same key in `system.reg` (HKLM) points to `C:\windows\system32\wpc.dll`, the normal Windows Parental Controls entry, and is not reported.

## Running launcher

A running launcher is critical: close it now. The tool looks for a process named `nikke_launcher.exe` (Linux shows `nikke_launcher.`, because it cuts process names to 15 bytes), a process whose first command-line argument is a path to `nikke_launcher.exe` (Wine sets it to the Windows path), or a `wine`, `wine64`, `wine-preloader` or `wine64-preloader` process started on `nikke_launcher.exe`. Programs that only name the file, such as `sha256sum` or an editor, do not count. The report lists the process ID and command line of each match.

## Hosts file

The hosts file (`C:\Windows\System32\drivers\etc\hosts`, or `/etc/hosts` elsewhere) is checked for `insightjs.com`, `analytics.insightjs.com` and `insightjs.org` mapped to `0.0.0.0`, `127.0.0.1`, `::1` or `::`. Text after `#` is ignored. This is protection, not a sign of infection, and it does not change the verdict.

The report shows each domain as blocked, not blocked or unknown, and gives the lines to add for the domains that are not blocked. If the file does not exist, the report says it blocks nothing. If it exists but cannot be read, each domain is shown as unknown and all three lines are given. Editing the hosts file needs administrator rights, and the tool never edits it. The IP 89.127.233.127 cannot be blocked in the hosts file; the report says to block it in a firewall or router. [What to do](what-to-do.md#block-the-domains-and-the-ip) shows how to add the lines.

## Times in the report

Times taken from log lines are the local time of the computer that ran the launcher. `debug.log` lines carry no year, so the report shows them as month, day and time with "year not logged". File times and the `Started:` time are in UTC. On a computer in UTC+1, the 22-byte hex `.tmp` file was written one second before the download, but its UTC file time reads one hour earlier than the local time in the download's log line.

## Verdicts

| Verdict | Meaning | `--cli` exit code |
|---|---|---|
| No traces found | An install or launcher data was found, with info findings only. When only launcher data was found, the report says that `debug.log` and the download logs were not checked. | 0 |
| Exposed | Warnings only: the launcher loaded the script or contacted insightjs.com. No sign that the agent ran. | 1 |
| Infected | At least one critical finding: the agent was downloaded or ran, persistence exists, or the launcher is running now. | 2 |
| NIKKE not found | No install and no launcher data in the places searched, and no critical or warning finding. | 3 |

The most severe finding sets the verdict, so a critical finding gives Infected even when no NIKKE install was found, for example Chrome persistence in a profile or `k2f` files in Temp. Info findings never change the verdict. Exit code 4 means invalid arguments: an unknown option, or with `--cli` a path that is not a folder or a folder that cannot be read.

The window and the report list the steps for each verdict. An Exposed result also lists the account steps of an infected computer, for the case where the launcher was open on or after October 24, 2026. [What to do](what-to-do.md) has all the steps.

## Limits

- `debug.log` and the `tinyget` logs are in the NIKKE folder, so deleting or reinstalling NIKKE removes them. On the infected test install, `debug.log` held all 9 launches from 2026-10-29 to 2026-11-03. The `k2f.agent.state` check in the launcher data does not depend on these logs.
- Finding nothing does not prove that the computer is clean.
- The commands the agent ran leave no logs, so the tool cannot tell what the attacker did.
- On a Mac the tool only finds NIKKE inside the Wine-based setups and folders listed in [Where it looks](locations.md#macos).
- The checks were tested against a real infected install under Proton on Linux. The Windows and macOS code has not been run against a real infection.
