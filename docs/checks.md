# What it checks

The tool checks four kinds of locations: NIKKE installs, launcher data folders, user profiles and Wine prefixes. [Where it looks](locations.md) explains how it finds them. Every scan, a folder scan included, also checks the running programs and the hosts file, and on Windows the DLLs that running programs have loaded.

Each finding has one of three severities:

- `CRITICAL`: the agent was downloaded or ran, the launcher contacted analytics.insightjs.com, the agent left persistence, or the launcher is running now.
- `WARNING`: the launcher loaded the malicious script or contacted insightjs.com.
- `INFO`: context, such as an install that was found, a location that could not be checked, or a file that looks related but does not change the verdict.

A finding quotes at most 5 evidence lines, each cut to 240 characters. Folder and file names along the paths below are matched without regard to letter case, except the three network-state file names, which must match exactly.

## NIKKE install

An install is a folder that holds `Launcher/nikke_launcher.exe` or `Launcher/intl_service/debug.log`.

`Launcher/intl_service/debug.log` is read line by line, whatever its size. A line longer than 64 KiB is cut.

- A line with `k2f_chan` means the agent ran (critical). The report quotes the `k2f_chan registered`, `adopted <id>`, `resuming <id>`, `agent started as <hostname>` and `lua downloaded to ...` lines.
- A line with `analytics.insightjs.com` or `insight.bundle` is critical: the launcher asked the server that sends the agent.
- A line that names `insightjs` without them is a warning. Only the loader ran. One case is the launcher falling back to `insightjs.org`, whose current script fails with a `SyntaxError` at line 61.
- The install is listed as info, with the time `debug.log` was last written, or a note that the file is missing. The launcher appends to `debug.log` at each launch, so the file holds every launch since it was created.
- A `debug.log` that exists but cannot be read is an info finding under "What this scan could not check". The first answer then shows "No" in orange, because the scan could not tell whether the agent ran.

Every file under `Launcher/log/`, up to 8 levels down and 64 MiB, is read too. This includes the `tinyget` logs, one file per launch.

- A file that starts with LuaJIT bytecode (the bytes `1B 4C 4A`) is the downloaded agent itself (critical). The launcher saves the agent under a `tinyget` log name. The report gives the file size. The known builds are 205,135 bytes, and an Oct 23 build saved as `k2f.lua` was 165,108 bytes.
- `insight.bundle` in a file with a finished download means the launcher downloaded the agent (critical). A finished download is an `OnDownloadResult` line for `insight.bundle` with `result=0` and a `total=` above 0, or a `curl perform success` line for it. The report names the file and gives the time from the log line.
- `insight.bundle` with no finished download is a warning: the loader asked for the agent, but the request failed (for example `curl_error=7`, `result=2`, `total=0` once the server stopped answering), so it does not show that the agent arrived.
- In a file without `insight.bundle`, `analytics.insightjs.com` is critical, and `insightjs` alone is a warning, as in `debug.log`.

### Agent runs and payload builds

These lines do not change the verdict. They make up the agent runs and the payload build of the first answer.

- Runs come from the `debug.log` lines `lua downloaded to log\tinyget\<name>` (the download, saved as `tinyget.<time>.log`, or `k2f.lua` on early runs), `adopted <id>` (the first start, when the agent creates its ID), `resuming <id>` (a later start) and `agent started as <host>` (the computer name the agent sends). A `tinyget` log that records an `AddTask` download of `insight.bundle` followed by a finished `OnDownloadResult` for the same task adds a download that `debug.log` does not have, for example after `debug.log` was deleted. A failed attempt adds no run.
- `tinyget.mem.log` keeps the response headers of the `insight.bundle` download. The launcher rewrites this fixed-size file from the start at each launch, so its end can hold an older session. The ETag that nginx sends is `"<mtime in hex>-<size in hex>"`, so it gives the upload time and the size of the build. The 7 known builds are 205,135 bytes (`-3214f`): `6ae60b83` (Oct 31 15:38:43 GMT), `6ae69086` (Nov 1 01:06:14), `6ae78037` (Nov 1 18:08:55), `6ae8ccff` (Nov 2 17:48:47), `6ae90538` (Nov 2 21:48:40), `6ae9d408` (Nov 3 12:31:04) and `6ae9f628` (Nov 3 14:56:40). Another ETag is reported as not one of the known builds.

## Launcher data

A launcher data folder is `AppData/Roaming/nikke_launcher` or `AppData/Roaming/nikke_launcher_hmt`. Every file in it up to 12 levels down and 64 MiB is read.

- `k2f_chan` or `k2f.agent` in any file is critical. `k2f_chan` is the agent's bridge channel name. `k2f.agent.state` is the ID the agent saves in the launcher's Local Storage (`tbs_cache/Local Storage/leveldb`). Deleting the NIKKE folder removes `debug.log` but not `k2f.agent.state`. LevelDB later moves records from its `.log` file into `.ldb` tables, whose blocks are often Snappy-compressed and whose keys share prefixes, so a plain text search can miss the name there. The tool reads each `.ldb` table, decompresses its blocks and rebuilds the full keys before it searches. The report cuts the quoted line before `agent_pass`, so it never shows the saved password that follows the key.
- `insightjs` in a file under a folder named `Code Cache` or `Cache` means the launcher loaded the malicious script (warning). The script ran; this alone does not show that the agent was downloaded.
- `TransportSecurity` stores HSTS entries under `base64(SHA-256(host name in DNS wire format))`, so it never contains the text `insightjs`. The tool computes the keys of the three domains and looks for them. On the infected test install, `JeFWywdZy+3jPC93e3P7ACdJ8liQHB7rH+9VHn7kswg=` is insightjs.com and `wxL1BeG57AG6frvPqS7txqpE3NyN0/fSUZHCbEn9NSw=` is analytics.insightjs.com, written one second after the agent started. The report gives each entry's `sts_observed` time, the last time the browser received the header.
- analytics.insightjs.com in `TransportSecurity` or in `Network Persistent State` means the launcher contacted the server that sends the agent (critical, "The launcher contacted the agent server"). A launch where the loader ran without the agent recorded only insightjs.com.
- insightjs.com or insightjs.org alone in `TransportSecurity`, and `insightjs` in `Network Persistent State` or `Reporting and NEL`, mean the launcher connected to insightjs.com (warning). A file that names analytics.insightjs.com counts only for the critical finding.
- `insightjs` in any other file is a warning.
- With no match, the folder is listed as info with the number of files checked.

A launcher data folder that is a symbolic link or a junction is read through its target, unless the target is missing, a drive root or a folder above the link. Such a link is listed as info and not read.

When launcher data is found but no install folder, an info finding says that `debug.log` and the download logs were not checked, and suggests scanning the install folder with "Scan a folder..." or `nikke-check --cli <folder>`.

## User profiles

The user profiles are the Windows user running the tool, every user of a Wine prefix except `Public`, and any other folder that holds `AppData/Local` or `AppData/Roaming`, such as `Users/<name>` on a Windows partition mounted under Linux. `Public`, `Default`, `Default User` and `All Users` are left out.

In each profile:

- `AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper` is Chrome persistence (critical) when it holds `platform_experience_helper.dll` at any depth, or a subfolder named with 64 hex characters (a SHA-256). A hash-named subfolder without the DLL is still critical, and the finding says the DLL may already have been removed. The agent creates this folder without checking that Chrome is installed, so it can be there on a computer without Chrome. Per-user Chrome installs keep Chrome's own Platform Experience Helper (`platform_experience_helper.exe`, `LoadFeatures`) in the same folder, so a folder with neither sign is listed as info. The report lists what the folder holds.
- The same check runs on the `PlatformExperienceHelper` folder in the user data of Edge, Brave, Vivaldi, Opera, Opera GX and Chromium, with the same rules (critical, "Edge persistence is installed" and so on). The HKCU key is per user, so any of these browsers could load the DLL.
- `platform_experience_helper.dll`, `platform_experience_helper.dll.old` or `old-clsid.txt` in `AppData/Local/Google/Chrome/Application/PlatformExperienceHelper` are files of an older version of the persistence (critical). The agent's cleanup code deletes them there, so an earlier version put its DLL in Chrome's own folder. Chrome's `platform_experience_helper.exe` in that folder is normal and is not reported.
- Files in `AppData/Local/Temp` whose name starts with `k2f` are critical. The agent names its temporary files `k2f-bcreds-*` (collected browser credentials) and `k2f_screen_*.jpg` (screenshots). An Oct 23 build also used `k2f-keyscan-*.db`, and `.png` for its screenshots (reported).
- A `.tmp` file in that Temp folder of exactly 22 bytes that holds 22 lowercase hex characters is info, with at most 5 listed. On the infected computer, a file like this (`onominan.tmp`) was written one second before the agent download. Delta Force prefixes hold an `onominan.tmp` of the same kind dated 2026-09-20, a week before the CDN files were changed, so other Tencent software writes it too and it does not change the verdict.

For the Windows user running the tool, two more checks run:

- The same Temp checks in `%TEMP%`.
- The older persistence files in the `Google\Chrome\Application\PlatformExperienceHelper` folder under `%ProgramW6432%`, `%ProgramFiles%`, `%ProgramFiles(x86)%` and `%LOCALAPPDATA%`.
- The default value of `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32`, read through the registry API in the 64-bit view and in the 32-bit view (`WOW6432Node`). A key with a DLL path is registry persistence (critical). A key whose default value is empty or missing is a leftover (critical): the agent's `chrome_uninstall` clears the value and leaves the key, and the DLL may still be on disk. The report shows the value. The HKLM copy that points to `wpc.dll` is part of Windows and is not read.

A Windows folder scan runs these checks as well when the scanned folder is your own profile or a folder above it.

A profile on a Windows drive seen from Linux or macOS gets the file checks, but its registry (`NTUSER.DAT`) is not read. The DLL step then says to delete the key from that Windows.

## Wine prefix registry

In each Wine prefix, a `user.reg` (the HKCU hive) that contains the key `[Software\\Classes\\CLSID\\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` is critical. With a DLL path as its default value (`@=`) it is registry persistence; with `@=""` or no `@=` line it is the leftover described above. The report quotes the key and its default value. The same key in `system.reg` (HKLM) points to `C:\windows\system32\wpc.dll`, the normal Windows Parental Controls entry, and is not reported.

The older persistence files are also looked for in `drive_c/Program Files` and `drive_c/Program Files (x86)` under `Google/Chrome/Application/PlatformExperienceHelper`.

## Running programs

A running launcher is critical: close it now. The tool looks for a process named `nikke_launcher.exe` (Linux shows `nikke_launcher.`, because it cuts process names to 15 bytes), a process whose first command-line argument is a path to `nikke_launcher.exe` (Wine sets it to the Windows path), or a `wine`, `wine64`, `wine-preloader` or `wine64-preloader` process started on `nikke_launcher.exe`. Programs that only name the file, such as `sha256sum` or an editor, do not count. The report lists the process ID and command line of each match.

On Windows, after the locations, the tool lists the modules of every running process it is allowed to open (Toolhelp snapshots; processes that deny access are skipped). A module at `PlatformExperienceHelper\<64 hex>\platform_experience_helper.dll`, at `PlatformExperienceHelper\platform_experience_helper.dll`, or at the path the HKCU key names is critical ("The persistence DLL is loaded now"). Windows keeps a loaded DLL locked, so the DLL step then asks for a restart before the files are deleted. The report lists the process ID, the program and the DLL of each match.

## Data the malware could reach

When an install or launcher data was found, the tool lists what the agent's commands could read. It only checks that the files exist and never opens them. These lists do not change the verdict; they fill the password step and "Your data the malware could reach" in Details.

- Saved logins: `Login Data` or `Login Data For Account` in each profile of Chrome, Edge, Brave, Vivaldi, Opera, Opera GX and Chromium, and `logins.json` or `key4.db` in each Firefox profile, the browsers the agent's `browserscan` reads. Chromium creates `Login Data` in every profile, so the file can be there with no saved password.
- Wallet extensions: the 28 extension IDs of the agent's `wallet_files` command, such as `nkbihfbeogaeaoehlefnkodbefgpgknn` (MetaMask), in the `Extensions` folder of each Chromium profile.
- Secret files from the agent's `keyscan` list: SSH private keys (`~/.ssh/id_*`), cloud and CLI credentials (AWS, Google Cloud, Azure, GitHub CLI, Docker, Kubernetes, npm, PyPI, crates.io and others), GnuPG private keys and `.env`.

The tool checks every user profile it found. On Linux and macOS, when a Wine prefix was found, it also checks your home folder, which the agent could read through the prefix's `Z:` drive. A folder scan adds it too, so for a prefix copied from another computer the list shows this computer's files; the report says so.

## Hosts file

The hosts file (`C:\Windows\System32\drivers\etc\hosts`, or `/etc/hosts` elsewhere) is checked for `insightjs.com`, `analytics.insightjs.com` and `insightjs.org` mapped to `0.0.0.0`, `127.0.0.1`, `::1` or `::`. Text after `#` is ignored. This is protection, not a sign of infection, and it does not change the verdict.

The report shows each domain as blocked, not blocked or unknown, and gives the lines to add for the domains that are not blocked. If the file does not exist, the report says it blocks nothing. If it exists but cannot be read, each domain is shown as unknown and all three lines are given. Editing the hosts file needs administrator rights, and the tool never edits it. The attacker's IP addresses, 89.127.233.127 and 89.126.250.172, cannot be blocked in the hosts file; the report says to block them in a firewall or router. [What to do](what-to-do.md#block-the-domains-and-the-ip-addresses) shows how to add the lines.

## Times in the report

Times taken from log lines are the local time of the computer that ran the launcher. `debug.log` lines carry no year, so the report shows them as month, day and time with "year not logged". File times and the `Started:` time are in UTC. On a computer in UTC+1, the 22-byte hex `.tmp` file was written one second before the download, but its UTC file time reads one hour earlier than the local time in the download's log line.

## Verdicts

| Verdict | Meaning | `--cli` exit code |
|---|---|---|
| No traces found | An install or launcher data was found, with info findings only. When only launcher data was found, the report says that `debug.log` and the download logs were not checked. | 0 |
| Exposed | Warnings only: the launcher loaded the script or contacted insightjs.com. No sign that the agent ran. | 1 |
| Infected | At least one critical finding: the agent was downloaded or ran, the launcher contacted analytics.insightjs.com, persistence or its leftover exists, the DLL is loaded, or the launcher is running now. | 2 |
| NIKKE not found | No install and no launcher data in the places searched, and no critical or warning finding. | 3 |

The most severe finding sets the verdict, so a critical finding gives Infected even when no NIKKE install was found, for example Chrome persistence in a profile or `k2f` files in Temp. Info findings never change the verdict. Exit code 4 means invalid arguments: an unknown option, or with `--cli` a path that is not a folder or a folder that cannot be read.

The window and the report list the steps for each verdict. An Exposed result also lists the account steps of an infected computer, for the case where the launcher was open on or after October 23, 2026. [What to do](what-to-do.md) has all the steps.

## Limits

- `debug.log` and the `tinyget` logs are in the NIKKE folder, so deleting or reinstalling NIKKE removes them. On the infected test install, `debug.log` held all 9 launches from 2026-10-29 to 2026-11-03. The `k2f.agent.state` check in the launcher data does not depend on these logs.
- Finding nothing does not prove that the computer is clean.
- The commands the agent ran leave no logs, so the tool cannot tell what the attacker did.
- On a Mac the tool only finds NIKKE inside the Wine-based setups and folders listed in [Where it looks](locations.md#macos).
- The checks were tested against a real infected install under Proton on Linux. The Windows and macOS code has not been run against a real infection, and the loaded-DLL check has not run on Windows at all.
- `service_util.dll`, which the agent's cleanup code also deletes, is not checked: the decompiled code does not give its path.
