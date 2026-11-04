# What to do

The "What to do" tab and the `WHAT TO DO` part of the report list the steps that match what the scan found, in the order to do them, and skip the ones that do not apply. This page explains them and gives the paths for each system. Your verdict is the large title at the top of the "What happened" tab, or the `VERDICT:` line of the report.

A clean device, in the steps below, is a phone or another computer that never ran the NIKKE launcher.

## Infected

Critical traces were found: the agent was downloaded or ran, the launcher contacted analytics.insightjs.com, the agent left persistence, or the launcher is running now. While the launcher was open, the attacker could run commands on this computer.

Steps 5 to 8 are done from a clean device, so you can start them right away while this computer stays offline.

1. Close the launcher now and disconnect this computer from the network. If the launcher does not close: on Windows, open Task Manager (Ctrl+Shift+Esc) and end nikke_launcher.exe. On Linux, run `pkill -f nikke_launcher.exe` in a terminal. On Windows, the scan also lists the programs that have the malware's DLL loaded. Close them, but do not end explorer.exe, which runs the taskbar and the desktop: the restart in step 3 unloads the DLL from every program.
2. Save the report before you delete anything: click "Save report..." (or "Copy report" and paste it into a text file). Deleting `tbs_cache` also deletes the `k2f.agent.state` trace. Turn on "Hide my info" before you share the report.
3. If the report lists a DLL or registry finding, remove the persistence. On Windows the order is: delete the registry key, restart Windows, then delete the DLL folder. See [Remove the DLL persistence](#remove-the-dll-persistence).
4. Before you open the launcher again, delete its cache folder, `tbs_cache`, in the launcher data folder. It can still hold the malicious script from before the fix. See [Delete the launcher cache](#delete-the-launcher-cache).
5. From a clean device, change your passwords: the NIKKE / Level Infinite account first, then email, Discord, banking, and every password saved in your browsers. The window names the browser profiles that have saved logins.
6. Log out of all sessions on those services. The agent can collect browser cookies, and a stolen cookie works without the password.
7. Revoke the API tokens and SSH keys stored on this computer, and replace them. The window lists the credential files it found, such as `~/.ssh/id_ed25519` or `~/.config/gh/hosts.yml`, but other files can hold tokens too.
8. If you hold cryptocurrency, move it to a wallet with a new seed phrase created on a clean device. The window names the wallet extensions it found.
9. On Linux and macOS (Proton, umu, Wine, CrossOver, Whisky), the remote commands could read your whole home folder and the environment variables of the launcher process, not only the Wine prefix. See [Why the home folder is exposed under Wine](#why-the-home-folder-is-exposed-under-wine).
10. Block insightjs.com, analytics.insightjs.com and insightjs.org in your hosts file, and the IP addresses 89.127.233.127 and 89.126.250.172 in your firewall or router. See [Block the domains and the IP addresses](#block-the-domains-and-the-ip-addresses).
11. If the scan found launcher data but not the NIKKE install folder, scan the install folder too: "Scan a folder..." in the window, or `nikke-check --cli <folder>`. Its `debug.log` shows when the agent ran.
12. Do not open the NIKKE launcher until Level Infinite confirms a fix. Reinstalling the operating system is the safest way to be sure the computer is clean, because the agent could run any command.

## Exposed

The launcher loaded the malicious script or contacted insightjs.com, but no sign that the agent ran was found.

1. Save the report before you delete anything. Deleting `tbs_cache` also deletes the traces the scan found in it.
2. If the scan found launcher data but not the NIKKE install folder, scan the install folder: "Scan a folder..." in the window, or `nikke-check --cli <folder>`. Its `debug.log` can show that the agent ran, which changes the result to Infected. Do this before the other steps.
3. After a quick scan, also run the full scan ("Full scan" in the window, or `nikke-check --cli --full`): an older install more than 5 folder levels deep can hold the same proof.
4. Before you open the launcher again, delete `tbs_cache` in the launcher data folder. It can still hold the malicious script from before the fix. See [Delete the launcher cache](#delete-the-launcher-cache).
5. Block the three domains in your hosts file and the IP addresses 89.127.233.127 and 89.126.250.172 in your firewall or router. See [Block the domains and the IP addresses](#block-the-domains-and-the-ip-addresses).
6. Do not open the NIKKE launcher until Level Infinite confirms a fix.

The agent was served from October 23, 2026 at the latest, and only on some launches. If the launcher was open on or after that date, treat this computer as infected and follow these steps. The window lists them between the cache and the blocking steps, with the browsers, wallets and credential files it found:

7. From a clean device, change your passwords: the NIKKE / Level Infinite account first, then email, Discord, banking, and every password saved in your browsers.
8. Log out of all sessions on those services. The agent can collect browser cookies, and a stolen cookie works without the password.
9. Revoke API tokens and SSH keys that were stored on this computer.
10. If you hold cryptocurrency, move it to a wallet with a new seed phrase created on a clean device.
11. On Linux and macOS (Proton, umu, Wine, CrossOver, Whisky), the remote commands could read your whole home folder and the environment variables of the launcher process, not only the Wine prefix. See [Why the home folder is exposed under Wine](#why-the-home-folder-is-exposed-under-wine).

## No traces found

No trace of the malicious script or the agent was found in the NIKKE files this scan located. Finding nothing is not proof that the computer is clean.

1. Before you open the launcher again, delete `tbs_cache` in the launcher data folder. See [Delete the launcher cache](#delete-the-launcher-cache).
2. If the launcher was open on or after October 23, 2026, change your NIKKE / Level Infinite password from a clean device anyway.
3. Block the three domains in your hosts file and the IP addresses 89.127.233.127 and 89.126.250.172 in your firewall or router. See [Block the domains and the IP addresses](#block-the-domains-and-the-ip-addresses).
4. Do not open the NIKKE launcher until Level Infinite confirms a fix.

When only launcher data was found, the window first asks you to scan the install folder, as in step 2 of [Exposed](#exposed). After any quick scan it also offers the full scan, which opens folders more than 5 levels deep, where an older install can still hold the agent's log lines.

## NIKKE not found

No NIKKE install or launcher data was found in the places this scan checked.

1. If NIKKE is installed somewhere unusual, scan that folder: "Scan a folder..." in the window, or `nikke-check --cli <folder>`. If you do not know where it is, run the full scan: "Full scan" in the window, or `nikke-check --cli --full`.
2. Block the three domains in your hosts file and the IP addresses 89.127.233.127 and 89.126.250.172 in your firewall or router. See [Block the domains and the IP addresses](#block-the-domains-and-the-ip-addresses).
3. Do not open the NIKKE launcher until Level Infinite confirms a fix.

## Delete the launcher cache

`tbs_cache` is the cache of the launcher's built-in browser. It sits in the launcher data folder, `nikke_launcher` (or `nikke_launcher_hmt`). The report lists every launcher data folder it found under `Locations checked`, tagged `[Launcher data]`, with its full path.

Save the report first. `tbs_cache/Local Storage/leveldb` holds the `k2f.agent.state` trace, and it is gone once the folder is deleted.

- Windows: `%APPDATA%\nikke_launcher\tbs_cache`. Paste `%APPDATA%\nikke_launcher` into the Explorer address bar to open the folder.
- Linux with Steam and Proton: `<Steam library>/steamapps/compatdata/<game ID>/pfx/drive_c/users/steamuser/AppData/Roaming/nikke_launcher/tbs_cache`.
- Linux and macOS with any other Wine-based tool (Wine, Lutris, Heroic, Bottles, Faugus, CrossOver, Whisky, Wineskin and the others): `drive_c/users/<user>/AppData/Roaming/nikke_launcher/tbs_cache` inside the prefix. [Where it looks](locations.md) lists where each tool keeps its prefixes.

## Block the domains and the IP addresses

These are the lines to add to the hosts file. The "Protection" part of Details lists the ones still missing, and "Copy these lines" copies them.

```
0.0.0.0 insightjs.com
0.0.0.0 analytics.insightjs.com
0.0.0.0 insightjs.org
```

Editing the hosts file needs administrator rights. The tool never edits it.

- Windows: open the Start menu, type Notepad, right-click it and choose "Run as administrator". In Notepad, choose File > Open, paste `C:\Windows\System32\drivers\etc\hosts` into the File name box and press Enter ("Copy hosts path" in the window copies it). Paste the lines at the end of the file and save.
- Linux, Steam Deck and macOS: run this command in a terminal. It asks for your password. On a Steam Deck, set a password with `passwd` first if you never did.

```
printf '\n0.0.0.0 insightjs.com\n0.0.0.0 analytics.insightjs.com\n0.0.0.0 insightjs.org\n' | sudo tee -a /etc/hosts
```

Scan again afterwards: the "Protection" part then shows each domain as blocked.

The hosts file cannot block an IP address. Block 89.127.233.127, which sent the agent, and 89.126.250.172, which served insightjs.com until about October 21, in your firewall or router instead. On Windows, this command adds a firewall rule. Right-click the Start button, choose Terminal (Admin) or Windows PowerShell (Admin), and run:

```
New-NetFirewallRule -DisplayName "Block NIKKE malware servers" -Direction Outbound -RemoteAddress 89.127.233.127,89.126.250.172 -Action Block
```

On Linux with ufw, the command is:

```
sudo ufw deny out to 89.127.233.127 && sudo ufw deny out to 89.126.250.172
```

ufw records the rules even while it is off, and then blocks nothing. Check that `sudo ufw status` shows `Status: active`; `sudo ufw enable` turns it on. On macOS, and on Linux without ufw, block the addresses in your router's settings.

## Remove the DLL persistence

Do this when the report lists one of these findings. Save the report first.

- "Chrome persistence is installed", or the same for Edge, Brave, Vivaldi, Opera, Opera GX or Chromium
- "Registry persistence found (HKCU CLSID hijack)", or its empty leftover, "Registry leftover of the persistence (HKCU CLSID)"
- "Files of an older Chrome persistence are installed"
- "The persistence DLL is loaded now" (Windows only)

The agent creates the DLL folder even when Chrome is not installed, so these findings are not a false positive on a computer without Chrome.

### On Windows

Keep this computer offline until these steps are done: while the key is set, the browser loads the DLL each time it starts. The DLL stays locked while a program has it loaded, even with every browser window closed, so remove the registry key first and restart before you delete the files.

1. Delete the registry key `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}`. In the window, "Copy key path" copies it and "Open Registry Editor" starts Registry Editor: paste the path into the address bar at the top, press Enter, right-click the selected key and choose Delete. Or, in Command Prompt:

   ```
   reg delete "HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}" /f
   ```

   If the report also lists the `WOW6432Node` copy, delete it too:

   ```
   reg delete "HKCU\Software\Classes\WOW6432Node\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}" /f
   ```

   An empty key (the leftover) is deleted the same way.
2. Restart Windows. The restart closes the window. Open the tool again and scan: the result shows what is left to delete.
3. Open `%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper` in Explorer ("Open folder" in the window selects the right subfolder). For another browser, the folder is in that browser's `User Data`. Delete the subfolder named with 64 hex characters (digits and the letters a to f) that holds `platform_experience_helper.dll`. Leave the rest alone: Chrome keeps its own `platform_experience_helper.exe` and an empty `LoadFeatures` file there.
4. If the report lists "Files of an older Chrome persistence are installed", open the folder it names, `Google\Chrome\Application\PlatformExperienceHelper` under Program Files or `%LOCALAPPDATA%`. Delete only `platform_experience_helper.dll`, `platform_experience_helper.dll.old` and `old-clsid.txt`, the ones that are there. Keep `platform_experience_helper.exe`: it belongs to Chrome.
5. Scan again. The findings should be gone.

When the key is already gone and no program has the DLL loaded, for example on the scan after the restart, the window skips steps 1 and 2: delete the files right away, and restart only if Windows says a file is in use.

Microsoft Defender did not detect this DLL on one infected machine (Defender Offline, signatures 1.463.110.0), so a clean antivirus scan does not mean it is gone.

Leave the HKLM copy of the CLSID alone. It points to `wpc.dll`, which is part of Windows.

### In a Wine or Proton prefix

The files and the key are inside the prefix. Close the launcher and every other program of that prefix first. Then delete the 64-hex folder and the older files the report names, as in steps 3 and 4 above, with the paths inside the prefix.

The key is in the prefix's `user.reg`. Open regedit in the prefix, go to `HKEY_CURRENT_USER\Software\Classes\CLSID` and delete the `{E77CC89B-7401-4C04-8CED-149DB35ADD04}` key. The window gives the command with the prefix path filled in:

```
WINEPREFIX='/path/to/prefix' wine regedit
```

For a Steam prefix on a system without Wine, such as a Steam Deck, protontricks opens regedit in the prefix. The game ID is the number after `compatdata` in the path:

```
protontricks -c 'wine regedit' <game ID>
```

### On a Windows drive seen from Linux or macOS

A scan from Linux or macOS can read the files of a Windows partition, such as `Users/<name>` on a mounted drive, but not that Windows' registry. That Windows is not running, so the DLL is not locked: delete the 64-hex folder and the older files from Linux or macOS. Then start Windows, delete both keys as in step 1 above, and scan again from Windows.

If the drive is read-only (Windows Fast Startup and hibernation leave it that way), follow [On Windows](#on-windows) from that Windows instead.

## Why the home folder is exposed under Wine

Wine gives every prefix a `Z:` drive that maps to `/`, the root of your Linux or macOS system (the `dosdevices/z:` link in the prefix). Proton, umu, CrossOver and Whisky use Wine, so the same applies to them. A program running in the prefix, the agent included, can read through `Z:` every file your user account can read.

The agent's remote commands include `exec`, `ls`, `cat` and `download`. They could read your whole home folder and the environment variables of the launcher process, not only the Wine prefix. That covers SSH keys in `~/.ssh`, browser profiles and tokens kept in config files. The commands leave no logs, so the tool cannot tell what was read. This is why the account steps above apply on Linux and macOS too.
