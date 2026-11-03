# What to do

The window and the report list these steps for your verdict, in this order. This page explains them and gives the paths for each system. Your verdict is the large title at the top of the result screen, or the `VERDICT:` line of the report.

A clean device, in the steps below, is a phone or another computer that never ran the NIKKE launcher.

## Infected

Critical traces were found: the agent was downloaded or ran, it left persistence, or the launcher is running now. While the launcher was open, the attacker could run commands on this computer.

Steps 8 to 11 are done from a clean device, so you can start them right away while this computer stays offline.

1. Close the launcher now and disconnect this computer from the network. If the launcher does not close: on Windows, open Task Manager (Ctrl+Shift+Esc) and end nikke_launcher.exe. On Linux, run `pkill -f nikke_launcher.exe` in a terminal.
2. Do not open the NIKKE launcher until Level Infinite confirms a fix.
3. Save a copy of the report before you delete anything: click "Copy report" and paste it into a text file. Deleting `tbs_cache` also deletes the `k2f.agent.state` trace.
4. Before you open the launcher again, delete its cache folder, `tbs_cache`, in the launcher data folder. It can still hold the malicious script from before the fix. See [Delete the launcher cache](#delete-the-launcher-cache).
5. Block insightjs.com, analytics.insightjs.com and insightjs.org in your hosts file, and block the IP 89.127.233.127 in your firewall or router. See [Block the domains and the IP](#block-the-domains-and-the-ip).
6. On Windows, if the report lists "Chrome persistence is installed" or "Registry persistence found (HKCU CLSID hijack)", remove what the agent added for Chrome: the subfolder that holds `platform_experience_helper.dll`, then the registry key. See [Remove the Chrome persistence on Windows](#remove-the-chrome-persistence-on-windows).
7. Reinstalling Windows is the safest way to be sure the computer is clean, because the agent could run any command.
8. From a clean device, change your passwords: the NIKKE / Level Infinite account first, then email, Discord, banking, and every password saved in your browsers.
9. Log out of all sessions on those services. The agent can collect browser cookies, and a stolen cookie works without the password.
10. Revoke API tokens and SSH keys that were stored on this computer.
11. If you hold cryptocurrency, move it to a wallet with a new seed phrase created on a clean device.
12. On Linux and macOS (Proton, umu, Wine, CrossOver, Whisky), the remote commands could read your whole home folder and the environment variables of the launcher process, not only the Wine prefix. See [Why the home folder is exposed under Wine](#why-the-home-folder-is-exposed-under-wine).

## Exposed

The launcher loaded the malicious script or contacted insightjs.com, but no sign that the agent ran was found.

1. Do not open the NIKKE launcher until Level Infinite confirms a fix.
2. Before you open the launcher again, delete `tbs_cache` in the launcher data folder. It can still hold the malicious script from before the fix. See [Delete the launcher cache](#delete-the-launcher-cache).
3. Block the three domains in your hosts file and the IP 89.127.233.127 in your firewall or router. See [Block the domains and the IP](#block-the-domains-and-the-ip).

The agent was served from October 24, 2026 at the latest, and only on some launches. If the launcher was open on or after that date, treat this computer as infected and follow these steps:

1. From a clean device, change your passwords: the NIKKE / Level Infinite account first, then email, Discord, banking, and every password saved in your browsers.
2. Log out of all sessions on those services. The agent can collect browser cookies, and a stolen cookie works without the password.
3. Revoke API tokens and SSH keys that were stored on this computer.
4. If you hold cryptocurrency, move it to a wallet with a new seed phrase created on a clean device.
5. On Linux and macOS (Proton, umu, Wine, CrossOver, Whisky), the remote commands could read your whole home folder and the environment variables of the launcher process, not only the Wine prefix. See [Why the home folder is exposed under Wine](#why-the-home-folder-is-exposed-under-wine).

## No traces found

No trace of the malicious script or the agent was found in the NIKKE files this scan located. Finding nothing is not proof that the computer is clean.

1. Do not open the NIKKE launcher until Level Infinite confirms a fix.
2. Before you open the launcher again, delete `tbs_cache` in the launcher data folder. See [Delete the launcher cache](#delete-the-launcher-cache).
3. Block the three domains in your hosts file and the IP 89.127.233.127 in your firewall or router. See [Block the domains and the IP](#block-the-domains-and-the-ip).
4. If the launcher was open on or after October 24, 2026, change your NIKKE / Level Infinite password from a clean device anyway.

## NIKKE not found

No NIKKE install or launcher data was found in the places this scan checked.

1. If NIKKE is installed somewhere unusual, scan that folder: "Scan a folder..." in the window, or `nikke-check --cli <folder>`.
2. Do not open the NIKKE launcher until Level Infinite confirms a fix.
3. Block the three domains in your hosts file and the IP 89.127.233.127 in your firewall or router. See [Block the domains and the IP](#block-the-domains-and-the-ip).

## Delete the launcher cache

`tbs_cache` is the cache of the launcher's built-in browser. It sits in the launcher data folder, `nikke_launcher` (or `nikke_launcher_hmt`). The report lists every launcher data folder it found under `Locations checked`, tagged `[Launcher data]`, with its full path.

Save the report first. `tbs_cache/Local Storage/leveldb` holds the `k2f.agent.state` trace, and it is gone once the folder is deleted.

- Windows: `%APPDATA%\nikke_launcher\tbs_cache`. Paste `%APPDATA%\nikke_launcher` into the Explorer address bar to open the folder.
- Linux with Steam and Proton: `<Steam library>/steamapps/compatdata/<game ID>/pfx/drive_c/users/steamuser/AppData/Roaming/nikke_launcher/tbs_cache`.
- Linux and macOS with any other Wine-based tool (Wine, Lutris, Heroic, Bottles, Faugus, CrossOver, Whisky, Wineskin and the others): `drive_c/users/<user>/AppData/Roaming/nikke_launcher/tbs_cache` inside the prefix. [Where it looks](locations.md) lists where each tool keeps its prefixes.

## Block the domains and the IP

These are the lines to add to the hosts file. The "Protection" part of the result lists the ones still missing, and "Copy these lines" copies them.

```
0.0.0.0 insightjs.com
0.0.0.0 analytics.insightjs.com
0.0.0.0 insightjs.org
```

Editing the hosts file needs administrator rights. The tool never edits it.

- Windows: open the Start menu, type Notepad, right-click it and choose "Run as administrator". Open `C:\Windows\System32\drivers\etc\hosts` (choose "All files" in the Open dialog so the file shows), add the lines at the end and save.
- Linux, Steam Deck and macOS: run this command in a terminal. It asks for your password. On a Steam Deck, set a password with `passwd` first if you never did.

```
printf '\n0.0.0.0 insightjs.com\n0.0.0.0 analytics.insightjs.com\n0.0.0.0 insightjs.org\n' | sudo tee -a /etc/hosts
```

Scan again afterwards: the "Protection" part then shows each domain as blocked.

The hosts file cannot block an IP address. Block 89.127.233.127 in your firewall or router instead. On Windows, this command adds a firewall rule. Right-click the Start button, choose Terminal (Admin) or Windows PowerShell (Admin), and run:

```
New-NetFirewallRule -DisplayName "Block 89.127.233.127" -Direction Outbound -RemoteAddress 89.127.233.127 -Action Block
```

On Linux with ufw, the command is `sudo ufw deny out to 89.127.233.127`. On macOS, and on Linux without ufw, block the address in your router's settings.

## Remove the Chrome persistence on Windows

Do this when the report lists "Chrome persistence is installed" or "Registry persistence found (HKCU CLSID hijack)". Save the report first.

The DLL stays locked while Windows has it loaded, even with every Chrome window closed, so remove the registry key first and restart before you delete the file.

1. Delete the registry key `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}`. In Command Prompt:

   ```
   reg delete "HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}" /f
   ```

   If the report also lists the `WOW6432Node` copy, delete it too:

   ```
   reg delete "HKCU\Software\Classes\WOW6432Node\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}" /f
   ```

2. Restart Windows.
3. Open `%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper` in Explorer. Delete the subfolder named with 64 hex characters (digits and the letters a to f) that holds `platform_experience_helper.dll`. Leave the rest alone: Chrome keeps its own `platform_experience_helper.exe` and an empty `LoadFeatures` file there.
4. Scan again. Both findings should be gone.

Microsoft Defender did not detect this DLL on one infected machine (Defender Offline, signatures 1.463.110.0), so a clean antivirus scan does not mean it is gone.

Leave the HKLM copy of the CLSID alone. It points to `wpc.dll`, which is part of Windows.

The tool's steps cover Windows. When a Wine or Proton prefix shows these findings, the report gives the folder and the `user.reg` file inside that prefix.

## Why the home folder is exposed under Wine

Wine gives every prefix a `Z:` drive that maps to `/`, the root of your Linux or macOS system (the `dosdevices/z:` link in the prefix). Proton, umu, CrossOver and Whisky use Wine, so the same applies to them. A program running in the prefix, the agent included, can read through `Z:` every file your user account can read.

The agent's remote commands include `exec`, `ls`, `cat` and `download`. They could read your whole home folder and the environment variables of the launcher process, not only the Wine prefix. That covers SSH keys in `~/.ssh`, browser profiles and tokens kept in config files. The commands leave no logs, so the tool cannot tell what was read. This is why the account steps above apply on Linux and macOS too.
