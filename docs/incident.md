# What happened

All times on this page are GMT, in 2026. The full analysis is in the write-up: https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5

On September 27, three JavaScript files on Level Infinite's CDN (playerinfinite.com, served from Tencent COS) were modified to load `https://insightjs.com/l.js`. The NIKKE PC launcher shows its pages in an embedded Chromium (CEF), so it ran that script. From November 1 at the latest, and only on some launches, the script used the launcher's JavaScript bridge to download a remote-access agent. It is not known how the attacker got write access to the CDN, or whether they still have it. No official statement from Level Infinite is known.

## The modified CDN files

All three files were modified on September 27 between 06:41 and 06:42. Each one loads `l.js` with its own `f` parameter.

| File | Loads | Cleaned |
|---|---|---|
| `https://sg-gpts.playerinfinite.com/comm/assets/lib/aegis-fix.min.js` | `https://insightjs.com/l.js?f=aegis` | Replaced by Level Infinite on November 3 at 17:04:28 |
| `https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/images.7fec4c32.js` | `https://insightjs.com/l.js?f=images` | Replaced by Level Infinite on November 3 at 17:21:31 |
| `https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/FeedList.feb647c9.js` | `https://insightjs.com/l.js?f=feedlist` | Cleaned at the origin on October 28 at 15:46:09, but still served by two CDN servers on November 3 |

The CDN servers 43.175.144.148 and 43.175.145.181 still delivered the modified `FeedList.feb647c9.js` (SHA-256 `2f2aac505f486067af6831d6c75ea74df63acb1ed4e4002709c5962c68bd9203`) on November 3 at 18:59, also for requests with cache-busting query strings. Depending on the server it reaches, the launcher can still load the script.

## Timeline

| Time (GMT) | Event |
|---|---|
| Sep 27, 01:59 | insightjs.com is registered through PublicDomainRegistry, with 1984 ehf name servers. |
| Sep 27, 06:41 to 06:42 | The three CDN files are modified. |
| Oct 28, 15:46:09 | `FeedList.feb647c9.js` is cleaned at the origin. |
| Nov 1, 19:37 | Earliest reported start of the agent. From November 1 at the latest, `l.js` downloads the agent on some launches. |
| Nov 3, 17:04:28 | Level Infinite replaces `aegis-fix.min.js`. |
| Nov 3, 17:21:31 | Level Infinite replaces `images.7fec4c32.js`. |
| Nov 3, by 17:30 | The `l.js` that insightjs.com serves now looks like an ordinary analytics script. |
| Nov 3, 17:55 | A third party registers insightjs.org, the loader's fallback domain. It now shows a warning page in four languages. |
| Nov 3, 18:31 | 89.127.233.127, the server that sent the agent, does not answer (the connection times out). |
| Nov 3, 18:59 | 43.175.144.148 and 43.175.145.181 still serve the modified `FeedList.feb647c9.js`. |

## The loader

The code added to each CDN file hides the `l.js` URL in a `Uint32Array` and names insightjs.org as a fallback domain. It adds a `<script>` tag that loads `l.js`, then removes the tag. The insightjs.com address stays in the cache of the launcher's built-in browser, which is one of the traces behind the Exposed verdict.

## The agent

From November 1 at the latest, and only on some launches, `l.js` used the launcher's JavaScript bridge to download `https://analytics.insightjs.com/comm/assets/insight.bundle` from 89.127.233.127, a VPS at 1984 ehf in Iceland. The launcher saved it in `Launcher/log/` under a `tinyget` log name.

`insight.bundle` is LuaJIT bytecode, 205,135 bytes, SHA-256 `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec`. It is a remote-access agent with these commands: `exec`, `ls`, `cd`, `cat`, `download`, `file_chunk`, `screens`, `creds`, `keyscan`, `browserscan`, `chrome_scan`, `wallet_files`, `whoami`, `sysinfo`, `host_facts`, `chrome_install`, `chrome_cleanup`, `chrome_uninstall` and `payload_cleanup`.

The agent runs only while the launcher is open, except for the Chrome persistence on Windows described below. Under Wine and Proton, the prefix's `Z:` drive maps to `/`, so its commands can reach the whole Linux or macOS home folder ([details](what-to-do.md#why-the-home-folder-is-exposed-under-wine)).

The agent leaves these traces:

- Lines in `Launcher/intl_service/debug.log`, which the launcher appends to at each launch. The infected test install held all 9 launches from October 29 to November 3.
- `k2f.agent.state`, its saved ID, in the launcher's Local Storage (`tbs_cache/Local Storage/leveldb`). The launcher data is outside the NIKKE folder, so this trace survives deleting the NIKKE folder.
- Temporary files named `k2f-bcreds-*` (collected browser credentials) and `k2f_screen_*.jpg` (screenshots).

## Persistence on Windows

On Windows the agent can install persistence in Google Chrome (a real Chrome install, not the launcher's CEF). It writes a DLL to `%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\<64 hex characters>\platform_experience_helper.dll` and registers it under `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32`, so that Chrome loads it.

Two things that look similar are normal:

- The HKLM copy of that CLSID, which points to `wpc.dll`, the Windows Parental Controls entry.
- Chrome's own `PlatformExperienceHelper` folder, with `platform_experience_helper.exe` and `LoadFeatures`, which per-user Chrome installs keep in the same place.

## How this tool relates

`nikke-check` reads the traces above from disk. The loader in the launcher cache, or a connection to insightjs.com in its network state, gives an Exposed verdict. The download logs, the agent file, the `debug.log` lines, `k2f.agent.state`, the `k2f` Temp files, the Chrome persistence and a running launcher give an Infected verdict. It also reports whether the hosts file blocks the three domains. It does not contact any server, and it cannot tell which commands the agent ran, because they leave no logs. [What it checks](checks.md) has the rules for each finding.

## Indicators of compromise

```
Domains
  insightjs.com
  analytics.insightjs.com
  insightjs.org                (fallback; registered by a third party on 2026-11-03 17:55 GMT)

IP addresses
  89.127.233.127               served insight.bundle (1984 ehf VPS, Iceland)
  43.175.144.148               CDN server, still served the modified FeedList.feb647c9.js on 2026-11-03
  43.175.145.181               CDN server, same

URLs
  https://insightjs.com/l.js?f=aegis
  https://insightjs.com/l.js?f=images
  https://insightjs.com/l.js?f=feedlist
  https://analytics.insightjs.com/comm/assets/insight.bundle

Modified CDN files
  https://sg-gpts.playerinfinite.com/comm/assets/lib/aegis-fix.min.js
  https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/images.7fec4c32.js
  https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/FeedList.feb647c9.js

SHA-256
  cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec  insight.bundle (LuaJIT bytecode, 205,135 bytes)
  2f2aac505f486067af6831d6c75ea74df63acb1ed4e4002709c5962c68bd9203  FeedList.feb647c9.js, modified copy

Log strings in Launcher/intl_service/debug.log
  k2f_chan registered
  adopted <id>
  agent started as <hostname>
  startup already in progress
  lua downloaded to ...

Files in Launcher/log/
  a tinyget log that names insight.bundle or analytics.insightjs.com
  a file that starts with LuaJIT bytecode (1B 4C 4A): the saved agent

Launcher Local Storage (tbs_cache/Local Storage/leveldb)
  k2f.agent.state

Windows persistence
  %LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\<64 hex>\platform_experience_helper.dll
  HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32
  (in a Wine prefix: the same key in user.reg)

Temp files
  %TEMP%\k2f-bcreds-*
  %TEMP%\k2f_screen_*.jpg
```
