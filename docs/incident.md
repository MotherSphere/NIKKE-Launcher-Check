# What happened

All times on this page are GMT, in 2026. The full analysis is in the write-up: https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5

On September 27, four JavaScript files on Level Infinite's CDN (playerinfinite.com, served from Tencent COS) were modified to load `https://insightjs.com/l.js`. The NIKKE PC launcher shows its pages in an embedded Chromium (CEF), so it ran that script. From October 23 at the latest, and only on some launches, the script used the launcher's JavaScript bridge to download a remote-access agent. It is not known how the attacker got write access to the CDN, or whether they still have it. No official statement from Level Infinite is known.

## The modified CDN files

All four files were modified on September 27 between 06:41 and 06:42. Each one loads `l.js` with its own `f` parameter.

| File | Loads | Cleaned |
|---|---|---|
| `https://sg-gpts.playerinfinite.com/comm/assets/lib/aegis-fix.min.js` | `https://insightjs.com/l.js?f=aegis` | Replaced by Level Infinite on November 3 at 17:04:28 |
| `https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/images.7fec4c32.js` | `https://insightjs.com/l.js?f=images` | Replaced by Level Infinite on November 3 at 17:21:31 |
| `https://na-webassets.playerinfinite.com/comm/assets/lib/vue-bucket.min.js` | `https://insightjs.com/l.js?f=vue` | Replaced on November 3 at 17:13:36 |
| `https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/FeedList.feb647c9.js` | `https://insightjs.com/l.js?f=feedlist` | Cleaned at the origin on October 28 at 15:46:09, but still served by two CDN servers on November 3 |

The CDN servers 43.175.144.148 and 43.175.145.181 still delivered the modified `FeedList.feb647c9.js` (SHA-256 `2f2aac505f486067af6831d6c75ea74df63acb1ed4e4002709c5962c68bd9203`) on November 3 at 18:59, and again at 20:23, also for requests with cache-busting query strings. Depending on the server it reaches, the launcher can still load the script.

The modified `vue-bucket.min.js` (135,273 bytes, SHA-256 `3aaafbd612f04501a6fdb0bb8b2f8a87796223e5584ac18ea5eb180feeafb193`, Last-Modified September 27 06:41:44) was recovered from a launcher HTTP cache by another victim. At 20:23 on November 3, all three CDN servers above served the clean copy (134,592 bytes, SHA-256 `459343517635a96caa109b050361b4d32393e8727b2f54b44749db783feb4199`).

## Timeline

| Time (GMT) | Event |
|---|---|
| Sep 27, 01:59 | insightjs.com is registered through PublicDomainRegistry, with 1984 ehf name servers. |
| Sep 27, 06:41 to 06:42 | The four CDN files are modified. |
| Oct 23, 16:40 | Earliest reported start of the agent, about an hour after a new certificate for analytics.insightjs.com (15:37). |
| Oct 24, 01:16 | A reported start on a Linux machine under Proton, where the payload was saved as `Launcher/log/tinyget/k2f.lua`. A Windows machine logged a start at 01:43 the same day. |
| Oct 28, 15:46:09 | `FeedList.feb647c9.js` is cleaned at the origin. |
| Oct 24 to Nov 3 | More reported starts. The agent was served on some launches only: one machine got it on 3 of about 19 launches since September 27. |
| Oct 31 15:38:43 to Nov 3 14:56:40 | Upload times of seven different builds of `insight.bundle`, all 205,135 bytes, from the server's `Last-Modified` and `ETag` headers: `6ae60b83` (Oct 31 15:38:43), `6ae69086` (Nov 1 01:06:14), `6ae78037` (Nov 1 18:08:55), `6ae8ccff` (Nov 2 17:48:47), `6ae90538` (Nov 2 21:48:40), `6ae9d408` (Nov 3 12:31:04) and `6ae9f628` (Nov 3 14:56:40), each followed by `-3214f`. The Oct 23 agent came from an earlier, smaller build (165,108 bytes, reported). |
| Nov 3, 17:04:28 | Level Infinite replaces `aegis-fix.min.js`. |
| Nov 3, 17:13:36 | `vue-bucket.min.js` is replaced. |
| Nov 3, 17:21:31 | Level Infinite replaces `images.7fec4c32.js`. |
| Nov 3, by 17:30 | The `l.js` that insightjs.com serves now looks like an ordinary analytics script. |
| Nov 3, 17:55 | A third party registers insightjs.org, the loader's fallback domain. It now shows a warning page in four languages. |
| Nov 3, 18:31 | 89.127.233.127, the server that sent the agent, does not answer (the connection times out). |
| Nov 3, 20:23 | 43.175.144.148 and 43.175.145.181 still serve the modified `FeedList.feb647c9.js`. |

## The loader

The code added to each CDN file hides the `l.js` URL in a `Uint32Array` and names insightjs.org as a fallback domain. It adds a `<script>` tag that loads `l.js`, then removes the tag. The insightjs.com address stays in the cache of the launcher's built-in browser, which is one of the traces behind the Exposed verdict.

## The agent

The Lua agent has no network code of its own: every check-in and upload goes through `l.js` in the launcher's embedded browser (`tbs_browser.exe` on Windows). From October 23 at the latest, and only on some launches, `l.js` used the launcher's JavaScript bridge to download `https://analytics.insightjs.com/comm/assets/insight.bundle` from 89.127.233.127, a VPS at 1984 ehf in Iceland. The launcher saved it in `Launcher/log/tinyget/` under a `tinyget` log name, or as `k2f.lua` on the earliest reported runs.

`insight.bundle` is LuaJIT bytecode, 205,135 bytes. The copy fetched on November 3 at 16:22 has SHA-256 `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec`. Victims ran other builds of the same size, so this hash does not match every infection. It is a remote-access agent with these commands: `exec`, `ls`, `cd`, `cat`, `download`, `file_chunk`, `screens`, `creds`, `keyscan`, `browserscan`, `chrome_scan`, `wallet_files`, `whoami`, `sysinfo`, `host_facts`, `chrome_install`, `chrome_cleanup`, `chrome_uninstall` and `payload_cleanup`.

The agent runs only while the launcher is open, except for the Chrome persistence on Windows described below. The launcher often stays open in the notification area while the game runs, so the agent can stay active for hours. Only `exec` starts new programs; the other commands run inside the launcher process, so Prefetch and process logs do not show them. Under Wine and Proton, the prefix's `Z:` drive maps to `/`, so its commands can reach the whole Linux or macOS home folder ([details](what-to-do.md#why-the-home-folder-is-exposed-under-wine)).

The agent leaves these traces:

- Lines in `Launcher/intl_service/debug.log`, which the launcher appends to at each launch. The infected test install held all 9 launches from October 29 to November 3.
- `k2f.agent.state`, its saved ID, in the launcher's Local Storage (`tbs_cache/Local Storage/leveldb`). The launcher data is outside the NIKKE folder, so this trace survives deleting the NIKKE folder.
- Temporary files named `k2f-bcreds-*` (collected browser credentials) and `k2f_screen_*.jpg` (screenshots).

## Persistence on Windows

On Windows the agent can install persistence aimed at Google Chrome (a real Chrome install, not the launcher's CEF). When the server sends the `chrome_install` command with the DLL, the agent writes it to `%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\<64 hex characters>\platform_experience_helper.dll` and registers it under `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32`, so that Chrome loads it. The agent creates that folder itself and never checks that Chrome is installed, so the DLL can be present on a PC without Chrome.

Before writing the DLL, the agent puts its own agent ID after a `/px/` placeholder and a 64-hex token from the server over a `BEARER000…` placeholder, then saves it under a folder name the server sends. Every installed DLL therefore has its own hash. The agent's `chrome_uninstall` only clears the default value of the HKCU key, so an empty key there is a leftover to delete too.

A victim who inspected the DLL without running it reported this (it was not checked here):

- It is a 64-bit DLL of 250,368 bytes, and its folder name is its own SHA-256.
- It reads password fields in web pages, catches wallet recovery phrases passed through `JSON.stringify` and `JSON.parse`, and names MetaMask, Phantom, Binance and SubWallet.
- It sends to `https://analytics.insightjs.com/px/<32 hex>`, where the 32 hex characters were that machine's agent ID. The DLL seems to be built per victim, so its hash is not a shared indicator: look for the path and the registry key.
- Microsoft Defender Offline (signatures 1.463.110.0) did not detect it.
- It stays locked until Windows restarts, even with Chrome closed. [What to do](what-to-do.md#remove-the-dll-persistence) gives the order of the steps.

The agent's cleanup code also deletes `service_util.dll` and a copy of `platform_experience_helper.dll` in Chrome's own `Application\PlatformExperienceHelper` folder, which probably come from an earlier version.

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
  89.126.250.172               insightjs.com before about Oct 22, reported by a victim (same 1984 ehf network)
  43.175.144.148               CDN server, still served the modified FeedList.feb647c9.js on 2026-11-03
  43.175.145.181               CDN server, same

URLs
  https://insightjs.com/l.js?f=aegis
  https://insightjs.com/l.js?f=images
  https://insightjs.com/l.js?f=feedlist
  https://insightjs.com/l.js?f=vue
  https://analytics.insightjs.com/comm/assets/insight.bundle
  https://analytics.insightjs.com/px/<32 hex>     (used by the Chrome DLL)

Modified CDN files
  https://sg-gpts.playerinfinite.com/comm/assets/lib/aegis-fix.min.js
  https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/images.7fec4c32.js
  https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/FeedList.feb647c9.js
  https://na-webassets.playerinfinite.com/comm/assets/lib/vue-bucket.min.js

SHA-256
  cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec  insight.bundle, Nov 3 16:22 copy (other builds exist)
  2f2aac505f486067af6831d6c75ea74df63acb1ed4e4002709c5962c68bd9203  FeedList.feb647c9.js, modified copy
  3aaafbd612f04501a6fdb0bb8b2f8a87796223e5584ac18ea5eb180feeafb193  vue-bucket.min.js, modified copy

Log strings in Launcher/intl_service/debug.log
  k2f_chan registered
  adopted <id>
  agent started as <hostname>
  startup already in progress
  lua downloaded to log\tinyget\...   (tinyget.<time>.log, or k2f.lua on early runs)
  resuming <id>

Files in Launcher/log/
  a tinyget log that names insight.bundle or analytics.insightjs.com
  a file that starts with LuaJIT bytecode (1B 4C 4A): the saved agent, such as tinyget/k2f.lua

Launcher Local Storage (tbs_cache/Local Storage/leveldb)
  k2f.agent.state

Windows persistence
  %LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\<64 hex>\platform_experience_helper.dll
  HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\InprocServer32
  (in a Wine prefix: the same key in user.reg)
  service_util.dll, and platform_experience_helper.dll in Chrome's Application\PlatformExperienceHelper (named by the cleanup code)

Temp files
  %TEMP%\k2f-bcreds-*
  %TEMP%\k2f_screen_*.jpg
```
