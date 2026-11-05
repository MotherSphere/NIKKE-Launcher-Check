# Security policy

## Reporting a vulnerability in nikke-check

Report security problems in nikke-check itself privately: open the [Security tab](https://github.com/MotherSphere/NIKKE-Launcher-Check/security) of this repository and click "Report a vulnerability". Do not open a public issue for them.

nikke-check reads launcher logs, caches, registry files and browser folders on computers that may be compromised, so a crafted file there is part of what it has to survive. Examples of what to report this way:

- a file on a scanned computer that makes nikke-check crash, hang, write or delete a file, or start a program
- anything that makes nikke-check connect to the network or send data off the computer
- a release file that does not match its `SHA256SUMS.txt` or was not built by the release workflow from the tagged source
- a way for "Hide my info" (`--redact`) to leave a computer name, user name, agent ID or home folder in the report

Say which release and system you used, what happened and how to trigger it. Remove tokens, cookies and personal data from any log you attach.

## What to report elsewhere

- Traces, logs or questions about the NIKKE PC launcher compromise itself: open a normal [issue](https://github.com/MotherSphere/NIKKE-Launcher-Check/issues), or comment on the [write-up](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5).
- A missed trace or a wrong verdict: open a normal issue, so other players can see it.
- Antivirus warnings about nikke-check: see [Antivirus warnings](README.md#antivirus-warnings).

## Supported versions

Only the latest release gets fixes. A fix ships as a new release, built and published by the release workflow.

## Response

One person maintains nikke-check. Reports are answered in the private report itself. There is no bug bounty.
