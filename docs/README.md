# Documentation

The [project README](../README.md) has the download links, the quick start and the verdicts. These pages go into more detail.

For players:

- [Using the tool](usage.md): checking the download with `SHA256SUMS.txt`, the first start on each system, the window and its three tabs, saving the report and "Hide my info" (`--redact`), the command line, the exit codes and the Windows console notes.
- [What to do](what-to-do.md): the steps for each verdict, where the launcher cache `tbs_cache` is on each system, how to block the domains and the two IP addresses, how to remove the DLL persistence on Windows, in a Wine prefix or from a mounted Windows drive, and why a Linux or macOS home folder is exposed under Wine.

Technical reference:

- [What happened](incident.md): the three modified CDN files, a GMT timeline, the loader, the agent and its persistence, and the indicators of compromise.
- [What it checks](checks.md): each check with its severity, the agent runs and payload builds, the data the malware could reach, the hosts file check, the times in the report, the verdict rules and the limits.
- [Where it looks](locations.md): the search roots and depths on Windows, Linux and macOS, the Wine prefixes, the skipped mounts, the walk rules and the entry cap.
- [Building and releases](building.md): building from source, the tests, the CI builds and the Release Please process.
