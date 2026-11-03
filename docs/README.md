# Documentation

The [project README](../README.md) has the download links, the quick start and the verdicts. These pages go into more detail.

For players:

- [Using the tool](usage.md): checking the download with `SHA256SUMS.txt`, the first start on each system, the window, the report, the command line, the exit codes and the Windows console notes.
- [What to do](what-to-do.md): the steps for each verdict, where the launcher cache `tbs_cache` is on each system, how to block the domains, how to remove the Chrome persistence on Windows, and why a Linux or macOS home folder is exposed under Wine.

Technical reference:

- [What happened](incident.md): the three modified CDN files, a GMT timeline, the loader, the agent and its persistence, and the indicators of compromise.
- [What it checks](checks.md): each check with its severity, the hosts file check, the times in the report, the verdict rules and the limits.
- [Where it looks](locations.md): the search roots and depths on Windows, Linux and macOS, the Wine prefixes, the skipped mounts, the walk rules and the entry cap.
- [Building and releases](building.md): building from source, the tests, the CI builds and the Release Please process.
