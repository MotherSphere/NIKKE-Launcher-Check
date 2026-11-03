# Where it looks

"Scan this computer" (or `nikke-check --cli` with no folder) searches the places below for NIKKE installs, launcher data folders, user profiles and Wine prefixes. "Scan a folder..." and `nikke-check --cli PATH...` search only the folders given; see [Folder scans](#folder-scans). [What it checks](checks.md) describes what is read in each location.

## Windows

- Every fixed and removable drive from `A:\` to `Z:\`, 5 folder levels deep (enough for `C:\Program Files\Level Infinite\NIKKE\Launcher\nikke_launcher.exe`), skipping `\Windows`. Mapped network drives and CD drives are not walked, and the report lists the network drives it skipped.
- `%APPDATA%\nikke_launcher` and `%APPDATA%\nikke_launcher_hmt`.
- The `%USERPROFILE%` profile.

The tool also reads the install path the launcher records, which finds installs deeper than 5 levels:

- `url_protocol.reg` in the launcher data folder
- `HKCU\Software\Classes\nikkelauncher\DefaultIcon`
- `GameInstallPath` under `Software\Microsoft\Windows\CurrentVersion\Uninstall\nikke_launcher`, in HKCU, and in both the 64-bit and 32-bit views of HKLM

A recorded path counts only if it still holds `Launcher/nikke_launcher.exe` or `Launcher/intl_service/debug.log`, since an install can be moved after it was recorded.

Empty card readers and optical drives do not make Windows show "There is no disk in the drive" boxes during the scan: the tool turns those boxes off for its own process.

## Linux

The tool walks `$HOME` (7 levels), then `/mnt`, `/media`, `/run/media/$USER`, `/opt` and `/games` (6 levels each). Where `/media` is a link to `/run/media` (Fedora Silverblue, Bazzite), only `/run/media/$USER` is walked. Under `sudo` or `pkexec`, the home folder and user name come from `/etc/passwd` for the user who ran the command (`SUDO_USER` or `PKEXEC_UID`), not from root.

It also opens these Wine prefixes directly. A folder counts as a prefix when it holds a `drive_c` folder.

- `~/.wine`
- Steam compatdata, `<library>/steamapps/compatdata/*/pfx`, for the Steam folder itself and every library listed in its `libraryfolders.vdf`, under `~/.local/share/Steam`, `~/.steam/steam`, Flatpak Steam (`~/.var/app/com.valvesoftware.Steam/.local/share/Steam`) and Snap Steam (`~/snap/steam/common/.local/share/Steam`)
- `~/Games/*` (Lutris and others) and `~/Games/umu/*`
- Heroic, `~/Games/Heroic/Prefixes/*` and `~/Games/Heroic/Prefixes/default/*`
- Bottles, `~/.local/share/bottles/bottles/*` and `~/.var/app/com.usebottles.bottles/data/bottles/bottles/*`
- Faugus, `~/Faugus/*`

### Network and remote mounts

"Scan this computer" skips the network and remote mounts listed in `/proc/self/mountinfo`:

- the network filesystems `nfs`, `nfs4`, `cifs`, `smb3`, `smbfs`, `ncpfs`, `afs`, `ceph`, `glusterfs`, `lustre`, `9p`, `davfs` and `sshfs`
- every FUSE type (`fuse` and `fuse.*`, such as sshfs, rclone, s3fs or a phone over MTP), except those that keep their data on local disks: `mergerfs`, `bindfs`, `gocryptfs`, `encfs`, `cryfs`, `ntfs-3g`, `fuse-overlayfs`, `squashfuse`, `lxcfs` and `unionfs`. `fuseblk` (ntfs-3g on a disk partition) is local too.
- automount points that are not mounted yet, unless `/etc/fstab` gives them a local filesystem type, because opening one would mount it

A network home folder is still scanned. Reading a large share is slow, and a disconnected one can block the scan. "Stop scan" in the window goes back to the start screen without waiting for it. The report lists the mounts it skipped; scan one with "Scan a folder..." if NIKKE is on it.

## macOS

NIKKE has no native Mac client, so on a Mac it runs only through Wine-based tools. The tool searches `$HOME` (6 levels), `/Applications` (4 levels) and each local volume in `/Volumes` (5 levels). Links in `/Volumes`, such as `Macintosh HD`, which points to `/`, are not walked.

Network volumes and other non-local mounts are skipped wherever a walk meets them, and the report lists them. The tool reads the list from the kernel's cached mount table, which never asks a server, so a dead share cannot block it. A network home folder is still scanned.

It opens the prefixes of:

- Wine, `~/.wine`
- CrossOver, `~/Library/Application Support/CrossOver/Bottles/*`
- Whisky, `~/Library/Containers/com.isaacmarovitz.Whisky/Bottles/*`
- Wineskin, Kegworks and Sikarugir wrappers, `*.app/Contents/SharedSupport/prefix` in `/Applications` and `~/Applications`, and one folder down, such as `~/Applications/Wineskin/NIKKE.app`, where their Winery saves new wrappers
- Heroic, `~/Games/Heroic/Prefixes/*` and `~/Games/Heroic/Prefixes/default/*`

When a folder cannot be read, the report names it. On macOS this usually means Terminal needs Full Disk Access (System Settings > Privacy & Security).

## Inside a Wine prefix

Any `drive_c` folder found along the way also counts as a Wine prefix, on every system. In each prefix the tool:

- checks every user folder in `drive_c/users` except `Public`, and the launcher data in its `AppData/Roaming`. A user folder that is a symbolic link is skipped: Proton links your login name to `steamuser`, which is the same profile.
- searches `drive_c` for an install, 5 levels deep in a computer scan and 12 in a folder scan, skipping `drive_c/windows`
- checks whether the folder that holds the prefix is an install, since installs often keep their prefix inside (`NIKKE/prefix` next to `NIKKE/Launcher`)
- reads the install path the launcher writes into `user.reg` (App Paths, Uninstall and the `nikkelauncher` URL protocol) and into `url_protocol.reg` in the launcher data, and follows its drive letter through the prefix's `dosdevices` link

A recorded path counts only if it still holds `Launcher/nikke_launcher.exe` or `Launcher/intl_service/debug.log`, since an install can be moved after it was recorded.

## Folder scans

"Scan a folder...", a dropped folder, `nikke-check <folder>` and `nikke-check --cli PATH...` walk each folder 12 levels deep, and the `drive_c` of each Wine prefix inside it 12 levels deep. Network mounts are not skipped in a folder scan. The running-program check and the hosts file check run as in a computer scan.

On Windows, a folder scan of your own profile, or of a folder above it such as `C:\Users`, also runs the checks for the user running the tool: `%TEMP%` and the HKCU registry key (see [User profiles](checks.md#user-profiles)).

## Walk rules

Walks never follow symbolic links: Wine links `dosdevices/z:` to `/`, which would loop. They skip `node_modules`, `.git`, `.cache`, `.Trash*`, `$Recycle.Bin`, `System Volume Information`, `dosdevices`, `/proc`, `/sys`, `/dev` and `/run/user`. A walk does not enter a launcher data folder or a `drive_c` folder. The launcher data checks read the first, and the prefix rules above walk the second.

A scan stops after 3,000,000 entries and the report says so ("The entry limit was reached, so some folders were not visited."). Folders it may not read are counted as permission errors and skipped. When a search root, a Steam or bottle folder, or a prefix folder cannot be read, the report names it.

On the Linux machine used for testing, a full scan visited about 597,000 entries in 2.0 seconds with a warm file cache. The start screen warns that a full scan can take a few minutes.
