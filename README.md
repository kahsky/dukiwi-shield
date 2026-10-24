# 🛡️ Dukiwi Shield

Dukiwi Shield is an antivirus, protection and integrity-checking program for Linux: the **ClamAV** antivirus with
a system service and real-time protection, firewall and network profiles, known vulnerabilities, integrity and
rootkit checks, hardening, link and e-mail checking, honeypot, backups and encrypted vault. **Linux Mint 22**,
**Ubuntu 24.04 to 26.04** and **Fedora 44+**. The interface follows the system language: French, English, German,
Italian (English for any other locale), changeable in Settings. Developed by **Dukiwi SA** —
Estavayer-le-Lac, Switzerland.

![Dukiwi Shield interface](https://www.dukiwi.com/repo/dukiwi-shield/dukiwi-shield.png?v=200)


## Installation

### Linux Mint 22 and Ubuntu 24.04 to 26.04 (signed APT repository, automatic updates)

The `noble` suite serves all these releases:

```bash
sudo mkdir -p /usr/share/keyrings
curl -fsSL https://www.dukiwi.com/repo/apt/dukiwi.gpg | sudo tee /usr/share/keyrings/dukiwi.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/dukiwi.gpg] https://www.dukiwi.com/repo/apt noble main" | sudo tee /etc/apt/sources.list.d/dukiwi.list
echo "msmtp msmtp/apparmor boolean false" | sudo debconf-set-selections   # answers the only question asked during installation (see below)
sudo apt update && sudo apt install -y dukiwi-shield
```

Unattended installation: chkrootkit recommends a mail server and the package picks msmtp, the lightest one; msmtp
asks on the way whether to enable its AppArmor profile (default answer: no). The `debconf-set-selections` line
answers in advance. Without it, `DEBIAN_FRONTEND=noninteractive` in front of `apt install` gives the same result.

### Fedora 44+ (and derivatives: Nobara, Ultramarine…) — signed dnf repository

```bash
sudo curl -fsSL -o /etc/yum.repos.d/dukiwi.repo https://www.dukiwi.com/repo/rpm/dukiwi.repo
sudo rpm --import https://www.dukiwi.com/repo/rpm/dukiwi.asc
sudo dnf install dukiwi-shield
```

Signed "noarch" RPM, signed dnf repository (packages and index). On Fedora the application talks dnf and rpm
instead of apt and dpkg, firewalld instead of UFW (Home / Public / Work profiles ↔ home / public / work zones),
SELinux instead of AppArmor in the checklist, `rpm -V` instead of debsums, dnf security advisories (with their
CVEs) in System status; the OSV inventory of unfixed vulnerabilities does not exist for Fedora. Under GNOME, the
AppIndicator extension (`gnome-shell-extension-appindicator`, recommended by the package) shows the shield.
Application updates arrive through dnf or Software.

Updates then come through Mint's Update Manager, Ubuntu's Software or dnf. The application also announces new
versions itself (popup or Security tab) and can install them on its own when the option is enabled in Settings.

### Direct download

- Mint / Ubuntu: [dukiwi-shield_2.5.1_all.deb](https://www.dukiwi.com/repo/dukiwi-shield/dukiwi-shield_2.5.1_all.deb)
- Fedora: [dukiwi-shield-2.5.1-1.noarch.rpm](https://www.dukiwi.com/repo/rpm/fedora/noarch/dukiwi-shield-2.5.1-1.noarch.rpm)
- All versions: [www.dukiwi.com/repo](https://www.dukiwi.com/repo)

### Installing a downloaded package by hand

```bash
sudo apt install ./dukiwi-shield_2.5.1_all.deb          # Mint / Ubuntu
sudo dnf install ./dukiwi-shield-2.5.1-1.noarch.rpm      # Fedora
```

The installation enables the system service and the scheduler, then starts the initial scan:

```bash
systemctl status dukiwi-shield-daemon          # service (root)
systemctl list-timers dukiwi-shield-update # next update check
journalctl -u dukiwi-shield-daemon -f          # follow the initial scan
```

### Uninstalling

```bash
sudo apt remove dukiwi-shield   # Mint / Ubuntu
sudo dnf remove dukiwi-shield   # Fedora
```

---

## Features

- **Quick scan (2.5.1)** — "Quick scan" button on the dashboard, the Scan tab, the simple view and the shield menu:
  scans the home folders and the places where malware settles in (`/tmp`, `/var/tmp`, `/dev/shm`, cron and systemd
  folders, autostart, `/etc/profile.d`, `/etc/init.d`, `/usr/local`, `/opt`, `/var/www`, `/srv`, `/root`) plus the
  executables of running programs that do not come from the system. Same engine, quarantine and cache as the full
  scan (unchanged files already verified are not read again); started by the service without a password.
- **Extensions, SSH keys, scheduled tasks and services, SUID files, weekly summary (2.5)** —
  1. *Real-time persistence watch*: every minute the service compares a cheap fingerprint of the autostart folders,
     crontabs, `/etc/cron.*`, `/etc/systemd/system`, user units, `at` jobs, `/etc/profile.d`, `rc.local`, `ld.so.preload`
     and the browser extension folders; when it changes, the full inventory runs and every new item raises an alert
     (before, once a day). New kinds: systemd timers (system and user) and pending `at` jobs.
  2. *Browser extensions*: each extension's sensitive permissions are read (read and change all sites, native
     messaging, debugger, proxy, cookies, history, clipboard…). A new extension and, above all, an update that adds
     such permissions (a typical sign of a sold or hijacked extension) raise an alert naming them.
  3. *Authorized SSH keys* (Security › SSH keys): `authorized_keys` of every account checked every 30 seconds; a new
     key raises an alert (red when the SSH server runs). The page lists every key (type, comment, SHA256 fingerprint
     like `ssh-keygen -l`, options) with "Remove": no password for your own keys, administrator for another account.
  4. *SUID/SGID files outside packages*: daily scan of the local file systems, the decrypted eCryptfs view and the
     temporary folders (containers, Flatpak and snap left out), package owner checked (dpkg with merged `/usr`, rpm).
     New checklist item, red when such a file sits in `/tmp`, `/dev/shm`, `/var/tmp`, `/run` or a home; "Ignore" by path
     and SHA-256 (comes back if the file changes); a new one raises an alert.
  5. *Weekly summary*: every Monday from 08:00 the service sums up the last 7 days (score and its change, scans and
     files, alerts, threats isolated, links blocked, programs suspended, network events, changes reported, items to
     fix), keeps 8 weeks, shows it at the top of Security › Journal and in the weekly popup, and e-mails it when e-mail
     notifications are set up.
- **Restore test, after an attack, password quality, browser settings, Internet exposure (2.4)** —
  1. *Restore test*: once a month, as soon as a destination is plugged in or reachable, a few random files of the
     latest backup are restored to a temporary folder, read in full and, when the original has not changed since (same
     size and date), compared with it; "Test the restore" runs it at once (Backups tab). The service does the same for
     the latest Timeshift snapshot (rsync mode). New checklist item "Restore test"; a failed test raises a popup.
  2. *After an attack* (Security › After an attack): thirteen steps to tick, each with its button: isolate, full scan,
     alerts, integrity, autostart and extensions, certificates/proxy/DNS, passwords from another device, sign out the
     other sessions, updates, recover files from a backup, report (NCSC in Switzerland, national offices elsewhere),
     keep the PDF report, restore the network.
  3. *Password quality*: checklist item; "Apply" installs pam_pwquality if needed and writes
     `/etc/security/pwquality.conf.d/90-dukiwi-shield.conf` (12 characters minimum, no dictionary word, no user name).
     Existing passwords stay valid.
  4. *Browser security*: Firefox profiles (safe browsing, download checks, HTTPS-only mode, signed extensions) and
     Chrome, Chromium, Brave, Edge (safe browsing). "Apply" writes a marked block in the Firefox `user.js` of the user
     asking for it and a *recommended* policy (that the user can change) for the Chromium family.
  5. *Internet exposure* (Firewall › Internet exposure): after explicit consent, the Dukiwi server
     (`repo/api/exposure.php`) tries to connect back to the public address on 26 common ports plus the ports this computer
     listens on (parallel connections, 3 seconds, one test per address every 10 minutes, nothing stored). UPnP: the
     router is found by SSDP or, when the local firewall drops the reply, on the usual description addresses; its port
     mappings are listed and those pointing to this computer count in the checklist.
- **Filtered DNS, isolate the computer, sandbox, home encryption assistant (2.3)** —
  1. *Filtered DNS* (Firewall › Filtered DNS): systemd-resolved asks Quad9 (Switzerland, no logs) or Cloudflare
     1.1.1.2, which refuse to resolve malware and phishing domains, over DNS-over-TLS when the network allows it
     (`/etc/systemd/resolved.conf.d/90-dukiwi-shield-dns.conf`, `Domains=~.`). After applying, the service checks
     that names still resolve and goes back to the network DNS otherwise; on a network with the Enterprise profile the
     filter is suspended so internal company names keep working. New checklist item.
  2. *Isolate the computer* (Firewall › Isolate, shield menu): the network is cut (NetworkManager, otherwise firewalld
     panic mode, otherwise ufw denying everything), programs started from a temporary folder, deleted from disk or
     named in a red alert of the last 24 hours are suspended, and a full scan starts. A red banner stays on every page
     until "Restore the network"; suspended programs stay suspended until you decide. Isolating never asks for a
     password; restoring needs the administrator in family mode.
  3. *Sandbox*: right-click a file in Nemo › "Open in a sandbox": the file is copied to a temporary folder that becomes
     the home of its default program under firejail (no network, private /tmp, no session bus, no capabilities,
     seccomp). Before opening, the launcher checks that the real home and the network are really out of reach and
     refuses otherwise (firejail only warns when it detects another sandbox). firejail is a recommended dependency.
  4. *Home encryption assistant* (Security › Encryption): disk already encrypted (LUKS) or home already encrypted
     (eCryptfs, fscrypt), file system, ext4 `encrypt` feature, fscrypt and pam_fscrypt, free space for the copy; then the
     steps with the commands to copy (backup, install, setup, log out, migrate, check, clean up). It changes nothing itself.
- **Ransomware decoys, camera and microphone, miners, root certificates, network redirection (2.2)** —
  1. *Ransomware decoys*: a hidden file `.dukiwi-guard-<id>` (a real .docx, .jpg, .pdf or .xlsx) sits in Documents,
     Pictures, Desktop and the home folder of each user (localised XDG folders, a per-machine suffix so two computers
     syncing the same folder never share a decoy). No program has a reason to write it: the program that does is seen by
     fanotify, suspended (automatic response) and reported in a red popup with Terminate, Quarantine, Resume and "It's
     me". A decoy deleted, renamed or replaced is reported with the program that was writing in that folder at that
     moment, or as a warning when none is found, and recreated. Decoys are removed when the option is turned off or the
     package is uninstalled.
  2. *Camera and microphone*: a program that opens `/dev/video*` (read from `/proc/*/fd`) or records the microphone
     (`pactl list source-outputs` in each sound session; speaker monitors, PipeWire and volume meters left out) raises a
     popup "X is using the camera" with "Always allow" (listed in Trusted programs, removable).
  3. *Cryptocurrency miners*: known miner name, pool address (`stratum+tcp://`, pool domains) or miner options in the
     command line → danger and suspension; connection to a pool port with a saturated CPU → danger; a program outside
     the packages that keeps a CPU core busy for 15 minutes → warning (games under Steam, Lutris, Heroic or Wine left out).
  4. *Added root certificates*: system anchors (`/usr/local/share/ca-certificates`, `/etc/pki/ca-trust/source/anchors`)
     and NSS databases (Firefox, Chrome, Thunderbird, snap and Flatpak included; read on a copy with `certutil`). New
     checklist item "Added root certificates", "Ignore" by SHA-256 fingerprint; each new certificate raises an alert.
  5. *Network redirection*: `/etc/hosts` entries pointing to a public address, proxies (GNOME/Cinnamon, KDE, Firefox,
     `/etc/environment`, apt, dnf) and a new unknown public DNS server on an already known network (well-known resolvers,
     VPN links and the router's IPv6 address left out). New checklist item "Network redirection", "Ignore" per entry; each
     new one raises an alert.
  Three new switches in Settings › Real-time protection; journal category "Camera and microphone".
- **Score history, security journal and report (2.1)** — the service keeps one score per day (400 days) and the Score
  and checklist page shows its curve over 30 days, 90 days or a year, with a crosshair tooltip and a table of values.
  New Security › Journal page: alerts and service actions (scans, behaviour, firewall, network, honeypot, USB, updates,
  hardening, approvals, accounts, backups, settings) merged from the alert list and the service log, filtered by period,
  category, severity and text, exported as CSV or JSON; scan engine warnings are left out. "PDF report" and "HTML
  report" produce a security report of the computer (system, score and its trend, every check, vulnerabilities, integrity,
  alerts of the last 30 days), the PDF being printed offscreen by WebKit.
- **2.0.1: shield after the migration** — the previous package's user service could restart its shield just before its
  files were deleted; that ghost process kept the instance lock carried over with the data folder, so the Dukiwi Shield
  shield exited at once and no tray icon appeared. The lock has a new name, and the service stops the old user service
  and any leftover process of the previous package in every session, then launches the shield right away.
- **Dukiwi Shield 2.0** — the program is now Dukiwi Shield from end to end: package `dukiwi-shield`, files under
  `/opt/dukiwi-shield`, `/var/lib/dukiwi-shield` and `/var/log/dukiwi-shield`, service `dukiwi-shield-daemon`, modules
  `dukiwi_shield_*.py`, extensions and command `dukiwi-shield`. Installing it replaces the previous package
  (Conflicts/Replaces on Debian, Obsoletes on Fedora) and carries over its state, quarantine, scan cache, logs, policy,
  hardening files, update time, USB manifests and per-user data; old systemd links and the old autostart entry are
  removed and the old browser extensions are uninstalled by policy.
- **System service** (`dukiwi-shield-daemon`) — runs permanently as root and performs full scans and updates
  on behalf of a user **without admin rights**, hence **without a password**. If the service is missing, the
  application asks for the administrator password (`pkexec`).
- **Scheduled updates** — signature check **every day at 07:00** and **5 minutes after each boot** (systemd timer,
  caught up if the computer was off).
- **Automatic initial scan** — a full system scan starts on its own after the first installation (resumed
  automatically if interrupted by a shutdown).
- **Behavioural detection** — the service watches (fanotify) programs that modify many files in a short time:
  information popup (even for the system), or **potential danger** if the program is unknown to the system (not
  from a dpkg package, started from /tmp or the home directory) or if `clamd` recognises its executable or its files.
- **USB sticks** — scanned **before** they are made available (udev rule + private mount by the service), progress
  popup, then automatic mount and opening. USB hard drives (> 128 GiB) trigger a **question** "scan or not".
- **System status** — pending security updates and the **CVEs** they fix (extracted from apt changelogs), reboot
  required, button to the update manager, alert history.
- **Sliding popups** — bottom right, they slide out from behind the taskbar: signatures up to date, scan finished
  without threat, threats, unusual activity, USB.
- **Four languages** — French, English, German, Italian (locale detection, selector in the sidebar).
- **Simple view / advanced view** — the simple view (default) fits in the window without scrolling and reassures a
  non-expert: "Your system is protected", six indicators (antivirus, monitoring, firewall, remote access, updates,
  threats) with a fix button when something is wrong. The advanced view exposes all tabs.
- **Settings** — Internet upload threshold triggering a popup (5 GB by default, adjustable observation window),
  behavioural detection thresholds, USB, update check time, weekly full scan, popups to show, language and view.
  System settings are applied by the service, without a password.
- **Firewall and SSH** — UFW state (policies, rules) and SSH service, enable or disable, simple rules (port,
  protocol, action) and default policies, all through the service. Remote access is flagged when active.
- **Internet upload** — the service measures the volume sent (`/proc/net/dev`) and shows a popup above the
  threshold, with the list of connected programs (`ss`).
- **Security centre** (Security tab) — score and checklist (firewall, SSH, LUKS encryption, Secure Boot, AppArmor,
  automatic updates — an "Enable" button that turns on Mint's Update Manager automation (or unattended-upgrades)
  then automatic updates of Cinnamon Spices and Flatpaks —, accounts without password, passwordless sudo, exposed
  ports, exposed services, `ld.so.preload`, antivirus…), inventory of **open vulnerabilities** of the installed
  packages through OSV.dev (unfixed / Ubuntu Pro / fix available, Ubuntu priority and CVSS vector), Flatpak/Snap
  updates, integrity check (Lynis, chkrootkit, debsums, application files vs signed manifest).
- **Outbound connections** — programs connected to the Internet with country/operator, alert for a program
  unknown to the system or an address from the Feodo Tracker / SSLBL lists. Geolocation through ip-api.com: free
  service by default (HTTP, 15 batched requests/min, non-commercial use), at most one request every 5 s, an address
  requested once per 24 h, persistent cache; an **ip-api.com Pro** key (HTTPS, no limit) can be entered in
  Settings. The number of requests over 24 h is shown under the key.
- **Persistence** — autostart, systemd units, cron, `rc.local`, `ld.so.preload`, Chrome/Firefox extensions
  (out-of-store ones flagged); alert for every new entry.
- **Automatic response** — a program deemed dangerous is suspended (SIGSTOP) and the popup offers
  Terminate / Quarantine / Resume.
- **Family mode and admin lock** — disabling the firewall, opening a port, enabling SSH, installing an update or
  changing settings (family mode) requires administrator authentication through polkit (`pkexec`), valid for
  15 minutes.
- **Good practices (security awareness)** — page reachable from the simple view ("Learn to protect myself") with
  18 lessons for non-experts: do not click without reading, phishing, CEO fraud, unusual e-mail,
  `salaries.xlsx.exe`, booby-trapped USB sticks, virus / worm / Trojan / cryptolocker, what a vulnerability is, why
  updates matter, passwords, backups, fake support, social engineering, public Wi-Fi, admin password, reacting to
  an attack, extensions. A **tip of the day** appears as a popup at startup ("Read more" opens the lesson; can be
  disabled in Settings). Content in `ui/awareness.js`.
- **Network type (firewall)** — Home, Public or Work, as on Windows. Public: no incoming connection. Home: SSH (if
  active), CUPS printing, Samba sharing, mDNS discovery and KDE Connect allowed from private ranges (10/8,
  172.16/12, 192.168/16, fe80::/10), depending on what is installed. Work: SSH, CUPS and Samba from the current
  subnet only, stronger UFW logging. Profile rules are tagged `cav-profile` and replaced at each change; personal
  rules stay, and in Public the application flags those open to the whole Internet. Choosing the profile does not
  ask for a password (the service applies the rules), except in family mode.
- **One-click Lynis hardening** — the "Hardening (Lynis)" card of the Security tab lists every suggestion of the
  audit with a plain-language explanation: risk-free recommendations (sysctl parameters, core dumps, legal banners,
  unused protocols, audit tools, old kernels, permissions…) apply with one click or all at once (`dukiwi_shield_harden.py`:
  `90-dukiwi-shield-*` files, previous values kept for "Undo"), those to read before applying (umask, SSH,
  TMPDIR) stay manual, the others are explained (false positives, not relevant on a desktop). Lynis is re-run after
  each application; "apply automatically after each audit" setting in the settings.
- **Fast scan engine** — the service scans through clamd (signature database in memory, started on demand) with
  several parallel `clamdscan --fdpass` (up to 8 batches of 100 files, 3 for a USB stick), falling back to
  `clamscan --file-list` if clamd is missing. **Clean-file cache**: the fingerprint (size, mtime, ctime, inode) of
  every scanned clean file is kept in `scan-cache.db` (SQLite); an unchanged file is not read again for
  `scan_cache_days` days (30 by default, adjustable, "Rescan everything" checkbox on the scan). **USB sticks**: a
  hidden `.clamav` file (JSON signed with HMAC and a secret specific to the installation, never on the stick)
  lists the clean files; at the next insertion only new or modified files are read. **Stick during a scan**: the
  running scan is paused (workers suspended), the stick is scanned right away, then the scan resumes.
- **Profile remembered per network** — the service identifies the current network (NetworkManager connection
  holding the default route, otherwise the gateway's MAC address) and remembers the profile chosen for each
  network. An unknown network always goes Public ("New network" popup, "Change" button to the Firewall tab); a known
  network gets its profile back at each connection; "Forget" a network sends it back to Public. At the first update
  the current network inherits the profile already chosen.
- **UFW rules really applied** — the service calls `ufw --force rule allow …`: without the explicit `rule` keyword,
  ufw does not recognise a rule placed after `--force` ("Invalid syntax"), which made network profiles and rules
  added from the application fail; ufw's error message is now logged and shown.
- **Readable integrity warnings** — the full text is shown (chkrootkit lists paths under its "suspicious files"
  header: they are kept), known false positives are explained (.build-id, .packlist…) and "That's normal" approves a
  warning: set aside, it no longer counts in the state nor in the next reports ("Remove" reactivates it). The
  service classifies the hidden files reported by chkrootkit itself: shipped by an installed package (`dpkg -S`),
  known name (.build-id, .packlist, npm/Python markers) or unknown (to check); same treatment for "Linux.Xor.DDoS"
  (chkrootkit lists every executable file in /tmp: Chrome extensions, Timeshift scripts, text files and build
  directories are benign, only an unknown ELF binary remains to check); a fully benign finding becomes "known false
  positive" without intervention, and an incomplete chkrootkit report (old version) is re-run alone at startup.
- **Vulnerabilities** — installed but not running kernels are no longer queried on OSV (neither counted nor shown);
  OSV answers are paginated, a kernel exceeding the 1000 entries of a page. Vulnerabilities of the `mozjs*`
  JavaScript engine (SpiderMonkey extracted from Firefox ESR, used by cjs/gjs/polkit) that describe the browser (web
  content, media, tabs…) are classified "Not applicable (embedded engine)" with the list of programs using it;
  those specific to the engine (JIT, WebAssembly, garbage collector) stay "Unfixed"; "embedded JS engine, not
  Firefox nor Thunderbird" badge on those lines, existing report reclassified at service startup. Packages built by
  Linux Mint (`+linuxmint` version, Thunderbird, Firefox…) are outside Ubuntu's CVE tracking: their "needed"
  vulnerabilities are classified not applicable with the installed version as a note.
- **Vulnerabilities with no possible fix explained** — a built-in base (TunnelVision CVE-2024-3661…) shows under
  the vulnerability what it is (design flaw, Ubuntu's "deferred" status) and whether it concerns you (VPN configured
  or not); the checklist counts distinct CVEs, not once per package.
- **Permanent shield** — the tray is launched by `dukiwi-shield-tray` in a transient systemd user service
  (`Restart=always`): killed, it comes back within a second; the root service also checks every 20 s that each
  active graphical session has its shield and relaunches it otherwise. "Quit" requires administrator authentication
  (pkexec), stops the user service cleanly and tells the root service not to relaunch in this session (a new login
  relaunches it).
- **Explicit consent** — at first use (after the legal notice), a full page asks whether you accept the weekly
  anonymous report: what it is for, what is never sent, and the exact example of what would leave this computer
  (`telemetry_preview` command, nothing is transmitted). Mandatory answer, remembered, changeable later in Settings.
- **Usable telemetry** — the weekly (opt-in) submission adds approved integrity warnings and benign classifications
  (material for built-in rules), measurements of the last scan (duration, files, cache share, engine), applied
  hardening settings, packages with high vulnerabilities, the Lynis index and the main settings. Server side:
  IP fingerprint with a monthly salt, kept twelve months. `repo/api/summarize.py` deduplicates per installation,
  outputs allowlist candidates (threshold of distinct installations, already covered or not), aggregated
  measurements, and generates a JSON and an HTML statistics page without any identifier.
- **Readable quarantine and in-app modals** — each isolated file shows the detected signature as a title, then the
  file name and its original folder (index fed by the "moved to" lines of clamdscan/clamscan, service side and local
  scan side); confirmations (deletion, emptying, firewall, logs) go through a modal in the application's theme,
  never through a native `confirm()`.
- **Service in the C locale** — the tool outputs parsed (ufw, iptables, dpkg, apt…) are always in English: with a
  French system, systemd gave the service `LANG=fr_CH.UTF-8` and "ufw status" answered "État : actif", hence a
  firewall seen inactive after a successful activation. Fallback: presence of the `ufw-user-input` chains in the
  kernel (same test as ufw-init).
- **Verified firewall activation** — `ufw enable` answers "active" even when loading the rules fails if `ufw.conf`
  already said `ENABLED=yes`; the service checks the real state, forces disable → enable then `ufw-init start` to
  get the error, shows it ("The firewall could not be loaded: …"), enables `ufw.service` at boot and flags another
  active firewall manager (firewalld, nftables with `flush ruleset`, netfilter-persistent). Checklist and score are
  recomputed after each firewall/SSH action.
- **Telemetry after the first full scan and on demand** — the first full scan completed after consent triggers the
  anonymous report without waiting for the week (performance measurements); "Send telemetry now" button in
  Settings.
- **"Ignore" an intended passwordless sudo rule** — the "Passwordless sudo" checklist item gets an "Ignore" button:
  the flagged /etc/sudoers.d files are approved together with the SHA-256 of their content, so they no longer count in
  the score but are flagged again as soon as the file changes (a rule widened to `NOPASSWD: ALL` reappears). Approved
  rules are listed in Security › Trusted programs with "Remove"; administrator required in family mode.
- **Credits: every component and data source** — the Credits window lists the 26 tools Dukiwi Shield drives, grouped
  (Antivirus, Integrity and audit, Firewall and network, System, Backups and encryption, Applications and browsers,
  Interface), each with its role, licence and website, and the 10 data sources and online services it consults (Cisco
  Talos signatures, OSV.dev and the Ubuntu CVE Tracker, Fedora advisories, OpenPhish, Phishing.Database, URLhaus via
  urlhaus-filter, Feodo Tracker and SSLBL, ip-api.com, Have I Been Pwned and XposedOrNot, LVFS) with what each is used
  for; the version shown is the installed one and the description covers the whole security suite.
- **Sub-menus in the sidebar, one page per section** — Security, Firewall and Settings unfold in the sidebar like an
  accordion (chevron; a second click folds the sub-menu); the item itself opens the main page of the tab (Firewall: firewall and network type; Settings: general and popups;
  Security: score and checklist) and each sub-item opens a page showing only that section, with
  short translated labels (Firewall: Rules, Remote SSH; Security: Honeypot, Links and e-mails, Known vulnerabilities, Integrity and rootkits, Hardening, Application update, Data
  breaches, Apps outside repositories, Trusted programs; Settings: Internet upload, Behavioural detection and ten more); links to a card (checklist "Fix", popups, simple view) open its page. The sidebar scrolls when a sub-menu is long.
- **Security tab in sections** — the Security tab uses the same accordion: Score and checklist (the score ring now sits
  inside this section, counts in its title), Network honeypot, Links and e-mails, Known vulnerabilities, Integrity and
  rootkits, Hardening (Lynis), Application update, Data breaches, Apps outside the repositories and Trusted programs,
  moved here from Settings. Status and action buttons stay in each title while collapsed; links that jump to a card
  (checklist "Fix", simple view, popups) open its section first.
- **Accordion sections (Firewall, Settings)** — each card of the Firewall and Settings tabs is a collapsible section:
  the title stays visible with its status badges (firewall and SSH state, current network profile, number of rules),
  the content folds away, the open/closed state is remembered per section, with "Expand all" / "Collapse all". The
  Firewall tab is split into Firewall, Network type, Firewall rules and Remote access (SSH); the former "Security and
  family" settings card is split into Family and automatic response, Real-time protections, Links and e-mails,
  Outbound connections, Integrity and hardening, Application updates, Overall state and telemetry. "Fix" buttons of
  the checklist open the matching section directly.
- **URLhaus list restored** — abuse.ch withdrew its public URLhaus exports (HTTP 410 on every download URL, the API now
  requires a key): the link checker now reads the free urlhaus-filter mirror (malware-filter on GitLab, built from the
  URLhaus API every 12 hours, adblock format with exact addresses and whole hosts); a changed feed source drops the
  old ETag and downloads at once.
- **Six new checklist items** — *Automatic login* (LightDM, GDM, SDDM configuration: a stolen laptop opens straight
  onto the files), *Screen lock* (per user: Cinnamon/GNOME dconf lock-enabled and idle-delay, KDE kscreenlockerrc),
  *Firmware* (fwupd / LVFS updates checked daily, "Update the firmware" runs `fwupdmgr update` through the service,
  BIOS/UEFI capsules apply at the next reboot), *Thunderbolt / USB4* (security level "none" without IOMMU DMA
  protection), *Secrets in the clear* (SSH private keys without passphrase, keys or ~/.ssh readable by other accounts,
  .netrc, AWS, git and Docker credentials, listed per user), *Access attempts* (failed authentications of the last
  24 h from the journal: login, sudo, SSH; warning from five). A new user account (uid ≥ 1000) raises an orange popup
  and an event. Expensive checks are cached ten minutes; "How to" texts in four languages.
- **BadUSB: new USB keyboards cut off until approved** — a booby-trapped stick presents itself as a keyboard and
  types commands. Any new USB device that declares itself a keyboard (udev `ID_INPUT_KEYBOARD`) is cut off the moment
  it appears (`authorized` = 0, the kernel removes it) and a red popup asks "Allow this keyboard / Keep it cut off";
  an allowed keyboard is remembered (vendor:product:serial, Settings › Trusted programs, "Remove"). Guard rails so
  the user is never locked out: the only keyboard of the computer, or a keyboard+mouse receiver when no other pointer
  exists, is allowed at once with an information popup; keyboards present when the service starts are known. Setting
  "Cut off any new USB keyboard until you approve it" (on by default). `HidGuard` thread, udev `input` monitor.
- **Trapped networks** — the gateway's hardware address is remembered per network and checked every minute: a change
  on a known network (ARP poisoning, man-in-the-middle, or simply a new router) raises a red popup "The router of …
  has changed" with "This is my new router" (new reference), "Switch to Public" and "Details"; an unencrypted or WEP
  Wi-Fi without an active VPN gets an orange popup "Unencrypted Wi-Fi" once a day per network. Alerts in the events
  list with the same actions, e-mail if notifications are on.
- **Sender authentication in Thunderbird** — the banner of every message now says whether the sender is
  authenticated: SPF, DKIM and DMARC results read from the `Authentication-Results` headers set by the receiving
  server (ARC and `Received-SPF` too), aligned with the sender's domain; "NOT authenticated" in red when SPF, DKIM
  or DMARC failed (the address may be spoofed), "doubtful" in orange when the reply address belongs to another
  domain (CEO fraud: corporate sender, free-mail reply-to) or the display name contains another e-mail address,
  "could not be verified" when the server left no information. Counted in the badge and reported to the
  Security › Links and e-mails card (`extensions/thunderbird/auth.js`, pure functions tested on thirteen header
  scenarios).
- **Scan on arrival** — every file closed after writing in a download folder, on the desktop (XDG user dirs of each
  user, usual names otherwise) or on removable media (/media, /mnt, /run/media) is passed to clamd at once
  (`OnAccessScanner`, fed by the fanotify events of the activity monitor, files up to 512 MiB); an infected file is
  moved to quarantine before it can be opened (browsers write `.part` / `.crdownload` first, so the download fails
  cleanly), with a red popup "Infected file isolated on arrival", an event, an e-mail if notifications are on and
  the quarantine index entry. Setting "Scan files on arrival" (on by default); counters in the status and the
  telemetry.
- **Telemetry round 2026-10-23** — bursts of known maintenance tools (package managers, font/mime/icon caches,
  initramfs, DKMS, Timeshift, rsync/rclone backups) no longer raise information popups when the executable is a
  trusted system/snap/flatpak path (`QUIET_BURST_BASENAMES`: 24 "burst" alerts in a week for `fc-cache` of the
  Firefox snap, users approving dpkg or flatpak-system-helper by hand). Kernel source packages present only
  through headers or tools (`linux-libc-dev`, `linux-headers`, `linux-tools`, no kernel image installed — a Mint
  shipped on the HWE 6.14 kernel still has `linux` 6.8 through linux-libc-dev) have their vulnerabilities
  classified "not applicable: headers only, kernel not installed" (note and badge) instead of 49 high "unfixed"
  ones, and the "install the HWE kernel" advice only appears when the original kernel is really the running one;
  stored reports are reclassified at service startup. Central allowlist: Claude Code binaries of Claude Desktop.
- **Process watch: approve or trust from the event** — the alert keeps the full text of the warning: events offer
  "That's normal" (warning approved, even if the process is already gone, without PID) and "Trust" (program), then
  show "approved". Trusted programs are recognised by the watch and by the full audit: by path, and by name when the
  trusted path is itself a temporary directory (test binary rebuilt under /tmp). Old alerts without detail (before
  1.25.0) are shown as "N warning(s) during the integrity check (processes)"; the log (Logs) keeps a trace of each
  pass with, from now on, the program and its path.
- **Process watch: readable alert, no more stuck red** — a suspicious process (executable deleted from disk, started
  from /tmp, unknown LD_PRELOAD, ptrace) relaunched with a new PID was a "new" warning at each pass of the watch
  (every 5 min): red alert "1 — processes" without any detail, "That's normal" ineffective as soon as the PID
  changed, and the overall state stayed "danger" for 24 h after the last alert even once the report was clean again.
  The warning is compared and approved without PIDs nor line order; the alert, the popup, the mail and the log name
  the program, the reason (translated) and the pid / name / path lines; the overall state and the "Threats" row of
  the simple view follow the current integrity report (green as soon as the process is gone or approved) instead of
  the alert history.
- **Ubuntu 26.04: vulnerabilities of the right release** — the OSV inventory queried the Ubuntu 24.04 ecosystem for
  any unknown release (26.04 "resolute" included): an Ubuntu 26.04 on kernel 7.0 saw the vulnerabilities and the
  "kernel 6.8" alert of 24.04 / Mint 22 (issue #1). The Ubuntu release is now read from os-release (Ubuntu) or
  /etc/upstream-release (Mint), LTS inferred (April of even years); without a known release (LMDE…), the inventory
  is "unsupported" rather than wrong. The "Kernel" check and the HWE note quote the running kernel, the Ubuntu
  release, the HWE kernels found and the real `linux-generic-hwe-<release>` package, no longer assuming Linux Mint
  nor 6.8; the encryption, Secure Boot and sudo advice no longer assume Mint either. On Fedora the inventory stays
  "unsupported" (dnf advisories in System status) and the texts that hard-coded UFW, apt or debsums (firewall,
  updates, integrity, Lynis descriptions, legal notices) also name firewalld, dnf and rpm -V; the repository hint of
  the Update card becomes the dnf repository's, the service now exposing the distribution family in its status.
- **No more ghost window after an update (Ubuntu/GNOME)** — the shield relaunched after the package upgrade mapped
  then hid its window (`show_all()` + `hide()`): GNOME kept a "dukiwi-shield.py" entry in the dock with nothing
  visible. In shield mode the window is never mapped until it is opened; `StartupWMClass` in the launcher gives the
  dock the right name and icon however it is launched. And if the window was open at the time of the update
  (postinst SIGTERM), it reopens by itself once the new version is loaded (`window_open_at` marker, valid 5 min).
- **chkrootkit "INFECTED": four verified false-positive rules** — an Ubuntu media centre showed chkrootkit
  "INFECTED" findings while the full ClamAV scan (221,788 files) was clean. Built-in rules (version 6, existing
  reports reclassified at startup without re-running the tool): "Checking `ls'... INFECTED" → benign if the binary
  is shipped by a package and intact according to it (dpkg -V / rpm -V), to check urgently if modified; "Possible
  Suckit: /sbin/init INFECTED" → benign if the real init (systemd) is intact according to its package; "chkproc:
  Possible LKM Trojan installed" → processes that ended between the two readings of chkproc or normally visible to
  ps are benign, a process present in /proc but hidden from ps remains to check; "Possible Slapper / Scalper Worm
  installed" → same analysis as bindshells (program really listening on ports 2001, 2002, 4156, 1978, 1812, 2015:
  package or store application → benign).
- **Link and e-mail checking: Thunderbird, Firefox, Chrome, Chromium, Edge, Brave extensions** — service module
  `dukiwi_shield_urlguard.py`: malicious-site lists downloaded several times a day (OpenPhish and Phishing.Database on
  GitHub, URLhaus via the urlhaus-filter mirror; conditional ETag requests, compact indexes of sorted fingerprints: 4 MB for
  450,000 entries, 0.4 ms per check) and list-free heuristics: raw IP address, identifier before an "@", punycode,
  imitated brand (replaced characters "paypa1", typo on a neighbouring key, brand as a subdomain, real brand domain
  at the head of another host "paypal.com.example.ru", "paypal-secure" combination), shorteners resolved (HEAD
  without following, 3 hops) then checked, unencrypted login page, executable download, link whose displayed text
  is another address (e-mails). Verdict safe / caution / danger; brand imitations alone are "caution", "danger" with
  a login page, a dubious domain or punycode ("stream" is not "steam"). Sites "always allowed" by the user. Native
  messaging host `dukiwi-shield-native-host` (relay to the service socket, browser recognised by the parent
  process); commands `url_check`, `url_report`, `url_allow`, `url_scan` (attachment dropped in
  `/tmp/dukiwi-shield-mail-<uid>/`, owner verified, clamd → red popup "Infected attachment"), `urlguard`,
  `urlguard_refresh`, `urlguard_hello`. Browser extension (`extensions/browser`, MV3 Chrome/Edge/Brave/Chromium, MV2
  Firefox with blocking request): warning page "Back / Open anyway / Always allow this site", notification for
  "caution", badge, status popup. Thunderbird extension (`extensions/thunderbird`, MV2): banner at the top of each
  message (links checked, dangerous ones framed in red and click intercepted with confirmation in the message),
  attachments scanned by clamd when displayed and when e-mails arrive (notification + service popup). Automatic
  installation: `dukiwi-shield-browser-setup` (postinst / %post) writes the native manifests
  (`/usr/lib[64]/mozilla`, `/etc/opt/chrome`, `/etc/chromium`, `/etc/opt/edge`, `/etc/opt/brave`), a
  Chrome/Chromium/Edge/Brave policy (`ExtensionSettings` from
  `https://www.dukiwi.com/repo/extensions/urlguard-update.xml`, CRX3 signed by `crx3-pack.py` with the
  `repo/keys/chrome-extension.pem` key, never in git) and merges `ExtensionSettings` into the `policies.json` of
  Thunderbird (local XPI) and Firefox (XPI signed on the repository: Mozilla requires AMO signing, to be done with
  `web-ext sign --channel unlisted` then dropping the file in `repo/extensions/`). `build-extensions.sh` produces
  XPI, ZIP, CRX, update.xml and `manifest-info.json`; `publish.sh` copies them to `repo/extensions/`. Security ›
  Links and e-mails card (extensions seen, lists, last flagged links, allowed sites, installation help), settings
  `url_guard`, `url_guard_resolve`, `mail_scan_attachments` (on by default). Tested: native host (hello, check,
  allow, EICAR attachment recognised), headless Edge with the extension (phishing and lookalike redirected to the
  warning page, clean site let through), headless Thunderbird (extension accepted).
- **Immediate service stop** — after "Daemon stopped", the interpreter waited for thread pools still in flight (OSV
  requests of the daily tasks, launched 15 s after startup): `systemctl stop` and the package upgrade could wait
  several minutes. The service now exits right away (state already written synchronously); honeypot decoys and the
  firewall log reader are closed explicitly.
- **Network honeypot** — **on by default** (setting in Settings › Security and family; disabling reserved to the
  administrator in family mode; Security › Network honeypot card with an "Enable" button if it was turned off). The
  service listens on decoy ports with no service behind them: two random high ports (20000–32000, excluding
  chkrootkit's "bindshell" ports, remembered) and telnet 23 / 2323, opened in the firewall (ufw or firewalld,
  `cav-honeypot` rules, re-applied every 5 min) and marked "honeypot" in the listening ports. Every connection is
  logged with its source (address, DNS/mDNS name, MAC address, gateway or not) and the intent inferred from the first
  bytes (probe, SSH, HTTP, exploitation request, TLS, SMB, RDP, SOCKS, SIP, login attempt on the fake telnet with the
  identifier tried, never the password). A device that touches several decoys, attempts a login or an exploitation,
  or whose firewall log (`[UFW BLOCK]`, `LogDenied=unicast` on firewalld) shows SYNs to ≥ 5 closed ports is flagged
  as a scan: red popup "A device is probing this computer" with "Block this device" (DENY rule at the top of the
  firewall, never the gateway nor oneself), "Ignore" (known device) and "Details"; Security › Network honeypot card
  (sources, intents, latest events, block / unblock / forget), "Local network" row of the simple view, yellow
  overall state as long as a suspicious device is neither blocked nor ignored, e-mail if notifications are enabled.
  Connections coming from this computer are ignored. Nothing is sent outside (module `dukiwi_shield_honeypot.py`).
- **Fedora: clamd socket enabled** — scan.conf is shipped with LocalSocket commented out: uncommented by the package
  and by the service, otherwise no clamd engine. RPM package built, signed, installed and verified in a Fedora 44
  container from the signed dnf repository.
- **Fedora and derivatives** — distribution layer `dukiwi_shield_distro.py`: dnf (updates, security advisories and CVEs
  through `dnf updateinfo`, reboot through `needs-restarting`, dnf-automatic), rpm (file ownership, `rpm -V` instead
  of debsums with classification of configuration files), firewalld (home / public / work zones as profiles,
  services, ports, rich rules, activation), SELinux in the checklist, `clamd@scan` and `/etc/clamd.d/scan.conf`,
  application update through dnf (`rpm` entry of the manifest), direct msmtp. Noarch RPM package (`build-rpm.sh`,
  `dukiwi-shield.spec`), signed dnf repository (`rpm/fedora`) and `.repo` file shipped by the package; count of
  RPM downloads and dnf index reads.
- **Popups on Ubuntu (Wayland)** — a Wayland client cannot place its windows and GNOME centred the notifications in
  the middle of the screen; the shield uses GTK's X11 backend through XWayland when a Wayland session offers it, and
  the popups slide from the bottom again. "Notification position" setting: bottom right (default) or bottom left.
- **E-mail notifications** — Settings › E-mail notifications (administrator): SMTP server, port, STARTTLS / TLS /
  none, username, password, sender, recipients, immediate / daily / weekly frequency (time and day of the digest),
  language, chosen events (serious alerts, scan results, status digest). Off by default: nothing is sent. The
  service writes /etc/msmtprc (root, 600) and sends through sendmail; another system mail server is used as is. Test
  mail, digest on demand, cap of 30 mails per day, log. The interface warns that any program of the system with
  administrator rights will then be able to send mail with this account.
- **Installable on Ubuntu 26.04** — dependencies `pkexec | policykit-1` (the policykit-1 transitional package no
  longer exists) and `gir1.2-ayatanaappindicator3-0.1 | gir1.2-appindicator3-0.1` (libappindicator removed); the
  shield uses the Ayatana indicator when present. On GNOME, the AppIndicator extension
  (gnome-shell-extension-appindicator, installed by default on Ubuntu) is needed to see the icon.
- **One shield per session** — after a reboot, two icons and duplicate notifications could appear: the system
  service relaunched the shield before the session was ready (fallback outside the service), then the desktop's
  autostart launched a second one. Now: exclusive instance lock in the program, launcher that waits for the user
  manager instead of falling back and locks the unit creation, system service that gives the desktop 90 s, requires
  the user bus and terminates duplicates.
- **"Ignore" a vulnerability or a port, USB stick without scan or trusted: never a password** — even in family
  mode; every choice is written to the log. Still reserved to an administrator in family mode: "That's normal" on an
  integrity warning, trusting a program or an autostart entry, settings, hardening.
- **State re-read after "Ignore"** — three seconds after an "Ignore", "That's normal", "Trust" or "Show again",
  the interface re-reads the whole state (shield, simple view, checklist score, vulnerabilities, integrity,
  backups) to show the new status without changing tab.
- **Blue = information, everywhere** — the simple view shows the "information" state (blue shield, "For
  information only") when the service is blue (unfixed vulnerabilities), instead of yellow; the "System updates" row
  offers "Ignore". "Ignore all" (Vulnerabilities card, "Open vulnerabilities" checklist item, simple view) ignores
  all open vulnerabilities whatever their priority: green shield afterwards.
- **Readable dashboard with long texts** — the "System" tile shows the state on one line and the details (phased
  updates, held back by apt) on a discreet second line; the side column is bounded in width and moves under the
  title on a narrow window.
- **Kernel and process check (behavioural)** — two built-in checks, at each integrity check and every 5 minutes:
  *Kernel* (hidden module: alive in `/sys/module` but absent from `/proc/modules`, module loaded without a file for
  this kernel, "force loaded" taint, DKMS modules listed as benign, lockdown / signature / `modules_disabled` state)
  and *Processes* (executable deleted from disk, execution from /tmp or /dev/shm, library injected through
  LD_PRELOAD, process traced through ptrace; benign verdicts: updated program, AppImage, library from a package /
  Steam / store, known debugger). A new warning triggers a red popup and the red shield; "That's normal" remains
  available.
- **"Ignore" without a password** — dedicated command for the file backup and Timeshift (family mode included); the
  "Backups" row distinguishes Timeshift suspended (low space), too old, no snapshot.
- **chkrootkit "bindshell" classified** — "Potential bindshell installed: infected ports: 145" is checked on the
  spot: program really listening (shipped by a package or a store application → benign), no program (transient
  detection, or last byte of the IP address taken for a port by chkrootkit's regex → benign), program outside dpkg →
  to check. Lone "WARNING" line (artefact of verbose mode) ignored. "Purge leftovers" hardening: architecture kept
  (libvdpau1:i386) and package-by-package purge.
- **Simple view: never a red without explanation** — the subtitle quotes the service's exact reason ("integrity
  compromised", "unfixed vulnerabilities"…) and a "System integrity" row (rootkits, modified package or application
  files → red, Lynis recommendations → yellow) leads to the details and the "That's normal" button.
- **USB stick: continue without scan, trust** — the stick scan popup (and the question for a large disk) offers
  "Continue without scan" and "Trust this stick": the running scan is cancelled and the stick is mounted right away
  for the user, without a password (family mode: administrator). A trusted stick (serial number + UUID) is no
  longer scanned on insertion ("trusted stick" popup with "Scan anyway"); list and "Remove" in Settings › Trusted
  programs.
- **Enabling Timeshift answers right away** — the service updates the state from the configuration (without
  `timeshift --list`, which can last minutes while a snapshot is running) and starts the first snapshot then the
  full report in the background; the interface queries the service off the main thread with a generous timeout (no
  more "timed out" nor frozen interface).
- **Automatic Timeshift schedule even if Timeshift is already configured** — "Automatic schedule (recommended)"
  button when the schedule is not the application's ("schedule managed by the application" badge otherwise):
  applies without a password daily (5) / weekly (3) / monthly (2) with the space guard, keeping the snapshot
  location. An account without administration rights no longer needs to open Timeshift.
- **Network profile without a password for everyone** — switching Home / Public / Work never asks for
  administration rights any more, even in family mode.
- **Ignorable file backup** — the "Backups" row combines the backup of your files and Timeshift; each has its own
  "Ignore" / "Show again" (simple-view wizard, Backups tab): independent `backup_check` (files) and
  `timeshift_check` (Timeshift) settings. A green row = everything still counted is in order.
- **Ignorable Timeshift state** — "Ignore" button (Backups tab and simple-view wizard) for PCs without room for
  snapshots: `timeshift_check` setting, no more yellow nor "low space" alert, "ignored by you" badge and "Show
  again".
- **Ignored open ports** — "Ignore" on the "Open ports" checklist item and on each reachable port of the
  "Listening ports" list (port/protocol/program key): a wanted development web server no longer counts in the
  score nor in the items to fix; "ignored by you" badge and "Show again"; another program on the same port is
  flagged again.
- **Ignored vulnerabilities** — "Ignore" button on each unfixed (or Ubuntu Pro) vulnerability and "Ignore all" on
  the displayed list: the CVE, all packages included, no longer counts in the shield colour, the score nor the
  simple view; collapsed "Ignored vulnerabilities" section with "Show again"; new CVEs published later remain
  flagged. Without a password (except family mode).
- **debsums files classified** — a package file reported modified is benign if it belongs to Linux Mint's
  adjustments (`/usr/share/linuxmint/adjustments`, `.overwrite` patterns, files cited by `.execute`) or if it is
  diverted by `dpkg-divert`; otherwise it remains "to check". chkrootkit in verbose mode: tool messages glued to a
  test line and "started/finished" ignored. Report reclassified at startup.
- **Lynis warnings classified** — the real state is checked before alerting (TIME-3185: NTP active and clock
  aligned = known false positive, otherwise "Fix" re-runs the synchronisation; KRNL-5788: reboot needed); the
  existing report is reclassified at startup.
- **Visible integrity progress** — the output of each tool is read continuously: Lynis sections, chkrootkit tests,
  debsums files, unhide phases give a percentage and the current step, shown tool by tool in the scan (integrity
  phase) and in the Integrity card (`integrity_progress` event).
- **Resilient engine** — a batch refused by clamd (service unreachable, descriptor refused) is retried after
  waiting for clamd, then handed to clamscan; at the fifth failed batch, the rest of the scan switches to clamscan
  instead of failing. chkrootkit: system tool lines ("RTNETLINK answers…") ignored, "ifpromisc" finding classified
  (NetworkManager/wpa_supplicant on Wi-Fi = benign, unknown process = to check). The overall state only turns red
  for signs of compromise (rootkits, modified files); Lynis warnings alone give yellow.
- **Enable Timeshift in one click** — button in the Backups tab and in the simple-view wizard, without a password:
  the service writes the recommended configuration (system snapshots on the main disk, 5 daily, 3 weekly,
  2 monthly, btrfs mode if the root is an @ subvolume, otherwise rsync excluding home directories), installs the
  hourly cron task and starts the first snapshot. Disabling requires administrator authentication. **Space guard**:
  the system size is measured (`du`, cached for a week) and enabling is refused if less than 1.2 × that size + 10 GB
  is free (message with the figures, "Open Timeshift" button to pick a dedicated disk); the cron task only starts a
  snapshot if 10 GB remain, and the service suspends the schedules (popup, orange indicator) if the disk drops
  below that threshold.
- **Weekly digest** — weekly popup (and button in the Security tab): scans, threats, alerts, score and its change,
  backup, tips read.
- **Data breaches** — password test through Have I Been Pwned with k-anonymity (5 characters of the SHA-1, never
  the password); monitoring of e-mail addresses through the free XposedOrNot base, or Have I Been Pwned with a
  personal API key; weekly recheck and popup at every new breach. Only the address is sent to the service
  consulted. (The `repo/api/hibp.php` relay remains available should Dukiwi obtain a key one day.)
- **Applications outside repositories** — inventory of Flatpak (broad permissions, source outside Flathub), Snap
  (classic confinement, sensitive plugs) and AppImage (no sandbox), with "Trust".
- **Encrypted vault** — gocryptfs folder (`~/.coffre` encrypted, mounted on `~/Coffre`), creation, opening and
  closing from the simple view or the Backups tab, password entered in a native dialog, automatic closing after
  30 min, included in backups.
- **Guided restore** — choice of destination, backup and folder, copy into `~/Restauration` without ever
  overwriting current files.
- **Travel mode** — one button: Public firewall profile, backup if a medium is plugged in, updates, reminders (VPN,
  locking, two-factor authentication, USB sticks); coming back restores the profile.
- **Opt-in anonymous telemetry** — off by default; once a week: version, system, score, alert types, approved
  programs and entries (anonymised paths), without personal identifier. Received by `repo/api/telemetry.php`
  (`api/data/*.jsonl` files, summary with `api/summarize.py`) to feed the **signed central allowlist**
  (`api/allowlist.json` + `.sig`, verified with the Dukiwi key, downloaded daily).
- **Enterprise policy** — `/etc/dukiwi-shield/policy.json` deployed by dukiwi-kit (root-owned file, optional
  detached signature): enforced and locked settings, firewall profile, trusted programs; see
  `policy.example.json`. Locked settings appear greyed out.
- **Inactive kernels** — vulnerabilities of installed but not running kernels (for example the 6.8 GA when the
  system runs an HWE 7.0 kernel) are counted separately and no longer enter the total; a note shows the running
  kernel (`uname -r`) and how to remove the old ones.
- **HWE kernel** — vulnerabilities of the original kernel of the Ubuntu release (for example 6.8 of 24.04 /
  Mint 22) already fixed in an HWE kernel (6.14, 7.0…) are marked "fixed in the HWE kernel" and counted; the
  vulnerabilities card explains how to install that kernel (Mint: Update Manager → Linux Kernels; Ubuntu:
  `linux-generic-hwe-<release>`). The kernel, the Ubuntu release and the HWE kernels quoted are those of the
  system, never fixed in advance.
- **"Fix" button** — every checklist item that is not green offers "Fix" (direct action: firewall, update, scan,
  settings, port list…) or "How to" (step-by-step explanation: encryption, Secure Boot, AppArmor, sudo,
  accounts…). The port list gives a verdict per port: local only, filtered by the firewall (nothing to do) or
  reachable from the network, with an explanation per service (SMTP, Apache, Avahi, CUPS, Samba…) and a "Block
  this port" button. NOPASSWD sudo rules shipped by a system package (mintupdate, mintdrivers, mintsystem) and
  unchanged (dpkg verification) are recognised as normal; only hand-added or modified rules are flagged.
- **Backups (availability, the "A" of the CIA triad)** — "Backups" tile in the simple view and full page in the
  advanced view. The service reads the state of **Timeshift** (installed, schedule, last snapshot); the
  application copies personal folders (Documents, Pictures, Videos, Music, Desktop, editable) to a **USB stick /
  external disk** (incremental rsync snapshots with hard links, adjustable retention, plain mirror on FAT/NTFS), a
  **folder** (NAS) or a **cloud** through rclone (S3 compatible, Infomaniak Swiss Backup S3 or Swift, kDrive
  WebDAV, existing rclone remote; archiving of replaced files). Minimal wizard in the simple view ("Back up here" on
  the detected medium), automatic daily/weekly/monthly schedule as soon as the destination is plugged in, history,
  restore instructions. Files never backed up or Timeshift not scheduled: yellow indicator (can be disabled in
  Settings). Everything runs with the user's rights, without a password.
- **Full analysis** — "Scan my computer" (simple view, dashboard, tray) starts with the integrity check (Lynis,
  chkrootkit, debsums, application files), then launches the antivirus scan **skipping the system files that
  debsums confirmed identical to their package** (several hundred thousand files), hence a much faster analysis.
  The final popup summarises threats, integrity and the number of skipped files. In the advanced view, the Scanner
  tab offers "Full scan (integrity + files)", "Files only" and "Integrity only". Lynis, chkrootkit and debsums are
  now dependencies of the package; Lynis is initialised at installation and refreshed after each apt run
  (`APT_AUTOGEN`). As Lynis, unhide and chkrootkit recommend a mail server (apt would install Postfix, which opens
  port 25), the package depends on `msmtp-mta`, a simple client without daemon nor port, which satisfies that
  recommendation.
- **Install updates** — the "Update" button (simple view) and "Install updates" (System status) run
  `apt-get update` then `apt-get upgrade` through the service, in a transient systemd unit; a popup confirms the
  end. **Phased** packages (Ubuntu phasing) or packages **held back** by apt (dependencies, "kept back") do not
  count as missing updates: the indicator stays green with the mention "waiting for our turn". Detection simulates
  `apt upgrade` in memory (python3-apt), so it reflects exactly what the machine would install.
- **"That's me"** — every alert (program unknown to the system that modifies files or connects to the Internet,
  unknown startup entry, out-of-store extension) offers a "That's me" button: the program or entry joins the
  approval list (Settings → Approved programs) and never triggers a message again; a suspended process is resumed.
  A binary replaced while running (Chrome updated, for example) is no longer considered unknown.
- **Tips read** — a lesson opened for at least 5 seconds through "Read more" is marked "Read" and no longer comes
  back as a popup; when everything is read, the daily popup disappears (clickable badge to mark a lesson unread
  again).
- **Classified packages** (System status) — every pending update is labelled **Security** (vulnerability fix),
  **Recommended** (application / library) or **Phased** (Ubuntu phased update, with the roll-out percentage). If
  nothing is pending, the card shows "Everything is up to date"; otherwise an **Install phased packages** button
  forces their installation (`APT::Get::Always-Include-Phased-Updates=true`, admin authentication).
- **Legal notice** — shown at first launch (to accept) and available at any time through Credits → Disclaimer:
  software provided "as is", first barrier only, exclusion of Dukiwi SA's liability (see below).
- **Tray icon** — green: all in order; yellow: non-critical updates, reboot, SSH active, app update; blue: old
  signatures or open vulnerabilities without fix; red: firewall inactive, security updates, danger detected,
  integrity compromised.
- **Modern scan** — progress ring, steps (inventory → analysis), files/s, estimated remaining time, live threats,
  cancel and resume, end summary, scan history.
- **Quick scan** — `/home`, `/etc`, `/var`, `/opt`, `/usr`, `/tmp` or a folder chosen through the native picker.
- **Quarantine** — infected files isolated (system quarantine and user quarantine).
- **HTML/CSS interface** — easy to modify (files in `ui/`).

## Warranty disclaimer and limitation of liability

Dukiwi Shield is provided by **Dukiwi SA "AS IS"**, without any warranty, express or implied. It is at most a
**first barrier**: no antivirus, firewall or detection tool can identify every threat, and a green indicator in no
way guarantees that a computer is clean. Only careful and informed behaviour on the user's part (security
awareness) really limits the risks.

**To the fullest extent permitted by applicable law, Dukiwi SA shall not be held liable** for any direct or
indirect damage (loss, encryption or disclosure of data, undetected infection, hacking, phishing, fraud, business
interruption, false positive, action triggered by the software such as stopping a process, a quarantine or a
firewall rule…) arising from the use, misuse or inability to use the software. The user alone is responsible for
their backups, settings and actions. The full text (12 articles, FR/EN/DE/IT) is shown in the application at first
launch and under Credits → Disclaimer; by using it, you accept it. This text is not legal advice.

---

## Requirements (running from source)

```bash
# Linux Mint / Ubuntu
sudo apt install clamav clamav-daemon clamav-freshclam python3-gi python3-pyudev python3-apt \
    gir1.2-webkit2-4.1 gir1.2-ayatanaappindicator3-0.1 gir1.2-gtk-3.0 ufw
# Fedora
sudo dnf install clamav clamd clamav-update python3-gobject python3-pyudev webkit2gtk4.1 \
    libayatana-appindicator-gtk3 gtk3 firewalld
```

---

## Quick start (without the .deb)

```bash
cd dukiwi-shield/
chmod +x dukiwi-shield.py
python3 dukiwi-shield.py
```

---

## Building the packages

```bash
./build-deb.sh        # dukiwi-shield_2.5.1_all.deb   (Mint / Ubuntu)
./build-rpm.sh        # dukiwi-shield-2.5.1-1.noarch.rpm (Fedora; requires rpmbuild: sudo apt install rpm)
```

Both packages share the same file tree (`build-deb.sh --stage-only`) and the same signed integrity manifest.

---

## System service and scheduling

| systemd unit                       | Role                                                                  |
|------------------------------------|-----------------------------------------------------------------------|
| `dukiwi-shield-daemon.service`      | Root daemon, socket `/run/dukiwi-shield/daemon.sock` (mode 0666) |
| `dukiwi-shield-update.timer`    | `OnCalendar=07:00` + `OnBootSec=5min` + `Persistent=true`             |
| `dukiwi-shield-update.service`  | Oneshot: asks the daemon for the update (`--request update`)          |

The daemon accepts, from any local user, a scan of `/` and of the system directories (`/home`, `/etc`, `/var`,
`/opt`, `/usr`, `/tmp`, `/boot`, `/root`, `/srv`), of media mounted under `/media` and `/mnt`, and of any folder
located in the requester's home directory (identified through `SO_PEERCRED`). Other paths are scanned locally
with the user's rights.

| File                                     | Role                                                              |
|------------------------------------------|-------------------------------------------------------------------|
| `/lib/udev/rules.d/80-dukiwi-shield-usb.rules` | Disables udisks automatic mounting of USB devices **only** when the service socket exists |
| `ui/i18n.js`                             | FR/EN/DE/IT translations (JSON) shared by the page and Python     |
| `ui/awareness.js`                        | FR/EN/DE/IT awareness lessons ("tip of the day" popup and Good practices page) |
| `dukiwi_shield_backup.py`                       | User backup engine (incremental rsync, rclone cloud, media detection) |
| `dukiwi_shield_extras.py`                       | Data breaches (HIBP), applications outside repositories, gocryptfs vault, weekly digest |
| `policy.example.json`                    | Example enterprise policy for dukiwi-kit |

System settings (Settings page, `/var/lib/dukiwi-shield/settings.json` file, defaults in `DEFAULT_SETTINGS`
of `dukiwi_shield_common.py`): Internet upload threshold and window (5 GB / 1 h), burst thresholds (50 files info,
25 home files for an untrusted program, 15 s window), automatic USB scan and size limit (128 GiB), update check
time (07:00, applied through a systemd drop-in), weekly scan.

The firewall/SSH commands of the socket (`firewall_set`, `firewall_defaults`, `firewall_rule_add`,
`firewall_rule_delete`, `ssh_set`) are accepted from any real local user (uid ≥ 1000): this is intended ("without
root"), but worth knowing on a multi-user machine.

Service files: state and quarantine in `/var/lib/dukiwi-shield/`, log in `/var/log/dukiwi-shield/scan.log`.

Command-line client (diagnostics):

```bash
/opt/dukiwi-shield/dukiwi-shield-daemon.py --request status
/opt/dukiwi-shield/dukiwi-shield-daemon.py --request scan /home
/opt/dukiwi-shield/dukiwi-shield-daemon.py --request update
/opt/dukiwi-shield/dukiwi-shield-daemon.py --request system-status
```

---

## Customising the interface

The interface is **HTML + CSS + JavaScript** in the `ui/` folder:

| File           | Role                                     |
|----------------|------------------------------------------|
| `ui/index.html`| HTML structure of the interface           |
| `ui/style.css` | Visual theme — edit the CSS variables     |
| `ui/app.js`    | Front-end logic                           |

### CSS variables (top of `style.css`)

```css
:root {
    --bg-primary:       #0a0e17;    /* Main background */
    --bg-card:          #1a2234;    /* Card background */
    --accent:           #22c55e;    /* Accent colour (green) */
    --accent-blue:      #3b82f6;    /* Blue */
    --accent-red:       #ef4444;    /* Red */
    --font-body:        'Segoe UI'; /* Body font */
    --sidebar-width:    260px;      /* Sidebar width */
}
```

---

## Architecture

```
dukiwi-shield/
├── dukiwi-shield.py              # Python app (GTK3 + WebKit2 + AppIndicator)
├── dukiwi-shield-daemon.py       # Root system service (Unix socket) + --request client
├── dukiwi_shield_common.py                 # Shared paths, exclusions, protocol
├── dukiwi_shield_guard.py                  # Decoys, camera/microphone, miners, root certificates, redirection
├── dukiwi_shield_protect.py                # Filtered DNS, isolation, home encryption check
├── dukiwi_shield_hygiene.py                # Password quality, browser settings, exposure test, UPnP
├── dukiwi-shield-sandbox                   # Open a file under firejail (Nemo action)
├── systemd/
│   ├── dukiwi-shield-daemon.service
│   ├── dukiwi-shield-update.service
│   └── dukiwi-shield-update.timer # 07:00 daily + 5 min after boot
├── udev/80-dukiwi-shield-usb.rules # USB stick scan before mounting
├── dukiwi-shield-unlock          # pkexec helper: administrator session for the daemon
├── polkit/com.dukiwi.dukiwi-shield.policy
├── keys/dukiwi.gpg            # Public key verifying updates
├── dukiwi.repo                      # dnf repository file shipped by the RPM (shared Dukiwi repository)
├── dukiwi-shield.spec               # RPM package (Fedora)
├── ui/
│   ├── index.html                   # HTML interface
│   ├── style.css                    # CSS theme (editable variables)
│   ├── app.js                       # Front-end JS logic
│   ├── i18n.js                      # FR/EN/DE/IT translations
│   └── awareness.js                 # FR/EN/DE/IT awareness lessons
├── icons/
│   ├── logo.svg                     # Application logo (window, menu, .desktop)
│   ├── shield-green.svg             # Tray: all in order
│   ├── shield-yellow.svg            # Tray: non-critical updates, reboot, SSH active
│   ├── shield-blue.svg              # Tray: old signatures, unfixed vulnerabilities
│   └── shield-red.svg               # Tray: firewall inactive, security updates, danger
├── dukiwi-shield.desktop         # Application menu entry
├── dukiwi-shield-autostart.desktop
├── build-deb.sh                     # .deb build script
└── README.md
```

---

## Licence

This project is distributed under the **GNU General Public License v3.0** (GPL v3).
See the [LICENSE](LICENSE) file for details.

© 2026 Dukiwi SA — Estavayer-le-Lac, Switzerland.
