# Tests

`tests/run_all.py` runs every `test_*.py` file and prints one line per file, then a total; exit code 1 if anything
fails. Pass a folder to test another copy of the code (`/opt/dukiwi-shield` for the installed version) and `--gui` to
include the tests that open windows.

| File | Covers |
|---|---|
| `test_decoys.py` | Ransomware decoys: reproducible content, test instance leaves them alone, fingerprints kept while an eCryptfs home is unmounted, real tampering detected (2.7.5) |
| `test_usb_and_preload.py` | UTF-8 mount options for FAT/ISO, scan of non-UTF-8 file names (needs clamd), LD_PRELOAD approval tied to the library file (2.7.6) |
| `test_alerts.py` | "It's OK" on red alerts, honeypot: ignored device → information, intrusion attempt → red (2.7.7) |
| `test_trust.py` | Dukiwi applications trusted out of the box (2.7.7), AppImage trusted by content across launches (2.7.9) |
| `test_bursts.py` | File-write bursts: early identification, package-manager parent (needs rpm), application folders, learned habits (2.7.8) |
| `test_score.py` | Backups and snapshots in the score even with the reminder ignored, protected folders, learned habits via the service (2.7.8) |
| `test_telemetry.py` | Path anonymisation (2.7.9), report right after an update (2.7.10), open integrity warnings (2.9.6), server endpoint `../repo/api/telemetry.php` (needs php) |
| `test_versions.py` | Version comparison in Python, same order as dpkg, works without dpkg (2.7.11) |
| `test_release_2_8.py` | What's new in the update offer, Timeshift targets, encryption detail, password step 2, monthly e-mail report, telemetry dashboard (needs php), transitional package (2.8.0) |
| `test_popups.py` | Notifications in the four corners, inside the usable area (GUI only, `--gui`) |
| `test_tray_double_icon.py` | Panel watcher answering after the D-Bus timeout: the XEmbed fallback shield is removed, none with no watcher (GUI only, `--gui`, private bus, ~1 min) (2.9.1) |
| `test_usb_mount_failure.py` | USB drive that refuses to mount: one notification (no main-loop loop), one udisks attempt per drive, NTFS reason (Windows fast startup, file system to repair) read by the service, udev rule also on `change` (2.9.2) |
| `test_chkrootkit_hidden.py` | Hidden files annotated « [From Debian package: …] » by Debian's chkrootkit: bare path checked with dpkg, the note itself never trusted (2.9.3) |
| `test_camera_listing.py` | Camera opened only to list the devices (light off): no popup, checked every second until closed; filming (USB alternate setting above 0) still reported; bulk / non-USB cameras as before (2.9.4) |
| `test_chkrootkit_bpfdoor.py` | chkrootkit BPFDoor rule: a program waiting on a UNIX seqpacket socket is a known false positive, a raw packet socket (`packet_recvmsg`) stays a warning (2.9.5) |

`_harness.py` holds the shared pieces: `isolate()` / `load()` to import the code under test with private state
folders, `TestDaemon` to run the service in test mode on a given starting state and talk to it, `Results` for the
PASS / FAIL / SKIP lines, `spawn()` for real processes the watchers can observe.

Writing a new test: copy the shape of an existing file, keep every file and process it creates inside `h.tmpdir()` /
`h.home_tmpdir()` (removed at the end), and never write to the real home folders or `/var/lib/dukiwi-shield`.
