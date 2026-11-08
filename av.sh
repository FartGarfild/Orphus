#!/bin/bash
# =============================================================================
# Orphus AV Scanner Unified (modular + quarantine + real-time + busybox-first)
# Features:
#   - Built-in signature updater (Maldet, ClamAV, YARA, MalwareBazaar, custom)
#   - Parallel workers with batch hashing (SHA256 + MD5) and YARA batching
#   - Zero-RAM lookup + strict RAM ceiling
#   - Live RAM / CPU / ETA / FPS progress monitor
#   - Full heuristics: strings, hex-ERE, b64 payloads, disguised files, SUID/SGID
#   - Magic-bytes fast filter
#   - Quarantine mode: moves detected files to an isolated directory
#   - Real-time watch mode: background daemon, scans new files as they appear
#   - Pure self-contained single file
#
# BusyBox-first: looks for a local busybox (./bin/busybox); if missing, tries
# to auto-download a static binary (no prompts). Once available, all key ops
# (hashing, strings, find/grep/awk in the signature pipeline) go through it
# instead of $PATH. System tools are only a fallback. Exception: the first
# download itself needs system wget/curl (nothing else to fetch busybox with).
#
# Usage:
#   ./av_scan.sh [OPTIONS]
#
# Options:
#   -u, --update            Update signatures and EXIT (no auto-scan after).
#                          Add --packs hosting,server,all to build several
#                          YARA/ClamAV packs in one go (see --packs below);
#                          without --packs only the default pack (server)
#                          is built.
#   -r, --max-ram MB        Max RAM limit in megabytes (default: 500). Enforced:
#                            at start the worker count is cut to what fits; at
#                            runtime, from 90% of the ceiling new yara starts
#                            are held back, and if memory stays over it the
#                            biggest yara is killed (its batch is rescanned per
#                            file; a file that can't fit is reported as
#                            SCAN_ABORTED, never counted as clean). Measured as
#                            processes' anonymous memory + /dev/shm usage.
#   -j, --workers N         Number of parallel worker processes (default: auto)
#   -d, --dir PATH          Target directory to scan (default: /mnt)
#   -s, --sigs PATH         Signature directory (default: ./signatures)
#   -m, --max-size MB       Max file size for deep inspection in MB (default: 50).
#                            Bigger files: scripts (php, js, sh, py ...) still
#                            get hash + YARA, archives are left to -A, media to
#                            --media-fast; everything else is NOT scanned and is
#                            counted in the report ("Not scanned (> -m N MB)")
#                            with the full list in <report>.skipped, biggest
#                            first.
#   --media-fast             Video/audio files (recognised by their magic bytes,
#                            not the extension: mp4/mov/m4a, mkv/webm, avi, wav,
#                            mp3, flac, ogg, flv, wmv, mpeg) bigger than 4 MB
#                            are checked by YARA on their first and last 2 MB
#                            only, without a full-file hash - where an appended
#                            or metadata-embedded script would sit. Turns a
#                            462 GB uploads dir from hours into minutes; the
#                            trade-off: code hidden in the MIDDLE of a big
#                            video is not seen. Also covers media over -m.
#   --explain FILE           Check ONE file and explain every step: which checks
#                            run for it with the current settings, its hashes
#                            and whether they are in the signature tables, every
#                            YARA rule that matches (with the matching strings),
#                            and for each hit whether it is REPORTED or
#                            suppressed - and by what (the exact ignore_sigs
#                            line, the built-in list of too generic rules, the
#                            vendor obfuscation allowlist, PUA). Quarantines
#                            nothing. Use the same --packs / --deep / -m as the
#                            scan you are asking about.
#   -o, --output FILE       Report file. Written to LIVE as threats are
#                            found (not just at the end) — if the scan gets
#                            interrupted, whatever's in this file up to
#                            that point is still valid. Without -o, a
#                            default ./av_scan_threats_<timestamp>.log is
#                            used automatically (never silently discarded).
#                            SUID/SGID findings are written to a SEPARATE
#                            companion file (same name + "-SUID") instead
#                            of mixed into this one — on a full-OS scan,
#                            standard system binaries alone can produce
#                            dozens of lines that bury what actually needs
#                            a look. Only created if there's anything in it.
#   --ignore-sigs FILE       Suppress noisy detections without editing
#                            downloaded signature/rule files (which get
#                            overwritten on the next -u). One ERE pattern
#                            per line, matched against "TYPE|info" of each
#                            detection. Default: signatures/ignore_sigs
#                            (auto-created with a commented template).
#                            Also applied: signatures/ignore_sigs.upstream,
#                            the shared list from the project repository
#                            (main branch), refreshed by every -u. Keep your
#                            own lines in ignore_sigs. Other source / off:
#                            env ORPHUS_IGNORE_SIGS_URL=<url> | none.
#   signatures/yara_exclude   (optional file, no flag) YARA rule FILES to
#                            leave out of compilation entirely, one name or
#                            glob per line (# comments). Unlike ignore_sigs
#                            this stops the rules from RUNNING at all — the
#                            generic regex ones cost real CPU and RAM. A few
#                            known-useless community files are excluded
#                            built-in (see YARA_BUILTIN_EXCLUDE); changing
#                            this file triggers a recompile on the next run.
#   *.ign2 / *.ign            (files, no flag) ClamAV-style ignore lists: every
#                            signature / YARA rule NAME listed in any *.ign2
#                            ("Name" or "Name:md5") or *.ign ("db:line:Name")
#                            under the signature dir is left out at compile time
#                            - not loaded at all, unlike ignore_sigs, which only
#                            hides results. ClamAV's own list (daily.ign2 from
#                            daily.cvd, its withdrawn / false-positive
#                            signatures) is honoured this way; put yours in
#                            signatures/custom/local.ign2. Also left out at
#                            compile time: the rules the scanner always discards
#                            anyway (url, IP, contains_base64, ...) and rules
#                            yarac warns "may slow down scanning" about (too
#                            general: they match almost every byte and blow up
#                            yara's RAM on big files) - except in pack "full".
#                            What was left out: <pack dir>/dropped_rules.txt.
#   --packs LIST             THE one option for "which signatures". A pack is
#                            one prebuilt YARA + ClamAV set, kept in
#                            signatures/.cache/packs/<id>/; a scan just picks it.
#                            One pack = items joined with "+":
#                              profiles   hosting  webshell+webapp+linux+exploit:
#                                                  the light set for PHP/CMS servers
#                                         server   hosting + malware+generic+docs:
#                                                  what matters on a Linux server
#                                                  (DEFAULT)
#                                         all      everything incl. legacy and the
#                                                  Windows PE ClamAV signatures
#                                         full     all + the known-useless files
#                                                  that are normally left out
#                              categories webshell webapp linux exploit malware
#                                         generic docs legacy
#                              ClamAV     any script elf doc pe other pua: ADD these
#                              target     ClamAV target groups to what the profile
#                              groups     brings (hosting = any,script,elf; server
#                                         + doc; all = everything, incl. Windows pe)
#                            Several packs are separated with ",": -u builds
#                            each of them in one go (then ship the whole
#                            signatures/.cache as ONE archive); a scan uses
#                            exactly one pack (a not yet built one is built on
#                            first use). Examples:
#                                ./av.sh -u --packs hosting,server,all
#                                ./av.sh -d /home --packs hosting
#                                ./av.sh -d /home --packs hosting+pe   (+ Windows PE)
#                                ./av.sh -d /srv --packs webshell+linux
#                            ClamAV PUA.* signatures ("potentially unwanted":
#                            adware, packers, hack tools, the source of most
#                            s_PUA_* false positives) are OFF by default: add the
#                            group "pua" (--packs server+pua) or --clam-pua.
#                            Your own rule files (not from the two community
#                            repos) are always loaded. RAM of the yara process
#                            grows with the pack, so heavy packs need more -r.
#                            Old --yara-rules / --clam-groups / --yara-all still
#                            work for now (with a [DEPRECATED] hint).
#   -X, --exclude PATH        Skip this file/directory entirely (repeat for
#                            multiple: -X /path/one -X /path/two). The AV's
#                            own install dir, signature dir, and quarantine
#                            dir are always excluded automatically.
#   -A, --scan-archives      Look inside archives (.zip/.jar/.tar/.tar.gz/
#                            .tgz/.tar.bz2/.tar.xz/.gz/.bz2/.xz, plus .7z/
#                            .rar if 7z/unrar is installed) — off by
#                            default (extraction has real CPU/time cost and
#                            some risk from malformed/huge archives, hence
#                            the safety limits below). A detection inside
#                            an archive is reported against the ARCHIVE
#                            FILE itself (with the internal member path
#                            noted), not a temp path, and quarantine (if
#                            enabled) moves the whole archive.
#   --archive-limits SIZE,EXTRACT,DEPTH,FILES
#                            Safety limits for -A, any field may be left empty
#                            to keep its default (e.g. --archive-limits ,,4,):
#                              SIZE     skip archives bigger than this, MB
#                                       compressed (default: 200)
#                              EXTRACT  abort extraction past this much
#                                       decompressed data, MB - zip-bomb
#                                       defense (default: 500)
#                              DEPTH    nested-archive levels (default: 2)
#                              FILES    scan only the first N members of one
#                                       archive (default: 2000)
#                            Where archives are unpacked (RAM or disk) follows
#                            --ram-dirs.
#   --yara-mode MODE          How YARA runs (default: threads).
#                              threads  one yara process for the whole scan with
#                                       several threads (-p): workers hand it their
#                                       batches; RAM ~ one copy of the ruleset,
#                                       whatever -j is
#                              workers  old model: each worker runs its own yara
#                                       (one ruleset copy per worker = -j x RAM)
#   --yara-threads N          Threads of that one yara process (threads mode;
#                            default: the number of workers, max 32)
#   --yara-timeout SECONDS    Abort a single yara call after this long
#                            (default: 300; --deep: 600) — protects against a scan
#                            hanging indefinitely on a pathological file.
#                            On a timeout, that batch is retried one file
#                            at a time with a short timeout each: fast
#                            files still get scanned normally, and
#                            whichever one is actually slow gets reported
#                            (as SCAN_TIMEOUT) and skipped instead of
#                            stalling the whole scan.
#   -L, --long-time [SEC]     Just LOG any single batch call that takes
#                            longer than SEC seconds (default: 20; e.g.
#                            -L 60) — batch type, elapsed time, and the
#                            exact file list — to <output>.slow, without
#                            aborting or changing scan behavior at all.
#                            Survives even a successful finish (a separate
#                            file from the main report, which gets
#                            overwritten with the clean summary at the
#                            end) — tail -f it during a scan to watch live.
#   --sandbox-mode MODE       Isolate archive EXTRACTION (the highest-risk
#                            operation — parsing attacker-controlled zip/
#                            tar/7z/rar) as defense-in-depth against a bug
#                            in the extractor itself being exploited by a
#                            malicious archive. auto|bwrap|unshare|chroot|
#                            simple|none (default: auto — picks the
#                            strongest available: bwrap > unshare >
#                            simple; --sandbox-mode none opts out).
#                            Rewritten from a person's draft after finding
#                            and fixing several real bugs during
#                            review/testing (broken bwrap argument
#                            passing, leaked chroot bind mounts, missing
#                            access to the archive/extraction tool paths
#                            inside the isolated filesystem view).
#   --ram-dirs MODE         Where the scan keeps its temporary data:
#                              auto  (default) /dev/shm when the RAM ceiling
#                                    allows it; archives up to 50 MB are
#                                    unpacked in RAM, bigger ones on disk
#                              none  everything on disk (/tmp)
#                              all   also force the compiled signatures into
#                                    /dev/shm and unpack every archive (up to
#                                    the --archive-limits SIZE) in RAM
#   --no-busybox            Fully disable busybox (no auto-download, no local
#                            binary use) — system tools only
#   -b, --busybox PATH      Explicit path to an existing busybox binary
#   --mb-key KEY            MalwareBazaar Auth-Key for -u (optional; or the
#                            environment variable ORPHUS_MB_KEY)
#   -q, --quarantine        Enable quarantine mode (default dir: ./quarantine)
#   --quarantine-dir PATH   Enable quarantine mode with a custom directory
#   --quarantine-perm MODE  chmod mode for quarantined files (default: 0400,
#                            i.e. read-only, not executable)
#   -w, --real-time         After the base scan, switch to background watch
#                            mode: new files get scanned automatically
#                            (inotifywait, or polling as fallback). Also
#                            auto-enables -I (incremental) and dpkg SUID
#                            verification (see both below) — real-time's
#                            whole point is running/watching continuously,
#                            which is exactly when both pay off.
#   --watch-interval SEC    Polling interval for the fallback watcher (default: 5)
#   -I, --incremental        Skip files unchanged (mtime+size) since they
#                            were last found clean, using a persistent
#                            cache under the signature dir. Auto-on for -w;
#                            use --no-incremental to force it off there.
#   --incremental-cache PATH Override the cache file location (default:
#                            signatures/.incremental_cache.tsv)
#   --no-verify-suid         SUID/SGID files are verified against the distro
#                            package checksums (dpkg/rpm) by default, so known
#                            system binaries (sudo, su, mount ...) are not
#                            reported and modified ones are flagged TAMPERED.
#                            This turns that off (raw SUID/SGID listing).
#   --low-priority           Renice + ionice this process (and everything
#                            it spawns) to the lowest CPU/disk priority, and
#                            default to a single worker unless -j overrides
#                            — for running unobtrusively alongside other
#                            services on the same box (e.g. -w in the
#                            background long-term).
#   -P, --scan-processes     Check running processes for simple rootkit
#                            indicators: a process whose backing binary
#                            was deleted from disk (still running, but
#                            invisible to any file-based scan — the
#                            classic "malware deletes itself, keeps
#                            running in memory" case), a live process
#                            hashing to a known-malware signature, an
#                            LD_PRELOAD hooking indicator, and a process
#                            visible in /proc but hidden from `ps`. Can
#                            run standalone (no -d needed — just checks
#                            processes and exits) or alongside a normal
#                            file scan. Does NOT and cannot reliably catch
#                            a genuine kernel-level (LKM) rootkit, which
#                            can lie to /proc itself same as any tool.
#   -K, --check-kernel        Check kernel image / initramfs / loaded
#                            module (.ko) files against the package
#                            manager's own recorded checksums (dpkg -V
#                            logic) — a tampered boot file or a module not
#                            owned by any package is a strong persistence
#                            indicator. MEANINGLESS RUN AGAINST THE LIVE
#                            SYSTEM if that system's own kernel is what's
#                            compromised (same limitation as -P — it can
#                            lie to this check too). Only really means
#                            something paired with --offline-root, run
#                            from your host's rescue/recovery boot (every
#                            major provider offers one — the practical
#                            cloud-VPS equivalent of a LiveCD).
#                            ALSO compares every boot/vmlinuz-* with a list of
#                            known kernel builds (signatures/kernel_refs/*.tsv,
#                            one file per distribution: ubuntu debian alma rocky
#                            centos; all produced by ONE script,
#                            tools/gen_kernel_refs.py, from the distributions' own
#                            packages). This needs no dpkg, so it also works from
#                            a rescue system that is not Debian/Ubuntu, and it
#                            does not trust the checksums stored on the inspected
#                            disk. Verdicts: OK / MISMATCH (known name, wrong
#                            content) / RENAMED / UNKNOWN (not in the list).
#   --audit                   Compromise audit instead of a file scan (own module,
#                            read-only, takes seconds). Looks at what the file scanner
#                            cannot see: effective sshd settings (PermitRootLogin /
#                            PasswordAuthentication, first value wins across Include
#                            files), UID-0 and empty-password accounts, authorized_keys,
#                            ld.so.preload, cron/systemd/rc.local/shell-startup persistence,
#                            executables and ELF files in /tmp /var/tmp /dev/shm, miner and
#                            brute-force tool names, shell history (wiped / suspicious),
#                            and the sshd logs: login after many failures (password
#                            guessed), failed logins from 127.0.0.1 (brute force launched
#                            from this host), logins from different IPs seconds apart,
#                            root password logins, logins missing from wtmp. Best with
#                            --offline-root. -o FILE saves the report. Exit code:
#                            0 nothing, 1 only MEDIUM, 2 at least one HIGH.
#   --audit-since DATE        Same, and also list system files (etc, root, usr/local, opt,
#                            cron, systemd, tmp, bin dirs) changed since DATE (YYYY-MM-DD),
#                            e.g. the day the first suspicious login happened.
#   --offline-root PATH       Point every check (including -K, and the
#                            normal file scan via -d) at a MOUNTED, NOT
#                            BOOTED disk instead of the live filesystem —
#                            e.g. after booting your provider's rescue
#                            system and mounting the suspect disk at
#                            /mnt/suspect-root:
#                              ./av.sh --offline-root /mnt/suspect-root \
#                                -K -d /mnt/suspect-root
#                            This is what makes -K meaningful against a
#                            real kernel-level rootkit — everything reads
#                            through the RESCUE kernel, not a potentially
#                            compromised one. Booting into rescue mode
#                            itself is always a manual step through your
#                            provider's control panel — nothing here can
#                            or should try to trigger that automatically
#                            from within a system you don't trust the
#                            kernel of. Incompatible with -P (no running
#                            processes to inspect on an unmounted disk).
#   --clam-pua               Include the ClamAV PUA.* signatures (= group "pua"
#                            in --packs). Off by default; --deep still shows PUA
#                            hash hits.
#   --deep, --paranoid        One-off scan with maximum scrutiny: turns on
#                            SUID/SGID package verification and archive
#                            scanning (both -w-only by default), skips
#                            incremental-cache shortcuts, and — the main
#                            point — bypasses EVERY automatic suppression
#                            mechanism (ignore_sigs, the vendor-
#                            obfuscation allowlist) so nothing is
#                            filtered out before you see it. The person
#                            decides what's a false positive, not the tool.
#   --batch-size N            Files per hash/YARA batch (default: 200); the
#                            strings/hex heuristic batch follows it and the
#                            PE-section batch is half of it. Smaller =
#                            smoother progress, at some throughput cost.
#                            (Cap on compiled hex patterns: environment
#                            variable ORPHUS_MAX_HEX_PATTERNS, default 8000.)
#   --setup                  Install yara/yarac into bin/ (and fetch busybox
#                            if missing), then exit. Prefers --yara-url if
#                            given; otherwise compiles from source (needs a
#                            C toolchain — auto-installed via whichever of
#                            apt/dnf/yum/zypper/pacman/apk is present).
#   --yara-url URL            Install yara/yarac from a prebuilt tarball at
#                            this URL instead of compiling — no compiler
#                            needed on the target machine. YARA publishes no
#                            official prebuilt binaries, so this is meant to
#                            point at your OWN mirror: build once with
#                            --setup --compile on one machine, host the
#                            resulting bin/{yara,yarac} as a .tar.gz
#                            somewhere reachable, then every other machine
#                            just downloads it (same idea as busybox, just
#                            self-hosted since no upstream exists for yara)
#   --busybox-url URL         Override the busybox download URL (internal
#                            mirror), same idea as --yara-url
#   --setup --compile         Force compiling from source even if
#                            --yara-url is also given
#   --setup --force           Reinstall/rebuild even if bin/yara already exists
#   --force                   Also: with --offline-root, start even though the disk is
#                            NOT mounted read-only (by default the script refuses, exit 3),
#                            and allow -q/--quarantine: quarantine MOVES detected files off
#                            the inspected disk, so with --offline-root it only starts with
#                            --force (the disk must then be read-write). Either way the run
#                            is no longer evidence. --quarantine-dry-run needs no --force.
#   --check-deps             Print bundled/system/missing status for
#                            busybox and yara/yarac, then exit
#   -h, --help               Short help (main options and examples)
#   --help-all               This full reference (also runs --check-deps)
#   --debug                   Keep --setup's build/compile logs
#                            (configure/make output for yara/grep/bash) in
#                            /tmp even after a SUCCESSFUL build — off by
#                            default, since a successful build has no use
#                            for them and they'd otherwise just pile up in
#                            /tmp forever across every --setup run. Failed
#                            builds always keep their logs regardless,
#                            debug or not — that's the one case they're
#                            actually needed for.
#
# Examples — the usual workflow, in order:
#
#   1) One-time install (needs network + a C toolchain):
#        ./av.sh --setup                     build bin/yara, bin/yarac, grep, bash
#                                            (and fetch busybox). Binaries are
#                                            downloaded/built ONLY by --setup,
#                                            never during a scan.
#
#   2) Get and compile signatures (separate action, no scan afterwards):
#        ./av.sh -u                          update; builds the default pack (all)
#        ./av.sh -u --packs hosting,server,all
#                                            update and build several packs at
#                                            once. Pack = a prebuilt YARA/ClamAV
#                                            set kept in signatures/.cache/packs/.
#                                            Ship that .cache as one archive and
#                                            nothing has to be compiled on the
#                                            target machine.
#        ./av.sh -u --packs hosting,hosting+pe
#                                            the light pack, plus a variant of it
#                                            that also has the Windows PE ClamAV
#                                            signatures
#
#   3) Scan (the pack is chosen per scan, nothing is recompiled if it exists):
#        ./av.sh -d /home                    scan /home with the default pack (all)
#        ./av.sh -d /home --packs hosting    light pack for PHP/CMS hosting
#        ./av.sh -d /srv --packs webshell+linux  only these YARA categories
#        ./av.sh -d /var/www --packs server  web + Linux + documents, no Windows PE
#        ./av.sh -d /mnt/win --packs all     everything, incl. Windows signatures
#        ./av.sh -d /home -o report.log      also write the report to a file
#        ./av.sh -d /home -X /home/backup    skip a directory (repeat -X for more)
#        ./av.sh -d /home -j 4 -r 1000       4 workers, 1000 MB RAM ceiling
#                                            (YARA: one process x 4 threads,
#                                            one copy of the ruleset in RAM)
#        ./av.sh -d /home --yara-mode workers
#                                            old model: each worker runs its own
#                                            yara (one ruleset copy per worker)
#        ./av.sh -d / --deep -o audit.log    maximum scrutiny, ignores ignore_sigs
#        ./av.sh -d /home -A                 look inside archives too
#        ./av.sh -d /home -q                 move detected files to quarantine/
#
#   4) Other modes:
#        ./av.sh -w -d /home                 real-time watch after the base scan
#        ./av.sh -P                          check running processes only
#        ./av.sh --offline-root /mnt/disk -K -d /mnt/disk
#                                            rescue-mode audit of a mounted disk
#        ./av.sh --offline-root /mnt/disk --audit
#                                            was the host broken into? sshd settings,
#                                            accounts/keys, persistence, auth logs
#        ./av.sh --offline-root /mnt/disk --audit-since 2026-09-29 -o audit.txt
#                                            same + files changed since that day, saved
#        ./av.sh --check-deps                what is bundled / missing
#
#   5) Audit — "was this host broken into?" (--audit, separate from file scans):
#        # boot the rescue system, mount the suspect disk read-only at /mnt, then:
#        ./av.sh --offline-root /mnt --audit
#                                            everything below, in seconds
#        ./av.sh --offline-root /mnt --audit-since 2026-09-29 -o /root/audit.txt
#                                            + system files changed since that date
#                                            (use the date of the first suspicious
#                                            login); the report is saved in plain text
#        ./av.sh --audit                     the running system (a rootkit can lie to it)
#      Mount the suspect disk READ-ONLY first, and for ext4 (the usual case) with noload:
#          mount -o ro,noload /dev/sdXN /mnt        (xfs: -o ro,norecovery)
#      A plain "ro" mount of ext4 still REPLAYS THE JOURNAL, i.e. writes to the disk and
#      alters the evidence; reading a read-write mount also changes access times.
#      So every --offline-root run (audit, -K, scan) REFUSES TO START when the disk or a
#      partition under it is mounted read-write (exit code 3), and prints the exact
#      mount command for the detected filesystem. Override: --force (the run is then
#      only a warning, and no longer evidence). -q needs it, as it moves files.
#
#      Run it BEFORE or next to a file scan: an attacker who guessed the root password
#      needs no malware, so a clean file scan proves nothing about this.
#      Exit code: 0 nothing found, 1 only MEDIUM, 2 at least one HIGH.
#
#      How to read the output. Severity:
#        [!] HIGH   strong indicator: act on it (rotate secrets, close SSH password
#                   login, rebuild if in doubt)
#        [?] MEDIUM needs a human look: are these logins / keys / jobs really yours?
#            (plain) context for the report (lists of logins, users, ports)
#      Tags (AUDIT_<TAG>), grouped by check:
#        evidence hygiene
#          MOUNT_RW           MED   (only seen with --force) the disk or a partition under it
#                                   is mounted read-write; without --force it stops the run
#          MOUNT_RO           info  mounted read-only: good
#          MOUNT_JOURNAL      info  ext3/4 mounted ro without 'noload': the journal may have been
#                                   replayed at mount time
#          MOUNT              info  not a separate mount point, or cannot tell
#        sshd settings (first value in sshd_config / Include files wins)
#          SSH_ROOT_PASSWORD  HIGH  root may log in with a PASSWORD (PermitRootLogin yes
#                                   + PasswordAuthentication not "no"): brute-forceable
#          SSH_ROOT_LOGIN     MED   PermitRootLogin yes, but password login is off (keys)
#          SSH_PASSWORD       info  password login is on (root is not allowed by password)
#          SSH_OK             info  root by key only and no password login
#          SSH_OVERRIDDEN     info  a LATER line contradicts the effective value and is
#                                   ignored ("I set it to no, but it still works")
#          SSH_EMPTY_PW       HIGH  PermitEmptyPasswords yes
#          SSH_KEYS_CFG       MED   non-default AuthorizedKeysCommand / AuthorizedKeysFile
#          SSH_PORT           info  the port sshd listens on
#        accounts and keys
#          UID0               HIGH  a second account with UID 0 (hidden root)
#          EMPTY_PASSWORD     HIGH  account with an empty password in /etc/shadow
#          SYSTEM_SHELL       MED   service account (e.g. www-data) with a login shell
#          USERS / SUDO_NOPASSWD  info  login-capable users / sudo rules without password
#          AUTHORIZED_KEYS    MED   (root) / info (others): key count, mtime, comments —
#                                   check every key is known
#          KEY_OPTIONS        MED   a key with options (forced command, restrictions)
#          LD_PRELOAD         HIGH  /etc/ld.so.preload is not empty (userland rootkit)
#        persistence
#          CRONTAB            info  contents of user crontabs
#          CRON_SUSPICIOUS    MED   cron line with curl|sh, /dev/tcp, base64 -d, /tmp path...
#          SYSTEMD_SUSPICIOUS MED   a unit ExecStart-like line with the same patterns
#          STARTUP_SUSPICIOUS MED   rc.local / profile / .bashrc with the same patterns
#          DOCKER_TCP         HIGH  the Docker API listens on TCP (remote root)
#        files and history
#          TMP_ELF            HIGH  ELF binary in /dev/shm or with a hidden name in a tmp
#                                   dir; MED for an ELF in plain /tmp (often an installer)
#          TMP_EXEC           MED   executable file in /dev/shm; info in /tmp, /var/tmp
#          TOOL_NAME          MED   file named like a miner / brute-forcer / rootkit
#          HISTORY_WIPED / HISTORY_EMPTY  MED  shell history is /dev/null or empty
#          HISTORY_SUSPICIOUS MED   history line like wget ... | bash, nc -e, hydra...
#        sshd logs (auth.log*, secure*, also .gz)
#          LOGIN_AFTER_BRUTEFORCE HIGH  successful login from an IP that failed >=3 times
#                                   before: the password was probably guessed
#          LOCAL_BRUTEFORCE   HIGH  failed logins FROM 127.0.0.1: a brute-force tool ran
#                                   on this host, or an SSH tunnel goes through it
#          LOGIN_HANDOVER     MED   logins from different IPs within 60 s (one actor, or a
#                                   found password passed to another machine)
#          ROOT_PASSWORD_LOGINS MED root logged in BY PASSWORD from N distinct IPs
#          LOGIN_NOT_IN_WTMP  MED   in auth.log but not in wtmp: a login without a
#                                   terminal (remote command, tunnel, script), or wtmp
#                                   was edited
#          ACCEPTED           info  every successful login: user, method, IP, count,
#                                   first/last time, failures before the first success
#          AUTHLOG            info  which log files were parsed / how many failures
#          CHANGED            info  files changed since --audit-since DATE
#      These are indicators, not proof. Typical chain that means "break-in": SSH_ROOT_PASSWORD
#      + LOGIN_AFTER_BRUTEFORCE (+ LOGIN_HANDOVER, LOCAL_BRUTEFORCE). Nothing found does not
#      prove a clean host (processes in memory and deleted tools are invisible on disk).
#
#   Which pack for what: hosting = any + script + ELF ClamAV sigs and the
#   webshell/webapp/linux/exploit YARA rules (smallest RAM); server adds
#   documents and the malware/generic/docs YARA rules; all adds Windows PE and
#   the legacy rules. If a scan reports a RAM ceiling warning, pick a lighter
#   pack instead of raising the ceiling.
#
# File layout:
#   1. GLOBALS         — all script variables, defined once here
#   2. MODULE: platform / cpu
#   3. MODULE: busybox bootstrap (find / auto-download / bb wrapper)
#   4. MODULE: hash & yara & strings/file detection (busybox-first)
#   5. MODULE: CLI (usage, parse_args, colors)
#   6. MODULE: worker sizing / RAM guard
#   7. MODULE: quarantine (main-script side init)
#   8. MODULE: signature updater
#   9. MODULE: signature compiler (+ parallel awk pool)
#  10. MODULE: workdir & worker extraction
#  11. MODULE: dependency check
#  12. MODULE: file collection & worker orchestration
#  13. MODULE: progress monitor / cleanup
#  14. MODULE: reporting
#  15. MODULE: real-time watch (background daemon)
#  16. main()          — single entry point, calls modules in order
#  17. EMBEDDED WORKER  — separate self-contained script (also modular;
#                          does the scanning and the actual quarantine)
#
# Package layout (for building a distributable archive):
#   Paths below are relative to SCRIPT_DIR (where av_scan.sh lives). Only
#   av_scan.sh itself is required; everything else is either bundled or
#   auto-created on first run.
#
#   av_scan/
#   ├── av_scan.sh              [REQUIRED]
#   ├── bin/
#   │   ├── busybox              [RECOMMENDED] static busybox binary
#   │   │                        (x86_64 linux-musl static build; ARM: bring your own)
#   │   ├── yara                 [RECOMMENDED] built by `av_scan.sh --setup`
#   │   └── yarac                (not fetched automatically like busybox —
#   │                            YARA ships no ready static binaries, so
#   │                            --setup compiles them from source; needs
#   │                            a C toolchain + network once)
#   ├── signatures/              [OPTIONAL] signature DB; created by
#   │   ├── maldet/               update_signatures() on -u if missing, or
#   │   ├── clamav/                the scanner just runs on built-in
#   │   ├── hashes/                heuristics without it.
#   │   ├── yara/
#   │   ├── strings/
#   │   ├── custom/
#   │   │   ├── custom.sha256    [OPTIONAL] own hashes: "hash<TAB>name"
#   │   │   ├── custom.md5       [OPTIONAL] same for MD5
#   │   │   └── custom.strings   [OPTIONAL] own string signatures
#   │   ├── .cache/               [AUTO] persistent compiled cache
#   │   └── .compiled            [AUTO] compile flag, no need to ship
#   └── quarantine/              [AUTO, only with -q] auto-created
#       └── manifest.tsv           auto-created, no need to ship
#
#   Temp work dirs (/dev/shm/av_scan_$$ or $TMPDIR/av_scan_$$) are created
#   and removed by the script each run — not part of the package.
#
#   Minimal fully-offline archive: av_scan.sh + bin/{busybox,yara,yarac}
#   + signatures/ (pre-populated). Just av_scan.sh alone also works: run
#   `av_scan.sh --setup` once (needs network + a C toolchain) to build
#   yara/yarac locally, and busybox auto-downloads on first scan.
# =============================================================================
set -uo pipefail
export LC_ALL=C

# ============================================================================
# 1. GLOBALS — all script variables defined once here, before any code uses
#    them. init_*/detect_* functions and parse_args() fill in real values.
# ============================================================================
VERSION="0.3.4"
# Format of the compiled signature cache (signatures/.cache). Raise it whenever
# compile_signatures produces different output for the same sources: the cache
# is rebuilt on the next run. Independent of VERSION, which is just a label.
CACHE_FORMAT=6
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Re-exec into our OWN bundled bash (see build_bash_from_source /
# --setup), if it's present, and we aren't already running under it — as
# early as possible, before any other code runs. Rootkits (Diamorphine,
# t0rn-style, and others) commonly patch system binaries that admin
# tooling routinely runs through, /bin/bash among them — narrows how much
# of this scan's own execution ever touches a potentially-tampered
# interpreter. AV_NO_REEXEC=1 escapes this (debugging, or intentionally
# testing under system bash).
#
# HONEST LIMIT, stated plainly rather than implied: this does NOT fully
# solve the problem. Whatever shell interprets THIS invocation, up to and
# including the moment this check itself runs, is still exposed — no
# script can fully bootstrap trust in its own interpreter from within
# that same interpreter. Real protection comes from copying av.sh +
# bin/bash from a known-clean source and running "./bin/bash ./av.sh"
# directly, never touching system bash at all. This re-exec narrows
# exposure for the common case (person just runs "bash av.sh" or
# "./av.sh"), it does not eliminate it.
if [ -z "${AV_NO_REEXEC:-}" ] && [ -z "${AV_REEXECD:-}" ] && [ -x "$SCRIPT_DIR/bin/bash" ]; then
    if [ "$(readlink -f "$(command -v bash 2>/dev/null)" 2>/dev/null)" != "$(readlink -f "$SCRIPT_DIR/bin/bash" 2>/dev/null)" ]; then
        AV_REEXECD=1 exec "$SCRIPT_DIR/bin/bash" "$0" "$@"
    fi
fi

# Used everywhere this script launches ANOTHER bash process of its own
# (workers, the extracted setup module) — same reasoning as the re-exec
# above, just extended to child processes too, since a plain literal
# "bash" in those spots would resolve through $PATH to whatever system
# bash provides, undoing the point of re-exec'ing in the first place.
WORKER_BASH="bash"
[ -x "$SCRIPT_DIR/bin/bash" ] && WORKER_BASH="$SCRIPT_DIR/bin/bash"

# --- CLI-configured params (defaults, overridable via parse_args) ---
SIGNATURES="${SCRIPT_DIR}/signatures"
ROOT_DIR="/mnt"
ROOT_DIR_EXPLICIT=""    # set to 1 if -d/--dir was explicitly passed —
                        # lets -P/--scan-processes run standalone (process
                        # scan only, no file tree scan) when -d wasn't given
MAX_SCAN_MB=50
MAX_SCAN_MB_EXPLICIT=""  # set to 1 if -m/--max-size was explicitly
                        # passed — lets --deep raise the default without
                        # overriding a person's own explicit choice
MAX_RAM_MB=500
OUTPUT_FILE=""
LIVE_REPORT_FILE=""    # persistent (outside WORK_DIR) file threats are
                        # appended to AS THEY'RE FOUND, so Ctrl+C/SIGTERM
                        # mid-scan doesn't lose already-detected results
PERMS_REPORT_FILE=""   # companion file for permission findings (WORLD_WRITABLE_EXEC)
SUID_REPORT_FILE=""    # companion file for SUID_SGID findings specifically
                        # — set alongside LIVE_REPORT_FILE in init_live_report()
IGNORE_SIGS_FILE=""    # set in init_ignore_sigs(); patterns (ERE, one per
                        # line) matched against "TYPE|info" of each threat —
                        # a match suppresses that detection entirely (no
                        # log, no quarantine). For noisy signatures/rules
                        # that false-positive on specific legitimate
                        # software (e.g. CMSes that ship obfuscated core
                        # files for license protection, which structurally
                        # resembles webshell obfuscation to generic YARA
                        # heuristics). Same idea as LMD's ignore_sigs.
GENERIC_OBFUSCATION_RULES_FILE=""  # see init_vendor_obfuscation_allowlist
KNOWN_VENDOR_OBFUSCATION_FILE=""   # see init_vendor_obfuscation_allowlist
EXCLUDE_PATHS=()        # -X/--exclude PATH (repeatable): extra paths/dirs
                        # to skip. Always ALSO includes the scanner's own
                        # install dir, signature dir, quarantine dir, work
                        # dir, and report files — otherwise scanning a
                        # target that happens to contain the AV's own
                        # installation (e.g. scanning "/" or "/root")
                        # makes every YARA rule/signature file detect
                        # ITSELF, since the signature files literally
                        # contain the patterns being searched for. Logic
                        # lives inline in collect_files(), not a
                        # separately-named function.
DO_UPDATE=false
USE_RAM=true
ARCHIVE_USE_RAM=true   # captured separately from USE_RAM — see comment
                        # where it's set, in init_workers()
SIG_IN_RAM=false       # --sig-in-ram: force the COMPILED signature set
                        # (sha256.tsv/md5.tsv/rules.yarc/mdb.tsv — can be
                        # tens to a couple hundred MB for a real
                        # ClamAV+Maldet+YARA-repo combined database) into
                        # /dev/shm specifically, independent of the
                        # general USE_RAM/low-RAM-profile decision that
                        # governs the rest of WORK_DIR. Off by default —
                        # the low-RAM-profile default (500MB ceiling)
                        # already keeps normal runs modest on RAM; this is
                        # an explicit opt-in for people running on boxes
                        # with room to spare who want every batch's
                        # hash/YARA lookup to be a guaranteed RAM hit
                        # instead of hoping the OS page cache didn't get
                        # evicted partway through a long scan.
NO_RAM_EXPLICIT=""     # set when --no-ram is explicitly passed — the
                        # low-RAM-profile auto-tuning below can force
                        # USE_RAM=false on its own (default RAM ceiling is
                        # 500MB, which trips that), but that heuristic is
                        # about sizing the MAIN ephemeral WORK_DIR (which
                        # scales with worker count) and shouldn't also
                        # block the much smaller, independently-bounded
                        # archive-RAM-extraction feature — see ARCHIVE_USE_RAM.
ALLOW_BUSYBOX=true
MB_KEY="${ORPHUS_MB_KEY:-}"   # --mb-key / env ORPHUS_MB_KEY
WORKERS=""            # empty = "auto", resolved in init_workers()
MAX_HEX_PATTERNS="${ORPHUS_MAX_HEX_PATTERNS:-8000}" # cap on compiled hex_ere.txt entries, see compile_signatures
# Batch sizes: real-world testing showed the smaller "smoother progress"
# defaults (50) cost real throughput on weaker hardware — a slow VPS
# genuinely bottlenecks on the fixed per-call cost of grep/yara being paid
# more often, not just perceived choppiness. Raised the defaults back up;
# --batch-size/--heur-batch-size/--pe-batch-size are still there for anyone
# who wants smoother-but-slower progress updates instead.
BATCH_SIZE=200         # files per hash/YARA batch
HEUR_BATCH_SIZE=200    # files per strings/hex heuristic batch
PE_BATCH_SIZE=100      # files per PE-section (.mdb) batch
SANDBOX_MODE="auto"    # --sandbox-mode auto|bwrap|unshare|chroot|simple|none
                        # — isolates archive EXTRACTION specifically (the
                        # highest-risk operation: parsing an
                        # attacker-controlled zip/tar/7z/rar). Defaults
                        # to auto (external review flagged "off by
                        # default" as a real gap) — degrades gracefully
                        # (bwrap > unshare > simple), and even the
                        # weakest tier still runs unprivileged with
                        # resource limits rather than fully unsandboxed;
                        # if NONE of those tools exist either, extraction
                        # still runs normally, just without isolation, so
                        # this can't newly break anything. --sandbox-mode
                        # none opts back out explicitly. See MODULE:
                        # sandboxed extraction in the worker for the
                        # actual implementation.
SANDBOX_USER="nobody"
SANDBOX_MEM_KB=1048576  # 1GB, simple mode only
SANDBOX_CPU_SEC=60
YARA_MODE="threads"    # --yara-mode threads|workers (see _yara_ram_cap)
YARA_THREADS_ARG=""    # --yara-threads N (threads mode; default = number of workers)
YARA_TIMEOUT_SEC=300   # --yara-timeout: abort a yara call after this many
EXPLAIN_FILE=""           # --explain FILE: why is / isn't this file reported
MEDIA_FAST=false          # --media-fast: video/audio (by magic bytes) -> YARA on head+tail only, no full hash
CLAM_PUA=false            # --clam-pua / pack item "pua": ClamAV PUA.* signatures (off by default)
PACK_CLAM_ADD=""          # ClamAV groups added by a pack ("hosting+pe" -> pe)
PACK_ID=""                # cache id of the selected pack (see _pack_apply)
RAM_DIRS="auto"           # --ram-dirs auto|none|all
BATCH_SIZE_EXPLICIT=""    # --batch-size given: heuristic/PE batches follow it
HEUR_BATCH_EXPLICIT=""; PE_BATCH_EXPLICIT=""   # old per-batch options given
PACKS_SPEC=""             # --packs: with -u, build these YARA/ClamAV packs (hosting,server,all,...)
CLAM_GROUPS_ARG=""        # --clam-groups: override which ClamAV target groups go into the pack
YARA_RULES_SPEC="server"        # default pack: server = hosting + malware/generic/docs (no Windows PE); "hosting" is
                        # the lighter opt-in): which community YARA rule
                        # categories to compile (see _yara_category)
YARA_ALL=false          # --yara-all: every category, built-in file
                        # exclusions bypassed too — at real RAM cost
YARA_CATS=""            # expanded category list, filled by
                        # _yara_expand_profile
YARA_TIMEOUT_SEC_EXPLICIT=""  # set to 1 if --yara-timeout was explicitly
                        # passed — lets --deep raise the default without
                        # overriding a person's own explicit choice
                        # seconds (yara's own -a flag) — a real scan can
                        # otherwise hang indefinitely on a pathological
                        # file/rule combination (reported in practice: a
                        # live yara process sitting idle-looking but never
                        # finishing on ordinary PHP/JS files). On a
                        # timeout, the batch is retried file-by-file with a
                        # much shorter per-file timeout to both salvage
                        # results from the files that AREN'T the problem
                        # and identify+report the one(s) that are.
LONG_TIME_MODE=false    # -L/--long-time: log any SINGLE batch call that
                        # takes longer than LONG_TIME_THRESHOLD_SEC (batch
                        # type, elapsed time, exact file list) to the live
                        # report — pure observability, no behavior change.
                        # Pairs well with --yara-timeout for cases you
                        # want to actively abort, or use alone just to
                        # monitor "what's slow" without touching behavior.
LONG_TIME_THRESHOLD_SEC=20
SCAN_ARCHIVES=false     # -A/--scan-archives: opt-in (extraction has real
                        # cost and some risk — see MODULE: archive scanning)
ARCHIVE_MAX_MB=200      # skip archives bigger than this (compressed size)
ARCHIVE_MAX_EXTRACT_MB=500 # abort extraction past this much decompressed
                        # data — defense against decompression bombs
ARCHIVE_RAM_MAX_MB=50   # extract archives up to this COMPRESSED size
                        # straight into /dev/shm (RAM) — faster than disk,
                        # especially on IOPS-capped hosts. Bigger archives
                        # fall back to disk (still respects --no-ram /
                        # /dev/shm free-space checks either way) to avoid
                        # unbounded RAM pressure from one huge archive.
ARCHIVE_MAX_DEPTH=2     # how many nested-archive levels to recurse into
ARCHIVE_MAX_FILES=2000  # only scan the first N files inside one archive
DO_SETUP=false         # --setup: build yara/yarac (and fetch busybox) then exit
DEBUG_MODE=false       # --debug: keep build/compile logs (yara/grep/bash
                        # setup) in /tmp even on SUCCESS, for inspection.
                        # Default is to delete them once a build succeeds
                        # — they only exist to help diagnose a FAILED
                        # build, and otherwise just accumulate in /tmp on
                        # every --setup run, forever, for no reason.
SETUP_FORCE=false       # --setup --force: rebuild even if already present
SETUP_COMPILE_ONLY=false # --setup --compile: skip --yara-url, always compile
DO_CHECK_DEPS=false     # --check-deps: print dependency status and exit
YARA_URL_ARG=""         # --yara-url: fetch a prebuilt yara/yarac tarball
                        # instead of compiling from source (own mirror/CDN)
BUSYBOX_URL_ARG=""      # --busybox-url: override the busybox download URL

# --- Quarantine ---
QUARANTINE_ENABLED=false
QUARANTINE_DRY_RUN=false   # --quarantine-dry-run: report what WOULD be
                        # quarantined without moving anything — see the
                        # comment where it's checked in quarantine_file()
QUARANTINE_SKIP_ARCHIVES=false  # always false now (with -q archives are quarantined too); --no-quarantine-archives: when a threat
                        # is found INSIDE an archive member, the file
                        # that gets quarantined is necessarily the whole
                        # ARCHIVE CONTAINER (there's no way to cleanly
                        # remove just one member without rewriting the
                        # archive) — real collateral cost if the archive
                        # has hundreds of otherwise-clean files alongside
                        # the flagged one. This reports the finding as
                        # normal but leaves the container in place,
                        # letting a person review and decide by hand.
QUARANTINE_DIR="${SCRIPT_DIR}/quarantine"
QUARANTINE_PERM="0400"   # read-only, not executable (NOT literal "100" —
                          # that means --x------, the opposite)

# --- Real-time watch (background daemon) ---
REALTIME_MODE=false
WATCH_INTERVAL=5
REALTIME_FIFO=""
REALTIME_WORKER_PID=""
REALTIME_REPORT=""
LOW_PRIORITY=false     # --low-priority: run as unobtrusively as possible
                        # (nice + ionice, fewer workers unless -j overrides)
WORKERS_EXPLICIT=""    # set to 1 if -j/--workers was explicitly passed
INCREMENTAL_MODE=false # -I/--incremental, also auto-enabled for -w unless
                        # --no-incremental explicitly says otherwise — see
                        # MODULE: incremental scan cache
INCREMENTAL_EXPLICIT_OFF=""
INCREMENTAL_CACHE_FILE=""  # default set in init_incremental_cache()
SKIPPED_UNCHANGED=0     # files skipped this run because the cache says
                        # they're unchanged since they were last found clean
SUID_VERIFY_MODE=true   # dpkg/rpm package-checksum verification for
                        # SUID/SGID files — ON BY DEFAULT (changed from
                        # opt-in): the existing "unowned" short-circuit
                        # (see _verify_package_file) already skips the
                        # dpkg lookup entirely for anything outside
                        # /usr,/bin,/sbin,/lib,/opt, so this only costs a
                        # dpkg -S call for the small, fixed set of REAL
                        # system SUID/SGID binaries — not the unbounded
                        # cost the old opt-in gate was guarding against.
                        # Real complaint this fixes: a normal one-off scan
                        # unconditionally reported passwd/sudo/su/mount/
                        # ssh-keysign/etc (every standard Ubuntu SUID
                        # binary, plus its snap-packaged duplicates) EVERY
                        # single run, package-verified-clean or not —
                        # pure noise a person has to re-triage each time.
                        # --no-verify-suid restores the old raw/unverified
                        # behavior if dpkg isn't trusted or available.
SUID_VERIFY_EXPLICIT_OFF=""
DEEP_MODE=false         # --deep/--paranoid: convenience umbrella for a
                        # one-off scan that wants -w's extra scrutiny
                        # (SUID/SGID package verification, archive
                        # scanning) without actually running in real-time
                        # mode — see parse_args for exactly what it sets.
                        # ALSO bypasses every automatic suppression
                        # mechanism (ignore_sigs, vendor-obfuscation
                        # allowlist, incremental cache skip) — the whole
                        # point of a deep pass is maximum precision with
                        # no exclusions at all; the person reviews and
                        # dismisses findings themselves, not the tool.
REALTIME_TAIL_PID=""
REALTIME_WATCH_PID=""

# --- Platform (filled by detect_platform) ---
OS=""
ARCH=""

# --- Toolchain (filled by init_toolchain / detect_sha256 / detect_md5 / detect_yara) ---
BUSYBOX_BIN=""        # path to busybox binary (empty = not found/disabled)
BUSYBOX_PATH_ARG=""   # explicit path from -b/--busybox, if given
BB_APPLETS=""         # cached applet list, space-padded on both ends
STRINGS_CMD="bash"
FILE_CMD="bash"
SHA256_CMD="none"
MD5_CMD="none"
SHA1_CMD="none"
YARA_CMD="none"
YARAC_BIN=""           # path to yarac (compile-time only; empty = not found
GREP_BIN=""            # bundled static grep (bin/grep, see --setup); empty
                        # = fall back to whatever "grep" resolves to on PATH

# --- Runtime work paths (filled by init_workdir) ---
WORK_DIR=""
WORKER_FILE=""
SIG_DIR=""

# --- Terminal colors (filled by setup_colors) ---
R=''; Y=''; G=''; C=''; B=''; Z=''

# --- Scan state ---
START_MS=0
END_MS=0
ELAPSED_S=0
TOTAL_FILES=0
WORKER_PIDS=()
MONITOR_PID=""
HAS_SETSID=false       # set once in launch_workers()/start_realtime_worker()
                        # — controls whether cleanup() can safely kill each
                        # worker's WHOLE PROCESS GROUP (needed to also kill
                        # a yara/grep/etc subprocess currently running
                        # INSIDE a worker when the worker itself gets
                        # killed — plain `kill $worker_pid` only kills the
                        # worker's own PID, not its in-flight children,
                        # which is exactly what orphaned them running
                        # unkillable in the background after Ctrl+C).
TF=0            # files scanned (total across workers)
TT=0            # threats found (total across workers)
QC=0            # quarantined (total across workers)
SC=0            # suppressed by ignore_sigs (total across workers)
SPEED=0
RPT=""          # final report text

# ============================================================================
# 2. MODULE: platform / cpu
# ============================================================================
#__SETUP_MODULE_START__
# Everything from here through the end of run_self_setup() is the
# self-contained BOOTSTRAP module: platform detection, busybox
# acquisition, and building yara/grep/bash from source. Marked off so it
# can be extracted to its own file (see extract_setup_module below) and
# run/debugged in isolation — the explicit design goal being "should work
# almost anywhere: needs only a filesystem and a kernel, and if the
# system's own tools are compromised or missing, build known-good
# replacements from source rather than trusting whatever's already there."
detect_platform() {
    case "$(uname -s 2>/dev/null)" in
        Darwin) OS="macos" ;;
        *)      OS="linux" ;;
    esac
    ARCH="$(uname -m 2>/dev/null)"
    case "$ARCH" in
        x86_64|amd64)   ARCH="x86_64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        armv7*)         ARCH="armv7" ;;
        *)              ARCH="x86_64" ;;
    esac
}

cpu_count() {
    command -v nproc &>/dev/null && { nproc; return; }
    command -v sysctl &>/dev/null && { sysctl -n hw.logicalcpu 2>/dev/null; return; }
    grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 4
}

now_ms() {
    date +%s%3N 2>/dev/null || echo $(( $(date +%s) * 1000 ))
}

# ============================================================================
# 3. MODULE: busybox bootstrap (find / auto-download / bb wrapper)
# ============================================================================
net_fetch() {
    # Downloader chain: system wget -> system curl -> busybox wget (last).
    # Optional 4th arg is a User-Agent (e.g. for the ClamAV mirror).
    # Optional 5th arg is a max expected size in MB (default 300 — generous
    # enough for every real thing this script downloads: main.cvd at
    # ~90MB, source tarballs at a few MB each, busybox at ~1.1MB).
    #
    # FIX (real, CONFIRMED gap found in security review): none of the
    # three downloaders had ANY bound on total transfer size — only
    # --connect-timeout/-T, which cap the CONNECTION/read-idle phase, not
    # the overall transfer. Confirmed directly: curl pulled 740MB from an
    # effectively infinite local source in 5 seconds with nothing
    # stopping it. First attempt at a fix added native per-tool flags
    # (curl --max-filesize/--max-time, wget -Q) on top of this — a real
    # report then came in of THIS WRAPPED download failing on a real
    # server while a plain, bare `curl url --output file` (no extra flags
    # at all) succeeded. wget's -Q turned out to be a red herring anyway
    # (its own docs say quota does NOT interrupt a single-file download,
    # only stops STARTING further ones — meaningless here, and apparently
    # not harmless either on some build). Rather than keep guessing which
    # specific flag misbehaves on which specific tool version without
    # being able to reproduce it directly, all the native per-tool size/
    # time flags are gone — every downloader now just fetches plainly
    # (matching the manual command confirmed to work), and the ONE
    # protection mechanism is the post-download size check below,
    # verified end-to-end including its own truncation edge case (see the
    # comment on it further down).
    local url="$1" dest="$2" timeout="${3:-10}" ua="${4:-}" max_mb="${5:-300}"
    local max_bytes=$(( max_mb * 1024 * 1024 ))

    _fetch_size_ok() {
        local f="$1" sz
        [ -s "$f" ] || return 1
        # NOTE: can't use the worker's _stat_size() here — net_fetch()
        # runs in the MAIN script during setup/toolchain init, before any
        # worker exists, and that function only exists within the
        # worker's own section of this file. Inlined, OS-portable
        # equivalent instead (same Linux/macOS stat flag difference).
        if [ "$OS" = "macos" ]; then sz=$(stat -f '%z' "$f" 2>/dev/null)
        else sz=$(stat -c '%s' "$f" 2>/dev/null); fi
        # FIX (real edge case found in testing): a source that gets cut
        # off exactly AT the cap (confirmed: curl's --max-filesize against
        # an effectively infinite stream stopped at exactly max_bytes and
        # still exited 0) is a TRUNCATED file, not a legitimately-sized
        # one — "<=" would have accepted it. A real file's size matching
        # our arbitrary round-number cap byte-for-byte is not plausible;
        # strictly "<" both catches the truncation case and still passes
        # every real download we do (all comfortably under their caps).
        [ -n "$sz" ] && [ "$sz" -lt "$max_bytes" ]
    }

    # Order: system wget -> system curl -> bundled busybox wget LAST. The
    # busybox wget applet does not validate TLS certificates, so it only
    # runs when neither system tool is installed (and warns for https).
    # wget --tries=2 (GNU default is 20) and curl's --speed-limit/--max-time
    # keep a stalled server from hanging a cron/--setup run forever; these
    # are time limits only (the size cap is still _fetch_size_ok below).
    if command -v wget &>/dev/null; then
        # FIX (real bug reported): -Q/--quota was added here for a
        # size cap, but wget's OWN documented behavior is that quota does
        # NOT interrupt a single file's download — it only stops
        # STARTING further downloads afterward (relevant for recursive
        # wget, meaningless for a single -O fetch like this one). At
        # best a no-op; suspected of actively breaking the download on
        # the specific wget build a real report came in against (direct
        # curl worked, our wrapped call didn't) — removed. The
        # post-download size check below is the real, verified
        # protection regardless of which tool ran.
        if [ -n "$ua" ]; then
            wget -q --tries=2 --timeout="$timeout" -U "$ua" -O "$dest" "$url" 2>/dev/null
        else
            wget -q --tries=2 --timeout="$timeout" -O "$dest" "$url" 2>/dev/null
        fi
        if _fetch_size_ok "$dest"; then return 0; else rm -f "$dest" 2>/dev/null; fi
    fi
    if command -v curl &>/dev/null; then
        # NOTE: --max-filesize also dropped here, same reasoning as -Q
        # above — even though curl's own docs are clearer about it than
        # wget's -Q, a real report came in of the WRAPPED download
        # failing while a plain manual curl (no extra flags at all)
        # succeeded, and untangling exactly which flag was at fault
        # without being able to reproduce it directly isn't worth the
        # risk of guessing wrong twice. The post-download size check
        # below is the one mechanism actually verified end-to-end
        # (including its own edge case — see the comment on it above),
        # so that's what all three downloaders rely on uniformly now.
        if [ -n "$ua" ]; then
            curl -fsSL -A "$ua" --connect-timeout "$timeout" --speed-limit 1024 --speed-time 60 --max-time 1800 -o "$dest" "$url" 2>/dev/null
        else
            curl -fsSL --connect-timeout "$timeout" --speed-limit 1024 --speed-time 60 --max-time 1800 -o "$dest" "$url" 2>/dev/null
        fi
        if _fetch_size_ok "$dest"; then return 0; else rm -f "$dest" 2>/dev/null; fi
    fi
    if [ -n "$BUSYBOX_BIN" ] && "$BUSYBOX_BIN" wget --help &>/dev/null 2>&1; then
        case "$url" in https://*) echo -e "${Y:-}[WARN] No system wget/curl -> busybox wget, which does NOT verify TLS certificates: $url${Z:-}" >&2 ;; esac
        if [ -n "$ua" ]; then
            "$BUSYBOX_BIN" wget -q -T "$timeout" -U "$ua" -O "$dest" "$url" 2>/dev/null
        else
            "$BUSYBOX_BIN" wget -q -T "$timeout" -O "$dest" "$url" 2>/dev/null
        fi
        if _fetch_size_ok "$dest"; then return 0; else rm -f "$dest" 2>/dev/null; fi
    fi
    rm -f "$dest" 2>/dev/null
    return 1
}

busybox_url() {
    # Overridable via -b-url/BUSYBOX_URL_ARG for internal mirrors — useful
    # when target machines can't reach busybox.net directly.
    if [ -n "$BUSYBOX_URL_ARG" ]; then
        echo "$BUSYBOX_URL_ARG"
        return
    fi
    case "${OS}_${ARCH}" in
        linux_x86_64) echo "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox" ;;
        # ARM (arm64/armv7): auto-download DISABLED for now — there is no
        # verified upstream static build for these. Use -b/--busybox with
        # your own binary or a mirror URL; otherwise system tools are used.
        *) echo "" ;;
    esac
}

verify_busybox_binary() {
    # HONEST LIMITATION, stated plainly: busybox.net does not publish a
    # SHA256SUM file for this specific build directory (checked directly
    # — not present), so this canNOT do full cryptographic verification
    # against a known-good hash the way build_grep_from_source() etc. can
    # for source tarballs pulled through apt. What this DOES check,
    # strengthened from a purely superficial "--help mentions busybox"
    # text match (which a crafted malicious binary could trivially fake):
    #   1. Real ELF executable (magic bytes \x7fELF) — rejects garbage,
    #      HTML error pages saved as the binary, truncated downloads, and
    #      non-executable content outright, before ever running it.
    #   2. Plausible size range for a real busybox static binary (roughly
    #      400KB-3MB — the specific build we fetch is ~1.1MB) — rejects
    #      wildly-wrong-sized substitutions.
    #   3. --help output actually looks like busybox (existing check).
    # Together these are real defense-in-depth against a corrupted/wrong
    # download or a naive substitution, but NOT a substitute for
    # cryptographic signature verification against a MOTIVATED attacker
    # who controls the download path (a compromised mirror or an
    # on-path MITM could still craft a malicious ELF that passes all
    # three checks). If that threat model matters for your environment,
    # the safer path is: skip auto-download entirely, provide your own
    # vetted busybox via -b/--busybox pointing at a binary you've
    # verified through a trusted channel yourself.
    local c="$1"
    [ -x "$c" ] || return 1
    local magic
    magic=$(head -c4 "$c" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
    [ "$magic" = "7f454c46" ] || return 1
    # FIX (real bug found — matches the exact symptom reported: manual
    # curl download succeeded, but this verification always failed
    # regardless): _stat_size() is a WORKER-only function (defined
    # between #__WORKER_START__/#__WORKER_END__), not available here —
    # verify_busybox_binary() runs from the MAIN script (called by
    # find_local_busybox()/download_busybox()). The call silently failed
    # every time ("command not found"), sz fell back to 0 via the "||"
    # fallback, and 0 is never >= 400000 — meaning this size check
    # rejected EVERY real busybox binary unconditionally, download
    # perfectly fine or not. Inlined, OS-portable equivalent instead
    # (same fix already applied to net_fetch()'s own size check).
    local sz
    if [ "$OS" = "macos" ]; then sz=$(stat -f '%z' "$c" 2>/dev/null)
    else sz=$(stat -c '%s' "$c" 2>/dev/null); fi
    { [ -n "$sz" ] && [ "$sz" -ge 400000 ] && [ "$sz" -le 3000000 ]; } || return 1
    # FIX (root cause of the "busybox randomly disappears" report, found by
    # reproducing it): the old `"$c" --help 2>&1 | head -1 | grep -qi busybox`
    # runs under `set -o pipefail`. `head -1` exits after the first line while
    # busybox is still writing the rest of its (multi-KB) help text -> SIGPIPE
    # (status 141) -> the whole pipeline "fails" although the output was right.
    # Measured with a stand-in binary: ~0.4% spurious failures on an idle box,
    # ~7% under CPU load (e.g. leftover workers after Ctrl+C). No pipe now:
    # capture the output first, then match it.
    local out
    out=$("$c" --help 2>&1) || true
    case "$out" in
        *[Bb]usy[Bb]ox*) return 0 ;;
    esac
    return 1
}

find_local_busybox() {
    # Priority: explicit -b/--busybox -> $SCRIPT_DIR/bin/busybox.
    local candidates=()
    [ -n "$BUSYBOX_PATH_ARG" ] && candidates+=("$BUSYBOX_PATH_ARG")
    candidates+=("$SCRIPT_DIR/bin/busybox")

    local c
    for c in "${candidates[@]}"; do
        # FIX (real, reproducible-enough report): verify_busybox_binary()
        # failed on a file confirmed byte-for-byte unchanged from a known-
        # good copy — right after Ctrl+C'ing a PREVIOUS av.sh invocation
        # moments earlier. No direct code path was found connecting the
        # two (cleanup() only ever touches /tmp and /dev/shm, never
        # SCRIPT_DIR/bin), so the exact mechanism is unconfirmed — quite
        # possibly some transient process-group/session quirk in that
        # specific rescue environment right after a SIGINT, since
        # verify_busybox_binary's last check actually EXECUTES the file
        # (`"$c" --help`), unlike the earlier magic-byte/size checks which
        # only read it. Rather than guess further, this retries a couple
        # of times with a brief pause before concluding "genuinely not
        # there" — cheap insurance against a transient hiccup, regardless
        # of whatever the underlying cause turns out to be; a truly
        # missing/corrupt file will still consistently fail all attempts.
        local attempt
        for attempt in 1 2 3; do
            verify_busybox_binary "$c" && { BUSYBOX_BIN="$c"; return 0; }
            [ "$attempt" -lt 3 ] && sleep 0.3
        done
    done
    return 1
}

download_busybox() {
    local url="$1" dest="$SCRIPT_DIR/bin/busybox"
    # FIX: download into a TEMP file and only move it into place after it
    # verifies. The old code wrote straight to $dest: wget -O truncates the
    # target before connecting and net_fetch()/this function did `rm -f
    # "$dest"` on any failure — so a spurious verify failure followed by an
    # unreachable network DESTROYED a perfectly good bundled busybox.
    local tmp="$dest.new.$$"
    mkdir -p "$SCRIPT_DIR/bin"
    echo -e "${C}[*] BusyBox not found locally -> auto-downloading (~1MB)...${Z}"
    rm -f "$tmp" 2>/dev/null
    net_fetch "$url" "$tmp" 15 "" 10 >/dev/null 2>&1
    chmod +x "$tmp" 2>/dev/null
    if verify_busybox_binary "$tmp"; then
        mv -f "$tmp" "$dest" 2>/dev/null || { rm -f "$tmp" 2>/dev/null; echo -e "${R}[FAIL] cannot place busybox at $dest${Z}"; return 1; }
    else
        rm -f "$tmp" 2>/dev/null
        echo -e "${R}[FAIL] BusyBox download/verify failed (existing $dest left untouched)${Z}"
        return 1
    fi
    chmod +x "$dest" 2>/dev/null
    echo -e "${G}[OK] busybox saved: $dest${Z}"
    BUSYBOX_BIN="$dest"
    return 0
}

ensure_busybox() {
    # busybox ships together with the scanner, so find_local_busybox should
    # succeed on the first try. Anything past that (auto-download, system
    # fallback) means the package is damaged/incomplete, hence WARN/FAIL.
    [ "$ALLOW_BUSYBOX" = true ] || { echo -e "${Y}[INFO] BusyBox disabled (--no-busybox) -> system tools only${Z}"; return 1; }

    find_local_busybox && { echo -e "${G}[OK] Local busybox: $BUSYBOX_BIN${Z}"; return 0; }

    echo -e "${R}[WARN] Expected bundled busybox not found at ${SCRIPT_DIR}/bin/busybox${Z}"
    echo -e "${R}       This is unusual — check the package (file missing or corrupted).${Z}"

    if [ "$OS" = "macos" ]; then
        echo -e "${Y}[INFO] macOS: no official static busybox builds -> system tools${Z}"
        return 1
    fi

    # Binaries are fetched ONLY by an explicit `--setup`. A scan must never
    # download or overwrite executables on its own (supply-chain risk, and a
    # failed fetch must not be able to damage the installed toolchain).
    if [ "${AV_SETUP_MODE:-0}" != 1 ]; then
        echo -e "${Y}[INFO] Auto-download is disabled during scans -> run '$0 --setup' to fetch busybox. Using system tools.${Z}"
        return 1
    fi

    local dl_url
    dl_url=$(busybox_url)
    if [ -z "$dl_url" ]; then
        echo -e "${Y}[INFO] No busybox auto-download for ${OS}/${ARCH} (ARM builds disabled for now) -> using system tools. Put your own static busybox in bin/busybox or pass --busybox-url URL.${Z}"
        return 1
    fi
    # FIX (real bug reported): check_network() as a pre-flight gate here
    # was actively wrong — a person confirmed BOTH the wget --spider AND
    # curl checks it uses succeed (exit 0) when run manually, yet the
    # script still reported "No network" and skipped straight past
    # attempting the real download. Whatever the exact cause (this is now
    # the THIRD bug found in this same small area of the script — a
    # pattern worth noticing), the check added a failure point of its own
    # without protecting against anything download_busybox() doesn't
    # already handle correctly on its own: if the network genuinely isn't
    # there, net_fetch() inside it will simply fail cleanly, with clear
    # messaging, same as any other real download failure. Removed the
    # gate entirely — go straight to attempting the download.
    echo -e "${Y}[*] Trying emergency auto-download as a fallback...${Z}"
    download_busybox "$dl_url" && return 0
    echo -e "${R}[WARN] Emergency download also failed -> system tools (shell fallback)${Z}"
    return 1
}

busybox_has_applet() {
    case "$BB_APPLETS" in
        *" $1 "*) return 0 ;;
        *) return 1 ;;
    esac
}

cache_busybox_applets() {
    [ -n "$BUSYBOX_BIN" ] || return 0
    local a
    BB_APPLETS=" "
    while IFS= read -r a; do
        [ -n "$a" ] && BB_APPLETS="${BB_APPLETS}${a} "
    done < <("$BUSYBOX_BIN" --list 2>/dev/null)
}

# bb <applet> [args...] — runs the applet via busybox if available/supported,
# else falls back to the system command of the same name.
bb() {
    local applet="$1"; shift
    if [ -n "$BUSYBOX_BIN" ] && busybox_has_applet "$applet"; then
        "$BUSYBOX_BIN" "$applet" "$@"
    else
        command "$applet" "$@"
    fi
}

# _hash_each <openssl-ALG|bsd-md5> [file...]: openssl prints
# "MD5(name)= hash" and "md5 -q" prints bare hashes, but every batch parser
# reads the coreutils "<hash>  <name>" format, so those fallbacks matched
# nothing. Hashes each file via stdin and prints coreutils format, escaped
# like coreutils ("\<hash>  <name>" with \\ and \n) for odd names.
# No files = hash stdin. A copy lives in the worker (MODULE: low-level helpers).
_hash_each() {
    local tool="$1" f out
    shift
    local -a c
    case "$tool" in
        bsd-md5)   c=(md5 -q) ;;
        openssl-*) c=(openssl dgst "-${tool#openssl-}") ;;
        *) return 1 ;;
    esac
    if [ $# -eq 0 ]; then
        out=$("${c[@]}") || return 1
        printf '%s  -\n' "${out##* }"; return
    fi
    for f in "$@"; do
        out=$("${c[@]}" < "$f" 2>/dev/null) || continue
        out="${out##* }"
        [[ "$out" =~ ^[0-9a-f]+$ ]] || continue
        case "$f" in
            *\\*|*$'\n'*) f="${f//\\/\\\\}"; printf '\\%s  %s\n' "$out" "${f//$'\n'/\\n}" ;;
            *) printf '%s  %s\n' "$out" "$f" ;;
        esac
    done
}

# ============================================================================
# 4. MODULE: hash & yara & strings/file detection (busybox-first)
#    Priority: busybox applet -> system tool -> (for strings/file) our own
#    self-contained dd+od based detector.
# ============================================================================
detect_sha256() {
    # FIX (real bottleneck found and measured): busybox's sha256sum is
    # ~1.8x slower than a real coreutils sha256sum on realistic file sizes
    # (confirmed: 340ms vs 188ms hashing 200 files). Combined with the
    # grep lookup fix below, this was the dominant cost in a real scan
    # (hash= was 69% of total time). Same reasoning as bundling a real
    # grep: prefer a known-fast implementation, busybox only as fallback
    # for portability when nothing else is available.
    if command -v sha256sum &>/dev/null; then echo "sha256sum"
    elif [ -n "$BUSYBOX_BIN" ] && busybox_has_applet sha256sum; then echo "$BUSYBOX_BIN sha256sum"
    elif command -v shasum &>/dev/null; then echo "shasum -a 256"
    elif command -v openssl &>/dev/null; then echo "_hash_each openssl-sha256"
    else echo "none"; fi
}

detect_md5() {
    if command -v md5sum &>/dev/null; then echo "md5sum"
    elif [ -n "$BUSYBOX_BIN" ] && busybox_has_applet md5sum; then echo "$BUSYBOX_BIN md5sum"
    elif command -v md5 &>/dev/null; then echo "_hash_each bsd-md5"
    elif command -v openssl &>/dev/null; then echo "_hash_each openssl-md5"
    else echo "none"; fi
}

detect_sha1() {
    # SHA1 support recovers a real, previously-silent gap: ClamAV's .hsb
    # signature format (same field layout as .hdb: hash:size:name) can
    # contain SHA1 hashes (40 hex chars) alongside MD5/SHA256 — our
    # parser used to only recognize 32 and 64-char hashes, so every SHA1
    # entry in a real daily.hsb/main.hsb was silently dropped, not just
    # skipped-with-a-warning.
    if command -v sha1sum &>/dev/null; then echo "sha1sum"
    elif [ -n "$BUSYBOX_BIN" ] && busybox_has_applet sha1sum; then echo "$BUSYBOX_BIN sha1sum"
    elif command -v shasum &>/dev/null; then echo "shasum -a 1"
    elif command -v openssl &>/dev/null; then echo "_hash_each openssl-sha1"
    else echo "none"; fi
}

detect_yara() {
    # YARA isn't part of busybox, but a bundled bin/yara (see --setup)
    # is preferred over a system install for the same reason as busybox:
    # a known, consistent binary rather than whatever's on $PATH. YARA now
    # also does the .ndb/.ldb hex-signature matching (see MODULE: ClamAV
    # format support) since grep -E -f cannot scale to that many patterns.
    if [ -x "$SCRIPT_DIR/bin/yara" ]; then
        echo "$SCRIPT_DIR/bin/yara"
    elif command -v yara &>/dev/null; then
        echo "yara"
    else
        echo "none"
    fi
}

detect_yarac() {
    if [ -x "$SCRIPT_DIR/bin/yarac" ]; then
        YARAC_BIN="$SCRIPT_DIR/bin/yarac"
    elif command -v yarac &>/dev/null; then
        YARAC_BIN="yarac"
    else
        YARAC_BIN=""
    fi
}

init_toolchain() {
    echo -e "[*] Initializing toolchain..."
    ensure_busybox
    cache_busybox_applets

    SHA256_CMD=$(detect_sha256)
    MD5_CMD=$(detect_md5)
    SHA1_CMD=$(detect_sha1)

    if [ -n "$BUSYBOX_BIN" ] && busybox_has_applet strings; then
        STRINGS_CMD="$BUSYBOX_BIN strings"; echo -e "${G}[OK] strings : busybox${Z}"
    elif command -v strings &>/dev/null; then
        STRINGS_CMD="strings"; echo -e "${Y}[OK] strings : system (fallback)${Z}"
    else
        STRINGS_CMD="bash"; echo -e "${Y}[WARN] strings : built-in bash detector${Z}"
    fi

    # "file" is not part of busybox; our own magic-bytes detector
    # (_bash_file_type, dd/od based) already covers what we need.
    FILE_CMD="bash"
    echo -e "${G}[OK] file    : built-in magic-bytes detector${Z}"

    echo -e " SHA256 : ${C}${SHA256_CMD}${Z}"
    echo -e " MD5    : ${C}${MD5_CMD}${Z}"
    if [ -n "$BUSYBOX_BIN" ]; then
        echo -e " BusyBox: ${G}${BUSYBOX_BIN}${Z}"
    else
        echo -e " BusyBox: ${Y}not in use (system-only mode)${Z}"
    fi
    echo ""
}

# ============================================================================
# 5. MODULE: CLI (usage, argument parsing, colors)
# ============================================================================
# -h: the short version. --help-all prints the full reference kept in the
# header comment of this file (every option, examples, audit tags, layout).
usage() {
    local me="${0##*/}"
    cat <<EOF
Orphus AV ${VERSION} - malware scanner for Linux web hosting (PHP/CMS sites).

Usage: ${me} [OPTIONS]

Examples:
  ${me} --setup                       install yara/yarac/busybox into bin/ (once)
  ${me} -u --packs hosting,server     update signatures and build packs, then exit
  ${me} -d /var/www --packs hosting   scan sites with the light hosting pack
  ${me} -d /home -o report.log        scan and also save the report to a file
  ${me} -d /home -q                   scan + move signature hits to quarantine/
  ${me} -d /home -w                   scan, then keep watching for new/changed files
  ${me} --offline-root /mnt --audit   was a mounted (read-only) disk broken into?
  ${me} --offline-root /mnt -K -d /mnt  check kernel/boot files of a mounted disk

Main options:
  -d, --dir PATH          Directory to scan (default: /mnt)
  -u, --update            Update signatures and exit (with --packs: build those packs)
  --packs PACK            Signatures: hosting | server (default) | all | full, or items
                          joined with + (hosting+pe, webshell+linux); -u: a,b,c
  -o, --output FILE       Also save the report to FILE
  -q, --quarantine        Move detected files to quarantine/ (--quarantine-dry-run: list only)
  -w, --real-time         After the scan, watch for new files (implies -I)
  -X, --exclude PATH      Skip a file or directory (repeatable)
  -A, --scan-archives     Also look inside zip/tar/gz/7z archives
                          (limits: --archive-limits SIZE,EXTRACT,DEPTH,FILES)
  -I, --incremental       Skip files unchanged since the last clean scan
  -j, --workers N         Parallel workers (default: CPU count)
  -r, --max-ram MB        RAM ceiling (default: 500)
  -m, --max-size MB       Deep-inspection size cap (default: 50; scripts are always checked)
  --ram-dirs MODE         Temporary data in RAM: auto (default) | none | all
  --yara-mode MODE        threads (default: one yara, several threads) | workers (one yara per worker)
  --deep                  Maximum scrutiny, ignores ignore_sigs and other suppression
  --explain FILE          Why is (or isn't) this one file reported? Every check, step by step
  --media-fast            Video/audio: scan only the first and last 2 MB (fast on big uploads)
  --clam-pua              Also use ClamAV PUA signatures (adware/tools; off by default)
  -K, --check-kernel      Kernel/boot integrity check (best with --offline-root)
  --audit                 Compromise audit (sshd, accounts, persistence, auth logs)
  --offline-root PATH     Inspect a mounted, not booted disk (must be read-only; --force overrides)
  --setup                 Install yara/yarac/grep/bash into bin/, then exit
  --check-deps            Show busybox/yara/grep status, then exit

Full option list, examples and the --audit legend: ${me} --help-all
EOF
    exit 0
}
usage_all() {
    awk '/^# ====/{c++; next} c==1' "$0" | sed 's/^# \{0,2\}//'
    echo ""
    check_dependencies_report
    exit 0
}

# Prints a plain status report of optional-but-important components
# (busybox, yara/yarac) so the user immediately knows what will and won't
# work, without having to start a scan first. Run automatically by -h/--help
# and by --check-deps.
check_dependencies_report() {
    echo "Dependency check:"
    if [ -x "$SCRIPT_DIR/bin/busybox" ]; then
        echo "  [OK]   busybox : bundled at bin/busybox"
    elif command -v busybox &>/dev/null; then
        echo "  [WARN] busybox : not bundled, found on system PATH instead"
    else
        echo "  [MISS] busybox : not found — will try to auto-download on first run"
        echo "         (needs network); or run: $0 --setup"
    fi

    if [ -x "$SCRIPT_DIR/bin/yara" ] && [ -x "$SCRIPT_DIR/bin/yarac" ]; then
        echo "  [OK]   yara/yarac : bundled at bin/yara, bin/yarac"
    elif command -v yara &>/dev/null && command -v yarac &>/dev/null; then
        echo "  [WARN] yara/yarac : not bundled, found on system PATH instead"
    else
        echo "  [MISS] yara/yarac : not found — .ndb/.ldb ClamAV signatures and"
        echo "         YARA_MATCH detection will be unavailable, and the"
        echo "         hex/string fallback path is much slower at scale."
        echo "         Fix: run '$0 --setup' to build them automatically"
        echo "         (needs a C toolchain, or the ability to install one)."
    fi

    if [ -x "$SCRIPT_DIR/bin/grep" ]; then
        echo "  [OK]   grep : bundled at bin/grep (static GNU grep)"
    else
        echo "  [WARN] grep : not bundled, using system/busybox grep instead —"
        echo "         busybox's grep is known to silently miss matches in"
        echo "         files containing NUL bytes, even with -a (confirmed)."
        echo "         Fix: run '$0 --setup' to build a bundled static grep."
    fi
    echo ""
}

# ============================================================================
# MODULE: self-setup (--setup)
#
# Two ways to get yara/yarac into $SCRIPT_DIR/bin/, tried in this order:
#
#   1. --yara-url URL — fetch a PREBUILT tarball (containing "yara" and
#      "yarac" binaries) from a URL you control. Unlike busybox, YARA
#      publishes no official prebuilt binaries, so there's no universal
#      default URL to hardcode here — but if you build once (this same
#      --setup does that) and host the resulting bin/{yara,yarac} tarball
#      on your own mirror/CDN/internal server, every other machine can
#      then install it with a plain download and NO compiler at all,
#      which is both faster and works identically across distros. This is
#      the "do it like busybox" path, just pointed at infrastructure you
#      host yourself instead of a project-run one that doesn't exist.
#
#   2. Compile from source (fallback, or always with --setup --compile).
#      Needs a C toolchain; installed automatically via whichever of
#      apt/dnf/yum/zypper/pacman/apk is present. Different distros name
#      packages differently, so each branch below lists its own package
#      names for the same underlying tools (gcc/make, autotools,
#      pkg-config, OpenSSL dev headers).
# ============================================================================
_install_build_toolchain() {
    local as_root="$1"
    if command -v apt-get &>/dev/null; then
        echo "[*] Installing build dependencies via apt..."
        $as_root apt-get update -qq
        $as_root apt-get install -y -qq build-essential autoconf automake libtool pkg-config libssl-dev curl
    elif command -v dnf &>/dev/null; then
        echo "[*] Installing build dependencies via dnf..."
        $as_root dnf install -y gcc make autoconf automake libtool pkgconfig openssl-devel curl
    elif command -v yum &>/dev/null; then
        echo "[*] Installing build dependencies via yum..."
        $as_root yum install -y gcc make autoconf automake libtool pkgconfig openssl-devel curl
    elif command -v zypper &>/dev/null; then
        echo "[*] Installing build dependencies via zypper..."
        $as_root zypper --non-interactive install gcc make autoconf automake libtool pkg-config libopenssl-devel curl
    elif command -v pacman &>/dev/null; then
        echo "[*] Installing build dependencies via pacman..."
        $as_root pacman -Sy --noconfirm base-devel autoconf automake libtool pkgconf openssl curl
    elif command -v apk &>/dev/null; then
        echo "[*] Installing build dependencies via apk..."
        $as_root apk add build-base autoconf automake libtool pkgconfig openssl-dev curl
    else
        echo -e "${R}[FAIL] No supported package manager found (apt/dnf/yum/zypper/pacman/apk)${Z}"
        echo -e "${R}       Install a C toolchain, autoconf, automake, libtool, pkg-config,${Z}"
        echo -e "${R}       and OpenSSL dev headers manually, then re-run --setup --compile,${Z}"
        echo -e "${R}       or use --yara-url to install a prebuilt binary instead.${Z}"
        return 1
    fi
}

# Installs yara/yarac from a prebuilt tarball URL — no compiler needed.
# Expects a .tar.gz (or .zip, if unzip is available) containing "yara" and
# "yarac" binaries somewhere inside (top level or in a subdirectory).
install_yara_from_url() {
    local url="$1"
    echo "[*] Downloading prebuilt yara/yarac from: $url"

    local workdir
    workdir=$(mktemp -d 2>/dev/null) || { echo -e "${R}[FAIL] mktemp failed${Z}"; return 1; }
    local dest="$workdir/download"

    if ! net_fetch "$url" "$dest" 60; then
        echo -e "${R}[FAIL] Download failed (bad URL, or unreachable from this machine)${Z}"
        rm -rf "$workdir"
        return 1
    fi

    local extract_dir="$workdir/extract"
    mkdir -p "$extract_dir"
    if tar -xzf "$dest" -C "$extract_dir" 2>/dev/null || tar -xf "$dest" -C "$extract_dir" 2>/dev/null; then
        :
    elif command -v unzip &>/dev/null && unzip -q "$dest" -d "$extract_dir" 2>/dev/null; then
        :
    else
        # Not an archive we can unpack — maybe it's a bare "yara" binary.
        # We still need yarac too, so this only helps if the URL is itself
        # a directory listing situation, which we can't handle generically.
        cp "$dest" "$extract_dir/yara" 2>/dev/null
    fi

    local found_yara found_yarac
    found_yara=$(find "$extract_dir" -type f -name "yara" 2>/dev/null | head -1)
    found_yarac=$(find "$extract_dir" -type f -name "yarac" 2>/dev/null | head -1)

    if [ -z "$found_yara" ] || [ -z "$found_yarac" ]; then
        echo -e "${R}[FAIL] Downloaded archive doesn't contain both a 'yara' and a 'yarac' binary${Z}"
        rm -rf "$workdir"
        return 1
    fi

    mkdir -p "$SCRIPT_DIR/bin"
    cp "$found_yara" "$SCRIPT_DIR/bin/yara"
    cp "$found_yarac" "$SCRIPT_DIR/bin/yarac"
    chmod +x "$SCRIPT_DIR/bin/yara" "$SCRIPT_DIR/bin/yarac"
    rm -rf "$workdir"

    if ! "$SCRIPT_DIR/bin/yara" --version &>/dev/null; then
        echo -e "${R}[FAIL] Downloaded 'yara' binary doesn't run on this machine (wrong arch/libc?)${Z}"
        rm -f "$SCRIPT_DIR/bin/yara" "$SCRIPT_DIR/bin/yarac"
        return 1
    fi

    echo -e "${G}[OK] Installed prebuilt yara/yarac from URL — no compiler needed${Z}"
    "$SCRIPT_DIR/bin/yara" --version
    return 0
}

# Builds yara/yarac from source. Needs a C toolchain (installed
# automatically if a supported package manager is found) and network
# access to fetch the YARA source tarball from GitHub.
build_yara_from_source() {
    local version="${SETUP_YARA_VERSION:-4.5.8}"

    if [ "$(id -u 2>/dev/null)" != "0" ] && ! command -v sudo &>/dev/null; then
        echo -e "${R}[FAIL] Need root or sudo to install build dependencies${Z}"
        return 1
    fi
    local as_root=""
    [ "$(id -u 2>/dev/null)" != "0" ] && as_root="sudo"

    _install_build_toolchain "$as_root" || return 1

    local workdir
    workdir=$(mktemp -d 2>/dev/null) || { echo -e "${R}[FAIL] mktemp failed${Z}"; return 1; }
    # Build logs in a private dir, not fixed /tmp names (symlink-plantable).
    local logdir
    logdir=$(mktemp -d "${TMPDIR:-/tmp}/av_setup_log.XXXXXX" 2>/dev/null) || { echo -e "${R}[FAIL] mktemp failed${Z}"; rm -rf "$workdir"; return 1; }
    echo "[*] Downloading YARA v${version} source..."
    if ! net_fetch "https://github.com/VirusTotal/yara/archive/refs/tags/v${version}.tar.gz" "$workdir/yara.tar.gz" 30; then
        echo -e "${R}[FAIL] Could not download YARA source (network?)${Z}"
        rm -rf "$workdir"
        return 1
    fi
    tar -xzf "$workdir/yara.tar.gz" -C "$workdir" || { echo -e "${R}[FAIL] Corrupt download${Z}"; rm -rf "$workdir"; return 1; }

    (
        cd "$workdir/yara-${version}" || exit 1
        echo "[*] Configuring (static libyara, dynamic libcrypto/libc/libm only)..."
        ./bootstrap.sh >/dev/null 2>&1
        ./configure --disable-shared --enable-static >"$logdir/configure.log" 2>&1 || exit 1
        echo "[*] Building (this can take a minute)..."
        make -j"$(nproc 2>/dev/null || echo 2)" >"$logdir/make.log" 2>&1 || exit 1
        strip ./yara ./yarac 2>/dev/null || true
    )
    local build_rc=$?

    if [ $build_rc -ne 0 ] || [ ! -x "$workdir/yara-${version}/yara" ]; then
        echo -e "${R}[FAIL] Build failed — see $logdir/configure.log and $logdir/make.log${Z}"
        rm -rf "$workdir"
        return 1
    fi
    [ "$DEBUG_MODE" = true ] || rm -rf "$logdir" 2>/dev/null

    mkdir -p "$SCRIPT_DIR/bin"
    cp "$workdir/yara-${version}/yara" "$workdir/yara-${version}/yarac" "$SCRIPT_DIR/bin/"
    chmod +x "$SCRIPT_DIR/bin/yara" "$SCRIPT_DIR/bin/yarac"
    rm -rf "$workdir"

    echo -e "${G}[OK] Built: $SCRIPT_DIR/bin/yara, $SCRIPT_DIR/bin/yarac${Z}"
    "$SCRIPT_DIR/bin/yara" --version
    echo "     Dependencies: $(ldd "$SCRIPT_DIR/bin/yara" 2>/dev/null | awk '{print $1}' | grep -v '^$' | tr '\n' ' ')"
    return 0
}

# Builds a fully static GNU grep from source. Unlike YARA (dynamically
# linked against libcrypto/libc/libm at best), grep has no such
# dependencies once PCRE support is dropped — the result is a genuinely
# static binary, zero runtime dependencies, guaranteed identical behavior
# on every target machine regardless of whatever grep the OS ships.
#
# WHY THIS MATTERS (found empirically, not theoretically): busybox's grep
# silently finds NOTHING in files containing NUL bytes, even with -a —
# confirmed with a real repro (system grep found the match, busybox grep
# didn't, no error either way). Since binary-safe string search is used
# throughout scanning (webshells embedded in otherwise-binary files,
# SIG_STRING_MATCH, base64 payload screening), a correctness gap here is
# a real, silent detection gap — a bundled, known-good grep closes it for
# good instead of hoping the OS's grep behaves.
build_grep_from_source() {
    local version="${SETUP_GREP_VERSION:-3.11}"

    if [ -x "$SCRIPT_DIR/bin/grep" ] && [ "${SETUP_FORCE:-false}" != true ]; then
        echo -e "${G}[OK] bin/grep already present -> nothing to do${Z}"
        return 0
    fi

    if [ "$(id -u 2>/dev/null)" != "0" ] && ! command -v sudo &>/dev/null; then
        echo -e "${R}[FAIL] Need root or sudo to install build dependencies${Z}"
        return 1
    fi
    local as_root=""
    [ "$(id -u 2>/dev/null)" != "0" ] && as_root="sudo"
    _install_build_toolchain "$as_root" || return 1

    local workdir
    workdir=$(mktemp -d 2>/dev/null) || { echo -e "${R}[FAIL] mktemp failed${Z}"; return 1; }
    # Build logs in a private dir, not fixed /tmp names (symlink-plantable).
    local logdir
    logdir=$(mktemp -d "${TMPDIR:-/tmp}/av_setup_log.XXXXXX" 2>/dev/null) || { echo -e "${R}[FAIL] mktemp failed${Z}"; rm -rf "$workdir"; return 1; }
    echo "[*] Downloading GNU grep v${version} source..."
    # Multiple official GNU mirrors — ftp.gnu.org occasionally rate-limits
    # or is geo-blocked on some networks; falling through a short mirror
    # list is cheap insurance against a one-off download failure.
    local grep_urls=(
        "https://ftp.gnu.org/gnu/grep/grep-${version}.tar.gz"
        "https://mirror.team-cymru.com/gnu/grep/grep-${version}.tar.gz"
        "https://mirrors.kernel.org/gnu/grep/grep-${version}.tar.gz"
        "https://ftpmirror.gnu.org/grep/grep-${version}.tar.gz"
    )
    local fetched=false gurl
    for gurl in "${grep_urls[@]}"; do
        if net_fetch "$gurl" "$workdir/grep.tar.gz" 30; then
            fetched=true
            break
        fi
    done
    if [ "$fetched" != true ]; then
        echo -e "${R}[FAIL] Could not download grep source from any mirror (network?)${Z}"
        rm -rf "$workdir"
        return 1
    fi
    tar -xzf "$workdir/grep.tar.gz" -C "$workdir" || { echo -e "${R}[FAIL] Corrupt download${Z}"; rm -rf "$workdir"; return 1; }

    (
        cd "$workdir/grep-${version}" || exit 1
        echo "[*] Configuring (no PCRE -> no external deps -> true static link)..."
        ./configure --disable-perl-regexp LDFLAGS="-static" >"$logdir/configure.log" 2>&1 || exit 1
        echo "[*] Building..."
        make -j"$(nproc 2>/dev/null || echo 2)" >"$logdir/make.log" 2>&1 || exit 1
        strip ./src/grep 2>/dev/null || true
    )
    local build_rc=$?

    if [ $build_rc -ne 0 ] || [ ! -x "$workdir/grep-${version}/src/grep" ]; then
        echo -e "${R}[FAIL] Build failed — see $logdir/configure.log and $logdir/make.log${Z}"
        rm -rf "$workdir"
        return 1
    fi
    [ "$DEBUG_MODE" = true ] || rm -rf "$logdir" 2>/dev/null

    mkdir -p "$SCRIPT_DIR/bin"
    cp "$workdir/grep-${version}/src/grep" "$SCRIPT_DIR/bin/grep"
    chmod +x "$SCRIPT_DIR/bin/grep"
    rm -rf "$workdir"

    echo -e "${G}[OK] Built: $SCRIPT_DIR/bin/grep${Z}"
    "$SCRIPT_DIR/bin/grep" --version | head -1
    echo "     Dependencies: $(ldd "$SCRIPT_DIR/bin/grep" 2>&1 | head -1)"
    return 0
}

# Builds a fully static bash from source — same reasoning as grep/yara
# (guaranteed known-good behavior, no dependency on whatever's on the
# host), but with an ADDITIONAL, distinct motivation: a rootkit that
# patches system binaries (classic technique — Diamorphine, t0rn-style,
# LD_PRELOAD hooking) very often includes /bin/bash itself among the
# tools it tampers with, since bash is what most admin tooling (including
# this scanner) runs through. Re-exec'ing early into a bundled, verified
# bash (see the re-exec check near the top of main()) narrows how much of
# the scan ever touches a potentially-compromised interpreter.
#
# HONEST LIMIT: this does NOT fully solve the problem. If the shell that
# runs THIS SPECIFIC INVOCATION (before the re-exec check even executes)
# is itself compromised, that first fraction of a second of execution is
# still exposed — no script can fully bootstrap trust in its own
# interpreter from within that same interpreter. The real protection
# comes from copying av.sh + bin/bash from a KNOWN-CLEAN source and
# invoking "./bin/bash ./av.sh" directly, never touching system bash at
# all. The re-exec is a narrowing of exposure for the common case (person
# just runs "bash av.sh" or "./av.sh"), not a full guarantee.
build_bash_from_source() {
    local version="${SETUP_BASH_VERSION:-5.2.21}"

    if [ -x "$SCRIPT_DIR/bin/bash" ] && [ "${SETUP_FORCE:-false}" != true ]; then
        echo -e "${G}[OK] bin/bash already present -> nothing to do${Z}"
        return 0
    fi

    if [ "$(id -u 2>/dev/null)" != "0" ] && ! command -v sudo &>/dev/null; then
        echo -e "${R}[FAIL] Need root or sudo to install build dependencies${Z}"
        return 1
    fi
    local as_root=""
    [ "$(id -u 2>/dev/null)" != "0" ] && as_root="sudo"
    _install_build_toolchain "$as_root" || return 1

    local workdir
    workdir=$(mktemp -d 2>/dev/null) || { echo -e "${R}[FAIL] mktemp failed${Z}"; return 1; }
    # Build logs in a private dir, not fixed /tmp names (symlink-plantable).
    local logdir
    logdir=$(mktemp -d "${TMPDIR:-/tmp}/av_setup_log.XXXXXX" 2>/dev/null) || { echo -e "${R}[FAIL] mktemp failed${Z}"; rm -rf "$workdir"; return 1; }
    echo "[*] Downloading GNU bash v${version} source..."
    local bash_urls=(
        "https://ftp.gnu.org/gnu/bash/bash-${version}.tar.gz"
        "https://mirror.team-cymru.com/gnu/bash/bash-${version}.tar.gz"
        "https://mirrors.kernel.org/gnu/bash/bash-${version}.tar.gz"
        "https://ftpmirror.gnu.org/bash/bash-${version}.tar.gz"
    )
    local fetched=false burl
    for burl in "${bash_urls[@]}"; do
        if net_fetch "$burl" "$workdir/bash.tar.gz" 30; then
            fetched=true
            break
        fi
    done
    if [ "$fetched" != true ]; then
        echo -e "${R}[FAIL] Could not download bash source from any mirror (network?)${Z}"
        rm -rf "$workdir"
        return 1
    fi
    tar -xzf "$workdir/bash.tar.gz" -C "$workdir" || { echo -e "${R}[FAIL] Corrupt download${Z}"; rm -rf "$workdir"; return 1; }

    (
        cd "$workdir/bash-${version}" || exit 1
        echo "[*] Configuring (static link, no NLS — smaller, fewer moving parts)..."
        ./configure --enable-static-link --disable-nls --without-bash-malloc LDFLAGS="-static" \
            >"$logdir/configure.log" 2>&1 || exit 1
        echo "[*] Building..."
        make -j"$(nproc 2>/dev/null || echo 2)" >"$logdir/make.log" 2>&1 || exit 1
        strip ./bash 2>/dev/null || true
    )
    local build_rc=$?

    if [ $build_rc -ne 0 ] || [ ! -x "$workdir/bash-${version}/bash" ]; then
        echo -e "${R}[FAIL] Build failed — see $logdir/configure.log and $logdir/make.log${Z}"
        rm -rf "$workdir"
        return 1
    fi
    [ "$DEBUG_MODE" = true ] || rm -rf "$logdir" 2>/dev/null

    mkdir -p "$SCRIPT_DIR/bin"
    cp "$workdir/bash-${version}/bash" "$SCRIPT_DIR/bin/bash"
    chmod +x "$SCRIPT_DIR/bin/bash"
    rm -rf "$workdir"

    echo -e "${G}[OK] Built: $SCRIPT_DIR/bin/bash${Z}"
    "$SCRIPT_DIR/bin/bash" --version | head -1
    echo "     Dependencies: $(ldd "$SCRIPT_DIR/bin/bash" 2>&1 | head -1)"
    return 0
}

run_self_setup() {
    echo -e "${B}=== av_scan.sh self-setup ===${Z}"
    echo "Target: $SCRIPT_DIR/bin/{yara,yarac,grep}"
    echo ""

    if [ -x "$SCRIPT_DIR/bin/yara" ] && [ -x "$SCRIPT_DIR/bin/yarac" ] && [ "${SETUP_FORCE:-false}" != true ]; then
        echo -e "${G}[OK] bin/yara and bin/yarac already present -> nothing to do (use --setup --force to rebuild)${Z}"
    elif [ -n "$YARA_URL_ARG" ] && [ "${SETUP_COMPILE_ONLY:-false}" != true ]; then
        install_yara_from_url "$YARA_URL_ARG" || {
            echo -e "${Y}[WARN] Prebuilt install failed -> falling back to compiling from source${Z}"
            build_yara_from_source
        }
    else
        build_yara_from_source
    fi

    echo ""
    build_grep_from_source

    echo ""
    build_bash_from_source

    # busybox too, while we're setting things up, if it isn't there yet.
    if [ ! -x "$SCRIPT_DIR/bin/busybox" ]; then
        echo ""
        echo "[*] busybox not bundled yet — attempting the same auto-download used at scan time..."
        BUSYBOX_BIN=""
        AV_SETUP_MODE=1 ensure_busybox
    fi

    echo ""
    echo -e "${G}[OK] Setup complete.${Z} Re-run $0 --help to confirm dependency status."
    return 0
}
#__SETUP_MODULE_END__


parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u|--update)     DO_UPDATE=true; shift ;;
            -r|--max-ram)    MAX_RAM_MB="$2"; shift 2 ;;
            -j|--workers)    WORKERS="$2"; WORKERS_EXPLICIT=1; shift 2 ;;
            -d|--dir)        ROOT_DIR="$2"; ROOT_DIR_EXPLICIT=1; shift 2 ;;
            -s|--sigs)       SIGNATURES="$2"; shift 2 ;;
            -m|--max-size)   MAX_SCAN_MB="$2"; MAX_SCAN_MB_EXPLICIT=1; shift 2 ;;
            -o|--output)     OUTPUT_FILE="$2"; shift 2 ;;
            --ignore-sigs)   IGNORE_SIGS_FILE="$2"; shift 2 ;;
            -X|--exclude)    EXCLUDE_PATHS+=("$2"); shift 2 ;;
            -A|--scan-archives)  SCAN_ARCHIVES=true; shift ;;
            --archive-limits)
                [ $# -ge 2 ] || { echo "[FAIL] --archive-limits needs SIZE,EXTRACT,DEPTH,FILES" >&2; exit 1; }
                local _al _a1 _a2 _a3 _a4 _ax
                IFS=',' read -r _a1 _a2 _a3 _a4 _ax <<< "$2,"
                if [ -n "$_ax" ]; then echo "[FAIL] --archive-limits takes 4 fields: SIZE,EXTRACT,DEPTH,FILES (got: '$2')" >&2; exit 1; fi
                [ -n "$_a1" ] && ARCHIVE_MAX_MB="$_a1"
                [ -n "$_a2" ] && ARCHIVE_MAX_EXTRACT_MB="$_a2"
                [ -n "$_a3" ] && ARCHIVE_MAX_DEPTH="$_a3"
                [ -n "$_a4" ] && ARCHIVE_MAX_FILES="$_a4"
                shift 2 ;;
            --archive-max-mb)         _deprecated --archive-max-mb "--archive-limits $2,,,"; ARCHIVE_MAX_MB="$2"; shift 2 ;;
            --archive-ram-max-mb)     _deprecated --archive-ram-max-mb "--ram-dirs"; ARCHIVE_RAM_MAX_MB="$2"; shift 2 ;;
            --archive-max-extract-mb) _deprecated --archive-max-extract-mb "--archive-limits ,$2,,"; ARCHIVE_MAX_EXTRACT_MB="$2"; shift 2 ;;
            --archive-max-depth)      _deprecated --archive-max-depth "--archive-limits ,,$2,"; ARCHIVE_MAX_DEPTH="$2"; shift 2 ;;
            --archive-max-files)      _deprecated --archive-max-files "--archive-limits ,,,$2"; ARCHIVE_MAX_FILES="$2"; shift 2 ;;
            --yara-timeout)           YARA_TIMEOUT_SEC="$2"; YARA_TIMEOUT_SEC_EXPLICIT=1; shift 2 ;;
            --yara-mode)
                case "${2:-}" in
                    threads|workers) YARA_MODE="$2" ;;
                    *) echo "[FAIL] --yara-mode requires threads or workers (got: '${2:-<missing>}')" >&2; exit 1 ;;
                esac
                shift 2 ;;
            --yara-threads)
                case "${2:-}" in
                    ""|*[!0-9]*) echo "[FAIL] --yara-threads requires a whole number (got: '${2:-<missing>}')" >&2; exit 1 ;;
                esac
                YARA_THREADS_ARG="$2"; shift 2 ;;
            --yara-rules)             _deprecated --yara-rules "--packs ${2//,/+}"
                                      _yara_validate_spec "$2" || exit 1; PACKS_SPEC="${2//,/+}"; shift 2 ;;
            --packs)                  [ $# -ge 2 ] || { echo "[FAIL] --packs needs a value" >&2; exit 1; }
                                      _pack_validate "$2" || exit 1; PACKS_SPEC="$2"; shift 2 ;;
            --clam-groups)            [ $# -ge 2 ] || { echo "[FAIL] --clam-groups needs a value" >&2; exit 1; }
                                      _deprecated --clam-groups "--packs <pack>+<group> (note: + ADDS groups to the pack, --clam-groups replaced them)"
                                      _clam_validate_groups "$2" || exit 1; CLAM_GROUPS_ARG="$2"; shift 2 ;;
            --yara-all)               _deprecated --yara-all "--packs full"; YARA_ALL=true; shift ;;
            --clam-pua)               CLAM_PUA=true; shift ;;
            --media-fast)             MEDIA_FAST=true; shift ;;
            --explain)                [ $# -ge 2 ] || { echo "[FAIL] --explain needs a file" >&2; exit 1; }
                                      EXPLAIN_FILE="$2"; shift 2 ;;
            --sandbox-mode)
                # FIX (real bug reported): "$2" used to be accepted
                # unconditionally — a missing value (e.g. "--sandbox-mode
                # -L", another flag immediately following with no actual
                # mode given) silently swallowed THAT flag as if it were
                # the mode string, corrupting SANDBOX_MODE to "-L" AND
                # eating -L itself, with zero warning (an unrecognized
                # mode falls through to "none" behavior silently rather
                # than erroring). Now validated against the real option
                # set right here, so a mistake like this is caught
                # immediately and loudly instead of silently corrupting
                # two flags at once.
                case "$2" in
                    auto|bwrap|unshare|chroot|simple|none) : ;;
                    *) echo "[FAIL] --sandbox-mode requires one of: auto|bwrap|unshare|chroot|simple|none (got: '${2:-<missing>}')" >&2; exit 1 ;;
                esac
                SANDBOX_MODE="$2"; shift 2 ;;
            -P|--scan-processes) SCAN_PROCESSES=true; shift ;;
            -K|--check-kernel)   CHECK_KERNEL=true; shift ;;
            --offline-root)      OFFLINE_ROOT="$2"; shift 2 ;;
            --audit)             AUDIT_MODE=true; shift ;;
            --audit-since)       AUDIT_MODE=true; AUDIT_SINCE="$2"; shift 2 ;;
            --sig-in-ram)        _deprecated --sig-in-ram "--ram-dirs all"; RAM_DIRS=all; shift ;;
            --deep|--paranoid)   SUID_VERIFY_MODE=true; SCAN_ARCHIVES=true; DEEP_MODE=true
                                 # Real gap found: the default 10MB deep-
                                 # inspection cap (hash/YARA/strings ALL
                                 # gated on it) silently skipped files
                                 # like /var/lib/clamav/main.cvd (89MB) —
                                 # a blind spot --deep's own "no
                                 # exclusions" philosophy shouldn't have.
                                 # Bumped unless the person ALSO passed an
                                 # explicit -m/--max-size of their own.
                                 [ -z "$MAX_SCAN_MB_EXPLICIT" ] && MAX_SCAN_MB=200
                                 # Same gap, second instance (real bug
                                 # reported: lots of files skipped as
                                 # "took too long to scan" under --deep):
                                 # raising MAX_SCAN_MB to 200 without ALSO
                                 # raising the time budget means a large
                                 # file --deep newly stops skipping on
                                 # size still gets skipped on time instead
                                 # — see _yara_bisect_slow_batch for the
                                 # other half of this fix (its short
                                 # per-file timeout is now proportional to
                                 # this value, so raising it here actually
                                 # helps there too).
                                 [ -z "$YARA_TIMEOUT_SEC_EXPLICIT" ] && YARA_TIMEOUT_SEC=600
                                 shift ;;
            -L|--long-time)
                # optional seconds right after it: -L 60 ; plain -L = default
                LONG_TIME_MODE=true
                if [[ "${2:-}" =~ ^[0-9]+$ ]]; then LONG_TIME_THRESHOLD_SEC="$2"; shift 2; else shift; fi ;;
            --long-time-threshold)    _deprecated --long-time-threshold "-L $2"; LONG_TIME_THRESHOLD_SEC="$2"; shift 2 ;;
            --ram-dirs)
                case "${2:-}" in
                    auto|none|all) RAM_DIRS="$2" ;;
                    *) echo "[FAIL] --ram-dirs requires auto, none or all (got: '${2:-<missing>}')" >&2; exit 1 ;;
                esac
                shift 2 ;;
            --no-ram)        _deprecated --no-ram "--ram-dirs none"; RAM_DIRS=none; shift ;;
            --no-busybox)    ALLOW_BUSYBOX=false; shift ;;
            -b|--busybox)    BUSYBOX_PATH_ARG="$2"; shift 2 ;;
            --busybox-url)   BUSYBOX_URL_ARG="$2"; shift 2 ;;
            --yara-url)      YARA_URL_ARG="$2"; shift 2 ;;
            --mb-key)        MB_KEY="$2"; shift 2 ;;
            -q|--quarantine) QUARANTINE_ENABLED=true; shift ;;
            --quarantine-dry-run) QUARANTINE_ENABLED=true; QUARANTINE_DRY_RUN=true; shift ;;
            --debug)         DEBUG_MODE=true; shift ;;
            --no-quarantine-archives) _deprecated --no-quarantine-archives "(nothing: with -q archives are quarantined too)"; shift ;;
            --quarantine-dir)  QUARANTINE_ENABLED=true; QUARANTINE_DIR="$2"; shift 2 ;;
            --quarantine-perm) QUARANTINE_PERM="$2"; shift 2 ;;
            -w|--real-time|--realtime) REALTIME_MODE=true; shift ;;
            --low-priority|--background|--bg) LOW_PRIORITY=true; shift ;;
            -I|--incremental)  INCREMENTAL_MODE=true; shift ;;
            --no-incremental)  INCREMENTAL_MODE=false; INCREMENTAL_EXPLICIT_OFF=1; shift ;;
            --verify-suid)     _deprecated --verify-suid "(nothing: it is on by default)"; SUID_VERIFY_MODE=true; shift ;;
            --no-verify-suid)  SUID_VERIFY_MODE=false; SUID_VERIFY_EXPLICIT_OFF=1; shift ;;
            --incremental-cache) INCREMENTAL_CACHE_FILE="$2"; shift 2 ;;
            --watch-interval)  WATCH_INTERVAL="$2"; shift 2 ;;
            --max-hex-patterns) _deprecated --max-hex-patterns "ORPHUS_MAX_HEX_PATTERNS=$2"; MAX_HEX_PATTERNS="$2"; shift 2 ;;
            --batch-size)    BATCH_SIZE="$2"; BATCH_SIZE_EXPLICIT=1; shift 2 ;;
            --heur-batch-size) _deprecated --heur-batch-size "--batch-size"; HEUR_BATCH_SIZE="$2"; HEUR_BATCH_EXPLICIT=1; shift 2 ;;
            --pe-batch-size) _deprecated --pe-batch-size "--batch-size"; PE_BATCH_SIZE="$2"; PE_BATCH_EXPLICIT=1; shift 2 ;;
            --setup)         DO_SETUP=true; shift ;;
            --force)         SETUP_FORCE=true; shift ;;
            --compile)       SETUP_COMPILE_ONLY=true; shift ;;
            --check-deps)    DO_CHECK_DEPS=true; shift ;;
            -h|--help)       usage ;;
            --help-all)      usage_all ;;
            *) echo "Unknown parameter: $1"; exit 1 ;;
        esac
    done
}

# _abs_path PATH -> absolute, no repeated/trailing "/" ("/" stays "/"),
# "."/".." resolved logically (like cd) for the part that exists. The
# self-exclusions and -X in collect_files() are string matches (find
# -path), so "-d .", "-X cache/" or a relative -X never matched before.
_abs_path() {
    local p="$1" d b
    case "$p" in /*) ;; *) p="$PWD/$p" ;; esac
    if [ -d "$p" ] && d=$(CDPATH= cd -- "$p" 2>/dev/null && pwd); then
        p="$d"
    else
        p=$(printf '%s' "$p" | tr -s '/'); [ "$p" != "/" ] && p="${p%/}"
        d="${p%/*}"; b="${p##*/}"
        if [ -n "$b" ] && [ "$b" != "." ] && [ "$b" != ".." ] && d=$(CDPATH= cd -- "${d:-/}" 2>/dev/null && pwd); then
            if [ "$d" = "/" ]; then p="/$b"; else p="$d/$b"; fi
        fi
    fi
    printf '%s\n' "$p"
}

# _phys_dir DIR -> DIR with every symlink resolved (unchanged if it can't
# be entered).
_phys_dir() {
    local d
    if d=$(CDPATH= cd -P -- "$1" 2>/dev/null && pwd -P); then printf '%s\n' "$d"; else printf '%s\n' "$1"; fi
}

# Runs right after parse_args: numeric options must be whole numbers
# (bash arithmetic would die mid-scan on "abc"/"1.5" — or silently misread
# "08"/"1e3"), and path options become absolute.
normalize_args() {
    local spec opt name min val i
    for spec in -r:MAX_RAM_MB:1 -j:WORKERS:1 -m:MAX_SCAN_MB:1 \
                "--archive-limits(SIZE):ARCHIVE_MAX_MB:1" --archive-ram-max-mb:ARCHIVE_RAM_MAX_MB:0 \
                "--archive-limits(EXTRACT):ARCHIVE_MAX_EXTRACT_MB:1" "--archive-limits(DEPTH):ARCHIVE_MAX_DEPTH:0" \
                "--archive-limits(FILES):ARCHIVE_MAX_FILES:1" --yara-timeout:YARA_TIMEOUT_SEC:1 \
                "-L(SEC):LONG_TIME_THRESHOLD_SEC:0" --watch-interval:WATCH_INTERVAL:1 \
                "max-hex-patterns(ORPHUS_MAX_HEX_PATTERNS):MAX_HEX_PATTERNS:0" --batch-size:BATCH_SIZE:1 \
                --heur-batch-size:HEUR_BATCH_SIZE:1 --pe-batch-size:PE_BATCH_SIZE:1; do
        opt="${spec%%:*}"; name="${spec#*:}"; min="${name#*:}"; name="${name%:*}"
        val="${!name}"
        [ "$name" = WORKERS ] && [ -z "$WORKERS_EXPLICIT" ] && continue   # "" = auto
        if ! [[ "$val" =~ ^[0-9]{1,9}$ ]] || [ $(( 10#$val )) -lt "$min" ]; then
            echo "[FAIL] $opt: '$val' is not a whole number >= $min" >&2
            exit 1
        fi
        printf -v "$name" '%d' "$(( 10#$val ))"
    done

    # --batch-size drives the other two batch sizes (heuristics = same,
    # PE sections = half), unless an old --heur/--pe-batch-size was given
    if [ -n "$BATCH_SIZE_EXPLICIT" ]; then
        [ -n "${HEUR_BATCH_EXPLICIT:-}" ] || HEUR_BATCH_SIZE=$BATCH_SIZE
        if [ -z "${PE_BATCH_EXPLICIT:-}" ]; then
            PE_BATCH_SIZE=$(( BATCH_SIZE / 2 )); [ "$PE_BATCH_SIZE" -lt 1 ] && PE_BATCH_SIZE=1
        fi
    fi

    # --ram-dirs: one switch instead of --no-ram / --sig-in-ram /
    # --archive-ram-max-mb
    case "$RAM_DIRS" in
        none) USE_RAM=false; NO_RAM_EXPLICIT=1 ;;
        all)  SIG_IN_RAM=true; ARCHIVE_RAM_MAX_MB=$ARCHIVE_MAX_MB ;;
    esac

    # The scan root is resolved to its PHYSICAL path: find does not descend
    # into a symlinked root (www -> public_html scanned 0 files), and the
    # exclusions below are matched against what find prints.
    [ -n "$ROOT_DIR" ] && ROOT_DIR=$(_abs_path "$ROOT_DIR")
    [ -d "$ROOT_DIR" ] && ROOT_DIR=$(_phys_dir "$ROOT_DIR")
    [ -n "$SIGNATURES" ] && SIGNATURES=$(_abs_path "$SIGNATURES")
    [ -n "$QUARANTINE_DIR" ] && QUARANTINE_DIR=$(_abs_path "$QUARANTINE_DIR")
    [ -n "$OUTPUT_FILE" ] && OUTPUT_FILE=$(_abs_path "$OUTPUT_FILE")
    for i in "${!EXCLUDE_PATHS[@]}"; do
        [ -n "${EXCLUDE_PATHS[$i]}" ] && EXCLUDE_PATHS[$i]=$(_abs_path "${EXCLUDE_PATHS[$i]}")
    done
    return 0
}

setup_colors() {
    if [ -t 1 ]; then
        R='\033[0;31m' Y='\033[1;33m' G='\033[0;32m'
        C='\033[0;36m' B='\033[1m' Z='\033[0m'
    fi
}

# ============================================================================
# 6. MODULE: worker sizing / RAM guard
# ============================================================================
# --low-priority: renice + ionice the CURRENT process (this main script) —
# children (workers) forked afterward inherit both the nice value and the
# ionice class/priority automatically on Linux, so this one call covers
# the whole process tree without needing to wrap every worker launch.
# Best-effort: missing `ionice` (non-Linux, minimal container) or lack of
# permission to renice just means one less lever pulled, not a failure.
apply_low_priority() {
    [ "$LOW_PRIORITY" = true ] || return 0
    echo -e "${C}[*] --low-priority: reducing CPU/IO priority to stay out of the way${Z}"
    renice -n 19 -p $$ &>/dev/null || true
    if command -v ionice &>/dev/null; then
        # Class 3 = idle: only gets disk I/O when nothing else wants it.
        # Falls back to best-effort class 2 at the lowest priority (7) on
        # kernels/schedulers where idle I/O class isn't available.
        ionice -c 3 -p $$ &>/dev/null || ionice -c 2 -n 7 -p $$ &>/dev/null || true
    fi
}

# Caps WORKERS so that WORKERS x (RAM of one yara process) fits MAX_RAM_MB.
# $1 = optional path of a compiled ruleset to size from.
# One yara process holds the whole compiled set, so its RAM scales with it.
# Measured with the real script (built-in file exclusions active), peak RSS of
# one yara process loading the set: ~119MB for profile all (29MB rules.yarc),
# ~101MB for server (21MB), ~14MB for hosting (4MB) -> about 3x the .yarc size
# plus a constant; with a ClamAV-converted set (hex-only rules, ~2.3x) that
# stays on the safe side. 120MB is kept as the floor: it also covers the
# memory a worker spends while scanning big files.
_yara_ram_cap() {
    local yarc="$1" est=120 sz est2 max_safe
    export YARA_MODE     # workers read it even if we return early below
    [ "$YARA_CMD" != "none" ] || return 0
    _yara_expand_profile
    case " $YARA_CATS " in
        *" legacy "*)  est=150 ;;
        *" malware "*) est=130 ;;
    esac
    if [ -n "$yarc" ] && [ -f "$yarc" ]; then
        sz=$(( $(wc -c < "$yarc" 2>/dev/null || echo 0) / 1048576 ))
        est2=$(( sz * 3 + 40 ))
        [ "$est2" -gt "$est" ] && est=$est2
    fi
    max_safe=$(( MAX_RAM_MB / est ))
    [ "$max_safe" -lt 1 ] && max_safe=1
    # Every yara PROCESS holds its own full copy of the ruleset, but the
    # THREADS inside one process (-p N, also with --scan-list) share it.
    # Measured (4.5.4, 150k hex rules): 8 processes 895 MB RSS vs one process
    # with 8 scanning threads 112 MB, same work. So for a heavy ruleset the
    # parallelism moves from "N processes" to "few processes x several
    # threads": workers (hashing, heuristics, PE parsing) stay at full count,
    # only the number of CONCURRENT yara processes is limited (YARA_SLOTS).
    # Two ways to run YARA (--yara-mode):
    #  threads (default): ONE yara process for the whole scan with -p T threads.
    #    Workers keep doing hashes/strings/heuristics and only hand their YARA
    #    batches to a queue; a dedicated consumer (WORKER_ID pool_yara) scans
    #    them. Every yara PROCESS holds a full copy of the ruleset, threads
    #    share it (measured, 4.5.4, 150k hex rules: 8 processes 895 MB RSS vs
    #    1 process x 8 threads 112 MB), so RAM is ~one ruleset whatever -j is.
    #    Small side calls in workers (archives, decoded base64) are limited to
    #    one more yara process at a time (YARA_SLOTS=1).
    #  workers: the old model, every worker runs its own yara (-p 1), i.e. one
    #    ruleset copy per worker. Kept for compatibility / comparison.
    local cpus; cpus=$(cpu_count)
    if [ "${YARA_MODE:-threads}" = "workers" ]; then
        # one yara per worker, but never more concurrent yara processes than
        # the RAM ceiling holds (same guard as 0.3.3)
        YARA_THREADS=1
        YARA_SLOTS=$WORKERS
        [ "$max_safe" -lt "$YARA_SLOTS" ] && YARA_SLOTS=$max_safe
        if [ -z "${_YARA_CAP_SHOWN:-}" ] || [ "$YARA_SLOTS" != "${_YARA_SLOTS_SHOWN:-}" ]; then
            if [ "$YARA_SLOTS" -lt "$WORKERS" ]; then
                echo -e "${Y}[*] YARA (--yara-mode workers): ~${est} MB per yara process, only ${YARA_SLOTS} of ${WORKERS} fit into ${MAX_RAM_MB} MB at a time - the others wait. The default --yara-mode threads keeps one ruleset copy.${Z}"
            else
                echo -e "[*] YARA (--yara-mode workers): ${YARA_SLOTS} yara process(es) x ~${est} MB"
            fi
        fi
        _YARA_SLOTS_SHOWN=$YARA_SLOTS
    else
        YARA_SLOTS=1
        # default: one thread per worker, but not more than CPUs (more threads
        # than cores only make each batch slower, closer to the yara timeout)
        local tdef=$WORKERS; [ "$tdef" -gt "$cpus" ] && tdef=$cpus
        YARA_THREADS=${YARA_THREADS_ARG:-${AV_YARA_THREADS:-$tdef}}
        [ "$YARA_THREADS" -lt 1 ] 2>/dev/null && YARA_THREADS=1
        [ "$YARA_THREADS" -gt 32 ] && YARA_THREADS=32      # yara's own limit (YR_MAX_THREADS)
        [ -z "${_YARA_CAP_SHOWN:-}" ] && echo -e "[*] YARA: 1 process x ${YARA_THREADS} thread(s) (~${est} MB for the ruleset; one more copy at most for archive/base64 side checks). Old model: --yara-mode workers"
        [ $(( est * 2 )) -gt "$MAX_RAM_MB" ] && echo -e "${R}[WARN] The ruleset (~${est} MB per copy, up to 2 copies) does not fit the ${MAX_RAM_MB} MB ceiling — use a lighter --packs / --yara-rules profile or raise -r${Z}"
    fi
    _YARA_CAP_SHOWN=1
    export YARA_SLOTS YARA_THREADS YARA_MODE
}

init_workers() {
    # WORKERS may be set via -j/--workers; otherwise auto by CPU count.
    [ -z "$WORKERS" ] && WORKERS=$(cpu_count)

    # Guard: WORKERS must be a positive int (avoid div-by-zero later in awk).
    case "$WORKERS" in
        ''|*[!0-9]*) WORKERS=$(cpu_count) ;;
    esac
    [ "${WORKERS:-0}" -ge 1 ] 2>/dev/null || WORKERS=1

    # --low-priority: default to a single worker unless the person
    # explicitly asked for more via -j — the whole point is to stay out
    # of the way of everything else running on the box, and running
    # several workers in parallel (even niced/ionice'd) still competes for
    # the same disk/IOPS budget as a single one, just faster and busier.
    if [ "$LOW_PRIORITY" = true ] && [ -z "$WORKERS_EXPLICIT" ]; then
        WORKERS=1
    fi

    echo -e "${B}[*] RAM Guard: ceiling ${C}${MAX_RAM_MB} MB${Z}"

    # Early estimate: from the previous compile's cache if there is one, else
    # from the profile table. Re-checked against the REAL compiled ruleset
    # right after compile_signatures (see main) — that one includes the
    # ClamAV-converted rules, which this early pass can't see on a first run.
    _yara_ram_cap "$SIGNATURES/.cache/packs/$(_yara_pack_id)/rules.yarc"

    # Capture the person's ORIGINAL --no-ram preference for archive
    # extraction BEFORE the low-RAM-profile auto-tuning below can
    # override USE_RAM — archive RAM extraction is independently bounded
    # by ARCHIVE_RAM_MAX_MB (default 50MB, tiny compared to a worker's own
    # RAM ceiling) and shouldn't be silently disabled just because the
    # overall RAM ceiling looks modest.
    ARCHIVE_USE_RAM="$USE_RAM"

    if [ "$MAX_RAM_MB" -le 512 ]; then
        USE_RAM=false
        if [ "$WORKERS" -gt 4 ]; then
            echo -e "${Y}[WARN] Low-RAM profile: workers reduced to 4${Z}"
            WORKERS=4
        fi
    elif [ "$MAX_RAM_MB" -le 1024 ] && [ "$WORKERS" -gt 8 ]; then
        WORKERS=8
    fi
}

# ============================================================================
# 7. MODULE: quarantine (main-script side init)
#    The actual file move happens in the worker (quarantine_file) right
#    where the threat is detected, to avoid a gap between detection and
#    isolation.
# ============================================================================
init_quarantine() {
    [ "$QUARANTINE_ENABLED" = true ] || return 0

    mkdir -p "$QUARANTINE_DIR" 2>/dev/null
    chmod 700 "$QUARANTINE_DIR" 2>/dev/null

    # If quarantine is inside the scan target, quarantined files could get
    # rescanned on the next pass (or by real-time watch).
    case "$QUARANTINE_DIR" in
        "$ROOT_DIR"/*|"$ROOT_DIR")
            echo -e "${Y}[WARN] Quarantine dir is inside the scan target ($ROOT_DIR) — quarantined files may get rescanned${Z}"
            ;;
    esac

    echo -e "${C}[*] Quarantine: ${QUARANTINE_DIR} (perm ${QUARANTINE_PERM})${Z}"
}

count_quarantined() {
    bb grep -h "QUARANTINED:" "$WORK_DIR/reports"/*.txt 2>/dev/null | bb wc -l | tr -d ' '
}

count_suppressed() {
    bb grep -h "^SUPPRESSED:" "$WORK_DIR/reports"/*.txt 2>/dev/null | cut -d: -f2 | \
        awk '{s+=$1} END {print s+0}'
}

# Locates (or creates, with a helpful commented template) the ignore_sigs
# file — patterns that suppress specific noisy detections without editing
# downloaded signature/rule files (which get overwritten on the next -u).
# Same idea as LMD's ignore_sigs: https://github.com/rfxn/linux-malware-detect
init_ignore_sigs() {
    [ -n "$IGNORE_SIGS_FILE" ] || IGNORE_SIGS_FILE="${SIGNATURES}/ignore_sigs"

    if [ ! -f "$IGNORE_SIGS_FILE" ]; then
        mkdir -p "$(dirname "$IGNORE_SIGS_FILE")" 2>/dev/null
        cat << 'EOF' > "$IGNORE_SIGS_FILE" 2>/dev/null
# Orphus AV Scanner — ignore_sigs
#
# One extended-regex (ERE) pattern per line, matched against
# "TYPE|info|FILEPATH" of each detection, e.g.:
#   YARA_MATCH|rule=WEBSHELL_PHP_Dynamic_Big|/home/site/upload/engine/init.php
# A match SUPPRESSES that detection entirely — no log entry, no
# quarantine. Patterns match as substrings anywhere on the line, so a
# bare "rule=WEBSHELL_PHP_Dynamic_Big" suppresses that rule EVERYWHERE,
# on every file, on every future scan — including a real webshell on some
# other site that happens to trip the same rule. Prefer scoping to a path
# too, e.g. "rule=WEBSHELL_PHP_Dynamic_Big.*/upload/engine/" only
# suppresses it under that one directory, leaving the rule fully active
# everywhere else.
#
# Use this for signatures/rules that are individually too broad for your
# specific software (e.g. a CMS that ships obfuscated/encoded core files
# for license protection — generic webshell-obfuscation heuristics can't
# tell that apart from an actual backdoor by pattern alone).
#
# Active by default (not commented out) — affects virtually anyone
# scanning system binaries, not specific to any one server: the real
# /usr/sbin/chroot binary (and its snap-packaged duplicates under
# /snap/core*/*/usr/sbin/chroot) contains the literal string "/bin/sh -i"
# as part of its own internal fallback-shell logic, not because it's
# compromised. Scoped to paths ending in /sbin/chroot specifically — the
# same pattern text on any OTHER file still triggers normally.
pattern=/bin/sh -i.*/sbin/chroot$
#
# Same class of false positive, different universal system file: the
# netcat-openbsd manual page (/usr/share/man/man1/nc_openbsd.1.gz)
# documents "-e /bin/sh -i"-style usage examples as part of explaining
# what the flag does — text content, not an actual reverse shell.
# Present on any Debian/Ubuntu box with netcat-openbsd installed.
pattern=/bin/sh -i.*nc_openbsd\.1\.gz$
#
# Examples (uncomment / adapt the path to your actual install):
# rule=WEBSHELL_PHP_Dynamic_Big.*/upload/engine/
# rule=WEBSHELL_PHP_Encoded_Big.*/upload/engine/
# rule=EXT_WEBSHELL_PHP_Generic.*/vendor/matomo/device-detector/README\.md
EOF
    fi
}

# Shared ignore list from the project repository (main branch), refreshed on
# every -u into signatures/ignore_sigs.upstream. Workers apply it IN ADDITION
# to the local signatures/ignore_sigs, which stays yours and is never touched.
#   ORPHUS_IGNORE_SIGS_URL=<url>   other source (a mirror, a fork)
#   ORPHUS_IGNORE_SIGS_URL=none    do not download; also stops using the file
# A failed or bad download keeps the previous copy. Every line must be a valid
# ERE, and a line that would hide detections in an ordinary site path
# (canary test below) is dropped: one careless commit upstream cannot blind
# every scanner that pulls the list. --deep ignores all of it anyway.
IGNORE_SIGS_UPSTREAM_URL_DEFAULT="https://raw.githubusercontent.com/FartGarfild/Orphus/main/ignore_sigs"
_ignore_sigs_upstream_url() {
    local u="${ORPHUS_IGNORE_SIGS_URL-$IGNORE_SIGS_UPSTREAM_URL_DEFAULT}"
    [ "$u" = none ] && u=""
    printf '%s' "$u"
}
update_ignore_sigs_upstream() {
    local sig_dir="$1" url dest tmp ok=0 badre=0 broad=0 p
    url=$(_ignore_sigs_upstream_url)
    dest="$sig_dir/ignore_sigs.upstream"
    if [ -z "$url" ]; then
        echo "  - shared ignore list: disabled (ORPHUS_IGNORE_SIGS_URL=none)"
        return 0
    fi
    echo "[*] Shared ignore list (ignore_sigs from the project repository)..."
    tmp=$(mktemp "$sig_dir/.ignore_sigs.dl.XXXXXX" 2>/dev/null) || return 0
    net_fetch "$url" "$tmp" 15 "" 2 >/dev/null 2>&1
    if [ ! -s "$tmp" ] || bb head -c 2000 "$tmp" | bb grep -qiE '<(html|!doctype)'; then
        rm -f "$tmp"
        echo "  ! download failed -> keeping the previous copy$([ -f "$dest" ] || echo ' (none yet)')"
        return 0
    fi
    # canary detections in ordinary site / system locations: no shared line
    # may hide these
    local canary
    canary=$'YARA_MATCH|rule=Orphus_Canary_Rule|/home/user/public_html/index.php\nKNOWN_MALWARE|name=Orphus.Canary-1|md5=0|/var/www/html/wp-config.php\nSIG_STRING_MATCH|pattern=eval(base64_decode(|/home/site/www/upload/shell.php\nHEURISTIC|reason=canary|/tmp/x.php'
    canary=$(printf '%b' "$canary")
    {
        while IFS= read -r p || [ -n "$p" ]; do
            p="${p%$'\r'}"
            case "$p" in ''|'#'*|[[:space:]]*'#'*) printf '%s\n' "$p"; continue ;; esac
            # (busybox grep compiles the regex only once it reads a line)
            printf 'x\n' | bb grep -E -- "$p" >/dev/null 2>&1
            if [ $? -eq 2 ]; then badre=$((badre+1)); printf '# [dropped: invalid ERE] %s\n' "$p"; continue; fi
            if printf '%s\n' "$canary" | bb grep -qE -- "$p" 2>/dev/null; then
                broad=$((broad+1)); printf '# [dropped: too broad] %s\n' "$p"; continue
            fi
            ok=$((ok+1)); printf '%s\n' "$p"
        done < "$tmp"
        printf '%s %s %s\n' "$ok" "$badre" "$broad" > "$tmp.cnt"
    } > "$tmp.ok"
    read -r ok badre broad < "$tmp.cnt" 2>/dev/null
    rm -f "$tmp" "$tmp.cnt"
    { printf '# Downloaded by av.sh -u from %s on %s. Overwritten on every -u:\n# put your own lines in ignore_sigs, not here.\n' "$url" "$(date -u '+%Y-%m-%d %H:%M UTC')"; cat "$tmp.ok"; } > "$tmp.new"
    rm -f "$tmp.ok"
    mv -f "$tmp.new" "$dest"
    echo "  ✓ shared ignore list: ${ok:-0} line(s) -> $dest"
    [ "${badre:-0}" -gt 0 ] && echo -e "  ${Y}[WARN] ${badre} invalid pattern(s) left out${Z}"
    [ "${broad:-0}" -gt 0 ] && echo -e "  ${Y}[WARN] ${broad} pattern(s) left out as too broad (would hide detections in ordinary site paths)${Z}"
    return 0
}

# Known-vendor-obfuscation allowlist: an ALTERNATIVE to path-based
# ignore_sigs that works automatically on ANY install, no per-server path
# configuration needed. If a file matches one of the "generic" YARA rules
# in GENERIC_OBFUSCATION_RULES_FILE (broad obfuscation heuristics that
# can't distinguish a real backdoor from a vendor protecting their own
# code) AND the SAME file also contains one of the fingerprint strings in
# KNOWN_VENDOR_OBFUSCATION_FILE (distinctive enough that a real attacker
# copying it verbatim to impersonate the vendor would be an unusually
# sophisticated, deliberate move, not a generic webshell), the detection
# is suppressed automatically. Ships pre-populated with DataLife Engine's
# own obfuscator fingerprint (confirmed from real samples: a
# "DataLife Engine - by SoftNews Media Group" header combined with a
# strrev('edoced_46esab') [= "base64_decode" reversed] decode wrapper) —
# add more vendors' fingerprints here as you run into them.
init_vendor_obfuscation_allowlist() {
    [ -n "$GENERIC_OBFUSCATION_RULES_FILE" ] || GENERIC_OBFUSCATION_RULES_FILE="${SIGNATURES}/generic_obfuscation_rules"
    [ -n "$KNOWN_VENDOR_OBFUSCATION_FILE" ] || KNOWN_VENDOR_OBFUSCATION_FILE="${SIGNATURES}/known_vendor_obfuscation"

    if [ ! -f "$GENERIC_OBFUSCATION_RULES_FILE" ]; then
        mkdir -p "$(dirname "$GENERIC_OBFUSCATION_RULES_FILE")" 2>/dev/null
        cat << 'EOF' > "$GENERIC_OBFUSCATION_RULES_FILE" 2>/dev/null
# Orphus AV Scanner — generic_obfuscation_rules
#
# One ERE pattern per line, matched against a YARA rule NAME. These are
# rules broad/generic enough ("does this look obfuscated at all") that
# they can't tell a real backdoor apart from a vendor obfuscating their
# OWN code (license protection etc) — a match against one of these rule
# names is only auto-suppressed if the SAME file also matches a
# fingerprint in known_vendor_obfuscation (both conditions required, not
# either alone). Add more rule names here as you find other overly-broad
# ones tripping on legitimate vendor code.
^WEBSHELL_PHP_Dynamic_Big$
^WEBSHELL_PHP_Encoded_Big$
^EXT_WEBSHELL_PHP_Generic$
^WEBSHELL_PHP_Generic_Eval$
^WEBSHELL_PHP_OBFUSC_Encoded_Mixed_Dec_And_Hex$
^WEBSHELL_PHP_OBFUSC_Fopo$
^WEBSHELL_PHP_Gzinflated$
^webshell_php_by_string_obfuscation$
^apt_CN_Tetrisplugins_JS$
EOF
    fi

    if [ ! -f "$KNOWN_VENDOR_OBFUSCATION_FILE" ]; then
        mkdir -p "$(dirname "$KNOWN_VENDOR_OBFUSCATION_FILE")" 2>/dev/null
        cat << 'EOF' > "$KNOWN_VENDOR_OBFUSCATION_FILE" 2>/dev/null
# Orphus AV Scanner — known_vendor_obfuscation
#
# One ERE pattern per line — a distinctive fingerprint of a SPECIFIC,
# LEGITIMATE vendor's own code-obfuscation scheme (usually license
# protection on core files, not malware). Only consulted for files that
# ALSO matched a rule listed in generic_obfuscation_rules — this file
# alone never suppresses anything by itself. Add a new line per vendor
# you run into, ideally a string unlikely to appear by accident.
#
# NOTE: grep matches line-by-line — "." does NOT cross newlines here, so
# a pattern spanning e.g. a header comment AND a decode call several
# lines later (real files have a large base64 blob in between) will never
# match. Keep each pattern to something that appears on ONE line.
#
# DataLife Engine (dle-news.ru) — confirmed from real obfuscated core
# files: a "base64_decode" spelled backwards and un-reversed via strrev()
# at decode time (a deliberate trick to dodge naive "eval(base64_decode"
# string signatures — which is also exactly why our OWN eval(base64_decode
# heuristic never caught it either, for what it's worth). Distinctive
# enough on its own without needing to also match the header line.
strrev\('edoced_46esab'\)
#
# Standard Webpack (3.x-style) bundler bootstrap — confirmed on a real
# revslider (Slider Revolution) Gutenberg block bundle that tripped
# apt_CN_Tetrisplugins_JS: verified BOTH the file's own mtime (identical
# to every sibling file in the same build output directory — consistent
# with one normal deployment, not a separately-planted file) and its
# actual content, which is textbook webpack module-wrapper code with
# eval() used only for source-map support (//# sourceURL/
# sourceMappingURL annotations) — none of the Tetris campaign's actual
# distinguishing markers (a0_0x-style variable names, fromCharCode-based
# string reconstruction) are present. Scoped ONLY to
# apt_CN_Tetrisplugins_JS in generic_obfuscation_rules, not any of the
# webshell rules — an attacker COULD in principle copy this exact
# boilerplate line to wrap malicious code, but doing so gets them
# nothing against the webshell-family rules, only this one narrower
# APT-campaign rule, and genuine malicious payload content would still
# need to pass every other signature/heuristic in the pipeline.
return __webpack_require__\(__webpack_require__\.s = 0\);
EOF
    fi
}

# Sets up a persistent live threat log OUTSIDE WORK_DIR (which cleanup()
# deletes on interrupt) — workers append to it AS threats are found, so an
# interrupted scan still leaves usable results behind instead of losing
# everything found up to that point.
init_live_report() {
    local f
    if [ -n "$OUTPUT_FILE" ]; then
        # Root writing through a planted symlink (e.g. -> /etc/shadow) would
        # truncate/append to its target: refuse. An existing regular file is
        # unlinked and created anew (noclobber below), never written into —
        # so a hard link to another file is not modified either.
        for f in "$OUTPUT_FILE" "${OUTPUT_FILE}-SUID" "${OUTPUT_FILE}.slow"; do
            if [ -L "$f" ]; then
                echo -e "${R}[FAIL] -o: refusing to write through a symlink: $f${Z}" >&2
                exit 1
            fi
        done
        if [ -e "$OUTPUT_FILE" ] && [ ! -d "$OUTPUT_FILE" ]; then
            echo -e "${Y}[WARN] -o: replacing existing file ${OUTPUT_FILE}${Z}"
            rm -f -- "$OUTPUT_FILE" 2>/dev/null
        fi
        LIVE_REPORT_FILE="$OUTPUT_FILE"
    else
        LIVE_REPORT_FILE="$(pwd)/av_scan_threats_$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "$$").log"
        # Name already taken (or planted): never open it, take a fresh name.
        if [ -e "$LIVE_REPORT_FILE" ] || [ -L "$LIVE_REPORT_FILE" ]; then
            LIVE_REPORT_FILE="${LIVE_REPORT_FILE%.log}_$$.log"
        fi
    fi
    # SUID/SGID findings go to their own companion file — on a full-OS
    # deep scan, standard system binaries (passwd/sudo/su/mount/etc, and
    # every one of their snap-packaged duplicates) alone can produce
    # dozens of lines that bury the handful of findings someone actually
    # needs to look at. Same base name, "-SUID" appended, next to the
    # main report.
    SUID_REPORT_FILE="${LIVE_REPORT_FILE}-SUID"
    # Same idea for bad file permissions (0777 and friends on a whole site
    # tree gives hundreds of lines): own file, own counter, not "threats".
    PERMS_REPORT_FILE="${LIVE_REPORT_FILE}-PERMS"

    # noclobber = O_EXCL: the report is always a NEW file we created, never
    # an existing path (or whatever a symlink planted there points to).
    if ! ( set -C; : > "$LIVE_REPORT_FILE" ) 2>/dev/null; then
        echo -e "${Y}[WARN] Can't create ${LIVE_REPORT_FILE} (exists or not writable) -> live threat log disabled (results only available at the end)${Z}"
        LIVE_REPORT_FILE=""
        return 0
    fi

    {
        echo "# Orphus AV Scanner — live threat log (updated as threats are found)"
        echo "# Target: $ROOT_DIR"
        echo "# Started: $(date 2>/dev/null || echo unknown)"
        echo "# If this scan gets interrupted, whatever is below this line is still valid."
        echo "#"
    } >> "$LIVE_REPORT_FILE" 2>/dev/null

    echo -e "${C}[*] Live threat log: ${LIVE_REPORT_FILE}${Z}"

    if [ "$LONG_TIME_MODE" = true ]; then
        rm -f -- "${LIVE_REPORT_FILE}.slow" 2>/dev/null
        ( set -C; : > "${LIVE_REPORT_FILE}.slow" ) 2>/dev/null
        echo -e "${C}[*] Slow-batch log (-L): ${LIVE_REPORT_FILE}.slow — tail -f it to watch live${Z}"
    fi
}

# ============================================================================
# 8. MODULE: signature updater
# ============================================================================
update_signatures() {
    local sig_dir="$1"
    local mb_key="${2:-}"
    mkdir -p "$sig_dir"/{maldet,clamav,hashes,yara,strings,custom}
    # Downloads go to a private mktemp dir, not fixed /tmp names that a
    # local user could pre-plant as symlinks (root would write through them).
    local dl
    dl=$(mktemp -d "${TMPDIR:-/tmp}/av_update.XXXXXX" 2>/dev/null) || { echo "[FAIL] mktemp failed"; return 1; }

    echo -e "\033[1;36m[*] Updating signature databases...\033[0m"

    # 1. Maldet
    echo "[*] Maldet sigpack..."
    net_fetch "https://cdn.rfxn.com/downloads/maldet-sigpack.tgz" "$dl/maldet-sigpack.tgz" 15
    if [ -s "$dl/maldet-sigpack.tgz" ]; then
        tar -xzf "$dl/maldet-sigpack.tgz" -C "$sig_dir/maldet" --strip-components=1 2>/dev/null || true
        echo "  ✓ Maldet: $(bb find "$sig_dir/maldet" -type f 2>/dev/null | bb wc -l | tr -d ' ') files"
        rm -f "$dl/maldet-sigpack.tgz"
    else
        echo "  ! Maldet download failed (skipped)"
    fi

    # 2. ClamAV
    echo "[*] ClamAV databases..."
    local clam_dir="$sig_dir/clamav"
    net_fetch "https://packages.microsoft.com/clamav/main.cvd" "$dl/main.cvd" 10 "Mozilla/5.0"
    net_fetch "https://packages.microsoft.com/clamav/daily.cvd" "$dl/daily.cvd" 10 "Mozilla/5.0"
    if [ -s "$dl/main.cvd" ] && [ -s "$dl/daily.cvd" ]; then
    # Check it's actually a CVD, not an HTML block page from Cloudflare
    if head -c 11 "$dl/main.cvd" | grep -q "ClamAV-VDB"; then
        dd if="$dl/main.cvd"  bs=512 skip=1 status=none 2>/dev/null | tar -xz -C "$clam_dir" 2>/dev/null || true
        dd if="$dl/daily.cvd" bs=512 skip=1 status=none 2>/dev/null | tar -xz -C "$clam_dir" 2>/dev/null || true
        # FIX (real annoyance reported): files packed inside a .cvd's own
        # internal tar stream carry epoch-zero (1970-01-01) mtimes — a
        # property of ClamAV's own packaging, not something extraction
        # itself warns about. Left as-is, this surfaces later as noisy
        # "implausibly old time stamp" warnings the FIRST time anyone
        # (a backup script, `tar -cvf` of the whole install dir, etc.)
        # tries to archive these files again. Stamped to the current
        # time right after extraction so that epoch timestamp never
        # propagates downstream to any other tool.
        find "$clam_dir" -exec touch {} + 2>/dev/null
        echo " ✓ ClamAV unpacked"
    else
        echo " ! ClamAV files are not valid CVD (probably Cloudflare block)"
    fi
    rm -f "$dl/main.cvd" "$dl/daily.cvd"
	else
    echo " ! ClamAV download failed (skipped)"
	fi
    rm -rf "$dl"

    # 3. MalwareBazaar (optional; curl+jq are outside busybox, silently
    # skipped if either is missing)
    if [ -n "$mb_key" ] && [ "$mb_key" != "YOUR_AUTH_KEY_HERE" ]; then
        echo "[*] MalwareBazaar hashes..."
        if command -v curl &>/dev/null && command -v jq &>/dev/null; then
            curl -s -H "Auth-Key: $mb_key" \
                -d "query=get_recent&selector=sha256&limit=30000" \
                https://mb-api.abuse.ch/api/v1/ 2>/dev/null | \
                jq -r '.data[]? | select(.sha256_hash) | "\(.sha256_hash)\tMalwareBazaar"' \
                > "$sig_dir/hashes/malwarebazaar.sha256" 2>/dev/null || true
            local cnt
            cnt=$(wc -l < "$sig_dir/hashes/malwarebazaar.sha256" 2>/dev/null | tr -d ' ')
            echo "  ✓ MalwareBazaar: ${cnt:-0} hashes"
        else
            echo "  ! curl/jq not found (outside busybox) -> skipped"
        fi
    fi

    # 4. YARA rules (git is outside busybox; optional, skipped if missing)
    echo "[*] YARA rules..."
    local yara_dir="$sig_dir/yara"
    if command -v git &>/dev/null; then
        for repo in "https://github.com/Neo23x0/signature-base.git" "https://github.com/Yara-Rules/rules.git"; do
            local name; name=$(basename "$repo" .git)
            git -C "$yara_dir/$name" pull --quiet 2>/dev/null || \
                git clone --depth 1 "$repo" "$yara_dir/$name" --quiet 2>/dev/null || true
        done
    else
        echo "  ! git not found (outside busybox) -> YARA rule update skipped"
    fi

    # Rules are compiled later, per pack, by the signature build step (it uses
    # bin/yarac from --setup). The old per-file compile here only looked at
    # $PATH, so it reported "yarac not found" although bin/yarac existed.
    detect_yarac
    if [ -z "$YARAC_BIN" ]; then
        echo "  ! yarac not found -> YARA rules will be used as text (slower; run --setup)"
    fi
    rm -f "$yara_dir/index.yar" "$yara_dir/rules.yarc" 2>/dev/null   # stale output of older versions

    update_ignore_sigs_upstream "$sig_dir"

    # 5. Custom boilerplate
    local custom_dir="$sig_dir/custom"
    if [ ! -f "$custom_dir/custom.strings" ]; then
        cat << 'EOF' > "$custom_dir/custom.strings"
eval(base64_decode
/bin/sh -i
bash -i >
nc -e /bin
python -c import socket
PHPDATA.*mbd;[0-9-]+\s*<\/PHPDATA>
round\((\d+\.?\d*\+?){2,}\)
goto [A-Za-z0-9_]+;
EOF
    fi
    [ ! -f "$custom_dir/custom.md5" ] && cat << 'EOF' > "$custom_dir/custom.md5"
# Add your MD5 hashes (hash<TAB>name)
EOF
    [ ! -f "$custom_dir/custom.sha256" ] && cat << 'EOF' > "$custom_dir/custom.sha256"
# Add your SHA256 hashes (hash<TAB>name)
EOF

    echo -e "\033[1;32m[OK] Signature update finished\033[0m"
    echo "    Size: $(du -sh "$sig_dir" 2>/dev/null | cut -f1)"
    echo ""

    report_signature_counts "$sig_dir"
}

# Prints raw entry counts per signature file, split into "parsed by this
# scanner" vs "excluded" (see MODULE: ClamAV format support). Lets you spot
# at a glance if an update download came back empty/truncated.
report_signature_counts() {
    local sig_dir="$1"
    local parsed_exts="hdb hdu hsb hsu ndb ndu ldb ldu mdb mdu"
    local excluded_exts="msb msu cdb idb wdb pdb gdb ftm fp sfp"

    echo -e "${C}[*] Signature source counts (raw lines per file):${Z}"

    local ext f lines total_parsed=0
    for ext in $parsed_exts; do
        while IFS= read -r f; do
            [ -f "$f" ] || continue
            lines=$(bb wc -l < "$f" 2>/dev/null || echo 0)
            [ "$lines" -eq 0 ] 2>/dev/null && continue
            printf "  %-24s %10d lines\n" "$(basename "$f")" "$lines"
            total_parsed=$((total_parsed + lines))
        done < <(bb find "$sig_dir" -type f -name "*.${ext}" 2>/dev/null)
    done
    echo -e "  ${G}Total parsed (supported formats): ${total_parsed} lines${Z}"

    local excl_bytes=0
    for ext in $excluded_exts; do
        while IFS= read -r f; do
            [ -f "$f" ] || continue
            excl_bytes=$((excl_bytes + $(bb stat -c%s "$f" 2>/dev/null || echo 0)))
        done < <(bb find "$sig_dir" -type f -name "*.${ext}" 2>/dev/null)
    done
    if [ "$excl_bytes" -gt 0 ]; then
        local excl_human
        if [ "$excl_bytes" -ge 1048576 ]; then
            excl_human="$(( excl_bytes / 1048576 )) MB"
        elif [ "$excl_bytes" -ge 1024 ]; then
            excl_human="$(( excl_bytes / 1024 )) KB"
        else
            excl_human="${excl_bytes} bytes"
        fi
        echo -e "  ${Y}Excluded (unsupported formats — .mdb/.msb/.cdb/.idb/.wdb/.pdb/.ftm/.fp/.sfp): ${excl_human} not parsed${Z}"
    fi
    echo ""
}

# ============================================================================
# PARALLEL AWK WRAPPER
# ============================================================================
# $1 = input file, $2 = output file, $3 = awk script
run_awk_parallel() {
    local infile="$1"
    local outfile="$2"
    local awk_code="$3"

    if [ ! -s "$infile" ]; then
        : > "$outfile"
        return 0
    fi

    local nproc_cmd
    nproc_cmd=$(nproc 2>/dev/null \
             || sysctl -n hw.ncpu 2>/dev/null \
             || grep -c ^processor /proc/cpuinfo 2>/dev/null \
             || echo 2)

    local line_cnt
    line_cnt=$(wc -l < "$infile" 2>/dev/null || echo 0)

    if [ "$nproc_cmd" -le 1 ]; then
        # FIX (real crash reproduced): plain system "awk" can silently BE
        # mawk (Ubuntu/Debian's update-alternatives default) — confirmed
        # mawk's regex engine both crashes outright on some ERE patterns
        # this script generates (a bounded quantifier "{n}" immediately
        # followed by a group, e.g. "{64}(:.*)?") AND silently
        # mis-evaluates two-number range quantifiers like "{32,64}"
        # (matches nothing, no error). busybox's awk handles both
        # correctly — already used on the parallel (nproc>1) path below,
        # so use it here too instead of whatever "awk" happens to resolve
        # to on the host.
        bb awk "$awk_code" "$infile" > "$outfile"
        return $?
    fi

    local chunk_dir
    chunk_dir=$(mktemp -d 2>/dev/null || mktemp -d -t 'awk_chunks.XXXXXX')
    # chunk_dir is removed explicitly at the end of this function (not via
    # a trap — a trap set here would fire on the whole script's exit, not
    # just this function's return).

    local awk_script_file="$chunk_dir/script.awk"
    printf '%s\n' "$awk_code" > "$awk_script_file"

    local num_chunks=$(( nproc_cmd * 10 ))
    if [ "$line_cnt" -lt "$num_chunks" ]; then
        num_chunks=$line_cnt
        [ "$num_chunks" -lt 1 ] && num_chunks=1
    fi

    local lines_per_chunk=$(( (line_cnt + num_chunks - 1) / num_chunks ))

    if command -v shuf >/dev/null 2>&1; then
        shuf "$infile" | split -l "$lines_per_chunk" - "$chunk_dir/chunk_"
    else
        split -l "$lines_per_chunk" "$infile" "$chunk_dir/chunk_"
    fi

    # List of all chunks
    local chunks=()
    local f
    for f in "$chunk_dir"/chunk_*; do
        [[ "$f" == *.awk ]] && continue
        chunks+=("$f")
    done

    local total=${#chunks[@]}
    echo "[*] Parallel: ${nproc_cmd} cores, ${total} chunks (~${lines_per_chunk} lines)" >&2

    # Progress bar
    print_progress() {
        local done=$1
        local total=$2
        local width=28
        local percent=0
        [ "$total" -gt 0 ] && percent=$(( done * 100 / total ))
        local filled=$(( done * width / total ))
        local bar=""
        local i
        for i in $(seq 1 $filled); do bar="${bar}#"; done
        for i in $(seq 1 $((width - filled))); do bar="${bar}-"; done
        printf "\r[*] [%s] %3d%% (%d/%d) " "$bar" "$percent" "$done" "$total" >&2
    }

    # Uses `wait -n` to reap finished children (kill -0 polling can't tell
    # zombies from running processes, which caused the pool to hang). Falls
    # back to `jobs -pr` on bash without `wait -n` (e.g. macOS system bash).
    local next=0
    local finished=0
    local -a pids=()

    local supports_wait_n=false
    if help wait 2>/dev/null | grep -q -- '-n'; then
        supports_wait_n=true
    fi

    _awk_pool_launch_more() {
        while [ "$next" -lt "$total" ] && [ "${#pids[@]}" -lt "$nproc_cmd" ]; do
            local chunk="${chunks[$next]}"
            next=$((next + 1))
            (
                bb awk -f "$awk_script_file" "$chunk" > "${chunk}.out"
                rm -f "$chunk"
            ) &
            pids+=("$!")
        done
    }

    _awk_pool_launch_more

    if [ "$supports_wait_n" = true ]; then
        while [ "${#pids[@]}" -gt 0 ]; do
            wait -n "${pids[@]}" 2>/dev/null
            local still=() pid
            for pid in "${pids[@]}"; do
                if kill -0 "$pid" 2>/dev/null; then
                    still+=("$pid")
                else
                    finished=$((finished + 1))
                    print_progress "$finished" "$total"
                fi
            done
            pids=("${still[@]}")
            _awk_pool_launch_more
        done
    else
        while [ "${#pids[@]}" -gt 0 ]; do
            sleep 0.1
            local running_now still=() pid
            running_now=" $(jobs -pr 2>/dev/null) "
            for pid in "${pids[@]}"; do
                case "$running_now" in
                    *" $pid "*) still+=("$pid") ;;
                    *)
                        wait "$pid" 2>/dev/null
                        finished=$((finished + 1))
                        print_progress "$finished" "$total"
                        ;;
                esac
            done
            pids=("${still[@]}")
            _awk_pool_launch_more
        done
    fi

    printf "\n[*] All chunks finished, merging...\n" >&2

    cat $(find "$chunk_dir" -name 'chunk_*.out' | sort) > "$outfile" 2>/dev/null
    echo "[*] Done." >&2

    rm -rf "$chunk_dir" 2>/dev/null
    return 0
}

# YARA rule FILES that are excluded from compilation by default — whole
# community-ruleset files confirmed (real scans, sample-checked) to hold
# only generic indicators or Windows-only checks with no signal on a Linux
# hosting server, while costing real CPU and RAM: generic regex rules were
# measured ~20x slower than plain-string rules on a 150MB file, and on
# text-heavy data kept hundreds of MB of match lists in memory. This is
# separate from _is_builtin_noisy_rule(), which only hides their OUTPUT —
# the rules still ran. Extend per-install with signatures/yara_exclude
# (one file name or glob per line, # comments) without editing the script.
#   antidebug_antivm.yar  65 Windows-PE anti-debug / anti-VM checks
#   crypto_signatures.yar 124 "contains a standard algorithm constant table"
#   domain.yar            1 rule, fires on any file mentioning a hostname
#   RAT_Cerberus.yar      1 rule, matched libmagic's /etc/apache2/magic
# NOTE: MALW_Miscelanea_Linux.yar is deliberately NOT here — 5 of its 7
# rules are real Linux botnet/backdoor signatures (AES.DDoS, BillGates,
# Elknot, MrBlack, Tsunami); its other 2 (rootkit, exploit) are already
# silenced by _is_builtin_noisy_rule().
YARA_BUILTIN_EXCLUDE="antidebug_antivm.yar crypto_signatures.yar domain.yar RAT_Cerberus.yar"

# Which community-repo rule files belong to which CATEGORY. Only files from
# the two repos `-u` clones (signature-base, Yara-Rules/rules) are
# classified; anything else — your own rules, maldet's — returns "-" and is
# ALWAYS kept. Categories, by what a file is FOR:
#   webshell  *webshell* files, Yara-Rules/webshells/
#   webapp    PHP/JS/CMS-specific (php, wordpress, joomla, skimmers, JS obfuscation)
#   linux     Linux/ELF malware (linux, lnx, elf, mirai)
#   exploit   exploit kits, CVE rules, expl_/exploit_/vul_/vuln_ files
#   malware   named malware families, APT/crime/RAT/ransom sets — mostly Windows
#   generic   gen_/generic_/susp_ heuristics — broad, FP-prone by design
#   docs      malicious documents, e-mail/phishing
#   legacy    crypto constants, anti-debug/VM, packers, utils, deprecated,
#             vendor/tests — measured to be almost pure noise on a server
#   index     *index.yar files that only #include others — always skipped
# Profiles: all     = everything incl. legacy,
#           server  = everything except legacy,
#           hosting = webshell+webapp+linux+exploit (light, opt-in).
_yara_category() {
    local p b
    p=$(printf '%s' "$1" | tr 'A-Z' 'a-z'); b=${p##*/}
    case "$p" in
        */signature-base/yara/*|*/signature-base/vendor/*|*/signature-base/tests/*|*/yara/rules/*) ;;
        *) echo "-"; return ;;
    esac
    case "$b" in index.yar|*_index.yar) echo index; return ;; esac
    case "$p" in
        */signature-base/tests/*|*/signature-base/vendor/*|*/yara/rules/antidebug_antivm/*|*/yara/rules/capabilities/*|\
        */yara/rules/crypto/*|*/yara/rules/packers/*|*/yara/rules/utils/*|*/yara/rules/deprecated/*|*/yara/rules/mobile_malware/*)
            echo legacy; return ;;
        */yara/rules/webshells/*) echo webshell; return ;;
    esac
    case "$b" in
        *webshell*) echo webshell ;;
        *linux*|*lnx*|*elf_*|*_elf*|*mirai*) echo linux ;;
        *php*|*wordpress*|*joomla*|*drupal*|*magento*|*skimmer*|*magecart*|*javascript*|*obfuscatorio*|*_js_*|*_js.yar|js_*) echo webapp ;;
        expl_*|exploit_*|vul_*|vuln_*) echo exploit ;;
        *maldoc*|*phish*) echo docs ;;
        *)
            case "$p" in
                */yara/rules/exploit_kits/*|*/yara/rules/cve_rules/*) echo exploit ;;
                */yara/rules/maldocs/*|*/yara/rules/email/*)          echo docs ;;
                */yara/rules/malware/*)                                echo malware ;;
                *)  case "$b" in
                        apt_*|crime_*|mal_*|hktl_*|spy_*|threat_*|pua_*|cn_*|seaspy_*) echo malware ;;
                        *) echo generic ;;
                    esac ;;
            esac ;;
    esac
}

# $1 = comma-separated list of categories/profiles; exits non-zero with a
# message on anything unknown, so a typo can't silently load nothing.
_yara_validate_spec() {
    local tok
    local -a toks
    IFS=',' read -ra toks <<< "$1"
    [ "${#toks[@]}" -eq 0 ] && { echo "[FAIL] --yara-rules needs a value" >&2; return 1; }
    for tok in "${toks[@]}"; do
        case "$tok" in
            hosting|server|all|webshell|webapp|linux|exploit|malware|generic|docs|legacy) ;;
            *) echo "[FAIL] --yara-rules: unknown category/profile '${tok:-<empty>}' (profiles: hosting|server|all; categories: webshell|webapp|linux|exploit|malware|generic|docs|legacy)" >&2
               return 1 ;;
        esac
    done
}

# Expands YARA_RULES_SPEC (and --yara-all) into YARA_CATS, a space-separated set.
_yara_expand_profile() {
    local tok cats=""
    local -a toks
    IFS=',' read -ra toks <<< "$YARA_RULES_SPEC"
    for tok in "${toks[@]}"; do
        case "$tok" in
            hosting) cats="$cats webshell webapp linux exploit" ;;
            server)  cats="$cats webshell webapp linux exploit malware generic docs" ;;
            all)     cats="$cats webshell webapp linux exploit malware generic docs legacy" ;;
            *)       cats="$cats $tok" ;;
        esac
    done
    [ "$YARA_ALL" = true ] && cats="webshell webapp linux exploit malware generic docs legacy"
    YARA_CATS=$(printf '%s\n' $cats | sort -u | tr '\n' ' ')
}

# ClamAV signatures carry a TargetType (the kind of file they apply to). They
# are split into groups so a pack can leave out what a Linux hosting box does
# not need (mostly Windows PE signatures):
#   any    TargetType 0 (any file)           script 3 (HTML) + 7 (ASCII/scripts)
#   elf    6 (ELF)                           doc    2 (OLE2) 4 (mail) 10 (PDF) 11 12
#   pe     1 (PE)                            other  5 (graphics) 9 (Mach-O) and the rest
_clam_validate_groups() {
    local g
    for g in $(printf '%s' "$1" | tr ',' ' '); do
        case "$g" in any|script|elf|doc|pe|other|pua) ;;
            *) echo "[FAIL] --clam-groups: unknown group '$g' (any|script|elf|doc|pe|other|pua)" >&2; return 1 ;;
        esac
    done
}

# Sets CLAM_GROUPS (space separated) for the current profile.
_clam_groups() {
    [ -z "$YARA_CATS" ] && _yara_expand_profile
    if [ -n "$CLAM_GROUPS_ARG" ]; then
        # the old --clam-groups REPLACES the profile's groups; pack items
        # (+pua, +pe) and --clam-pua still add to that
        local gg; gg="$(printf '%s' "$CLAM_GROUPS_ARG" | tr ',' ' ')"
        [ -n "$PACK_CLAM_ADD" ] && gg="$gg $(printf '%s' "$PACK_CLAM_ADD" | tr ',' ' ')"
        { [ "$CLAM_PUA" = true ] || [ "$YARA_ALL" = true ]; } && gg="$gg pua"
        CLAM_GROUPS=$(printf '%s\n' $gg | sort -u | tr '\n' ' ' | sed 's/ *$//')
        return 0
    fi
    local g="any script" c
    for c in $YARA_CATS; do
        case "$c" in
            linux)  g="$g elf" ;;
            docs)   g="$g doc" ;;
            legacy) g="$g elf doc pe other" ;;
        esac
    done
    [ -n "$PACK_CLAM_ADD" ] && g="$g $(printf '%s' "$PACK_CLAM_ADD" | tr ',' ' ')"
    { [ "$CLAM_PUA" = true ] || [ "$YARA_ALL" = true ]; } && g="$g pua"
    CLAM_GROUPS=$(printf '%s\n' $g | sort -u | tr '\n' ' ' | sed 's/ *$//')
}

# Name of the pack (= cache sub-directory) for the current profile.
# One deprecation hint per old option name (stderr, so reports stay clean).
_deprecated() {
    local v="_DEPR_$(printf '%s' "$1" | tr -c 'a-zA-Z0-9' '_')"
    [ -n "${!v:-}" ] && return 0
    printf -v "$v" 1
    echo "[DEPRECATED] $1 will be removed in a later version, use: $2" >&2
}

# --packs: packs separated by ",", items of one pack joined by "+".
# item = profile (hosting server all full) | YARA category | ClamAV group.
_pack_validate() {
    local pk it
    local -a pks its
    IFS=',' read -ra pks <<< "$1"
    [ "${#pks[@]}" -eq 0 ] && { echo "[FAIL] --packs needs a value" >&2; return 1; }
    for pk in "${pks[@]}"; do
        [ -n "$pk" ] || { echo "[FAIL] --packs: empty pack in '$1'" >&2; return 1; }
        IFS='+' read -ra its <<< "$pk"
        for it in "${its[@]}"; do
            case "$it" in
                hosting|server|all|full|webshell|webapp|linux|exploit|malware|generic|docs|legacy) ;;
                any|script|elf|doc|pe|other|pua) ;;
                *) echo "[FAIL] --packs: unknown item '${it:-<empty>}' in '$pk' (profiles: hosting server all full; categories: webshell webapp linux exploit malware generic docs legacy; ClamAV groups: any script elf doc pe other pua)" >&2
                   return 1 ;;
            esac
        done
    done
}
# Select ONE pack: sets YARA_RULES_SPEC / YARA_ALL / PACK_CLAM_ADD / PACK_ID.
_pack_apply() {
    local pk="$1" it yspec="" clam=""
    local -a its
    IFS='+' read -ra its <<< "$pk"
    for it in "${its[@]}"; do
        case "$it" in
            full) YARA_ALL=true; yspec="$yspec,all" ;;
            any|script|elf|doc|pe|other|pua) clam="$clam,$it" ;;
            *) yspec="$yspec,$it" ;;
        esac
    done
    yspec="${yspec#,}"; clam="${clam#,}"
    YARA_RULES_SPEC="${yspec:-server}"      # only ClamAV groups given: on top of the default
    PACK_CLAM_ADD="$clam"
    PACK_ID=$(printf '%s' "$pk" | tr -c 'a-zA-Z0-9\n' '_')
    YARA_CATS=""
}

_yara_pack_id() {
    local id
    if [ -n "$PACK_ID" ]; then id="$PACK_ID"
    elif [ "$YARA_ALL" = true ]; then id="full"; else id=$(printf '%s' "$YARA_RULES_SPEC" | tr -c 'a-zA-Z0-9\n' '_'); fi
    [ -n "$CLAM_GROUPS_ARG" ] && id="${id}_g_$(printf '%s' "$CLAM_GROUPS_ARG" | tr -c 'a-zA-Z0-9\n' '_')"
    [ "$CLAM_PUA" = true ] && case "_${id}_" in *_pua_*) ;; *) id="${id}_pua" ;; esac
    printf '%s' "$id"
}

# Part of the signature-cache key: switching profile must recompile.
_yara_profile_key() {
    [ -z "$YARA_CATS" ] && _yara_expand_profile
    printf 'yara=%s;all=%s' "$(printf '%s' "$YARA_CATS" | sed 's/ *$//; s/ /,/g')" "$YARA_ALL"
}

# $1 = bare file name, $2 = optional path to the per-install exclude list.
_yara_name_excluded() {
    local base="$1" list="$2" pat
    if [ "$YARA_ALL" != true ]; then
        case " $YARA_BUILTIN_EXCLUDE " in *" $base "*) return 0 ;; esac
    fi
    if [ -n "$list" ] && [ -f "$list" ]; then
        while IFS= read -r pat; do
            case "$pat" in ''|'#'*) continue ;; esac
            case "$base" in $pat) return 0 ;; esac
        done < "$list"
    fi
    return 1
}

# $1 = path of a candidate .yar/.yara file, $2 = optional exclude-list path.
# True if the file should NOT be compiled: it's an index, its category isn't
# selected, its name is excluded, or it is an index-like file that INCLUDEs
# an excluded one (the index `-u` builds uses absolute include paths and
# would pull excluded rules straight back in).
_yara_file_excluded() {
    local f="$1" list="$2" cat inc
    [ -z "$YARA_CATS" ] && _yara_expand_profile
    case "${f##*/}" in index.yar|*_index.yar) return 0 ;; esac
    cat=$(_yara_category "$f")
    if [ "$cat" != "-" ]; then
        case " $YARA_CATS " in *" $cat "*) ;; *) return 0 ;; esac
    fi
    _yara_name_excluded "${f##*/}" "$list" && return 0
    if [ "$cat" = "-" ]; then
        for inc in $(grep -oE 'include[[:space:]]+"[^"]+"' "$f" 2>/dev/null | cut -d'"' -f2); do
            _yara_name_excluded "${inc##*/}" "$list" && return 0
        done
    fi
    return 1
}

# Combined compile of all validated rule files, one NAMESPACE per file.
# $1 = the ClamAV-converted file (one rule per line) or empty.
# That file can hold hundreds of thousands of rules and yarac's time grows
# faster than linearly with rule count (measured: 100k rules 8s, 200k 29s,
# 400k 90s per pass), so it is compiled exactly ONCE — here, as part of the
# combined set — instead of being pre-checked and isolation-checked first
# (three full passes). Only if yarac reports errors in it are exactly those
# lines (yarac names every bad rule's line) dropped and the compile retried,
# so a single malformed rule can't cost the whole ClamAV set.
# Uses $YARAC_BIN, yara_extvars, yara_ns_args, out_dir (caller's scope).
# Names to leave out at compile time, from every *.ign2 / *.ign under the
# signature dir (ClamAV formats: .ign2 = "Name[:md5]", .ign = "db:line:Name").
_build_ignore_names() {
    local f
    bb find "$1" -type f \( -name '*.ign2' -o -name '*.ign' \) -not -path '*/.cache/*' 2>/dev/null |
    while IFS= read -r f; do
        case "$f" in
            *.ign2) bb awk -F: '!/^[ \t]*#/ && NF { print $1 }' "$f" ;;
            *.ign)  bb awk -F: '!/^[ \t]*#/ && NF { print $NF }' "$f" ;;
        esac
    done | tr -d '\r' | bb sed 's/^[ \t]*//; s/[ \t]*$//' | bb grep -v '^$' | bb sort -u
}
# $1 ClamAV file, $2 extension, $3 names -> prints the file to use (a filtered
# copy when some of its signatures are on an ignore list)
_clam_ign_filter() {
    [ -s "$3" ] || { printf '%s\n' "$1"; return 0; }
    local o="$out_dir/ign.$(printf '%s' "$1" | cksum | cut -d' ' -f1).${2}" fs=":" fld=3 n
    case "$2" in ndb|ndu) fld=1 ;; ldb|ldu) fs=";"; fld=1 ;; esac
    bb awk -F"$fs" -v fld="$fld" -v cnt="$o.cnt" 'NR == FNR { ig[$0] = 1; next }
        ($fld in ig) { n++; next } { print }
        END { print n + 0 > cnt }' "$3" "$1" > "$o" 2>/dev/null
    n=$(cat "$o.cnt" 2>/dev/null); rm -f "$o.cnt"
    if [ "${n:-0}" -gt 0 ]; then
        echo "$n" >> "$out_dir/ign_clam.cnt"      # (runs in a $(...) subshell)
        printf '%s\n' "$o"
    else
        rm -f "$o"; printf '%s\n' "$1"
    fi
}
# Rule names the worker always throws away (_is_builtin_noisy_rule): read
# from this very file, so the two lists can never drift apart.
_builtin_noisy_names() {
    bb awk '/^_is_builtin_noisy_rule\(\) *\{/ { on = 1; next }
        on && /case "\$1" in/ { grab = 1; next }
        grab { line = $0; sub(/\) *return 0.*/, "", line); gsub(/[\\ \t]/, "", line)
               n = split(line, a, "|"); for (i = 1; i <= n; i++) if (a[i] != "") print a[i]
               if ($0 ~ /\) *return 0/) exit }' "$0"
}
# $1 = a YARA source file, $2 = file with rule names: those rules are cut out
# of the file (the rule header up to its closing brace). Prints how many.
# The caller re-validates the file and restores the original if the result
# does not compile (e.g. another rule referenced a removed one).
_yara_rule_names() {
    bb grep -oE '(^|[;}[:space:]])((private|global)[[:space:]]+)*rule[[:space:]]+[A-Za-z0-9_]+' \
        | bb sed -E 's/.*rule[[:space:]]+//'
}
_yara_strip_rules() {
    local f="$1" names="$2" n
    bb awk -v names="$names" -v cnt="$f.strip.cnt" '
        BEGIN { while ((getline l < names) > 0) if (l != "") drop[l] = 1; close(names) }
        function braces(s,   i, c, d, inq, inre, last) {
            d = 0; inq = 0; inre = 0; last = ""
            for (i = 1; i <= length(s); i++) {
                c = substr(s, i, 1)
                if (inq)  { if (c == "\\") { i++; continue } if (c == "\"") inq = 0; continue }
                if (inre) { if (c == "\\") { i++; continue } if (c == "/") inre = 0; continue }
                if (c == "/" && substr(s, i + 1, 1) == "/") break
                if (c == "\"") { inq = 1; continue }
                if (c == "/" && last ~ /[=(,]/) { inre = 1; continue }
                if (c == "{") d++
                else if (c == "}") d--
                if (c !~ /[ \t]/) last = c
            }
            return d
        }
        skip {
            depth += braces($0); if (index($0, "{")) opened = 1
            if (opened && depth <= 0) skip = 0
            next
        }
        {
            line = $0
            if (match(line, /^[ \t]*((private|global)[ \t]+)*rule[ \t]+[A-Za-z0-9_]+/)) {
                hdr = substr(line, RSTART, RLENGTH); sub(/.*rule[ \t]+/, "", hdr)
                if (hdr in drop) {
                    n++; depth = braces(line); opened = (index(line, "{") > 0)
                    skip = !(opened && depth <= 0)
                    next
                }
            }
            print
        }
        END { print n + 0 > cnt }' "$f" > "$f.strip" 2>/dev/null
    n=$(cat "$f.strip.cnt" 2>/dev/null); rm -f "$f.strip.cnt"
    # safety: the rule names left must be exactly the old ones minus the
    # dropped ones (block comments with braces, a regex after "matches", two
    # rules on one line ... would otherwise silently take neighbours along)
    if [ "${n:-0}" -gt 0 ]; then
        local want got
        want=$(_yara_rule_names < "$f" | bb grep -vxFf "$names" | bb sort -u)
        got=$(_yara_rule_names < "$f.strip" | bb sort -u)
        [ "$want" = "$got" ] || n=0
    fi
    if [ "${n:-0}" -gt 0 ]; then mv -f "$f.strip" "$f"; else rm -f "$f.strip"; fi
    printf '%s\n' "${n:-0}"
}

_yara_compile_ns() {
    local try cerr rc=1 bad nbad total=0 gf fn ydir="$out_dir/yara"
    local slowpass=false
    for try in 1 2 3 4; do
        cerr=$("$YARAC_BIN" "${yara_extvars[@]}" "${yara_ns_args[@]}" "$out_dir/yara/rules.yarc" 2>&1 >/dev/null)
        rc=$?
        [ -z "$(bb find "$ydir" -maxdepth 1 -name 'generated_ndb_ldb.*.yar' 2>/dev/null | head -1)" ] && break
        if [ "$rc" -eq 0 ]; then
            # compiled; once, also drop ClamAV-converted rules yarac warns
            # "may slow down scanning" about (see the community-file pass)
            [ "$slowpass" = true ] || [ "$YARA_ALL" = true ] && break
            slowpass=true
            bad=$(printf '%s\n' "$cerr" | grep 'may slow down scanning' | grep -E 'generated_ndb_ldb\.[a-z]+\.yar\([0-9]+\)' \
                  | bb sed -E 's/.*(generated_ndb_ldb\.[a-z]+\.yar)\(([0-9]+)\).*/\1 \2/' | bb sort -u)
            [ -z "$bad" ] && break
            nbad=$(printf '%s\n' "$bad" | bb wc -l | tr -d ' ')
            SLOW_DROPPED=$(( ${SLOW_DROPPED:-0} + nbad ))
            for fn in $(printf '%s\n' "$bad" | bb awk '{print $1}' | bb sort -u); do
                gf="$ydir/$fn"; [ -f "$gf" ] || continue
                printf '%s\n' "$bad" | bb awk -v f="$fn" '$1 == f { print $2 }' > "$gf.bad"
                bb awk -v dlog="$ydir/dropped_rules.txt" -v f="$fn" 'NR==FNR { d[$1]=1; next } (FNR in d) { print "clamav-too-general\t" f "\tline " FNR >> dlog; next } { print }' "$gf.bad" "$gf" > "$gf.tmp" && mv -f "$gf.tmp" "$gf"
                rm -f "$gf.bad" "$gf.tmp"
            done
            continue
        fi
        bad=$(printf '%s\n' "$cerr" | grep '^error' | grep -E 'generated_ndb_ldb\.[a-z]+\.yar\([0-9]+\)' \
              | bb sed -E 's/.*(generated_ndb_ldb\.[a-z]+\.yar)\(([0-9]+)\).*/\1 \2/' | bb sort -u)
        [ -z "$bad" ] && break
        nbad=$(printf '%s\n' "$bad" | bb wc -l | tr -d ' ')
        total=$((total + nbad))
        for fn in $(printf '%s\n' "$bad" | bb awk '{print $1}' | bb sort -u); do
            gf="$ydir/$fn"; [ -f "$gf" ] || continue
            printf '%s\n' "$bad" | bb awk -v f="$fn" '$1 == f { print $2 }' > "$gf.bad"
            bb awk 'NR==FNR { d[$1]=1; next } !(FNR in d)' "$gf.bad" "$gf" > "$gf.tmp" && mv -f "$gf.tmp" "$gf"
            rm -f "$gf.bad" "$gf.tmp"
        done
    done
    [ "$total" -gt 0 ] && echo -e "  ${Y}[WARN] ClamAV->YARA: dropped ${total} generated rule(s) that yarac rejected (the rest are kept)${Z}"
    [ "$rc" -eq 0 ]
}

# $1 = one rule file (our copy in out_dir/yara) that failed validation in
# isolation. If yarac's ONLY complaint is rule names defined twice inside the
# file, the later definitions are renamed in place (<name>_dup<line>) so the
# rest of the file is not lost with them. True if the file now compiles.
# Uses $YARAC_BIN and yara_extvars (caller's scope).
_yara_fix_dup_names() {
    local f="$1" err
    err=$("$YARAC_BIN" "${yara_extvars[@]}" "$f" /dev/null 2>&1 >/dev/null | grep '^error')
    [ -n "$err" ] || return 1
    printf '%s\n' "$err" | grep -vq ': duplicated identifier "' && return 1
    printf '%s\n' "$err" | bb sed -nE 's/.*\(([0-9]+)\): duplicated identifier "([A-Za-z0-9_]+)".*/\1 \2/p' > "$f.dups"
    bb awk 'NR == FNR { d[$1] = $2; next }
        (FNR in d) {
            id = d[FNR]; s = $0; o = ""
            while ((i = index(s, id)) > 0) {
                b = (i > 1 ? substr(s, i - 1, 1) : ""); a = substr(s, i + length(id), 1)
                if (b !~ /[A-Za-z0-9_]/ && a !~ /[A-Za-z0-9_]/) {
                    o = o substr(s, 1, i - 1) id "_dup" FNR; s = substr(s, i + length(id)); break
                }
                o = o substr(s, 1, i - 1 + length(id)); s = substr(s, i + length(id))
            }
            print o s; next
        }
        { print }' "$f.dups" "$f" > "$f.tmp" && mv -f "$f.tmp" "$f"
    rm -f "$f.dups" "$f.tmp"
    "$YARAC_BIN" "${yara_extvars[@]}" "$f" /dev/null &>/dev/null || return 1
    echo -e "  ${Y}[WARN] ${f##*/}: $(printf '%s\n' "$err" | grep -c .) duplicated rule name(s) inside the file renamed to <name>_dup<line>${Z}"
}

# $1 = a text index.yar (fallback when no compiled set exists). Every file
# in it compiled alone, but all includes share ONE namespace, so a rule name
# defined by two files (common across the community repos) fails the whole
# index and with it all YARA. Drops each file the compiler names in an error
# (the later one of a clash: earlier = higher priority, see the copy order)
# and retries. Compiler: yarac, else yara itself against /dev/null.
_yara_index_dedup() {
    local idx="$1" err drop try=0
    local -a cc
    if [ -n "$YARAC_BIN" ]; then cc=("$YARAC_BIN" "${yara_extvars[@]}" "$idx" /dev/null)
    elif [ "$YARA_CMD" != "none" ]; then cc=($YARA_CMD "${yara_extvars[@]}" "$idx" /dev/null)
    else return 0; fi
    while [ -s "$idx" ] && [ "$try" -lt 50 ]; do
        try=$((try + 1))
        err=$("${cc[@]}" 2>&1 >/dev/null | grep 'error')
        if [ -z "$err" ]; then
            [ "${DEDUP_RENAMED:-0}" -gt 0 ] && echo -e "  ${Y}[*] YARA text index: renamed ${DEDUP_RENAMED} rule(s) whose name an earlier file already uses (<name>_dup<line>)${Z}"
            return 0
        fi
        # A rule name that an EARLIER file already defines (one namespace in
        # the text index): rename just that rule in the later file
        # (<name>_dup<line>) instead of dropping the whole file - e.g.
        # thor-webshells.yar shares names with gen_webshells.yar.
        local dl df dline dname renamed=0
        while IFS= read -r dl; do
            df=$(printf '%s' "$dl" | bb sed -nE 's/^(error: )?([^ (]+)\(([0-9]+)\): .*duplicated identifier "([A-Za-z0-9_]+)".*/\2/p')
            dline=$(printf '%s' "$dl" | bb sed -nE 's/^(error: )?([^ (]+)\(([0-9]+)\): .*duplicated identifier "([A-Za-z0-9_]+)".*/\3/p')
            dname=$(printf '%s' "$dl" | bb sed -nE 's/^(error: )?([^ (]+)\(([0-9]+)\): .*duplicated identifier "([A-Za-z0-9_]+)".*/\4/p')
            [ -n "$dname" ] || continue
            df="${idx%/*}/${df##*/}"; [ -f "$df" ] || continue
            bb awk -v ln="$dline" -v id="$dname" 'FNR == ln {
                    s = $0; o = ""
                    while ((i = index(s, id)) > 0) {
                        b = (i > 1 ? substr(s, i - 1, 1) : ""); a = substr(s, i + length(id), 1)
                        if (b !~ /[A-Za-z0-9_]/ && a !~ /[A-Za-z0-9_]/) { o = o substr(s, 1, i - 1) id "_dup" ln; s = substr(s, i + length(id)); break }
                        o = o substr(s, 1, i - 1 + length(id)); s = substr(s, i + length(id))
                    }
                    print o s; next }
                { print }' "$df" > "$df.tmp" && mv -f "$df.tmp" "$df" && renamed=$((renamed + 1))
        done < <(printf '%s\n' "$err" | grep 'duplicated identifier')
        if [ "$renamed" -gt 0 ]; then
            DEDUP_RENAMED=$(( ${DEDUP_RENAMED:-0} + renamed )); try=$((try - 1))
            DEDUP_PASSES=$(( ${DEDUP_PASSES:-0} + 1 )); [ "$DEDUP_PASSES" -gt 300 ] && return 1
            continue
        fi
        # "error: F(L): msg" (yarac) or "F(L): error: msg" (yara)
        # also "error: rule "R" in F(L): msg" (undefined identifier etc.)
        drop=$(printf '%s\n' "$err" | bb sed -nE 's/^(error: )?(rule "[^"]*" in )?([^ (]+)\([0-9]+\): .*/\3/p' | bb sed 's|.*/||' | bb sort -u | grep -vx "${idx##*/}")
        [ -n "$drop" ] || return 1
        printf '%s\n' "$drop" | bb awk 'NR == FNR { d["include \"" $0 "\""] = 1; next } !($0 in d)' - "$idx" > "$idx.tmp"
        [ "$(bb wc -l < "$idx.tmp")" -lt "$(bb wc -l < "$idx")" ] || { rm -f "$idx.tmp"; return 1; }
        mv -f "$idx.tmp" "$idx"
        echo -e "  ${Y}[WARN] YARA text index: left out $(printf '%s\n' "$drop" | grep -c .) file(s) that clash with an earlier one (duplicated rule names / errors): $(printf '%s' "$drop" | tr '\n' ' ')${Z}"
    done
    return 1
}

# Quick check after compile that the ruleset the workers will load really
# matches: the built-in string signature "eval(base64_decode" is always part
# of it (generated_strings.yar). A broken/missing ruleset otherwise looks
# exactly like "0 threats, CLEAN". One line on success, a warning otherwise.
yara_self_test() {
    [ "$YARA_CMD" != "none" ] || return 0
    local target="" probe flags=(-d filename= -d filepath= -d extension=)
    if [ -f "$SIG_DIR/yara/rules.yarc" ]; then target="$SIG_DIR/yara/rules.yarc"; flags+=(-C)
    elif [ -f "$SIG_DIR/yara/index.yar" ]; then target="$SIG_DIR/yara/index.yar"
    else
        echo -e "${R}[WARN] YARA self-test: no YARA ruleset was built -> YARA detection is OFF (hash/string signatures still run)${Z}"
        return 0
    fi
    probe=$(mktemp "$WORK_DIR/selftest.XXXXXX" 2>/dev/null) || return 0
    printf '<?php eval(base64_decode("dGVzdA==")); ?>\n' > "$probe"
    if timeout 120 $YARA_CMD "${flags[@]}" "$target" "$probe" 2>/dev/null | grep -q .; then
        echo -e "${G}[OK] YARA self-test passed${Z}"
    else
        echo -e "${R}[WARN] YARA self-test FAILED: the ruleset ($target) did not match the built-in test string -> YARA detection is NOT working${Z}"
    fi
    rm -f "$probe"
}

# Once rules.yarc exists, the text rule sources next to it — copies of every
# community .yar plus the ClamAV-converted generated_ndb_ldb.yar — are
# intermediates: a scan only ever loads rules.yarc and everything unique to
# them lives in it. Left in place they add roughly half again to the ruleset's
# footprint on disk and, copied into the working dir, to /dev/shm with
# --sig-in-ram. They are kept when rules.yarc is missing, since the text
# fallback (index.yar) is built from them.
# $1 = a yara/ directory (the working one or the cache's).
_yara_prune_sources() {
    local d="$1" f n=0
    [ -s "$d/rules.yarc" ] || return 0
    for f in "$d"/*.yar "$d"/*.yara; do
        [ -f "$f" ] && rm -f "$f" && n=$((n + 1))
    done
    [ "$n" -gt 0 ] && echo "  [*] Removed ${n} intermediate YARA source file(s) — rules.yarc is all a scan needs"
    return 0
}

# $1 cached file -> $2 place in this run's SIG_DIR: hard link (same file
# system, no copy) unless SIG_DIR is the explicit RAM copy (--ram-dirs all)
_sig_place() {
    if [ "$SIG_IN_RAM" != true ] && ln -f "$1" "$2" 2>/dev/null; then return 0; fi
    cp -f "$1" "$2" 2>/dev/null
}
# $1 new file -> cache dir $2 as name $3, atomically (rename over the old
# name: scans that hold the old file keep it)
_sig_install() {
    local tmp="$2/.$3.new.$$"
    { ln -f "$1" "$tmp" 2>/dev/null || cp -f "$1" "$tmp" 2>/dev/null; } && mv -f "$tmp" "$2/$3"
}

compile_signatures() {
    local sig_input="$1"
    local out_dir="$2"
    # FIX: the compiled artifacts (sha256.tsv, hex_ere.txt, ...) always land
    # in out_dir, which is a fresh EPHEMERAL work directory created per run
    # (/dev/shm/av_scan_$$). The old skip-check compared a flag file's mtime
    # against sig_input's mtime and, on "fresh enough", returned early
    # WITHOUT ever populating out_dir — meaning a positive cache hit would
    # leave the scan with zero signatures loaded. It also touch'd the flag
    # file INSIDE sig_input, which updates sig_input's own mtime as the same
    # operation, so flag-mtime == dir-mtime and "-nt" (strictly newer) was
    # always false anyway — the cache never activated here, just recompiled
    # every run (safe but wasteful, not silently broken). Either way, a
    # PERSISTENT cache dir (survives between runs, unlike out_dir) is the
    # correct fix: on a cache hit we copy from it into out_dir, so out_dir
    # is always populated one way or another.
    local cache_dir="$sig_input/.cache"
    local compiled_flag="$cache_dir/.compiled"
    local version_flag="$cache_dir/.compiled_version"

    # FIX (real bug reported): the cache freshness check only compared
    # mtimes — it had no idea the SCRIPT ITSELF changed (e.g. a built-in
    # heuristic pattern was fixed/removed). Updating av.sh alone, without
    # also running -u or clearing the cache, silently kept serving the
    # OLD compiled strings.txt/rules forever, so script fixes never took
    # effect for anyone reusing an existing signatures/ directory. Now the
    # cache is also invalidated whenever VERSION doesn't match what it was
    # compiled with.
    # The hash/string artifacts do not depend on the YARA profile, so the base
    # cache is stamped with VERSION only. Everything profile-specific (the
    # compiled YARA set, including the ClamAV-converted rules of the chosen
    # target groups) lives in its own PACK: .cache/packs/<id>/. Several packs
    # can sit side by side in one cache (one archive), and a scan just picks
    # the one that matches --yara-rules instead of recompiling.
    _clam_groups
    local pack_id pack_dir pack_stamp cached_pack_stamp="" cached_version=""
    pack_id=$(_yara_pack_id)
    pack_dir="$cache_dir/packs/$pack_id"
    pack_stamp="cf$CACHE_FORMAT|$(_yara_profile_key)|$CLAM_GROUPS"
    local cache_stamp="cf$CACHE_FORMAT"
    [ -f "$version_flag" ] && cached_version=$(cat "$version_flag" 2>/dev/null)
    [ -f "$pack_dir/.stamp" ] && cached_pack_stamp=$(cat "$pack_dir/.stamp" 2>/dev/null)

    # FIX (real bug reported): comparing against $sig_input's OWN top-level
    # mtime is fragile — creating ANY new direct child inside it (e.g. an
    # auto-created ignore_sigs or incremental-cache file the first time
    # either feature runs) bumps that mtime, making a cache written
    # SECONDS earlier look "stale" on the very next invocation even though
    # no actual signature data changed (this is exactly what caused
    # "-u finishes, cache is fresh, but the next plain scan recompiles
    # everything anyway"). Compare against the newest mtime among the
    # REAL signature source files instead (excluding .cache/ itself and
    # our own auxiliary state files) — semantically correct (what we
    # actually care about IS whether any signature content changed) and
    # immune to unrelated files appearing alongside it.
    local newest_src=""
    if [ -d "$sig_input" ]; then
        newest_src=$(bb find "$sig_input" -mindepth 1 -not -path '*/.cache/*' -not -path '*/kernel_refs*' \
            -not -name "ignore_sigs" -not -name ".incremental_cache.tsv" \
            -not -name ".cache" -not -name ".compiled*" \
            -not -name "generic_obfuscation_rules" -not -name "known_vendor_obfuscation" \
            -newer "$compiled_flag" -print -quit 2>/dev/null)
    fi

    # Every pack was compiled from the same sources: when those changed (-u,
    # newer files, other av.sh version) ALL packs are stale, not only this one.
    local wipe_packs=false
    { [ "$DO_UPDATE" = true ] || [ -n "$newest_src" ] || [ "$cached_version" != "$cache_stamp" ]; } && wipe_packs=true

    if [ "$wipe_packs" = false ] && [ -f "$compiled_flag" ] && [ "$cached_pack_stamp" = "$pack_stamp" ]; then
        echo -e "[*] Signatures already compiled -> reusing cache ($cache_dir, pack '$pack_id')"
        mkdir -p "$out_dir" "$out_dir/yara"
        # Hard links, not copies: the scan reads the cached files themselves
        # (0 bytes copied; with the work dir in /dev/shm the old copy was
        # hundreds of MB of RAM). A later -u writes NEW files and renames
        # them into the cache, so this run keeps its own consistent set.
        # --ram-dirs all puts SIG_DIR in /dev/shm: there a real copy is made.
        local f
        for f in sha256.tsv sha1.tsv md5.tsv hex_ere.txt strings.txt b64_payloads.tsv mdb.tsv str_sig_map.tsv; do
            [ -f "$cache_dir/$f" ] && _sig_place "$cache_dir/$f" "$out_dir/$f"
        done
        if [ -s "$pack_dir/rules.yarc" ]; then
            _sig_place "$pack_dir/rules.yarc" "$out_dir/yara/rules.yarc"
        else
            # no compiled set (no yarac when the pack was built): text fallback
            for f in "$pack_dir"/*.yar "$pack_dir"/*.yara; do
                [ -f "$f" ] && _sig_place "$f" "$out_dir/yara/${f##*/}"
            done
        fi
        return 0
    fi
    if [ "$wipe_packs" = true ] && [ -n "$cached_version" ] && [ "$cached_version" != "$cache_stamp" ]; then
        echo -e "${Y}[*] Signature cache format changed ($cached_version -> $cache_stamp) -> recompiling signatures${Z}"
    elif [ -n "$cached_pack_stamp" ] && [ "$cached_pack_stamp" != "$pack_stamp" ]; then
        echo -e "${Y}[*] YARA pack '$pack_id' changed -> recompiling${Z}"
    else
        echo -e "[*] Building YARA pack '$pack_id' (groups: ${CLAM_GROUPS})"
    fi

    echo -e "[*] Compiling signatures into flat artifacts..."

    # Built-in heuristics
    # FIX (real false positives reported): "chmod 777" as a bare literal
    # string was removed — it matched plain INSTALLATION INSTRUCTIONS in
    # docs/language files (e.g. "chmod 777 the cache/ folder"), not just
    # malicious code. The remaining patterns are specific reverse-shell /
    # backdoor indicators unlikely to appear in legitimate documentation.
    cat << 'EOF' > "$out_dir/strings.txt"
eval(base64_decode
/bin/sh -i
bash -i >
nc -e /bin
python -c import socket
EOF

    touch "$out_dir/sha256.tsv" "$out_dir/md5.tsv" "$out_dir/hex_ere.txt" "$out_dir/b64_payloads.tsv" "$out_dir/mdb.tsv"

    if [ ! -e "$sig_input" ]; then
        echo -e "${Y}[INFO] No signature base found. Using built-in heuristics only.${Z}"
        return
    fi

    local sig_files=()
    if [ -d "$sig_input" ]; then
        # Collect only text signature files, skip .git, yara, custom, and
        # non-actionable ClamAV extensions (PE-section hashes, container
        # sigs, icon hashes, domain/URL sigs, fuzzy hashes, and — important
        # — .fp/.sfp which are KNOWN-CLEAN whitelists, not malware sigs).
        # See "MODULE: ClamAV format support" below for details.
        while IFS= read -r -d '' sf; do
            sig_files+=("$sf")
        done < <(bb find "$sig_input" -type f \
            -not -path '*/.git/*' \
            -not -path '*/yara/*' \
            -not -path '*/custom/*' \
            -not -path '*/.cache/*' \
            -not -path '*/kernel_refs/*' \
            -not -name "*.pack" -not -name "*.idx" -not -name "*.cvd" \
            -not -name "*.yarc" -not -name "*.compiled" \
            -not -name "*.yar" -not -name "*.yara" \
            -not -name "*.msb" -not -name "*.msu" \
            -not -name "*.cdb" -not -name "*.idb" -not -name "*.wdb" \
            -not -name "*.pdb" -not -name "*.gdb" -not -name "*.ftm" \
            -not -name "*.fp" -not -name "*.sfp" \
            -not -name "*.ign" -not -name "*.ign2" \
            -not -name "*.info" -not -name "*.cfg" -not -name "*.crb" \
            -not -name "*.cdiff" \
            -print0 2>/dev/null)
    else
        sig_files+=("$sig_input")
    fi

    # ============================================================================
    # MODULE: ClamAV format support
    #
    # ClamAV signature files are a family of formats, not one — files are
    # routed by extension to a dedicated parser per format.
    #
    # Supported:
    #   .hdb/.hdu, .hsb/.hsu — file hashes (MD5/SHA256)
    #   .ndb/.ndu            — extended hex signatures with gap quantifiers:
    #                           {n}, {n-m}, {-n}, {n-}, ??, *, (aa|bb) —
    #                           compiled into YARA hex-string rules, not
    #                           grep -E patterns (see note below)
    #   .ldb/.ldu             — logical signatures: subsignatures AND their
    #                           boolean AND/OR expression are reconstructed
    #                           as a proper YARA rule (condition), so match
    #                           precision matches real ClamAV, not a
    #                           degraded "any fragment matches" heuristic
    #   .mdb/.mdu             — PE SECTION MD5 hashes ("size:md5:name").
    #                           The worker parses the PE section table
    #                           itself (see _pe_section_table in the
    #                           embedded worker), hashes each section's raw
    #                           bytes, and batch-matches (size,md5) pairs
    #                           against the compiled mdb.tsv — this is the
    #                           single largest chunk of a real ClamAV
    #                           database (often >50% of its total size),
    #                           so this is worth a real PE parser rather
    #                           than excluding it.
    #
    # Intentionally NOT supported (excluded above, not silently dropped):
    #   .msb/.msu              — PE section SHA256 hashes (same idea as
    #                          .mdb but SHA256) — real-world databases have
    #                          this be a tiny fraction of a percent of
    #                          total signatures (low priority; the MD5
    #                          form above already covers the bulk).
    #   .cdb, .idb            — container signatures / icon hashes, need an
    #                          archive/PE-resource parser we don't have.
    #   .wdb, .pdb, .gdb       — domain/URL signatures, not file content.
    #   .ftm                   — fuzzy hashes (need distance calc, not us).
    #   .fp, .sfp              — KNOWN-CLEAN whitelists, not malware sigs.
    #
    # WHY YARA INSTEAD OF grep -E: a real ClamAV .ndb+.ldb set is tens to
    # hundreds of thousands of hex patterns. grep -E -f rebuilds its match
    # automaton from every pattern on EVERY invocation — empirically, just
    # 10,000 patterns took 4.5s to build ONCE, and 200,000 timed out past
    # 30s. That made scanning thousands of files effectively hang. YARA is
    # built for exactly this (multi-pattern matching at malware-database
    # scale): a compiled ruleset of 50,000 rules loads and matches 500
    # files in under a second. NDB/LDB signatures are compiled into a YARA
    # rules file here, then yarac'd into one binary ruleset alongside any
    # externally-fetched YARA rules (see below), and matched through the
    # same batched process_yara_batch() used for hand-written YARA rules.
    # LDB subsignatures that use PCRE (start with "/") are skipped —
    # PCRE-in-YARA is a distinct syntax we don't attempt to convert; a rule
    # referencing a skipped subsignature is dropped entirely rather than
    # emitting a broken condition.
    # ============================================================================

    # --- ignore lists, the ClamAV way: names in *.ign2 / *.ign are not
    # loaded at all. ClamAV ships its own (daily.ign2 inside daily.cvd: its
    # list of withdrawn / false-positive signatures); your own go into e.g.
    # signatures/custom/local.ign2 (one name per line, # comments). They
    # apply to ClamAV signatures and to YARA rules alike.
    _build_ignore_names "$sig_input" > "$out_dir/ignore_names.txt"
    IGN_DROPPED_CLAM=0
    [ -s "$out_dir/ignore_names.txt" ] && echo "  [*] Ignore lists (*.ign2/*.ign): $(bb wc -l < "$out_dir/ignore_names.txt" | tr -d ' ') signature name(s)"

    local hash_files=() ndb_files=() ldb_files=() sect_files=() generic_files=()
    local sf ext
    for sf in "${sig_files[@]}"; do
        # maldet hex.dat = "HEXSIG:{HEX}name" (the source rfxn.ndb is made
        # from). The generic parser below matched none of its lines. Converted
        # into the NDB route only when no rfxn.ndb sits next to it (that one
        # already carries the same signatures; both would double-report).
        if [ "${sf##*/}" = "hex.dat" ]; then
            if [ ! -f "${sf%/*}/rfxn.ndb" ]; then
                bb awk -F: '$2 ~ /^[{]HEX[}]/ && $1 ~ /^[0-9a-fA-F?*{}()|-]+$/ { print $2 ":0:*:" $1 }' "$sf" \
                    > "$out_dir/cat_hexdat.tmp" 2>/dev/null
                [ -s "$out_dir/cat_hexdat.tmp" ] && ndb_files+=("$(_clam_ign_filter "$out_dir/cat_hexdat.tmp" ndb "$out_dir/ignore_names.txt")")
            fi
            continue
        fi
        ext="${sf##*.}"
        case "${ext,,}" in
            hdb|hdu|hsb|hsu|ndb|ndu|ldb|ldu|mdb|mdu) sf=$(_clam_ign_filter "$sf" "${ext,,}" "$out_dir/ignore_names.txt") ;;
        esac
        case "${ext,,}" in
            hdb|hdu|hsb|hsu) hash_files+=("$sf") ;;
            ndb|ndu)         ndb_files+=("$sf") ;;
            ldb|ldu)         ldb_files+=("$sf") ;;
            mdb|mdu)         sect_files+=("$sf") ;;
            *)               generic_files+=("$sf") ;;
        esac
    done

    # Shared NDB/LDB helper: converts a ClamAV hex signature into a YARA
    # hex-string token sequence (space-separated bytes / ?? / [n] / [n-m] /
    # [n-] / [0-m] / ( aa | bb ) alternation groups). Unlike the old ERE
    # path, jump distances stay EXACT — YARA is built to handle this at
    # scale, so there is no need to loosen them to "any distance".
    local ndb2yara_fn='
        function clam_grp(t) {
            if (t == "" || t == "0") return "any"
            if (t == "3" || t == "7") return "script"
            if (t == "6") return "elf"
            if (t == "1") return "pe"
            if (t == "2" || t == "4" || t == "10" || t == "11" || t == "12") return "doc"
            return "other"
        }
        function ndb2yara(raw,    s, out, i, c, n, buf, j, spec, inner, alts, cnt, k, a, pa, m, alt_out) {
            s = tolower(raw)
            gsub(/[ \t]+/, "", s)
            # Negated groups (!(..)) cannot be expressed in a YARA hex string.
            # The old code turned them into POSITIVE alternations (inverted
            # logic) — drop the signature instead of mis-converting it.
            if (index(s, "!") > 0) return ""
            n = length(s)
            out = ""
            buf = ""
            i = 1
            while (i <= n) {
                c = substr(s, i, 1)
                if (buf == "" && substr(s, i, 2) == "??") {
                    out = out "?? "
                    i += 2
                } else if (c == "*") {
                    if (buf != "") return ""
                    out = out "[0-] "
                    i += 1
                } else if (c == "{") {
                    if (buf != "") return ""
                    j = index(substr(s, i), "}")
                    if (j == 0) return ""
                    spec = substr(s, i + 1, j - 2)
                    if (spec ~ /^[0-9]+$/) out = out "[" spec "] "
                    else if (spec ~ /^[0-9]+-[0-9]+$/) out = out "[" spec "] "
                    else if (spec ~ /^[0-9]+-$/) out = out "[" spec "] "
                    else if (spec ~ /^-[0-9]+$/) out = out "[0" spec "] "
                    else return ""
                    i += j
                } else if (c == "(") {
                    if (buf != "") return ""
                    j = index(substr(s, i), ")")
                    if (j == 0) return ""
                    inner = substr(s, i + 1, j - 2)
                    if (inner == "b" || inner == "l") {
                        # (B)/(L) word-boundary markers: no YARA equivalent,
                        # harmless to drop (they used to become "( b )", which
                        # yarac rejects — taking the WHOLE generated file with it)
                        i += j
                    } else {
                        cnt = split(inner, alts, "|")
                        if (cnt < 2) return ""
                        alt_out = ""
                        for (k = 1; k <= cnt; k++) {
                            a = alts[k]
                            if (a !~ /^([0-9a-f][0-9a-f])+$/) return ""
                            pa = ""
                            for (m = 1; m <= length(a); m += 2) pa = pa substr(a, m, 2) " "
                            gsub(/ +$/, "", pa)
                            alt_out = (alt_out == "" ? pa : alt_out " | " pa)
                        }
                        out = out "( " alt_out " ) "
                        i += j
                    }
                } else if (c ~ /[0-9a-f?]/) {
                    # nibble wildcards (a? / ?a) are valid in both ClamAV and
                    # YARA; the old code dropped the "?" and shifted every
                    # following nibble, silently turning the signature into
                    # different bytes that never match the real sample
                    buf = buf c
                    if (length(buf) == 2) { out = out buf " "; buf = "" }
                    i += 1
                } else {
                    return ""
                }
            }
            if (buf != "") return ""
            gsub(/ +$/, "", out)
            # YARA rejects hex strings that start or end with a wildcard/jump,
            # and a leading/trailing one adds nothing to a whole-file search
            while (out ~ /^(\?\? |\[[^]]*\] )/) sub(/^(\?\? |\[[^]]*\] )/, "", out)
            while (out ~ / (\?\?|\[[^]]*\])$/) sub(/ (\?\?|\[[^]]*\])$/, "", out)
            return out
        }
        function yara_rule_name(base,    r) {
            r = base
            gsub(/[^a-zA-Z0-9_]/, "_", r)
            return "s_" r
        }
        # Rule id = the REAL ClamAV signature name (so a finding reads
        # "s_Win_Test_LilEXE_..." instead of a temp-file path) plus kind
        # (n=ndb, l=ldb), the parallel chunk id and the line number, which keep
        # it unique even when ClamAV reuses a family name on many lines.
        function rule_id(name, kind,    r, t) {
            r = name
            gsub(/[^a-zA-Z0-9_]/, "_", r)
            if (length(r) > 100) r = substr(r, 1, 100)
            t = FILENAME
            if (sub(/.*chunk_/, "", t) == 0) t = "x"
            return "s_" r "_" kind t "_" NR
        }
    '

    # GENERIC category fallback still uses the ERE-based approach (low
    # volume — custom/misc files, not the bulk .ndb/.ldb databases — so
    # grep -E -f's per-pattern-count cost isn't a practical problem here).
    local hex2ere_fn='
        function hex2ere(s, a, p, guard, n) {
            s = tolower(s)
            gsub(/[^0-9a-f?*{}|()-]/, "", s)
            if (length(s) < 8) return ""
            gsub(/\?\?/, "..", s)
            gsub(/\*/, ".*", s)
            guard = 0
            while (match(s, /\{(-[0-9]+|[0-9]+-[0-9]+|[0-9]+-|[0-9]+)\}/)) {
                guard++
                if (guard > 1000) { return "" }
                sub(/\{(-[0-9]+|[0-9]+-[0-9]+|[0-9]+-|[0-9]+)\}/, "@GAPSTAR@", s)
            }
            gsub(/@GAPSTAR@/, ".*", s)
            return s
        }
    '

    local tmp_raw_sigs="$out_dir/raw_compiled.tmp"
    : > "$tmp_raw_sigs"
    mkdir -p "$out_dir/yara"
    _clam_groups
    echo "  [*] ClamAV target groups in this pack: ${CLAM_GROUPS}"

    # --- HASH category (.hdb/.hdu/.hsb/.hsu): "hash:size:name" ---
    if [ ${#hash_files[@]} -gt 0 ]; then
        local tmp_hash="$out_dir/cat_hash.tmp" tmp_hash_out="$out_dir/cat_hash.out"
        cat "${hash_files[@]}" > "$tmp_hash"
        run_awk_parallel "$tmp_hash" "$tmp_hash_out" '
            {
                line = $0
                sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
                if (line == "" || line ~ /^#/) next
                n = split(line, a, ":")
                if (n < 1) next
                h = tolower(a[1])
                name = (n >= 3 ? a[3] : "ClamAV.Hash")
                if (h ~ /^[0-9a-f]{64}$/) print "SHA256\t" h "\t" name
                else if (h ~ /^[0-9a-f]{40}$/) print "SHA1\t" h "\t" name
                else if (h ~ /^[0-9a-f]{32}$/) print "MD5\t" h "\t" name
            }
        '
        cat "$tmp_hash_out" >> "$tmp_raw_sigs"
        rm -f "$tmp_hash" "$tmp_hash_out"
    fi

    # --- SECT category (.mdb/.mdu): "PESectionSize:PESectionMD5:Name" ---
    # Unlike HASH, the hash is the MIDDLE field, and it identifies a PE
    # SECTION's raw bytes, not the whole file — matched separately by the
    # worker's PE section parser (see check_pe_sections / process_pe_batch).
    if [ ${#sect_files[@]} -gt 0 ]; then
        local tmp_sect="$out_dir/cat_sect.tmp" tmp_sect_out="$out_dir/cat_sect.out"
        cat "${sect_files[@]}" > "$tmp_sect"
        run_awk_parallel "$tmp_sect" "$tmp_sect_out" '
            {
                line = $0
                sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
                if (line == "" || line ~ /^#/) next
                n = split(line, a, ":")
                if (n < 2) next
                sz = a[1] + 0
                h = tolower(a[2])
                name = (n >= 3 ? a[3] : "ClamAV.Section")
                if (sz > 0 && h ~ /^[0-9a-f]{32}$/) print "SECTMD5\t" sz "\t" h "\t" name
            }
        '
        cat "$tmp_sect_out" >> "$tmp_raw_sigs"
        rm -f "$tmp_sect" "$tmp_sect_out"
    fi

    # --- NDB category (.ndb/.ndu): "Name:Type:Offset:HexSig[:MinFL:MaxFL]" ---
    # The hex signature is always field 4, not "the last field" — optional
    # trailing :MinFL:MaxFL would otherwise shift it out. Compiled into a
    # YARA rule per signature (see MODULE: ClamAV format support above).
    if [ ${#ndb_files[@]} -gt 0 ]; then
        local tmp_ndb="$out_dir/cat_ndb.tmp" tmp_ndb_out="$out_dir/cat_ndb.out"
        cat "${ndb_files[@]}" > "$tmp_ndb"
        run_awk_parallel "$tmp_ndb" "$tmp_ndb_out" "$ndb2yara_fn"'
            {
                line = $0
                sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
                if (line == "" || line ~ /^#/) next
                n = split(line, a, ":")
                if (n < 4) next
                yhex = ndb2yara(a[4])
                if (yhex == "" || length(yhex) < 8) next
                # ClamAV TargetType: 1 = PE, 6 = ELF — the engine only applies
                # such a signature to files of that type; so do we
                cond = "$a"
                if (a[2] == "1") cond = "uint16(0) == 0x5A4D and $a"
                else if (a[2] == "6") cond = "uint32(0) == 0x464c457f and $a"
                rname = rule_id(a[1], "n")
                print "YARARULE_" (a[1] ~ /^PUA\./ ? "pua" : clam_grp(a[2])) "\trule " rname " { strings: $a = { " yhex " } condition: " cond " }"
            }
        '
        cat "$tmp_ndb_out" >> "$tmp_raw_sigs"
        rm -f "$tmp_ndb" "$tmp_ndb_out"
    fi
    rm -f "$out_dir/cat_hexdat.tmp"

    # --- LDB category (.ldb/.ldu): "Name;TargetBlock;Expression;Subsig0;Subsig1;..." ---
    # FIX: this used to split on ":" (and this comment said "Name:Type:..."), but
    # real ClamAV logical signatures are ";"-separated and the target block
    # itself contains colons ("Engine:90-255,Target:1") — checked against
    # ClamAV's own test signatures. Every real .ldb line was therefore
    # mis-split and produced an invalid rule, so no logical signature ever
    # worked (and, before the sanitizer, one bad rule dropped ALL converted
    # ClamAV signatures with it).
    # Unlike the old grep-based approach, the boolean AND/OR expression
    # (field 3) is now reconstructed as a real YARA condition instead of
    # being dropped — e.g. ClamAV "(0&1)|2" becomes YARA "($s0 and $s1) or
    # $s2". A rule is skipped entirely (not partially emitted) if any of
    # its subsignatures is PCRE-based ("/pattern/") or fails to convert,
    # since a condition referencing a missing $sN would be a broken rule.
    if [ ${#ldb_files[@]} -gt 0 ]; then
        local tmp_ldb="$out_dir/cat_ldb.tmp" tmp_ldb_out="$out_dir/cat_ldb.out"
        cat "${ldb_files[@]}" > "$tmp_ldb"
        run_awk_parallel "$tmp_ldb" "$tmp_ldb_out" "$ndb2yara_fn"'
            function translate_condition(expr, maxidx,    out2, j, L, ch, numstr) {
                out2 = ""
                j = 1
                L = length(expr)
                while (j <= L) {
                    ch = substr(expr, j, 1)
                    if (ch ~ /[0-9]/) {
                        numstr = ch
                        j++
                        while (j <= L && substr(expr, j, 1) ~ /[0-9]/) { numstr = numstr substr(expr, j, 1); j++ }
                        # a reference to a subsignature that does not exist
                        # would make yarac reject the rule
                        if (numstr + 0 > maxidx) return ""
                        out2 = out2 "$s" numstr
                    } else if (ch == "&") { out2 = out2 " and "; j++ }
                    else if (ch == "|") { out2 = out2 " or "; j++ }
                    else if (ch == "(" || ch == ")" || ch == " ") { out2 = out2 ch; j++ }
                    # match-count operators (>, <, =, ,) have no faithful
                    # translation here: drop the signature, do not emit junk
                    else return ""
                }
                return out2
            }
            {
                line = $0
                sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
                if (line == "" || line ~ /^#/) next
                n = split(line, a, ";")
                if (n < 4) next
                ok = 1
                strs = ""
                for (i = 4; i <= n; i++) {
                    sh = a[i]
                    # optional "offset:" prefix (n, EP+n, EOF-n, *, ...): we
                    # search the whole file, so the anchor is dropped
                    if (sh ~ /^[^:\/()]*:/) sub(/^[^:\/()]*:/, "", sh)
                    # PCRE subsignatures ("trigger/regex/flags"), "::" match
                    # modifiers and macros have no hex-string equivalent
                    if (sh ~ /\// || sh ~ /::/ || sh ~ /\$/) { ok = 0; break }
                    yhex = ndb2yara(sh)
                    if (yhex == "" || length(yhex) < 8) { ok = 0; break }
                    strs = strs "$s" (i - 4) " = { " yhex " } "
                }
                if (!ok) next
                cond = translate_condition(a[3], n - 4)
                if (cond == "") next
                tt = ""
                if (match(a[2], /Target:[0-9]+/)) tt = substr(a[2], RSTART + 7, RLENGTH - 7)
                if (tt == "1") cond = "uint16(0) == 0x5A4D and (" cond ")"
                else if (tt == "6") cond = "uint32(0) == 0x464c457f and (" cond ")"
                rname = rule_id(a[1], "l")
                print "YARARULE_" (a[1] ~ /^PUA\./ ? "pua" : clam_grp(tt)) "\trule " rname " { strings: " strs "condition: " cond " }"
            }
        '
        cat "$tmp_ldb_out" >> "$tmp_raw_sigs"
        rm -f "$tmp_ldb" "$tmp_ldb_out"
    fi

    # --- GENERIC category: everything else (custom.*, maldet's own bare-hash
    # formats like md5.dat/sha256v2.dat, our sha256:/str:/b64sig: DSL) — same
    # content-guessing approach as before, plus bare-hash support.
    if [ ${#generic_files[@]} -gt 0 ]; then
        local tmp_generic="$out_dir/cat_generic.tmp" tmp_generic_out="$out_dir/cat_generic.out"
        cat "${generic_files[@]}" > "$tmp_generic"
        run_awk_parallel "$tmp_generic" "$tmp_generic_out" "$hex2ere_fn"'
            {
                line = $0
                sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
                if (line == "" || line ~ /^#/) next
                if (line ~ /^sha256:/) {
                    split(line, a, ":")
                    print "SHA256\t" tolower(a[2]) "\tCustom.SHA256"
                    next
                }
                if (line ~ /^str:/) {
                    print "STR\t" substr(line, 5)
                    next
                }
                if (line ~ /^b64sig:/) {
                    print "B64\t" substr(line, 8) "\tCustom.B64"
                    next
                }
                # Bare hash (e.g. maldet md5.dat/sha256v2.dat: one hash per
                # line, optionally with a name after ":")
                # NOTE: intentionally NOT written as
                # /^[0-9a-fA-F]{64}(:.*)?$/ — mawk (Ubuntu/Debians default
                # "awk" via update-alternatives) crashes outright compiling
                # a bounded quantifier immediately followed by a group
                # (confirmed: "REcompile() - panic: values still on
                # machine stack"). length()+substr() sidesteps it, works
                # identically on every awk implementation.
                if (length(line) >= 64) {
                    hexpart = substr(line, 1, 64)
                    resthex = substr(line, 65)
                    if (hexpart ~ /^[0-9a-fA-F]{64}$/ && (resthex == "" || substr(resthex,1,1) == ":")) {
                        split(line, a, ":")
                        # "hash:size:name" (maldet md5v2.dat) lands here too:
                        # take the name, not the size (EICAR showed as name=68)
                        nm = a[2]; if (nm ~ /^[0-9*]+$/ && a[3] != "") nm = a[3]
                        print "SHA256\t" tolower(a[1]) "\t" (nm != "" ? nm : "Maldet.Hash")
                        next
                    }
                }
                if (length(line) >= 32) {
                    hexpart = substr(line, 1, 32)
                    resthex = substr(line, 33)
                    if (hexpart ~ /^[0-9a-fA-F]{32}$/ && (resthex == "" || substr(resthex,1,1) == ":")) {
                        split(line, a, ":")
                        nm = a[2]; if (nm ~ /^[0-9*]+$/ && a[3] != "") nm = a[3]
                        print "MD5\t" tolower(a[1]) "\t" (nm != "" ? nm : "Maldet.Hash")
                        next
                    }
                }
                # ClamAV/Maldet-style "hash:size:name". NOTE: not written
                # as {32,64} — separately confirmed mawk silently fails to
                # match ANY input against a two-number range quantifier
                # like {32,64} (no crash, just never matches, which is
                # arguably worse since it fails silently). "+" always
                # works the same everywhere; length(h)==64/32 below already
                # does the real 32-vs-64 disambiguation after split().
                if (line ~ /^[0-9a-fA-F]+:[0-9*]+:/) {
                    split(line, a, ":")
                    h = tolower(a[1]); name = a[3]
                    if (length(h) == 64) print "SHA256\t" h "\t" name
                    else if (length(h) == 32) print "MD5\t" h "\t" name
                    next
                }
                # Loosest fallback: last field looks like a hex signature
                if (line ~ /:[0-9]+:[0-9*a-fA-F>=-]*:/ || line ~ /:[0-9a-fA-F?*{}|()]{10,}$/) {
                    n = split(line, a, ":")
                    if (length(a[n]) >= 8) {
                        ere = hex2ere(a[n])
                        if (ere != "") print "HEX\t" ere
                    }
                    next
                }
            }
        '
        cat "$tmp_generic_out" >> "$tmp_raw_sigs"
        rm -f "$tmp_generic" "$tmp_generic_out"
    fi

    # Guarantee every expected output file exists (even empty) regardless
    # of whether the awk distribution below actually found any matching
    # lines — FIX (real bug found): awk's ">>" only creates a file the
    # first time that specific print branch actually fires, so a
    # signature set with zero SHA1 entries (common — the real ClamAV .hsb
    # format turned out to carry almost none) left sha1.tsv never created
    # at all. Later reads did `wc -l < sha1.tsv` — a MISSING input file
    # for a shell redirect fails at the shell level, which "2>/dev/null"
    # on that same command does NOT suppress (confirmed in practice: a
    # stray "No such file or directory" on stderr despite the redirect).
    touch "$out_dir/sha256.tsv" "$out_dir/sha1.tsv" "$out_dir/md5.tsv" \
          "$out_dir/strings.txt" "$out_dir/b64_payloads.tsv" "$out_dir/hex_ere.txt" \
          "$out_dir/mdb.tsv" 2>/dev/null

    if [ -s "$tmp_raw_sigs" ]; then
        # Distribute the merged processed stream into the .tsv/.txt/.yar outputs
        bb awk -F'\t' -v out="$out_dir" -v groups=" $CLAM_GROUPS " -v ign="$out_dir/ignore_names.txt" '
            BEGIN { while ((getline l < ign) > 0) if (l != "") ig[l] = 1; close(ign) }
            # names on an ignore list, from ANY source (custom/*.md5,
            # maldet md5v2.dat, ...): ClamAV files were already filtered
            ($1 == "SHA256" || $1 == "SHA1" || $1 == "MD5" || $1 == "SECTMD5") && ($3 in ig) { igd++; next }
            $1 == "SHA256"   { print $2 "\t" $3 >> (out "/sha256.tsv") }
            $1 == "SHA1"     { print $2 "\t" $3 >> (out "/sha1.tsv") }
            $1 == "MD5"      { print $2 "\t" $3 >> (out "/md5.tsv") }
            $1 == "STR"      { print $2 >> (out "/strings.txt") }
            $1 == "B64"      { print $2 "\t" $3 >> (out "/b64_payloads.tsv") }
            $1 == "HEX"      { print $2 >> (out "/hex_ere.txt") }
            $1 ~ /^YARARULE_/ {
                g = substr($1, 10)
                if (index(groups, " " g " ")) { print $2 >> (out "/yara/generated_ndb_ldb." g ".yar"); gn[g]++ } else gs[g]++
            }
            $1 == "SECTMD5"  { print $2 "\t" $3 "\t" $4 >> (out "/mdb.tsv") }
            END {
                if (igd) printf "  [*] Ignore lists: %d more hash signature(s) left out (custom / maldet files)\n", igd
                for (g in gn) printf "  [*] ClamAV->YARA group %-6s %8d rule(s) kept\n", g, gn[g]
                for (g in gs) printf "  [*] ClamAV->YARA group %-6s %8d rule(s) left out of this pack\n", g, gs[g]
            }
        ' "$tmp_raw_sigs"
    fi
    rm -f "$tmp_raw_sigs" "$out_dir"/ign.*.* 2>/dev/null

    # External hash lists
    bb find "$sig_input" -not -path '*/.git/*' \( -name "*.sha256" -o -name "malwarebazaar.sha256" \) 2>/dev/null | while read -r f; do
        [ -s "$f" ] && bb awk '{print $1 "\t" ($2 ? $2 : "External.Hash")}' "$f" >> "$out_dir/sha256.tsv"
    done

    # Base64 -> SHA256 precompute
    if [ -s "$out_dir/b64_payloads.tsv" ] && [ "$SHA256_CMD" != "none" ]; then
        local tmp_b64="$out_dir/b64_compiled.tsv"
        while IFS=$'\t' read -r payload name; do
            [ -z "$payload" ] && continue
            local dh
            dh=$(printf '%s' "$payload" | ( [ "$OS" = "macos" ] && base64 -D || base64 -d ) 2>/dev/null | $SHA256_CMD 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)
            [ -n "$dh" ] && echo -e "${dh}\t${name:-Custom.B64}" >> "$tmp_b64"
        done < "$out_dir/b64_payloads.tsv"
        mv -f "$tmp_b64" "$out_dir/b64_payloads.tsv" 2>/dev/null || touch "$out_dir/b64_payloads.tsv"
    fi

    # Custom
    local cdir=""
    if [ -d "$sig_input/custom" ]; then cdir="$sig_input/custom"
    elif [ -d "$SIG_DIR/custom" ]; then cdir="$SIG_DIR/custom"; fi
    if [ -n "$cdir" ] && [ -d "$cdir" ]; then
        bb find "$cdir" -name "*.md5" -exec cat {} + 2>/dev/null >> "$out_dir/md5.tsv" || true
        bb find "$cdir" -name "*.sha256" -exec cat {} + 2>/dev/null >> "$out_dir/sha256.tsv" || true
        bb find "$cdir" -name "*.strings" -exec cat {} + 2>/dev/null >> "$out_dir/strings.txt" || true
        echo "  ✓ Custom signatures loaded"
    fi
    # Ignore lists (*.ign2/*.ign) also cover custom/*.md5|*.sha256 entries
    # ("hash<TAB>name"): drop every hash line whose name is listed.
    if [ -s "$out_dir/ignore_names.txt" ]; then
        local _hf _nd
        for _hf in md5.tsv sha256.tsv sha1.tsv; do
            [ -s "$out_dir/$_hf" ] || continue
            bb awk -F'\t' -v ign="$out_dir/ignore_names.txt" '
                BEGIN { while ((getline l < ign) > 0) ig[l]=1 }
                !($2 in ig)' "$out_dir/$_hf" > "$out_dir/$_hf.ign" 2>/dev/null
            _nd=$(( $(bb wc -l < "$out_dir/$_hf" | tr -d ' ') - $(bb wc -l < "$out_dir/$_hf.ign" | tr -d ' ') ))
            mv -f "$out_dir/$_hf.ign" "$out_dir/$_hf"
            [ "$_nd" -gt 0 ] && echo "  [*] Ignore lists: removed $_nd ${_hf%.tsv} hash signature(s)"
        done
    fi

    # Strip known-degenerate hashes: the empty-input MD5/SHA256 constant.
    # A 0-byte file always hashes to the SAME value regardless of content —
    # if any upstream/custom signature source ever contains that hash
    # (whether by genuine upstream data or by our own parsing picking up
    # a blank/malformed field somewhere), every empty file anywhere would
    # match it. This filters both hashes out at the source, as defense in
    # depth alongside the explicit 0-byte skip in the scan paths.
    local empty_md5="d41d8cd98f00b204e9800998ecf8427e"
    local empty_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    local empty_sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    # NOTE: grep -v exits 1 (not an error) when it filters out EVERY line —
    # a plain "&&" chain would then skip the mv and leave the bad entry in
    # place, so the mv runs unconditionally after grep regardless of its
    # exit code.
    if [ -s "$out_dir/md5.tsv" ]; then
        bb grep -v "^${empty_md5}" "$out_dir/md5.tsv" > "$out_dir/md5.tsv.tmp" 2>/dev/null
        mv -f "$out_dir/md5.tsv.tmp" "$out_dir/md5.tsv" 2>/dev/null
    fi
    if [ -s "$out_dir/sha256.tsv" ]; then
        bb grep -v "^${empty_sha256}" "$out_dir/sha256.tsv" > "$out_dir/sha256.tsv.tmp" 2>/dev/null
        mv -f "$out_dir/sha256.tsv.tmp" "$out_dir/sha256.tsv" 2>/dev/null
    fi
    if [ -s "$out_dir/sha1.tsv" ]; then
        bb grep -v "^${empty_sha1}" "$out_dir/sha1.tsv" > "$out_dir/sha1.tsv.tmp" 2>/dev/null
        mv -f "$out_dir/sha1.tsv.tmp" "$out_dir/sha1.tsv" 2>/dev/null
    fi

    # Strip known-overbroad string patterns regardless of source (our own
    # built-in list, custom.strings, OR an external database like maldet's
    # own signature pack — confirmed in practice: "chmod 777" persisted
    # after removing it from our own built-in list, meaning some other
    # source was reintroducing it). "chmod 777" as bare text matches
    # ordinary installation INSTRUCTIONS in docs/language files, not just
    # malicious code — too weak a signal on its own from any source.
    if [ -s "$out_dir/strings.txt" ]; then
        bb grep -v -i "^chmod 777" "$out_dir/strings.txt" > "$out_dir/strings.txt.tmp" 2>/dev/null
        mv -f "$out_dir/strings.txt.tmp" "$out_dir/strings.txt" 2>/dev/null
    fi

    # Dedup strings.txt BEFORE generating YARA rules from it (not after —
    # that was a real bug: the general dedup pass used to run AFTER rule
    # generation, so a pattern appearing twice — e.g. once from the
    # built-in list and once from custom.strings — became TWO separate
    # YARA rules, both matching the same file and double-counting every
    # such hit in the threat total, even though the displayed list looked
    # fine since it dedupes the STRING content, hiding the duplicate).
    [ -s "$out_dir/strings.txt" ] && bb sort -u "$out_dir/strings.txt" -o "$out_dir/strings.txt" 2>/dev/null

    # Move string-based text signatures into the SAME YARA pass used for
    # NDB/LDB/external rules ("максимально задіяти YARA" — requested after
    # confirming the per-file grep -a string search was still a full extra
    # read of every file on top of the YARA pass, base64 scan, and hash
    # computation). One rule per pattern (mirrors the NDB/LDB approach),
    # with a companion name->pattern map so the worker can still report
    # "SIG_STRING_MATCH pattern=..." instead of a raw YARA rule name.
    #
    # NOTE: this is deliberately NOT done for hash signatures (sha256.tsv/
    # md5.tsv) — measured empirically: YARA's hash module evaluates one
    # condition per rule with no literal-atom prefiltering to skip most of
    # them, so a realistic 100k-entry hash database took ~58ms/file to
    # check via YARA vs the current batched "grep -F against a flat file"
    # approach (a few ms/file amortized across a whole batch) — YARA would
    # make hash lookups SLOWER, not faster, at real ClamAV/Maldet database
    # scale (hundreds of thousands of entries). String signatures don't
    # have this problem since they're normal byte/text patterns that DO
    # benefit from YARA's usual prefiltering.
    mkdir -p "$out_dir/yara"
    : > "$out_dir/yara/generated_strings.yar"
    : > "$out_dir/str_sig_map.tsv"
    if [ -s "$out_dir/strings.txt" ]; then
        bb awk -v yarout="$out_dir/yara/generated_strings.yar" -v mapout="$out_dir/str_sig_map.tsv" '
            function esc(s) { gsub(/\\/, "\\\\", s); gsub(/"/, "\\\"", s); return s }
            # Rule name = hash of the pattern, not its line number / the temp
            # file name: packs compiled at different times keep resolving
            # through the one shared str_sig_map.tsv (was: "strsig_3__tmp_av_scan_..."
            # leaking out as a raw YARA_MATCH after another pack was built).
            BEGIN { for (i = 1; i < 256; i++) ORD[sprintf("%c", i)] = i }
            function hx(s,   i, a, b, c) {
                a = 5381; b = 0
                for (i = 1; i <= length(s); i++) {
                    c = ORD[substr(s, i, 1)] + 0
                    a = (a * 33 + c) % 2147483647
                    b = (b * 65599 + c) % 2147483629
                }
                return sprintf("%08x%08x", a, b)
            }
            {
                line = $0
                if (line == "" || line ~ /^#/) next
                rname = "strsig_" hx(tolower(line))
                if (rname in seen) next
                seen[rname] = 1
                print "rule " rname " { strings: $a = \"" esc(line) "\" nocase ascii condition: $a }" >> yarout
                print rname "\t" line >> mapout
            }
        ' "$out_dir/strings.txt"
    fi

    # REVERTED (real regression reported): base64-payload screening used
    # to be folded into this same YARA pass via a reserved
    # "__av_av_b64_screen__" regex rule, to save one full-file read per
    # scanned file (an IOPS optimization). In practice, on real DLE
    # installations, this made specific files take 74-113+ SECONDS EACH —
    # confirmed to be exactly DLE's own license-obfuscated engine files,
    # which are (by design) one enormous single-line base64-ish blob.
    # YARA's regex engine scales badly against that shape of content with
    # an unbounded {200,} quantifier, in a way a plain `grep -oE` call
    # (the original, pre-YARA implementation) did not — confirmed by the
    # person: the exact same files processed correctly and faster before
    # this optimization. Reliability beats a marginal IOPS win here, so
    # base64 screening is back to being its own grep pass (see
    # check_file_heuristics -> _check_b64_payload in the worker) — no
    # generated_b64_screen.yar, no "__av_b64_screen__" rule anymore.
    rm -f "$out_dir/yara/generated_b64_screen.yar" 2>/dev/null

    # YARA: gather external rule sources (fetched during -u) plus our own
    # generated NDB/LDB/string rules, and compile them ALL into one
    # ruleset here — so every worker just loads a single pre-compiled
    # rules.yarc instead of each re-parsing rule text from scratch (see
    # MODULE: ClamAV format support above for why this matters at scale).
    #
    # FIX (real gap found on audit): this used to only look in
    # "$sig_input/yara/" — but Maldet's own sigpack ships a real YARA file
    # (rfxn.yara) inside "$sig_input/maldet/", which was never picked up
    # here. Worse, since its extension didn't match hdb/ndb/ldb/mdb, it
    # fell into the GENERIC line-based hash/pattern parser instead, which
    # doesn't understand YARA syntax — so it was silently doing nothing
    # useful with real rule definitions. Now searches ALL of $sig_input
    # for *.yar/*.yara files (any subdirectory, not just yara/), and those
    # files are excluded from sig_files/generic_files below so they're
    # compiled as actual YARA rules, not misrouted as hash/pattern text.
    if [ -d "$sig_input" ]; then
        # Selection is DETERMINISTIC (sorted) and uncapped up to a generous
        # safety limit. It used to be `find | head -500`: only the first 500 of
        # ~1300 rule files, in whatever order the filesystem happened to
        # enumerate directories — so which rules were compiled in depended on
        # the machine (measured: the same tree gave 500 files from one repo
        # and 0 from the other under different orders). Copies get a numeric
        # prefix so same-named files from different repos can't overwrite
        # each other in the flat directory.
        _yara_expand_profile
        local yf yx=0 ycopied=0 ylimit=3000
        while IFS= read -r yf; do
            if _yara_file_excluded "$yf" "$sig_input/yara_exclude"; then
                yx=$((yx + 1)); continue
            fi
            if [ "$ycopied" -ge "$ylimit" ]; then
                echo -e "${Y}[WARN] more than ${ylimit} YARA rule files selected — the rest are NOT loaded; narrow --packs or add to yara_exclude${Z}"
                break
            fi
            cp "$yf" "$out_dir/yara/$(printf '%04d' "$ycopied")_${yf##*/}" 2>/dev/null && ycopied=$((ycopied + 1))
        done < <(bb find "$sig_input" -not -path '*/.git/*' -not -path '*/.cache/*' \( -name "*.yar" -o -name "*.yara" \) 2>/dev/null | \
            bb awk -v pre="$sig_input" '
                # Copy order = priority under the ylimit cap and in a text
                # index clash (earlier wins): 1) own/maldet files (anything
                # outside the two community repos) and webshell/PHP/CMS ones,
                # 2) Linux, 3) the rest, 4) legacy dirs and the Windows-heavy
                # Yara-Rules malware/maldocs/email dirs. Sorted within a tier.
                { p = tolower(substr($0, length(pre) + 1)); t = 3
                  if (p !~ /\/(signature-base|yara\/rules)\//) t = 1
                  else if (p ~ /\/(deprecated|utils|crypto|capabilities|antidebug_antivm|packers|mobile_malware|tests|vendor)\//) t = 4
                  else if (p ~ /(webshell|wshell|php|magento|wordpress|joomla|drupal|skimmer|magecart|rfxn)/) t = 1
                  else if (p ~ /(linux|lnx|elf|mirai|unix)/) t = 2
                  else if (p ~ /\/yara\/rules\/(malware|maldocs|email)\//) t = 4
                  print t "\t" $0 }' | bb sort | cut -f2-)
        echo "  [*] YARA rules: profile '$([ "$YARA_ALL" = true ] && echo 'full' || echo "$YARA_RULES_SPEC")' -> $ycopied file(s) loaded, $yx left out [$(printf '%s' "$YARA_CATS" | sed 's/ *$//; s/ /,/g')]"
    fi

    # "filename"/"filepath"/"extension" are external variables in modern
    # YARA (not automatic built-ins) — plenty of real-world rules reference
    # them, and compilation fails outright if they aren't declared. Empty
    # defaults are fine: this scanner batches many files per yara call, so
    # there's no single "current filename" to give them anyway; rules that
    # depend on a real value just won't match on that condition.
    #
    # IMPORTANT: these -d declarations must be given IDENTICALLY at both
    # yarac (here) and yara scan time (process_yara_batch et al) — tested
    # empirically: compiling WITH -d but scanning WITHOUT (or vice versa)
    # makes yara -C fail with "error: 29" on EVERY file, silently
    # (--scan-list mode doesn't even print the error to a visible stream
    # by default), which would otherwise look exactly like "just no
    # matches" instead of "totally broken".
    local yara_extvars=(-d filename= -d filepath= -d extension=)

    local yar_sources
    yar_sources=$(bb find "$out_dir/yara" -maxdepth 1 \( -name "*.yar" -o -name "*.yara" \) 2>/dev/null | bb sort)
    if [ -n "$yar_sources" ] && [ -n "$YARAC_BIN" ]; then
        # Validate each file in ISOLATION first and only include the ones
        # that compile cleanly — one incompatible rule (unsupported module,
        # syntax our yarac build doesn't handle) would otherwise fail the
        # ENTIRE combined ruleset and silently disable all YARA detection,
        # including our own generated NDB/LDB rules.
        local yara_index="$out_dir/yara/_index.yar"
        local skipped=0 included=0
        local -a yara_ns_args=()
        : > "$yara_index"
        local gen_file=""
        # names cut out of the sources before validation: the ignore lists
        # above, plus the rules the worker would always throw away anyway
        # (pack "full" keeps the latter and the "too general" ones)
        local strip_names="$out_dir/yara_strip_names.txt" ydropped="$out_dir/yara/dropped_rules.txt"
        { cat "$out_dir/ignore_names.txt" 2>/dev/null; [ "$YARA_ALL" = true ] || _builtin_noisy_names; } | bb sort -u > "$strip_names"
        SLOW_DROPPED=0
        local n_ign=0 n_slow=0 vout k sn
        : > "$ydropped"
        while IFS= read -r yf; do
            [ -z "$yf" ] && continue
            case "${yf##*/}" in generated_ndb_ldb.*.yar) ;;
            *)
                if [ -s "$strip_names" ] && bb grep -qwFf "$strip_names" "$yf" 2>/dev/null; then
                    cp -f "$yf" "$yf.orig"
                    k=$(_yara_strip_rules "$yf" "$strip_names")
                    if [ "$k" -gt 0 ] && "$YARAC_BIN" "${yara_extvars[@]}" "$yf" /dev/null &>/dev/null; then
                        n_ign=$(( n_ign + k )); printf 'ignored\t%s\t%s rule(s)\n' "${yf##*/}" "$k" >> "$ydropped"
                    else
                        mv -f "$yf.orig" "$yf"
                    fi
                    rm -f "$yf.orig"
                fi
                if [ "$YARA_ALL" != true ]; then
                    vout=$("$YARAC_BIN" "${yara_extvars[@]}" "$yf" /dev/null 2>&1 >/dev/null)
                    sn=$(printf '%s\n' "$vout" | bb sed -nE 's/.*warning: rule "([A-Za-z0-9_]+)".*may slow down scanning.*/\1/p' | bb sort -u)
                    if [ -n "$sn" ]; then
                        printf '%s\n' "$sn" > "$yf.slow"; cp -f "$yf" "$yf.orig"
                        k=$(_yara_strip_rules "$yf" "$yf.slow")
                        if [ "$k" -gt 0 ] && "$YARAC_BIN" "${yara_extvars[@]}" "$yf" /dev/null &>/dev/null; then
                            n_slow=$(( n_slow + k ))
                            printf '%s\n' "$sn" | bb awk -v f="${yf##*/}" '{ print "too-general\t" f "\t" $0 }' >> "$ydropped"
                        else
                            mv -f "$yf.orig" "$yf"
                        fi
                        rm -f "$yf.orig" "$yf.slow"
                    fi
                fi ;;
            esac
            case "${yf##*/}" in generated_ndb_ldb.*.yar)
                # our own converter's output (one file per ClamAV target
                # group): not validated separately (see _yara_compile_ns)
                gen_file="$yf"
                echo "include \"${yf##*/}\"" >> "$yara_index"
                yara_ns_args+=("n${included}:$yf")
                included=$((included + 1))
                continue ;;
            esac
            if "$YARAC_BIN" "${yara_extvars[@]}" "$yf" /dev/null &>/dev/null || _yara_fix_dup_names "$yf"; then
                # RELATIVE include: index.yar is cached in the pack and used
                # from another (per-run) dir later; YARA resolves an include
                # against the including file's own dir
                echo "include \"${yf##*/}\"" >> "$yara_index"
                # one NAMESPACE per file: the same rule name legitimately
                # exists in both community repos (e.g. the Laudanum webshell
                # rules), and a single combined namespace makes yarac refuse
                # the whole set with "duplicated identifier"
                yara_ns_args+=("n${included}:$yf")
                included=$((included + 1))
            else
                skipped=$((skipped + 1))
            fi
        done <<< "$yar_sources"
        [ "$skipped" -gt 0 ] && echo -e "${Y}[WARN] Skipped ${skipped} incompatible YARA rule file(s) (unsupported module/syntax) — ${included} included${Z}"
        IGN_DROPPED_CLAM=$(bb awk '{ s += $1 } END { print s + 0 }' "$out_dir/ign_clam.cnt" 2>/dev/null); IGN_DROPPED_CLAM=${IGN_DROPPED_CLAM:-0}
        [ $(( n_ign + n_slow + IGN_DROPPED_CLAM )) -gt 0 ] && echo "  [*] Left out at compile time: ${IGN_DROPPED_CLAM} ClamAV signature(s) and ${n_ign} YARA rule(s) on ignore lists / always suppressed, ${n_slow} YARA rule(s) yarac calls too general (list: <pack>/dropped_rules.txt)"

        local t_c0 ngen=0
        t_c0=$(date +%s)
        [ -n "$gen_file" ] && ngen=$(cat "$out_dir"/yara/generated_ndb_ldb.*.yar 2>/dev/null | grep -c '^rule ')
        echo "  [*] Compiling the YARA ruleset: ${included} file(s)$([ -n "$gen_file" ] && echo ", incl. ${ngen} ClamAV-converted rule(s) — the ClamAV part alone can take several minutes (it is not stuck)")..."
        if [ "${#yara_ns_args[@]}" -gt 0 ] && _yara_compile_ns; then
            echo "  [*] YARA ruleset compiled in $(( $(date +%s) - t_c0 ))s"
            [ "${SLOW_DROPPED:-0}" -gt 0 ] && echo "  [*] ClamAV->YARA: ${SLOW_DROPPED} converted rule(s) left out as too general (yarac: may slow down scanning)"
        elif [ -s "$yara_index" ] && "$YARAC_BIN" "${yara_extvars[@]}" "$yara_index" "$out_dir/yara/rules.yarc" 2>/dev/null; then
            :
        else
            echo -e "${Y}[WARN] yarac failed on the combined ruleset -> falling back to source (slower)${Z}"
            rm -f "$out_dir/yara/rules.yarc" 2>/dev/null
            mv -f "$yara_index" "$out_dir/yara/index.yar" 2>/dev/null
            _yara_index_dedup "$out_dir/yara/index.yar"
        fi
        rm -f "$yara_index"
    elif [ -n "$yar_sources" ]; then
        # No yarac available: fall back to an include-index the worker can
        # load as source (works, just recompiles from text on every call).
        local yara_index="$out_dir/yara/index.yar"
        : > "$yara_index"
        while IFS= read -r yf; do
            [ -n "$yf" ] && echo "include \"${yf##*/}\"" >> "$yara_index"
        done <<< "$yar_sources"
        _yara_index_dedup "$yara_index"
    fi

    # Dedup (also collapses now-common ".*"-only variants of what used to be
    # distinct bounded-quantifier patterns)
    for f in sha256.tsv sha1.tsv md5.tsv strings.txt b64_payloads.tsv hex_ere.txt mdb.tsv; do
        [ -s "$out_dir/$f" ] && bb sort -u "$out_dir/$f" -o "$out_dir/$f" 2>/dev/null || true
    done

    # Cap hex_ere.txt: grep -E -f builds its match automaton from ALL
    # patterns on every call. A full real ClamAV .ndb+.ldb set is hundreds
    # of thousands of patterns — tested empirically, that alone can take
    # 30+ SECONDS to build per call, regardless of batching. Keep it small
    # enough that even a fresh automaton build stays sub-second.
    if [ -s "$out_dir/hex_ere.txt" ]; then
        local hex_count
        hex_count=$(bb wc -l < "$out_dir/hex_ere.txt" 2>/dev/null | tr -d ' ')
        if [ "${hex_count:-0}" -gt "$MAX_HEX_PATTERNS" ]; then
            echo -e "${Y}[WARN] hex_ere.txt has ${hex_count} patterns, capping to ${MAX_HEX_PATTERNS} (ORPHUS_MAX_HEX_PATTERNS to change) — coverage reduced, but grep -E -f cannot build a usable automaton from the full set${Z}"
            head -n "$MAX_HEX_PATTERNS" "$out_dir/hex_ere.txt" > "$out_dir/hex_ere.txt.tmp" && mv -f "$out_dir/hex_ere.txt.tmp" "$out_dir/hex_ere.txt"
        fi
    fi

    # Save compiled artifacts to the persistent cache so the next run can
    # reuse them without recompiling (see comment at the top of this function)
    #
    # FIX (real bug found): cp -rf only overwrites files that exist in the
    # FRESH out_dir/yara — it doesn't delete stray old files already
    # sitting in cache_dir/yara that aren't part of this compile (e.g. a
    # generated_b64_screen.yar left over from a previous script version
    # that no longer generates one at all). rm -rf the cache's yara/ dir
    # first so a recompile can't leave stale artifacts behind.
    mkdir -p "$cache_dir"
    rm -rf "$cache_dir/yara" 2>/dev/null                       # layout of versions before packs
    # Running scans hold HARD LINKS to the files they use (see the cache-hit
    # branch), so removing / replacing names here never pulls data from
    # under them. New files are put in place by rename (_sig_install).
    if [ "$wipe_packs" = true ]; then
        local opk
        for opk in "$cache_dir/packs"/*; do
            [ -d "$opk" ] && [ "$opk" != "$pack_dir" ] && rm -rf "$opk" 2>/dev/null
        done
    fi
    local pack_new="$pack_dir.new.$$"
    rm -rf "$pack_new" 2>/dev/null
    mkdir -p "$pack_new"
    _yara_prune_sources "$out_dir/yara"
    # packs that survive this compile may still carry rules for patterns that
    # are gone now: keep their map lines too (names are content hashes)
    if [ "$wipe_packs" != true ] && [ -s "$cache_dir/str_sig_map.tsv" ]; then
        cat "$out_dir/str_sig_map.tsv" "$cache_dir/str_sig_map.tsv" 2>/dev/null \
            | bb awk -F'\t' '!seen[$1]++' > "$out_dir/str_sig_map.tsv.m" 2>/dev/null \
            && mv -f "$out_dir/str_sig_map.tsv.m" "$out_dir/str_sig_map.tsv"
    fi
    local f
    for f in sha256.tsv sha1.tsv md5.tsv hex_ere.txt strings.txt b64_payloads.tsv mdb.tsv str_sig_map.tsv; do
        [ -f "$out_dir/$f" ] && _sig_install "$out_dir/$f" "$cache_dir" "$f"
    done
    if [ -d "$out_dir/yara" ]; then
        for f in "$out_dir/yara"/* "$out_dir/yara"/.[!.]*; do
            [ -f "$f" ] && { ln -f "$f" "$pack_new/${f##*/}" 2>/dev/null || cp -f "$f" "$pack_new/${f##*/}"; }
        done
    fi
    printf '%s' "$pack_stamp" > "$pack_new/.stamp" 2>/dev/null || true
    # swap the pack directory in one rename
    rm -rf "$pack_dir.old.$$" 2>/dev/null
    [ -d "$pack_dir" ] && mv -f "$pack_dir" "$pack_dir.old.$$" 2>/dev/null
    [ -e "$pack_dir" ] && rm -rf "$pack_dir" 2>/dev/null    # a concurrent compile won the race
    mv -f "$pack_new" "$pack_dir" 2>/dev/null
    rm -rf "$pack_dir.old.$$" 2>/dev/null
    touch "$compiled_flag" 2>/dev/null || true
    printf '%s' "$cache_stamp" > "$version_flag" 2>/dev/null || true

    echo -e "  SHA256 : ${C}$(bb wc -l < "$out_dir/sha256.tsv" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  SHA1   : ${C}$(bb wc -l < "$out_dir/sha1.tsv" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  MD5    : ${C}$(bb wc -l < "$out_dir/md5.tsv" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  PE Sections (mdb): ${C}$(bb wc -l < "$out_dir/mdb.tsv" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  HexERE : ${C}$(bb wc -l < "$out_dir/hex_ere.txt" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  Strings: ${C}$(bb wc -l < "$out_dir/strings.txt" 2>/dev/null | tr -d ' ')${Z}"
    echo -e "  YARA   : ${C}$(bb find "$out_dir/yara" -name "*.ya*" 2>/dev/null | bb wc -l | tr -d ' ')${Z}"
    echo ""
}


# ============================================================================
# 10. MODULE: workdir & worker extraction
# ============================================================================
choose_work_dir() {
    local use_ram="$1" workers="$2"
    if [ "$use_ram" = true ] && [ "$OS" = "linux" ] && [ -d "/dev/shm" ]; then
        local needed=$(( workers * 12 + 60 ))
        local avail
        avail=$(df -m /dev/shm 2>/dev/null | awk 'NR==2{print $4}')
        # mktemp -d: atomic, 0700, never reuses a path a local user
        # pre-created (fixed /tmp/av_scan_<pid> names were plantable).
        [ "${avail:-0}" -ge "$needed" ] && mktemp -d "/dev/shm/av_scan_$$_XXXXXX" 2>/dev/null && return
    fi
    mktemp -d "${TMPDIR:-/tmp}/av_scan_$$_XXXXXX" 2>/dev/null
}

# Ownership locks for the per-run dirs (work dir, signature run dir): the
# owner (and its workers, which inherit the fd) holds an flock on <dir>/.lock
# for the whole scan. A "kill -0 PID" check alone deleted the live dirs of a
# scan running in another PID namespace (container, unshare) or on another
# host sharing the signature dir.
_dir_lock_hold() {   # $1 dir, $2 fd number
    command -v flock >/dev/null 2>&1 || return 0
    eval "exec $2>\"\$1/.lock\"" 2>/dev/null && flock -n "$2" 2>/dev/null
    return 0
}
_dir_owner_gone() {  # $1 dir, $2 owner pid (from the name) -> 0 = safe to delete
    if command -v flock >/dev/null 2>&1; then
        if [ -e "$1/.lock" ]; then
            flock -n "$1/.lock" true 2>/dev/null     # free = nobody holds it
            return
        fi
        # no lock file (older version, or the owner is just starting)
        [ -n "$2" ] && kill -0 "$2" 2>/dev/null && return 1
        [ -n "$(find "$1" -maxdepth 0 -mmin +10 2>/dev/null)" ]
        return
    fi
    [ -n "$2" ] && [[ "$2" =~ ^[0-9]+$ ]] && ! kill -0 "$2" 2>/dev/null
}

_sweep_stale_shm_dirs() {
    # FIX (CRITICAL race condition, found by external review): this used
    # to match purely by NAME PATTERN (av_arch_*, av_scan_* etc) with no
    # way to tell "orphaned from a dead run" apart from "still in active
    # use by a DIFFERENT, concurrently-running instance" (cron + a manual
    # scan, or -w in the background plus a one-off audit — both
    # legitimate, expected setups this scanner is meant to support). A
    # second instance starting while a first was still running would
    # delete the first one's WORK_DIR, SIG_DIR, and any in-progress
    # archive extraction out from under it.
    #
    # Every ephemeral resource this scanner creates now embeds the PID of
    # the top-level av.sh process that owns it (see MAIN_SCRIPT_PID in
    # the worker, and $$ here in the main script) — this function extracts
    # that PID from each match and checks with `kill -0` whether a
    # process by that PID is still alive before ever removing anything.
    # Only DEMONSTRABLY dead runs get swept; anything that can't be
    # confidently attributed to a dead PID is left alone rather than
    # guessed at. Old-format names from before this fix (no embedded PID)
    # are also left alone for the same reason — a one-time manual cleanup
    # for those, same as noted when the prefix fix originally shipped.
    local d base pid
    _dead_pid() {
        [ -n "$1" ] && [[ "$1" =~ ^[0-9]+$ ]] || return 1
        ! kill -0 "$1" 2>/dev/null
    }
    for d in /dev/shm/av_arch_* /dev/shm/av_chroot.* /dev/shm/av_sigs_* /dev/shm/av_scan_* \
             "${TMPDIR:-/tmp}"/av_arch_* "${TMPDIR:-/tmp}"/av_chroot.* "${TMPDIR:-/tmp}"/av_scan_* \
             "${TMPDIR:-/tmp}"/av_filtered_*; do
        [ -e "$d" ] || continue
        base=$(basename "$d")
        case "$base" in
            av_scan_*|av_sigs_*)   pid="${base#av_*_}"; pid="${pid%%_*}" ;;
            av_arch_*)             pid="${base#av_arch_}"; pid="${pid%%_*}" ;;
            av_chroot.*)           pid="${base#av_chroot.}"; pid="${pid%%.*}" ;;
            av_filtered_*)         pid="${base#av_filtered_}"; pid="${pid%%_*}" ;;
            *)                     pid="" ;;
        esac
        case "$base" in
            av_scan_*|av_sigs_*) [ -d "$d" ] && { _dir_owner_gone "$d" "$pid" && rm -rf "$d" 2>/dev/null; continue; } ;;
        esac
        _dead_pid "$pid" && rm -rf "$d" 2>/dev/null
    done
}

init_workdir() {
    _sweep_stale_shm_dirs
    local _rd _rp
    for _rd in "$SIGNATURES/.cache"/run.* "$SIGNATURES/.cache/packs"/*.new.* "$SIGNATURES/.cache/packs"/*.old.*; do
        [ -d "$_rd" ] || continue
        _rp="${_rd##*/}"; _rp="${_rp#run.}"; _rp="${_rp##*.new.}"; _rp="${_rp##*.old.}"; _rp="${_rp%%.*}"
        case "$_rd" in
            */run.*) _dir_owner_gone "$_rd" "$_rp" && rm -rf "$_rd" 2>/dev/null ;;
            *) [[ "$_rp" =~ ^[0-9]+$ ]] && ! kill -0 "$_rp" 2>/dev/null \
                   && [ -n "$(find "$_rd" -maxdepth 0 -mmin +60 2>/dev/null)" ] && rm -rf "$_rd" 2>/dev/null ;;
        esac
    done
    WORK_DIR=$(choose_work_dir "$USE_RAM" "$WORKERS") && [ -d "$WORK_DIR" ] || {
        echo -e "${R}[FAIL] Cannot create a private work dir (mktemp -d in ${TMPDIR:-/tmp})${Z}" >&2; exit 1; }
    WORKER_FILE="$WORK_DIR/worker.sh"

    if [ "$SIG_IN_RAM" = true ] && [ "$OS" = "linux" ] && [ -d /dev/shm ]; then
        # Independent of WORK_DIR's own placement (see SIG_IN_RAM global
        # comment) — needs its own free-space check since a real combined
        # ClamAV+Maldet+YARA-repo database's compiled form (sha256.tsv/
        # md5.tsv/mdb.tsv/rules.yarc) can run into the hundreds of MB.
        local sig_needed=300 sig_avail
        sig_avail=$(df -m /dev/shm 2>/dev/null | awk 'NR==2{print $4}')
        if [ "${sig_avail:-0}" -ge "$sig_needed" ]; then
            SIG_DIR=$(mktemp -d "/dev/shm/av_sigs_$$_XXXXXX" 2>/dev/null) || SIG_DIR="$WORK_DIR/sigs"
        else
            echo -e "${Y}[WARN] --ram-dirs all: signatures in RAM requested but /dev/shm doesn't have enough free space (need ~${sig_needed}MB, have ${sig_avail:-0}MB) -> falling back to normal placement${Z}"
            SIG_DIR="$WORK_DIR/sigs"
        fi
    else
        # next to the cache (same file system): the cached signatures are
        # hard-linked in, not copied (see compile_signatures). Falls back to
        # the work dir if the signature dir is not writable.
        SIG_DIR=""
        if mkdir -p "$SIGNATURES/.cache" 2>/dev/null; then
            SIG_DIR=$(mktemp -d "$SIGNATURES/.cache/run.$$.XXXXXX" 2>/dev/null) || SIG_DIR=""
        fi
        [ -n "$SIG_DIR" ] || SIG_DIR="$WORK_DIR/sigs"
    fi

    mkdir -p "$WORK_DIR/reports" "$SIG_DIR"
    _dir_lock_hold "$WORK_DIR" 7
    _dir_lock_hold "$SIG_DIR" 6
    # every exit path (also the "exit 1" ones after this point) drops this
    # run's hard-link dir; the work dir has its own cleanup paths
    trap 'case "$SIG_DIR" in */.cache/run.*) rm -rf "$SIG_DIR" 2>/dev/null ;; esac' EXIT
}

extract_worker() {
    local inside=false
    while IFS= read -r ln; do
        [ "$ln" = "#__WORKER_START__" ] && { inside=true; continue; }
        [ "$ln" = "#__WORKER_END__" ] && break
        $inside && printf '%s\n' "$ln"
    done < "$0" > "$WORKER_FILE"
    chmod +x "$WORKER_FILE"
}

# Pulls the bootstrap/setup module (detect_platform through run_self_setup
# — see #__SETUP_MODULE_START__/_END__ markers) out into its own runnable
# script, same technique as extract_worker() above. Written to a
# PERSISTENT location next to this script (not the ephemeral WORK_DIR
# used for scan runs) specifically so it stays around afterward for
# independent debugging: edit it, re-run it directly with plain
# `bash setup_module.sh --setup [--force]`, without needing to invoke the
# whole scanner or touch any scan-related code at all.
extract_setup_module() {
    local target="${1:-$SCRIPT_DIR/setup_module.sh}"
    {
        echo '#!/bin/bash'
        echo '# Auto-extracted bootstrap/setup module — see av.sh for the source of'
        echo '# truth (#__SETUP_MODULE_START__/_END__ markers). Safe to run standalone:'
        echo '#   bash setup_module.sh --setup [--force]'
        echo 'SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"'
        echo 'R="" G="" Y="" C="" B="" Z=""'
        echo '[ -t 1 ] && { R="\033[0;31m"; Y="\033[1;33m"; G="\033[0;32m"; C="\033[0;36m"; B="\033[1m"; Z="\033[0m"; }'
        echo 'YARA_URL_ARG="${YARA_URL_ARG:-}"'
        echo 'SETUP_FORCE="${SETUP_FORCE:-false}"'
        echo 'SETUP_COMPILE_ONLY="${SETUP_COMPILE_ONLY:-false}"'
        echo 'BUSYBOX_BIN="${BUSYBOX_BIN:-}"'
        echo 'ALLOW_BUSYBOX="${ALLOW_BUSYBOX:-true}"'
        echo 'BUSYBOX_URL_ARG="${BUSYBOX_URL_ARG:-}"'
        echo 'BUSYBOX_PATH_ARG="${BUSYBOX_PATH_ARG:-}"'
        echo 'DEBUG_MODE="${DEBUG_MODE:-false}"'
        echo 'OS=""; ARCH=""'
        local inside=false
        while IFS= read -r ln; do
            [ "$ln" = "#__SETUP_MODULE_START__" ] && { inside=true; continue; }
            [ "$ln" = "#__SETUP_MODULE_END__" ] && break
            $inside && printf '%s\n' "$ln"
        done < "$0"
        echo ''
        echo 'detect_platform'
        echo 'for _a in "$@"; do case "$_a" in --force) SETUP_FORCE=true ;; --debug) DEBUG_MODE=true ;; esac; done'
        echo 'run_self_setup'
    } > "$target"
    chmod +x "$target"
}

# ============================================================================
# MODULE: process/memory anomaly scanning (-P/--scan-processes)
#
# Addresses a specific, real gap in pure file-tree scanning: a process can
# keep running after its own backing executable is deleted from disk (the
# kernel keeps the inode open as long as something references it) — the
# exact "видаляє процес й лишається тільки в ОЗУ" scenario. A file-based
# scanner alone can NEVER see this, no matter how good its signatures are,
# since there's no file left to check.
#
# HONEST SCOPE — stated plainly, not just implied: this catches simple,
# common rootkit techniques (deleted binaries, ps/proc hiding via
# userspace hooks, LD_PRELOAD injection). It does NOT and CANNOT reliably
# catch a genuine kernel-level (LKM) rootkit — one that patches the
# kernel itself can lie to /proc, ps, and every other userspace tool
# equally, INCLUDING this one, since we go through the exact same syscalls
# everything else does. Real detection at that level needs analysis from
# OUTSIDE the running kernel (offline disk/memory forensics), which is a
# fundamentally different tool than a bash-based file/process scanner.
# This module is a real, useful net for the common case, not a guarantee.
# ============================================================================
SCAN_PROCESSES=false   # -P/--scan-processes

# Known-malware names (IOCs), mostly from the "rival killer" lists that
# Linux miner botnets carry to wipe each other out (one such watchdog —
# /var/tmp/.X11R6 restarting "javad" — was found on a real hosting server),
# plus that sample's own files. Used ONLY to report, never to kill or
# delete: several of those lists also name real daemons (rsyslogd, chronyd,
# supervisord ...), which here are flagged only when the binary does not
# live in a system directory.
# File paths matched anywhere (names no real software uses):
IOC_PATH_ANY_RE='/(kworkerds[0-9a-z]*|khugepageds|\.?kerberods|systemctI|linuxsys|esocket4|ww4\.sh|\.universal-miner|\.gt_sys_health(\.json)?|\.gt_sys_wd(\.sh)?|\.gt_cron_health(\.json)?|\.sRDQ99i|\.sjo7ucV|427be17e|943fc088|\.auditsd_install_dir|libioset\.so|\.cache-jd|\.salkidwuewerwe|\.mmmjjsdfsdfwerrwerwer|systemxlv|xmrig[^/]*|\.ICEd-unix|\.X11R6|\.xwd|\.khp|\.khp-wdg)(/|$)'
# Names that are only damning directly in a temp dir (or bin/javad):
IOC_PATH_TMP_RE='(/(tmp|var/tmp|dev/shm)/(javad|httpgd|gates\.lod|osw\.hb|seasame|z[23]\.sh|xd\.json|wc\.conf|syslogdb?|j2\.conf|\.app\.log|\.syslog[^/]*|ddg)$|/bin/javad$)'
# Process names: always suspicious (exe basename or argv[0] basename) ...
IOC_PROC_NAME_RE='^(xmrig.*|linuxsys|esocket4|universal-miner|\.?gt_sys_health|\.?gt_sys_wd.*|\.?gt_cron_health|auditsd|rsysloged|journalctld|systemd-netd|systemd-devd|udev-manager|syslog-helper|kworkerds.*|kerberods|khugepageds|MySvcice|softwaretech|427be17e|943fc088|\.sd-top|javad|javab|javs|ww4.*|\.khp)$'
# ... anywhere in the command line (long, unique tokens) ...
IOC_PROC_CMD_RE='(khp-wdg|/\.X11R6|/\.xwd|/\.khp|/\.cache-jd/|universal-miner|xmrig|/linuxsys|/\.zsh( |$)|427be17e|943fc088)'
# ... and real daemon names that miners borrow: suspicious only outside
# the system binary directories
IOC_PROC_DISGUISE_RE='^(rsyslogd|syslog-ng|chronyd|supervisord|supervisor|httpx|unicorn|apt-update|bluetooth-notify|q-start|keeper|rosetta|zzh)$'

scan_processes() {
    echo -e "${B}[*] Scanning running processes for rootkit indicators...${Z}"
    [ -d /proc ] || { echo -e "${Y}[WARN] /proc not available -> skipping process scan${Z}"; return; }

    local pid_dir pid exe_link cmdline found=0

    # --- 1. Deleted-binary check + known-malware hash check for live exes ---
    # Reuses the ALREADY-COMPILED hash database (same sha256.tsv/md5.tsv
    # the file scan uses) — a process running a KNOWN-BAD binary gets
    # caught the same way a file would, just read from /proc/PID/exe
    # instead of a path on the tree.
    local has_hash_db=false
    [ -s "$SIG_DIR/sha256.tsv" ] && has_hash_db=true

    for pid_dir in /proc/[0-9]*; do
        pid="${pid_dir#/proc/}"
        [ -r "$pid_dir/exe" ] || continue
        exe_link=$(readlink "$pid_dir/exe" 2>/dev/null)
        [ -z "$exe_link" ] && continue
        cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null | head -c 150)

        case "$exe_link" in
            *" (deleted)")
                local real_path="${exe_link% (deleted)}"
                echo -e "${R}[!] [PROCESS_DELETED_BINARY] PID=${pid} exe=${real_path} cmdline=${cmdline}${Z}"
                found=$(( found + 1 ))
                ;;
            *)
                if [ "$has_hash_db" = true ] && [ -r "$pid_dir/exe" ]; then
                    local h
                    h=$($SHA256_CMD "$pid_dir/exe" 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)
                    if [ -n "$h" ] && bb grep -qF "$h" "$SIG_DIR/sha256.tsv" 2>/dev/null; then
                        local n; n=$(bb grep -m1 "^$h" "$SIG_DIR/sha256.tsv" | cut -f2)
                        echo -e "${R}[!] [PROCESS_KNOWN_MALWARE] PID=${pid} exe=${exe_link} name=${n:-Malware} cmdline=${cmdline}${Z}"
                        found=$(( found + 1 ))
                    fi
                fi
                ;;
        esac

        # LD_PRELOAD is the classic userspace hooking-rootkit technique
        # (intercepting libc calls like readdir/stat to hide files or
        # processes) — a process running with it set is at minimum worth
        # a look, even though plenty of legitimate tools use it too
        # (this is a LEAD to check, not proof by itself).
        if [ -r "$pid_dir/environ" ]; then
            local preload
            preload=$(tr '\0' '\n' < "$pid_dir/environ" 2>/dev/null | bb grep "^LD_PRELOAD=" | head -1)
            if [ -n "$preload" ]; then
                echo -e "${Y}[!] [PROCESS_LD_PRELOAD] PID=${pid} ${preload} cmdline=${cmdline}${Z}"
                found=$(( found + 1 ))
            fi
        fi

        # Known miner / botnet names and disguises (report only)
        local _ex="${exe_link% (deleted)}" _a0 _why=""
        _a0=$(tr '\0' '\n' < "$pid_dir/cmdline" 2>/dev/null | head -1); _a0="${_a0##*/}"
        if [[ "${_ex##*/}" =~ $IOC_PROC_NAME_RE ]] || [[ "$_a0" =~ $IOC_PROC_NAME_RE ]]; then
            _why="known malware name"
        elif [[ "$cmdline" =~ $IOC_PROC_CMD_RE ]]; then
            _why="known malware file in command line"
        elif [[ "${_ex##*/}" =~ $IOC_PROC_DISGUISE_RE ]] || [[ "$_a0" =~ $IOC_PROC_DISGUISE_RE ]]; then
            case "$_ex" in
                /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*|/usr/lib/*|/usr/libexec/*|/lib/*|/usr/local/bin/*|/usr/local/sbin/*|/opt/*/bin/*|/snap/*) ;;
                *) _why="system daemon name, binary outside system dirs" ;;
            esac
        fi
        # a userspace process named like a kernel thread (real kernel threads
        # have no exe and an empty command line)
        [ -z "$_why" ] && case "$cmdline" in "["*"]"*) _why="userspace process disguised as a kernel thread" ;; esac
        [ -z "$_why" ] && case "$_ex" in /tmp/*|/var/tmp/*|/dev/shm/*) _why="running from a temp dir" ;; esac
        if [ -n "$_why" ]; then
            echo -e "${R}[!] [PROCESS_SUSPICIOUS] PID=${pid} user=$(bb stat -c %U "$pid_dir" 2>/dev/null) exe=${exe_link} (${_why}) cmdline=${cmdline}${Z}"
            found=$(( found + 1 ))
        fi
    done

    # --- 2. /proc vs ps cross-check ---
    # A classic sign of a userspace rootkit hiding a process: it still has
    # a live /proc/PID entry (the kernel itself isn't lying, only ps/ls
    # are being fooled — e.g. via a hooked readdir()), but doesn't show up
    # in `ps`. Re-verified against a SECOND /proc sample before reporting
    # — a discrepancy from ordinary process churn (something exiting
    # between the two enumeration passes) is expected noise, not a
    # finding, and would NOT survive a re-check moments later.
    if command -v ps &>/dev/null; then
        local proc_pids ps_pids missing p still_there
        proc_pids=$(ls -d /proc/[0-9]* 2>/dev/null | sed 's|/proc/||' | sort -n)
        ps_pids=$(ps -eo pid --no-headers 2>/dev/null | tr -d ' ' | sort -n)
        missing=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids") 2>/dev/null)
        if [ -n "$missing" ]; then
            sleep 0.3
            still_there=$(ps -eo pid --no-headers 2>/dev/null | tr -d ' ' | sort -n)
            for p in $missing; do
                [ -d "/proc/$p" ] || continue   # already exited -> just churn
                if ! echo "$still_there" | grep -qx "$p"; then
                    local pcmd; pcmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | head -c 150)
                    echo -e "${R}[!] [PROCESS_HIDDEN_FROM_PS] PID=${p} visible in /proc but not ps, twice -- cmdline=${pcmd}${Z}"
                    found=$(( found + 1 ))
                fi
            done
        fi
    fi

    if [ "$found" -eq 0 ]; then
        echo -e "${G}[OK] No process anomalies detected${Z} (deleted binaries, known-malware hashes and names, disguised/temp-dir processes, LD_PRELOAD, ps/proc mismatch)"
    else
        echo -e "${Y}[*] ${found} process anomaly(ies) flagged above${Z} — investigate manually; this module cannot auto-quarantine a running process."
    fi
    echo -e "${C}[*] Note: catches simple/userspace rootkit techniques only — cannot see through a genuine kernel-level (LKM) rootkit, which can lie to /proc itself.${Z}"
}

# ============================================================================
# MODULE: kernel/boot integrity check (-K/--check-kernel, --offline-root)
#
# THE POINT OF THIS MODULE ONLY HOLDS IF RUN FROM A TRUSTED KERNEL. Run
# against the LIVE system, this is no better than scan_processes() above —
# still going through whatever kernel is currently running, which a real
# LKM rootkit fully controls and can lie to just like anything else. Its
# real value is when paired with --offline-root: boot your host's rescue
# system (every major provider — Hetzner, DigitalOcean, Vultr, OVH,
# etc. — offers one; it's the practical cloud-VPS equivalent of a LiveCD,
# just triggered manually through their control panel, not something this
# script can do FROM WITHIN a system you don't trust the kernel of), mount
# the suspect disk read-only somewhere (e.g. /mnt/suspect-root), then run:
#   ./av.sh --offline-root /mnt/suspect-root -K -d /mnt/suspect-root
# Now every check here reads through the RESCUE kernel, not the
# potentially-compromised one — which is the entire reason this is
# meaningfully different from running it live.
#
# Checks: kernel image + initramfs + loaded-module files against the
# package manager's OWN recorded checksums (dpkg -V) — a tampered boot
# image or an unowned .ko file are strong persistence indicators. This
# reuses the exact same "package should own this system file" logic
# already built for SUID/SGID verification, just aimed at /boot and
# /lib/modules instead.
#
# ON REMEDIATION: this deliberately only ever REPORTS. A confirmed kernel/
# boot-level compromise is not something to try to surgically fix in
# place — standard incident response is full reinstall from a known-clean
# image, not disinfection, precisely because nothing on a kernel-level-
# compromised system can be trusted to judge its own cleanliness anymore.
# This module's job is to hand you the evidence to make that call, not to
# pretend it can quarantine a kernel the way it quarantines a PHP file.
# ============================================================================
CHECK_KERNEL=false     # -K/--check-kernel
OFFLINE_ROOT=""         # --offline-root PATH — see module comment above

# Compares every boot/vmlinuz-* with a list of KNOWN kernel builds shipped in
# signatures/kernel_refs/*.tsv (made by tools/gen_kernel_refs.py from the
# distribution's own packages: hash<TAB>file<TAB>package<TAB>version<TAB>suite,
# hash = md5 (deb) or sha256 (rpm), told apart by length).
# Unlike the dpkg-based check below this needs no package manager and no
# trust in the checksums stored on the inspected disk — a rescue system such as
# SystemRescue (no dpkg) can run it, and a rootkit that also rewrote the
# disk's own dpkg md5sums cannot hide a modified kernel from it.
# Verdicts: match = OK; file name is a known kernel but the md5 matches none
# of its known builds = MISMATCH (strong); md5 known under another name =
# RENAMED; name not in the list = UNKNOWN (custom/other distro — look, not proof).
KREF_FINDINGS=0
scan_kernel_refs() {
    local root="${OFFLINE_ROOT:-}" refdir="${SIGNATURES}/kernel_refs" f name md5 sha res verdict a b
    KREF_FINDINGS=0
    if ! ls "$refdir"/*.tsv >/dev/null 2>&1; then
        echo -e "${Y}[INFO] No kernel reference list (${refdir}/*.tsv) -> skipping the known-kernel comparison${Z}"
        return
    fi
    local nref; nref=$(cat "$refdir"/*.tsv 2>/dev/null | grep -vc '^#')
    echo -e "${B}[*] Comparing boot kernels with ${nref} known kernel builds...${Z}"
    local seen=0
    for f in "${root}/boot"/vmlinuz-*; do
        [ -f "$f" ] && [ ! -L "$f" ] || continue
        seen=$((seen + 1))
        name="${f##*/}"
        md5=$(md5sum "$f" 2>/dev/null | cut -d' ' -f1)
        sha=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)
        [ -n "$md5" ] || continue
        # the first column is an md5 (32 hex, deb packages) or a sha256 (64 hex,
        # rpm packages) — a file matches when either of its hashes is listed
        res=$(cat "$refdir"/*.tsv 2>/dev/null | awk -F'\t' -v h="$md5" -v h2="$sha" -v n="$name" '
            /^#/ { next }
            ($1 == h || $1 == h2) && $2 == n { ok = $3 " " $4 }
            ($1 == h || $1 == h2) && $2 != n { other = $2 " (" $3 " " $4 ")" }
            $2 == n { known = 1 }
            END { if (ok != "") print "OK\t" ok; else if (other != "") print "RENAMED\t" other; else if (known) print "MISMATCH"; else print "UNKNOWN" }')
        verdict="${res%%$'\t'*}"; a="${res#*$'\t'}"
        case "$verdict" in
            OK)       echo -e "${G}[OK] ${f} = ${a} (matches the distribution's package)${Z}" ;;
            MISMATCH) echo -e "${R}[!] [KERNEL_REF_MISMATCH] ${f} — '${name}' is a known kernel, but this file's md5 (${md5}) matches NONE of its known builds${Z}"
                      KREF_FINDINGS=$((KREF_FINDINGS + 1)) ;;
            RENAMED)  echo -e "${Y}[!] [KERNEL_REF_RENAMED] ${f} — content equals ${a}, but the file has a different name${Z}"
                      KREF_FINDINGS=$((KREF_FINDINGS + 1)) ;;
            *)        echo -e "${Y}[?] [KERNEL_REF_UNKNOWN] ${f} (md5 ${md5}) — not in the list: custom kernel, another distribution, or newer/older than the list${Z}" ;;
        esac
    done
    [ "$seen" -eq 0 ] && echo -e "${Y}[INFO] No boot/vmlinuz-* regular files found under ${root:-/}boot${Z}"
}

scan_kernel_integrity() {
    local root="${OFFLINE_ROOT:-}"
    echo -e "${B}[*] Checking kernel/boot file integrity...${Z}"
    if [ -z "$root" ]; then
        echo -e "${Y}[WARN] Running against the LIVE kernel — if that kernel is what's"
        echo -e "       compromised, this check can be lied to same as anything else."
        echo -e "       For a check that actually means something against an LKM"
        echo -e "       rootkit: boot your host's rescue/recovery system, mount the"
        echo -e "       disk read-only, and re-run with --offline-root.${Z}"
    fi

    scan_kernel_refs

    if ! command -v dpkg &>/dev/null; then
        echo -e "${Y}[WARN] dpkg not found -> can't cross-check against the disk's package records (the known-kernel comparison above does not need it)${Z}"
        return
    fi

    local dpkg_root_arg=()
    [ -n "$root" ] && dpkg_root_arg=(--root="$root")

    # dpkg on the scanning host says nothing about a disk that has no dpkg
    # database (AlmaLinux/RHEL root under --offline-root, or rpm host with
    # a stray dpkg): every kernel file came out UNOWNED.
    if [ ! -s "${root}/var/lib/dpkg/status" ]; then
        echo -e "${Y}[WARN] No dpkg database at ${root:-}/var/lib/dpkg/status (not a dpkg-based system?) -> package cross-check skipped (the known-kernel comparison above does not need it)${Z}"
        return
    fi

    local found=$KREF_FINDINGS pkg md5file relpath expected actual f alt t ninit=0
    # Every /boot and /lib/modules file that dpkg -S can attribute to a
    # package gets its checksum cross-checked against that package's own
    # record. Files it can't attribute at all (not owned by any package —
    # a hand-dropped .ko, a DKMS-built module, or a genuinely planted
    # rootkit module) are reported separately as lower-confidence
    # "unowned" findings, since legitimate reasons for that exist too
    # (custom-compiled drivers) — worth a look, not proof by itself.
    # /boot/initrd*/initramfs* are not checked: built locally by
    # update-initramfs/dracut, never package-owned, so they were reported
    # UNOWNED on every run. A symlink to a regular /boot/vmlinuz-X (Ubuntu
    # /boot/vmlinuz, vmlinuz.old) is skipped too: X itself is checked.
    for f in "${root}/boot"/initrd* "${root}/boot"/initramfs*; do
        [ -f "$f" ] && [ ! -L "$f" ] && ninit=$(( ninit + 1 ))
    done
    [ "$ninit" -gt 0 ] && echo -e "${Y}[INFO] ${ninit} initrd/initramfs image(s) in ${root}/boot not checked (generated locally, no package record)${Z}"
    for f in "${root}/boot"/vmlinuz* \
             $(find "${root}/lib/modules" -name "*.ko" -o -name "*.ko.xz" -o -name "*.ko.zst" 2>/dev/null); do
        [ -f "$f" ] || continue
        if [ -L "$f" ]; then
            # Only a link to a regular vmlinuz-* directly in /boot (checked
            # by this same loop); a link anywhere else is checked below.
            t=$(readlink -f "$f")
            [ "${t%/*}" = "$(readlink -f "${root}/boot")" ] && [ -f "$t" ] && \
                case "${t##*/}" in vmlinuz-*) continue ;; esac
        fi
        relpath="${f#$root/}"
        pkg=$(dpkg "${dpkg_root_arg[@]}" -S "/$relpath" 2>/dev/null | head -1 | cut -d: -f1)
        # Merged /usr: Debian 13 packages record usr/lib/modules, find prints
        # lib/modules (1139 UNOWNED .ko). Retry the other name only if both
        # names are the same file.
        if [ -z "$pkg" ]; then
            case "$relpath" in
                usr/*) alt="${relpath#usr/}" ;;
                *)     alt="usr/$relpath" ;;
            esac
            if [ "${root}/$alt" -ef "$f" ]; then
                pkg=$(dpkg "${dpkg_root_arg[@]}" -S "/$alt" 2>/dev/null | head -1 | cut -d: -f1)
                [ -n "$pkg" ] && relpath="$alt"
            fi
        fi
        if [ -z "$pkg" ]; then
            echo -e "${Y}[!] [KERNEL_FILE_UNOWNED] ${f} — not tracked by any installed package${Z}"
            found=$(( found + 1 ))
            continue
        fi
        md5file="${root}/var/lib/dpkg/info/${pkg}.md5sums"
        [ -f "$md5file" ] || md5file="${root}/var/lib/dpkg/info/${pkg%:*}.md5sums"
        [ -f "$md5file" ] || continue
        expected=$(awk -v p="$relpath" 'substr($0, 35) == p { print $1; exit }' "$md5file" 2>/dev/null)
        [ -z "$expected" ] && continue
        actual=$(md5sum "$f" 2>/dev/null | cut -d' ' -f1)
        if [ "$expected" != "$actual" ]; then
            echo -e "${R}[!] [KERNEL_FILE_TAMPERED] ${f} (package: ${pkg}) — checksum does NOT match package record${Z}"
            found=$(( found + 1 ))
        fi
    done

    if [ "$found" -eq 0 ]; then
        echo -e "${G}[OK] No kernel/boot integrity issues found${Z} against package records"
    else
        echo -e "${R}[*] ${found} kernel/boot finding(s) above.${Z} If this was run with --offline-root"
        echo -e "    (trusted rescue kernel), treat a TAMPERED result as strong evidence for a full"
        echo -e "    rebuild — do not attempt to patch a compromised kernel/module in place."
    fi
}

# Is the inspected disk mounted read-only? Evidence hygiene: a read-write mount lets
# anything that touches it (this script included) change timestamps and journals.
# Prints: state<TAB>device<TAB>mountpoint<TAB>options<TAB>fstype   (state: ro | rw | none)
# "none" = the path is not a mount of its own (plain directory) or /proc/mounts is unreadable.
_mount_state() {
    local root="$1" real
    real=$(readlink -f "$root" 2>/dev/null || echo "$root")
    awk -v root="$real" '
        { mp=$2; gsub(/\\040/, " ", mp)
          if (mp == root || mp == "/" || index(root, mp "/") == 1) if (length(mp) >= best) { best=length(mp); dev=$1; bmp=mp; opts=$4; fst=$3 } }
        END { if (best == "") { print "none\t\t\t\t"; exit }
              st = (("," opts ",") ~ /,ro,/) ? "ro" : "rw"
              if (bmp == "/" && root != "/") st = "none"
              print st "\t" dev "\t" bmp "\t" opts "\t" fst }' "${AUD_PROC_MOUNTS:-/proc/mounts}" 2>/dev/null
}
# mounts located UNDER root (e.g. /mnt/var as a separate partition) that are not read-only
_mount_rw_children() {
    local root real
    real=$(readlink -f "$1" 2>/dev/null || echo "$1")
    awk -v root="$real" '{ mp=$2; gsub(/\\040/, " ", mp)
        if (index(mp, root "/") == 1 && (("," $4 ",") !~ /,ro,/)) print mp "\t" $1 "\t" $3 }' "${AUD_PROC_MOUNTS:-/proc/mounts}" 2>/dev/null
}
# The standard way to mount a suspect disk for inspection. ext3/ext4 would replay the
# journal on a plain "ro" mount (writes to the disk!), "noload" prevents that; xfs has
# "norecovery" for the same reason. A plain "remount,ro" only stops FURTHER writes.
_ro_mount_hint() {   # device mountpoint fstype
    local o="ro"
    case "$3" in ext3|ext4) o="ro,noload" ;; xfs) o="ro,norecovery" ;; esac
    echo "umount $2 && mount -o ${o} $1 $2"
}
# Called for every --offline-root run that reads the disk (audit, -K, file scan): the
# disk (or a partition under it) must be mounted read-only, otherwise the script
# REFUSES to start (exit 3). --force overrides it (needed e.g. for -q, which moves
# files on the inspected disk) and only leaves a warning. A path that is not a mount
# of its own (plain directory) cannot be judged and is let through.
enforce_readonly() {
    local st dev mp opts fst line m d t bad=0 msg="" quar=false
    [ -n "${OFFLINE_ROOT:-}" ] || return 0
    line=$(_mount_state "$OFFLINE_ROOT"); IFS=$'\t' read -r st dev mp opts fst <<< "$line"
    # Quarantine (-q) MOVES detected files off the inspected disk, i.e. it changes the
    # disk. With --offline-root that must be a conscious decision: --force.
    if [ "${QUARANTINE_ENABLED:-false}" = true ] && [ "${QUARANTINE_DRY_RUN:-false}" != true ] && [ "${AUDIT_MODE:-false}" != true ]; then
        quar=true
        if [ "${SETUP_FORCE:-false}" != true ]; then
            echo -e "${R}[FAIL] Quarantine mode (-q/--quarantine) is ON together with --offline-root.${Z}"
            echo -e "       -q MOVES every detected file off the inspected disk - that changes the disk and destroys"
            echo -e "       the original state (evidence). If you really want that, add --force (the disk must then"
            echo -e "       be mounted read-write). To only look: drop -q, or use --quarantine-dry-run (lists what"
            echo -e "       WOULD be moved, touches nothing)."
            exit 3
        fi
        echo -e "${Y}[WARN] --force + -q: quarantine is ON, detected files will be MOVED off ${OFFLINE_ROOT}.${Z}"
        [ "$st" = "ro" ] && echo -e "${Y}       ${OFFLINE_ROOT} is mounted read-only, so the moves will FAIL: remount it read-write (mount -o remount,rw ${mp}).${Z}"
    fi
    if [ "$st" = "rw" ]; then
        bad=1
        msg+="  ${OFFLINE_ROOT} is mounted READ-WRITE (${dev} on ${mp}, ${fst})"$'\n'
        msg+="    -> $(_ro_mount_hint "$dev" "$mp" "$fst")"$'\n'
    fi
    while IFS=$'\t' read -r m d t; do
        [ -n "$m" ] || continue
        bad=1
        msg+="  ${m} (${d}) under ${OFFLINE_ROOT} is mounted READ-WRITE"$'\n'
        msg+="    -> $(_ro_mount_hint "$d" "$m" "$t")"$'\n'
    done < <(_mount_rw_children "$OFFLINE_ROOT")
    [ "$bad" = 0 ] && return 0
    if [ "${SETUP_FORCE:-false}" = true ]; then
        echo -e "${Y}[WARN] --force: continuing although the inspected disk is NOT read-only:"
        printf '%s' "$msg"
        echo -e "       timestamps and journals can change; do not use this run as evidence.${Z}"
        return 0
    fi
    echo -e "${R}[FAIL] Refusing to start: the disk under --offline-root must be mounted read-only"
    echo -e "       (reading a read-write disk changes access times; an ext4 journal replay writes to it).${Z}"
    printf '%s' "$msg"
    echo -e "       Remount it and run again. To go on anyway (e.g. -q has to move files): add --force"
    exit 3
}

#__AUDIT_MODULE_START__
# ============================================================================
# MODULE: compromise audit (--audit, --audit-since DATE)
#
# Everything the file scanner CANNOT see: a clean disk full of clean files can
# still belong to an attacker who simply logged in with a guessed root password
# (no malware needed). This module is self-contained and read-only: it does not
# touch signatures, workers or the scan pipeline, so it runs in seconds.
#   ./av.sh --offline-root /mnt/suspect-root --audit
#   ./av.sh --offline-root /mnt/suspect-root --audit-since 2026-09-29 -o audit.txt
# (live, without --offline-root, it works too, but see the -K comment about
# trusting the running kernel.)
#
# Checks: effective sshd settings (first value wins across Include files),
# UID-0 / empty-password / service accounts with a shell, authorized_keys,
# /etc/ld.so.preload, cron / systemd / rc.local / shell-startup persistence,
# executables and ELF files in tmp dirs, known miner / brute-force tool names,
# shell history (wiped or suspicious), docker API on TCP, and sshd auth logs:
# successful login after many failures (password guessed), failed logins from
# 127.0.0.1 (brute force launched FROM this host or tunnelled through it),
# logins from different IPs seconds apart (credential hand-over), root
# password logins, and logins missing from wtmp (no tty = command / tunnel).
# Findings are indicators, not proof: HIGH = act on it, MED = look at it.
# Exit code: 0 nothing, 1 only MED, 2 at least one HIGH.
# ============================================================================
AUDIT_MODE=false          # --audit
AUDIT_SINCE=""            # --audit-since YYYY-MM-DD: also list recently changed system files
AUD_HIGH=0; AUD_MED=0; AUD_INFO=0
AUD_CNT=""                # counters live in a file: findings are printed from pipeline subshells too
AUD_ROOT=""
AUD_SSHD=""
AUD_PAT_STRONG='(curl|wget|fetch)[^|;&]*[|;&] *(ba|z|da|k)?sh([^a-z]|$)|(nc|ncat|netcat) +([^;|&]* )?-[a-zA-Z]*e( |$)|/dev/tcp/|base64 +(-d|--decode)|python[0-9.]* +-c|perl +-e|bash +-i|chmod +(\+?x|[0-7]{3,4}) +/(tmp|var/tmp|dev/shm)|xmrig|minerd|cpuminer|kinsing|kdevtmpfsi|stratum\+tcp|(^|[ /])(hydra|medusa|ncrack|masscan)( |$)|unset +HISTFILE|history +-c'
AUD_PAT_WEAK="${AUD_PAT_STRONG}|/(tmp|var/tmp|dev/shm)/[^ ]+"

_aud() {   # severity tag text...
    local sev="$1" tag="$2"; shift 2
    case "$sev" in
        HIGH) echo -e "${R}[!] [AUDIT_${tag}] $*${Z}"; echo H >> "$AUD_CNT" ;;
        MED)  echo -e "${Y}[?] [AUDIT_${tag}] $*${Z}"; echo M >> "$AUD_CNT" ;;
        *)    echo -e "    [AUDIT_${tag}] $*";          echo I >> "$AUD_CNT" ;;
    esac
}

_aud_mtime() { date -r "$1" '+%F %T' 2>/dev/null || echo "?"; }

# sshd_config parsed the way sshd does it: top to bottom, Include expanded in
# place, FIRST value of a keyword wins, Match blocks ignored.
# emits: key<TAB>value<TAB>file:line
_aud_sshd_collect() {
    local f="$1" depth="${2:-0}" n=0 line key g gg inmatch=0
    [ "$depth" -gt 5 ] && return 0
    [ -f "$f" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        n=$(( n + 1 ))
        line="${line%%#*}"
        set -f; set -- $line; set +f      # no globbing of Include patterns here
        [ $# -ge 1 ] || continue
        key=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
        case "$key" in
            match) inmatch=1; continue ;;
            include)
                shift
                for g in "$@"; do
                    case "$g" in /*) g="${AUD_ROOT}${g}" ;; *) g="${AUD_ROOT}/etc/ssh/${g}" ;; esac
                    for gg in $g; do [ -f "$gg" ] && _aud_sshd_collect "$gg" $(( depth + 1 )); done
                done
                continue ;;
        esac
        [ "$inmatch" = 1 ] && continue
        shift
        printf '%s\t%s\t%s\n' "$key" "$*" "${f#"$AUD_ROOT"}:$n"
    done < "$f"
}
_aud_sshd_val() {   # keyword default -> "value<TAB>where"
    local r
    r=$(printf '%s\n' "$AUD_SSHD" | awk -F'\t' -v k="$1" '$1==k{print $2"\t"$3; exit}')
    [ -n "$r" ] && printf '%s\n' "$r" || printf '%s\t(default)\n' "$2"
}

_aud_check_mount() {
    echo -e "${B}[*] is the disk read-only?${Z}"
    local st dev mp opts fst line m d t
    if [ -z "$AUD_ROOT" ]; then
        _aud INFO MOUNT "live system (no --offline-root): nothing to check; for evidence use a rescue system and a read-only mount"; return 0
    fi
    line=$(_mount_state "$AUD_ROOT"); IFS=$'\t' read -r st dev mp opts fst <<< "$line"
    case "$st" in
        ro)   _aud INFO MOUNT_RO "${AUD_ROOT} is on ${dev} mounted read-only (${mp}, ${fst})"
              case "$fst:,${opts}," in
                  ext3:*,noload,*|ext4:*,noload,*) : ;;
                  ext3:*|ext4:*) _aud INFO MOUNT_JOURNAL "no 'noload' in the mount options: if the disk was mounted by a plain 'ro', the ext4 journal may have been replayed at mount time (a write). Next time: mount -o ro,noload ${dev} ${mp}" ;;
              esac ;;
        rw)   _aud MED MOUNT_RW "${AUD_ROOT} is mounted READ-WRITE (${dev} on ${mp}, ${fst}, options: ${opts}) - timestamps can change and the journal may already have been replayed. Mount it for inspection like this: $(_ro_mount_hint "$dev" "$mp" "$fst")" ;;
        *)    _aud INFO MOUNT "${AUD_ROOT} is not a mount point of its own (plain directory or unreadable /proc/mounts) - cannot tell whether it is read-only" ;;
    esac
    while IFS=$'\t' read -r m d t; do
        [ -n "$m" ] && _aud MED MOUNT_RW "${m} (${d}) under ${AUD_ROOT} is mounted READ-WRITE: $(_ro_mount_hint "$d" "$m" "$t")"
    done < <(_mount_rw_children "$AUD_ROOT")
}

_aud_check_sshd() {
    echo -e "${B}[*] sshd configuration${Z}"
    if [ ! -f "$AUD_ROOT/etc/ssh/sshd_config" ]; then
        _aud INFO SSHD "no /etc/ssh/sshd_config (sshd not installed?)"; return 0
    fi
    AUD_SSHD=$(_aud_sshd_collect "$AUD_ROOT/etc/ssh/sshd_config" 0)
    local prl pa pe prl_v prl_w pa_v pa_w dup
    prl=$(_aud_sshd_val permitrootlogin prohibit-password); prl_v="${prl%%$'\t'*}"; prl_w="${prl#*$'\t'}"
    pa=$(_aud_sshd_val passwordauthentication yes);          pa_v="${pa%%$'\t'*}";   pa_w="${pa#*$'\t'}"
    pe=$(_aud_sshd_val permitemptypasswords no)
    prl_v=$(printf '%s' "$prl_v" | tr 'A-Z' 'a-z'); pa_v=$(printf '%s' "$pa_v" | tr 'A-Z' 'a-z')
    if [ "$prl_v" = "yes" ] && [ "$pa_v" != "no" ]; then
        _aud HIGH SSH_ROOT_PASSWORD "root can log in with a PASSWORD over SSH (PermitRootLogin ${prl_v} @ ${prl_w}; PasswordAuthentication ${pa_v} @ ${pa_w}) — brute-forceable from the internet"
    elif [ "$prl_v" = "yes" ]; then
        _aud MED SSH_ROOT_LOGIN "PermitRootLogin yes @ ${prl_w} (password auth is off, keys only)"
    elif [ "$pa_v" != "no" ]; then
        _aud INFO SSH_PASSWORD "PasswordAuthentication ${pa_v} @ ${pa_w} (root: ${prl_v})"
    else
        _aud INFO SSH_OK "root: ${prl_v}, password auth: ${pa_v}"
    fi
    [ "$(printf '%s' "${pe%%$'\t'*}" | tr 'A-Z' 'a-z')" = "yes" ] && _aud HIGH SSH_EMPTY_PW "PermitEmptyPasswords yes @ ${pe#*$'\t'}"
    # a later, ignored, contradicting value is the classic "I disabled it but it still works"
    for k in permitrootlogin passwordauthentication; do
        dup=$(printf '%s\n' "$AUD_SSHD" | awk -F'\t' -v k="$k" '$1==k{n++; if(n==1){v=$2} else if($2!=v){print k" "$2" @ "$3" (IGNORED, first value wins: "v")"}}')
        [ -n "$dup" ] && printf '%s\n' "$dup" | while IFS= read -r l; do _aud INFO SSH_OVERRIDDEN "$l"; done
    done
    printf '%s\n' "$AUD_SSHD" | awk -F'\t' '$1=="authorizedkeyscommand" || ($1=="authorizedkeysfile" && $2 !~ /\.ssh\/authorized_keys/) {print $1" "$2" @ "$3}' |
        while IFS= read -r l; do _aud MED SSH_KEYS_CFG "non-default key lookup: $l"; done
    _aud INFO SSH_PORT "Port $(_aud_sshd_val port 22 | cut -f1)"
}

_aud_homes() {
    { awk -F: '$6!="" && $6!="/" && $7!~/(nologin|false)$/ {print $6}' "$AUD_ROOT/etc/passwd" 2>/dev/null; echo /root; } | sort -u
}

_aud_check_accounts() {
    echo -e "${B}[*] accounts and keys${Z}"
    local pw="$AUD_ROOT/etc/passwd" sh="$AUD_ROOT/etc/shadow" l h f n cm
    if [ -f "$pw" ]; then
        awk -F: '$3==0 && $1!="root"{print $1}' "$pw" | while IFS= read -r l; do
            _aud HIGH UID0 "extra account with UID 0: $l"; done
        awk -F: '$3>0 && $3<1000 && $7!~/(nologin|false|sync|halt|shutdown)$/ && $7!=""{print $1" ("$7")"}' "$pw" | while IFS= read -r l; do
            _aud MED SYSTEM_SHELL "system account with a login shell: $l"; done
        l=$(awk -F: '$3>=1000 && $1!="nobody" && $7!~/(nologin|false)$/{printf "%s ", $1}' "$pw")
        [ -n "$l" ] && _aud INFO USERS "login-capable users: $l"
    fi
    if [ -r "$sh" ]; then
        awk -F: '$2==""{print $1}' "$sh" | while IFS= read -r l; do _aud HIGH EMPTY_PASSWORD "account with EMPTY password: $l"; done
    fi
    for f in "$AUD_ROOT"/etc/sudoers "$AUD_ROOT"/etc/sudoers.d/*; do
        [ -f "$f" ] || continue
        grep -nE '^[^#]*NOPASSWD' "$f" 2>/dev/null | head -5 | while IFS= read -r l; do
            _aud INFO SUDO_NOPASSWD "${f#"$AUD_ROOT"}:$l"; done
    done
    for h in $(_aud_homes); do
        for f in "$AUD_ROOT$h/.ssh/authorized_keys" "$AUD_ROOT$h/.ssh/authorized_keys2"; do
            [ -f "$f" ] || continue
            n=$(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)
            [ "${n:-0}" -eq 0 ] && continue
            cm=$(grep -vE '^[[:space:]]*(#|$)' "$f" | awk '{printf "%s ", $NF}' | cut -c1-150)
            if [ "$h" = "/root" ]; then
                _aud MED AUTHORIZED_KEYS "${f#"$AUD_ROOT"}: ${n} key(s), modified $(_aud_mtime "$f") — comments: ${cm}"
            else
                _aud INFO AUTHORIZED_KEYS "${f#"$AUD_ROOT"}: ${n} key(s), modified $(_aud_mtime "$f") — comments: ${cm}"
            fi
            grep -vE '^[[:space:]]*(#|$)' "$f" | grep -vE '^(ssh-|ecdsa-|sk-)' | cut -c1-120 | head -3 | while IFS= read -r l; do
                _aud MED KEY_OPTIONS "${f#"$AUD_ROOT"}: key with options (forced command / restrictions): $l"; done
        done
    done
    if [ -s "$AUD_ROOT/etc/ld.so.preload" ]; then
        _aud HIGH LD_PRELOAD "/etc/ld.so.preload is not empty (userland rootkit vector): $(tr '\n' ' ' < "$AUD_ROOT/etc/ld.so.preload" | cut -c1-200)"
    fi
}

# lines of file(s) matching a pattern -> findings (comments skipped, max 8 per file)
_aud_pat_scan() {   # severity tag pattern file...
    local sev="$1" tag="$2" pat="$3" f ln shown; shift 3
    for f in "$@"; do
        [ -f "$f" ] || continue
        shown=0
        while IFS= read -r ln; do
            _aud "$sev" "$tag" "${f#"$AUD_ROOT"}:$(printf '%s' "$ln" | cut -c1-200)"
            shown=$(( shown + 1 )); [ "$shown" -ge 8 ] && break
        done < <(grep -nE -- "$pat" "$f" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#')
    done
}

_aud_check_persistence() {
    echo -e "${B}[*] persistence: cron, systemd, rc.local, shell startup${Z}"
    local d f h
    # per-user crontabs: any content is worth a glance on a hosting box
    for f in "$AUD_ROOT"/var/spool/cron/crontabs/* "$AUD_ROOT"/var/spool/cron/*; do
        [ -f "$f" ] || continue
        grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | cut -c1-160 | head -10 | while IFS= read -r l; do
            _aud INFO CRONTAB "${f#"$AUD_ROOT"}: $l"; done
    done
    _aud_pat_scan MED CRON_SUSPICIOUS "$AUD_PAT_WEAK" \
        "$AUD_ROOT"/etc/crontab "$AUD_ROOT"/etc/cron.d/* "$AUD_ROOT"/var/spool/cron/crontabs/* "$AUD_ROOT"/var/spool/cron/*
    for d in hourly daily weekly monthly; do
        _aud_pat_scan MED CRON_SUSPICIOUS "$AUD_PAT_STRONG" "$AUD_ROOT"/etc/cron.$d/*
    done
    # systemd: only ExecStart-like lines; admin-made units in /etc get the weak pattern
    for f in "$AUD_ROOT"/etc/systemd/system/*.service "$AUD_ROOT"/etc/systemd/system/*/*.service; do
        [ -f "$f" ] && [ ! -L "$f" ] || continue
        _aud_pat_scan MED SYSTEMD_SUSPICIOUS "^[[:space:]]*Exec[A-Za-z]*=.*(${AUD_PAT_WEAK})" "$f"
    done
    for f in "$AUD_ROOT"/usr/lib/systemd/system/*.service "$AUD_ROOT"/lib/systemd/system/*.service; do
        [ -f "$f" ] || continue
        _aud_pat_scan MED SYSTEMD_SUSPICIOUS "^[[:space:]]*Exec[A-Za-z]*=.*(${AUD_PAT_STRONG})" "$f"
    done
    _aud_pat_scan MED STARTUP_SUSPICIOUS "$AUD_PAT_STRONG" "$AUD_ROOT"/etc/rc.local "$AUD_ROOT"/etc/profile \
        "$AUD_ROOT"/etc/bash.bashrc "$AUD_ROOT"/etc/profile.d/*
    for h in $(_aud_homes); do
        for f in .bashrc .profile .bash_profile .bash_login .bash_logout .zshrc; do
            _aud_pat_scan MED STARTUP_SUSPICIOUS "$AUD_PAT_WEAK" "$AUD_ROOT$h/$f"
        done
    done
    # docker API exposed on TCP = remote root for anyone
    for f in "$AUD_ROOT"/etc/docker/daemon.json "$AUD_ROOT"/etc/systemd/system/docker.service.d/* \
             "$AUD_ROOT"/lib/systemd/system/docker.service "$AUD_ROOT"/usr/lib/systemd/system/docker.service; do
        [ -f "$f" ] || continue
        grep -nE 'tcp://(0\.0\.0\.0|\[::\]|:)' "$f" 2>/dev/null | head -3 | while IFS= read -r l; do
            _aud HIGH DOCKER_TCP "${f#"$AUD_ROOT"}: docker API on TCP: $l"; done
    done
}

_aud_check_files() {
    echo -e "${B}[*] tmp directories, tools, shell history${Z}"
    local d f n=0 magic h hs pat
    for d in tmp var/tmp dev/shm run/shm; do
        [ -d "$AUD_ROOT/$d" ] || continue
        n=0
        while IFS= read -r f; do
            n=$(( n + 1 )); [ "$n" -gt 400 ] && break
            magic=$(head -c4 "$f" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
            # /dev/shm and hidden names are where attack tools live; an ELF in plain
            # /tmp is often just an installer or driver, so that is only worth a look
            if [ "$magic" = "7f454c46" ]; then
                case "$d:${f##*/}" in
                    dev/shm:*|run/shm:*|*:.*) _aud HIGH TMP_ELF "ELF binary in /$d (shm / hidden name): ${f#"$AUD_ROOT"} ($(_aud_mtime "$f"))" ;;
                    *) _aud MED TMP_ELF "ELF binary in /$d: ${f#"$AUD_ROOT"} ($(_aud_mtime "$f"))" ;;
                esac
            elif [ -x "$f" ]; then
                case "$d" in
                    dev/shm|run/shm) _aud MED TMP_EXEC "executable file in /$d: ${f#"$AUD_ROOT"} ($(_aud_mtime "$f"))" ;;
                    *) _aud INFO TMP_EXEC "executable file in /$d: ${f#"$AUD_ROOT"} ($(_aud_mtime "$f"))" ;;
                esac
            fi
        done < <(find "$AUD_ROOT/$d" -xdev -maxdepth 4 -type f 2>/dev/null)
    done
    for d in tmp var/tmp dev/shm root home opt usr/local/bin usr/local/sbin; do
        [ -d "$AUD_ROOT/$d" ] || continue
        find "$AUD_ROOT/$d" -xdev -maxdepth 4 -type f \( -iname 'xmrig*' -o -iname 'minerd*' -o -iname 'cpuminer*' \
            -o -iname 'kinsing*' -o -iname 'kdevtmpfsi*' -o -iname 'hydra' -o -iname 'medusa' -o -iname 'ncrack' \
            -o -iname 'masscan' -o -iname 'zmap' -o -iname 'pnscan' -o -iname 'libprocesshider*' \
            -o -iname 'diamorphine*' -o -iname 'sshbrute*' \) 2>/dev/null | head -20 |
            while IFS= read -r f; do _aud MED TOOL_NAME "miner / brute-force / rootkit tool by file name: ${f#"$AUD_ROOT"}"; done
    done
    for h in $(_aud_homes); do
        for hs in .bash_history .zsh_history; do
            f="$AUD_ROOT$h/$hs"
            if [ -L "$f" ] && [ "$(readlink "$f")" = "/dev/null" ]; then
                _aud MED HISTORY_WIPED "${f#"$AUD_ROOT"} -> /dev/null (history disabled)"; continue
            fi
            [ -e "$f" ] || continue
            if [ ! -s "$f" ]; then
                _aud MED HISTORY_EMPTY "${f#"$AUD_ROOT"} exists but is EMPTY (modified $(_aud_mtime "$f")) — history cleared?"; continue
            fi
            _aud_pat_scan MED HISTORY_SUSPICIOUS "$AUD_PAT_STRONG" "$f"
        done
    done
}

_aud_check_authlog() {
    echo -e "${B}[*] sshd authentication logs${Z}"
    local logs=() f out acc loc hop nacc nfail tot
    while IFS= read -r f; do [ -n "$f" ] && logs+=("$f"); done < <(lst=$(ls -1 "$AUD_ROOT"/var/log/auth.log* "$AUD_ROOT"/var/log/secure* 2>/dev/null | sort -u)
                  printf '%s\n' "$lst" | sort -rV 2>/dev/null || printf '%s\n' "$lst" | sort -r)
    if [ "${#logs[@]}" -eq 0 ]; then
        _aud INFO AUTHLOG "no /var/log/auth.log* or /var/log/secure* found (journald only? try: journalctl -D <root>/var/log/journal -u ssh)"
        return 0
    fi
    out=$(for f in "${logs[@]}"; do
            case "$f" in
                *.gz) gzip -dc "$f" 2>/dev/null ;;
                *.bz2) bzip2 -dc "$f" 2>/dev/null ;;
                *.xz) xz -dc "$f" 2>/dev/null ;;
                *) cat "$f" 2>/dev/null ;;
            esac
          done | awk '
        function ts_of(   mo, day, t, h) {
            if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/) {
                mo = substr($1,6,2)+0; day = substr($1,9,2)+0; t = substr($1,12,8); LABEL = substr($1,1,10) " " t
            } else {
                mo = (index("JanFebMarAprMayJunJulAugSepOctNovDec", $1)+2)/3; day = $2+0; t = $3; LABEL = $1 " " $2 " " $3
            }
            split(t, h, ":")
            return (CUM[mo]+day)*86400 + h[1]*3600 + h[2]*60 + h[3]
        }
        BEGIN { split("0 31 59 90 120 151 181 212 243 273 304 334", CUM, " ") }
        /sshd(\[[0-9]+\])?: Failed [a-z-]+ for / {
            ip=""; u=""
            for (i=1;i<=NF;i++) { if ($i=="for" && u=="") { u=$(i+1); if (u=="invalid") u=$(i+3) } if ($i=="from") { ip=$(i+1); break } }
            ts_of(); fail[ip]++; nfail++
            if (ip=="127.0.0.1" || ip=="::1" || ip=="::ffff:127.0.0.1") {
                lf++; if (lf==1) lfirst=LABEL; llast=LABEL
                if (!(u in lu) && nlu<8) { lu[u]=1; nlu++; lulist=lulist u " " }
            }
            next
        }
        /sshd(\[[0-9]+\])?: Accepted / {
            for (i=1;i<=NF;i++) if ($i=="Accepted") { a=i; break }
            meth=$(a+1); user=$(a+3); ip=$(a+5)
            ts=ts_of(); k=ip SUBSEP user SUBSEP meth
            if (!(k in cnt)) { first[k]=LABEL; pf[k]=fail[ip]+0 }
            cnt[k]++; last[k]=LABEL
            if (lastip!="" && ip!=lastip && ts>=lastts && ts-lastts<=60) hop[++nh]=lastlabel "\t" lastip "\t" LABEL "\t" ip "\t" user
            lastip=ip; lastts=ts; lastlabel=LABEL
        }
        END {
            for (k in cnt) { split(k, p, SUBSEP); printf "ACC\t%s\t%s\t%s\t%d\t%s\t%s\t%d\n", p[1], p[2], p[3], cnt[k], first[k], last[k], pf[k] }
            for (i=1;i<=nh;i++) print "HOP\t" hop[i]
            print "LOCAL\t" lf+0 "\t" lfirst "\t" llast "\t" lulist
            print "TOTAL\t" nfail+0
        }')
    _aud INFO AUTHLOG "parsed ${#logs[@]} log file(s): $(printf '%s ' "${logs[@]##*/}")"
    nfail=$(printf '%s\n' "$out" | awk -F'\t' '$1=="TOTAL"{print $2}')
    _aud INFO AUTHLOG "failed password attempts in these logs: ${nfail:-0}"
    # 1. success after many failures from the same IP = password guessed
    printf '%s\n' "$out" | awk -F'\t' '$1=="ACC" && $8>=3' | sort | while IFS=$'\t' read -r _ ip user meth cnt first lastl pf; do
        _aud HIGH LOGIN_AFTER_BRUTEFORCE "'${user}' logged in by ${meth} from ${ip} at ${first} (x${cnt}, last ${lastl}) AFTER ${pf} failed attempts from that IP — password was probably guessed"
    done
    # 2. brute force from the host itself
    loc=$(printf '%s\n' "$out" | awk -F'\t' '$1=="LOCAL"')
    if [ -n "$loc" ]; then
        IFS=$'\t' read -r _ n first lastl ulist <<< "$loc"
        [ "${n:-0}" -ge 5 ] && _aud HIGH LOCAL_BRUTEFORCE "${n} failed SSH logins FROM 127.0.0.1 between ${first} and ${lastl} (users tried: ${ulist}) — a brute-force tool ran on this host, or an SSH tunnel through it"
    fi
    # 3. several IPs within a minute
    printf '%s\n' "$out" | awk -F'\t' '$1=="HOP"' | head -10 | while IFS=$'\t' read -r _ t1 ip1 t2 ip2 user; do
        _aud MED LOGIN_HANDOVER "logins as '${user}' from different IPs within 60s: ${ip1} (${t1}) then ${ip2} (${t2}) — typical of one actor / credential hand-over"
    done
    # 4. root by password
    nacc=$(printf '%s\n' "$out" | awk -F'\t' '$1=="ACC" && $3=="root" && $4=="password"{n++} END{print n+0}')
    [ "$nacc" -gt 0 ] && _aud MED ROOT_PASSWORD_LOGINS "root logged in BY PASSWORD from ${nacc} distinct IP(s) in these logs — make sure every one of them is yours"
    # 5. every successful login (info) — the list the customer has to recognise
    printf '%s\n' "$out" | awk -F'\t' '$1=="ACC"' | sort | head -60 | while IFS=$'\t' read -r _ ip user meth cnt first lastl pf; do
        _aud INFO ACCEPTED "${user} ${meth} from ${ip}  x${cnt}  first ${first}  last ${lastl}  (failed before: ${pf})"
    done
    # 6. accepted logins that wtmp never saw = no tty (command / tunnel / script) or wtmp cleaned
    if command -v last >/dev/null 2>&1 && [ -f "$AUD_ROOT/var/log/wtmp" ]; then
        local seen
        seen=$(for f in "$AUD_ROOT"/var/log/wtmp "$AUD_ROOT"/var/log/wtmp.1; do [ -f "$f" ] && last -f "$f" -i -w 2>/dev/null; done |
               grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
        if [ -n "$seen" ]; then
            printf '%s\n' "$out" | awk -F'\t' '$1=="ACC" && $2 ~ /^([0-9]+\.){3}[0-9]+$/ {print $2"\t"$3"\t"$6}' | sort -u |
            while IFS=$'\t' read -r ip user first; do
                printf '%s\n' "$seen" | grep -qxF "$ip" || \
                    _aud MED LOGIN_NOT_IN_WTMP "${user} from ${ip} (${first}) is in the auth log but NOT in wtmp — no terminal (remote command, tunnel, script) or wtmp was edited"
            done
        fi
    fi
}

_aud_check_since() {
    [ -n "$AUDIT_SINCE" ] || return 0
    echo -e "${B}[*] system files changed since ${AUDIT_SINCE}${Z}"
    local d list=()
    for d in etc root usr/local opt var/spool/cron lib/systemd usr/lib/systemd tmp var/tmp dev/shm usr/bin usr/sbin bin sbin; do
        [ -d "$AUD_ROOT/$d" ] && list+=("$AUD_ROOT/$d")
    done
    find "${list[@]}" -xdev -type f -newermt "$AUDIT_SINCE" -printf '%TY-%Tm-%Td %TH:%TM  %u  %p\n' 2>/dev/null |
        grep -vE '/etc/(ld\.so\.cache|mtab|resolv\.conf|machine-id|hostname|hosts|adjtime)$|\.pm2/(logs|pids)|/\.npm/|/\.cache/|\.viminfo|\.lesshst|_history$' |
        sort | head -150 | while IFS= read -r l; do _aud INFO CHANGED "${l/"$AUD_ROOT"/}"; done
    # home dirs: only hidden files near the top (the rest is customer data — that is the file scanner's job)
    find "$AUD_ROOT/home" -xdev -maxdepth 3 -type f -name '.*' -newermt "$AUDIT_SINCE" -printf '%TY-%Tm-%Td %TH:%TM  %u  %p\n' 2>/dev/null |
        grep -vE '_history$|\.viminfo|\.lesshst|/\.cache/' | sort | head -40 | while IFS= read -r l; do _aud INFO CHANGED "${l/"$AUD_ROOT"/}"; done
}

run_audit() {
    AUD_ROOT="${OFFLINE_ROOT%/}"
    AUD_CNT=$(mktemp 2>/dev/null) || { echo "[FAIL] mktemp failed" >&2; return 1; }
    if [ -n "$AUDIT_SINCE" ] && ! date -d "$AUDIT_SINCE" >/dev/null 2>&1; then
        echo "[FAIL] --audit-since needs a date like 2026-09-29 (got: '${AUDIT_SINCE}')" >&2; return 1
    fi
    echo -e "${B}[*] Compromise audit of: ${AUD_ROOT:-/ (live system)}${Z}"
    if [ -z "$AUD_ROOT" ]; then
        echo -e "${Y}[WARN] Live system: a rootkit can hide from this audit. For a result worth"
        echo -e "       trusting, boot a rescue system, mount the disk and use --offline-root.${Z}"
    elif [ ! -d "$AUD_ROOT/etc" ]; then
        echo -e "${R}[FAIL] ${AUD_ROOT} does not look like a root filesystem (no etc/)${Z}"; return 1
    fi
    _aud_check_mount
    _aud_check_sshd
    _aud_check_accounts
    _aud_check_persistence
    _aud_check_files
    _aud_check_authlog
    _aud_check_since
    echo ""
    AUD_HIGH=$(grep -c '^H' "$AUD_CNT" 2>/dev/null); AUD_MED=$(grep -c '^M' "$AUD_CNT" 2>/dev/null); AUD_INFO=$(grep -c '^I' "$AUD_CNT" 2>/dev/null)
    rm -f "$AUD_CNT"
    echo -e "${B}[*] Audit summary: ${AUD_HIGH} HIGH, ${AUD_MED} MEDIUM, ${AUD_INFO} info${Z}"
    if [ "$AUD_HIGH" -gt 0 ]; then
        echo -e "${R}    HIGH items are strong indicators (guessed password, tooling, rootkit vectors)."
        echo -e "    Treat the host as compromised: rotate every secret, close password SSH, rebuild if in doubt.${Z}"
        return 2
    fi
    [ "$AUD_MED" -gt 0 ] && { echo -e "${Y}    MEDIUM items need a human look (are these logins / keys / jobs yours?).${Z}"; return 1; }
    echo -e "${G}    Nothing found by these checks. That is not proof of a clean host.${Z}"
    return 0
}

# Wrapper: with -o FILE the report is also saved (without colour codes).
run_audit_main() {
    local rc tmp
    if [ -n "$OUTPUT_FILE" ]; then
        tmp=$(mktemp 2>/dev/null) || { echo "[FAIL] mktemp failed" >&2; return 1; }
        run_audit > "$tmp" 2>&1; rc=$?
        cat "$tmp"
        sed 's/\x1b\[[0-9;]*m//g' "$tmp" >> "$OUTPUT_FILE"
        rm -f "$tmp"
        echo "[*] audit report appended to $OUTPUT_FILE"
    else
        run_audit; rc=$?
    fi
    return "$rc"
}
#__AUDIT_MODULE_END__

# ============================================================================
# 11. MODULE: dependency check
# ============================================================================
check_deps() {
    # Check via bb() first (busybox if available, else system) — matches
    # what the script actually uses at runtime.
    local miss=()
    for cmd in find awk grep od dd cut tr wc; do
        if [ -n "$BUSYBOX_BIN" ] && busybox_has_applet "$cmd"; then
            continue
        fi
        command -v "$cmd" &>/dev/null || miss+=("$cmd")
    done
    [ ${#miss[@]} -gt 0 ] && { echo -e "${R}[FAIL] Missing required tools (not in busybox or system): ${miss[*]}${Z}"; exit 1; }
}

# ============================================================================
# 12. MODULE: file collection & worker orchestration
# ============================================================================
# Purely informational — looks (shallow, few levels deep, fast) for
# well-known marker files of common CMS platforms in the scan target, to
# label the report with what it's likely looking at. Deliberately does
# NOT exclude or deprioritize anything based on this: a CMS's own
# cache/tmp/upload directories are exactly where a webshell is most
# likely to land (writable, less scrutinized) — auto-excluding them for
# "performance" would create a false sense of thoroughness while
# silently skipping the places that matter most. This is identification
# only, nothing more.
detect_cms() {
    local root="$1" found=()
    [ -d "$root" ] || return
    local f
    for f in "$root"/wp-config.php "$root"/*/wp-config.php; do
        [ -f "$f" ] && { found+=("WordPress"); break; }
    done
    for f in "$root"/configuration.php "$root"/*/configuration.php; do
        [ -f "$f" ] && bb grep -ql "JConfig" "$f" 2>/dev/null && { found+=("Joomla"); break; }
    done
    [ -d "$root/bitrix" ] && found+=("Bitrix")
    for f in "$root"/sites/default/settings.php "$root"/*/sites/default/settings.php; do
        [ -f "$f" ] && { found+=("Drupal"); break; }
    done
    for f in "$root"/engine/data/dbconfig.php "$root"/*/engine/data/dbconfig.php; do
        [ -f "$f" ] && { found+=("DataLife Engine"); break; }
    done
    [ -d "$root/wp-content" ] && [ ${#found[@]} -eq 0 ] && found+=("WordPress")
    for f in "$root"/config.inc.php "$root"/*/config.inc.php; do
        [ -f "$f" ] && bb grep -ql "PrestaShop\|OpenCart" "$f" 2>/dev/null && { found+=("PrestaShop/OpenCart-family"); break; }
    done
    ((${#found[@]})) && { printf '%s' "${found[0]}"; return; }
}

print_banner() {
    echo -e "${B}=================================================${Z}"
    echo -e "${B} Orphus AV Scanner Unified v${VERSION}${Z}  [OS: $OS | ARCH: $ARCH]"
    echo -e " RAM Ceiling  : ${C}${MAX_RAM_MB} MB${Z}"
    echo -e " Workers      : ${C}${WORKERS}${Z}"
    echo -e " Target       : ${C}${ROOT_DIR}${Z}"
    echo -e " Signatures   : ${C}${SIGNATURES}${Z}"
    echo -e " Max size     : ${C}${MAX_SCAN_MB} MB${Z}"
    local cms_detected; cms_detected=$(detect_cms "$ROOT_DIR")
    [ -n "$cms_detected" ] && echo -e " Detected CMS : ${C}${cms_detected}${Z} (informational only — nothing is excluded based on this)"
    echo -e " SHA256 / MD5 : ${C}${SHA256_CMD} / ${MD5_CMD}${Z}"
    echo -e " YARA         : ${C}${YARA_CMD}${Z}"
    echo -e " strings/file : ${C}${STRINGS_CMD} / built-in magic-bytes${Z}"
    if [ -n "$BUSYBOX_BIN" ]; then
        echo -e " BusyBox      : ${G}ON${Z} -> ${BUSYBOX_BIN}"
    elif [ "$ALLOW_BUSYBOX" = false ]; then
        echo -e " BusyBox      : ${Y}off (--no-busybox, intentional)${Z}"
    else
        echo -e " BusyBox      : ${R}MISSING (system-only) — unusual, check the package${Z}"
    fi
    if [ "$QUARANTINE_ENABLED" = true ]; then
        echo -e " Quarantine   : ${C}ON -> ${QUARANTINE_DIR} (perm ${QUARANTINE_PERM})${Z}"
    else
        echo -e " Quarantine   : off"
    fi
    if [ "$REALTIME_MODE" = true ]; then
        echo -e " Real-time    : ${C}ON${Z} (starts after the base scan)"
    fi
    echo -e "${B}=================================================${Z}"
}

# ============================================================================
# MODULE: incremental scan cache (-I/--incremental, auto-on for -w)
#
# Persists a "path -> (mtime, size)" record for every file found CLEAN on
# the last run. On a later run, any file whose mtime+size still matches is
# skipped ENTIRELY — never queued to a worker, so it costs zero disk I/O,
# not just a cheap in-worker check. This is the biggest lever on an
# IOPS-capped host for anything that gets rescanned repeatedly (real-time
# mode's base scan being the main case, but works for any repeat scan of
# the same tree via -I).
#
# Cache location defaults under the signature dir (persists like the
# compiled-signature cache) unless overridden with --incremental-cache.
# A file that comes back with a THREAT is never written to the cache, so
# it's always re-verified on the next run rather than silently trusted.
# ============================================================================
init_incremental_cache() {
    [ -n "$INCREMENTAL_CACHE_FILE" ] || INCREMENTAL_CACHE_FILE="${SIGNATURES}/.incremental_cache.tsv"
    mkdir -p "$(dirname "$INCREMENTAL_CACHE_FILE")" 2>/dev/null
    [ -f "$INCREMENTAL_CACHE_FILE" ] || : > "$INCREMENTAL_CACHE_FILE"
}

# A "clean" verdict is only valid for the signature set and the options it
# was made with: a file cached clean stayed skipped after -u added a
# signature for it. The cache's first line is "#orphus-icache<TAB>STAMP";
# STAMP changes whenever compile_signatures really (re)compiles (it touches
# .cache/.compiled), another YARA pack is used, ignore_sigs is edited, or
# -m/-A/--deep change. A cache with another (or no) stamp is ignored by the
# filter and not merged from by update_incremental_cache: full rescan, and
# the next run has a cache again.
_incremental_sig_stamp() {
    local cdir="${SIGNATURES}/.cache" pid t_c t_p t_i
    pid=$(_yara_pack_id 2>/dev/null)
    t_c=$(bb stat -c %y "$cdir/.compiled" 2>/dev/null)
    t_p=$(cat "$cdir/packs/$pid/.stamp" 2>/dev/null)
    t_i=$(bb stat -c %y "$IGNORE_SIGS_FILE" 2>/dev/null)
    local t_u=""; [ -n "$(_ignore_sigs_upstream_url)" ] && t_u=$(bb stat -c %y "${SIGNATURES}/ignore_sigs.upstream" 2>/dev/null)
    printf '%s' "sig=${SIGNATURES}|c=${t_c:-none}|pack=${pid}:${t_p}|ign=${t_i:-none}:${t_u:-none}|m=${MAX_SCAN_MB}|A=${SCAN_ARCHIVES}|deep=${DEEP_MODE}|mf=${MEDIA_FAST}" | tr '\t\n' '  '
}
_incremental_cache_valid() {
    local first=""
    [ -s "$INCREMENTAL_CACHE_FILE" ] || return 1
    IFS= read -r first < "$INCREMENTAL_CACHE_FILE" 2>/dev/null
    [ "$first" = "#orphus-icache"$'\t'"$(_incremental_sig_stamp)" ]
}

# Filters $WORK_DIR/all_files_raw.tsv (size\tmode\tkey\tpath, 4 fields;
# key = ctime:dev:inode) down into $WORK_DIR/all_files.tsv (size\tmode\tpath,
# the worker's normal 3-field format) — dropping any line whose (path, key,
# size) exactly matches a cache entry. Sets SKIPPED_UNCHANGED for the final
# report.
# A file name with an embedded newline splits its listing line; the
# orphaned second half can be crafted to look like a whole entry naming ANY
# path ("1<TAB>644<TAB>1<TAB>/home/other/x"), which would then be scanned
# (and quarantined) outside the target. Only paths under ROOT_DIR are kept;
# the fragment itself is still reported (anomaly pass in collect_files).
_AWK_UNDER_ROOT='function under_root(x,  r) { r = ENVIRON["AV_ROOT"]; if (x == r) return 1; if (r != "/") r = r "/"; return index(x, r) == 1 }'
_under_root() { AV_ROOT="$ROOT_DIR" bb awk "$_AWK_UNDER_ROOT"' under_root($0)'; }

apply_incremental_filter() {
    local raw="$WORK_DIR/all_files_raw.tsv"
    local out="$WORK_DIR/all_files.tsv"

    if [ "$INCREMENTAL_MODE" != true ] || ! _incremental_cache_valid; then
        AV_ROOT="$ROOT_DIR" bb awk -F'\t' "$_AWK_UNDER_ROOT"' under_root($4) {print $1"\t"$2"\t"$4}' "$raw" > "$out" 2>/dev/null
        SKIPPED_UNCHANGED=0
        return
    fi

    local skipcount_file="$WORK_DIR/.skipped_count"
    AV_ROOT="$ROOT_DIR" bb awk -F'\t' -v cachefile="$INCREMENTAL_CACHE_FILE" -v skipfile="$skipcount_file" "$_AWK_UNDER_ROOT"'
        BEGIN {
            while ((getline line < cachefile) > 0) {
                if (line ~ /^#/) continue
                split(line, c, "\t")
                known[c[1] "\x1f" c[2] "\x1f" c[3]] = 1   # path\x1fkey\x1fsize
            }
            close(cachefile)
        }
        {
            size=$1; mode=$2; mtime=$3; path=$4
            if (!under_root(path)) next
            if ((path "\x1f" mtime "\x1f" size) in known) { skipped++; next }
            print size "\t" mode "\t" path
        }
        END { print skipped+0 > skipfile }
    ' "$raw" > "$out" 2>/dev/null
    SKIPPED_UNCHANGED=$(cat "$skipcount_file" 2>/dev/null || echo 0)
}

# Post-scan: merges this run's results back into the cache. Files that
# were scanned (not skipped) and came back clean get added/refreshed;
# files that came back as a THREAT are explicitly dropped from the cache
# (always re-verified next time); files outside this run's scope entirely
# keep whatever cache entry they already had.
update_incremental_cache() {
    [ "$INCREMENTAL_MODE" = true ] || return 0
    local raw="$WORK_DIR/all_files_raw.tsv"
    [ -s "$raw" ] || return 0

    # "THREAT:TYPE|path|info" — the path itself may contain "|" (cut -f2
    # cut "/w/a|b.php" down to "/w/a", so the real file was cached clean and
    # skipped on every later run). Emit every "|"-prefix of "path|info" as a
    # candidate: extra candidates only keep more files out of the cache.
    local threat_paths="$WORK_DIR/.threat_paths"
    bb grep -h "^THREAT:" "$WORK_DIR/reports"/pool_*.txt "$WORK_DIR/reports"/anomaly_findings.txt 2>/dev/null | bb awk '
        {
            i = index($0, "|"); if (!i) next
            r = substr($0, i + 1); p = ""
            while ((j = index(r, "|")) > 0) {
                p = p substr(r, 1, j - 1); print p
                p = p "|"; r = substr(r, j + 1)
            }
            print p r
        }' > "$threat_paths" 2>/dev/null
    [ -f "$threat_paths" ] || : > "$threat_paths"

    # A worker that died (OOM, kill, crash) never wrote its pool_N.done
    # marker (finalize_worker): its files were not (all) scanned and must
    # not be cached as clean. Its pool lines are "size\tmode\tpath".
    # threads mode: if the YARA consumer did not finish, files of EVERY pool
    # may be missing their YARA check (we don't know which batches it had).
    local pool yara_lost=false
    [ -f "$WORK_DIR/reports/pool_yara.txt" ] && [ ! -f "$WORK_DIR/reports/pool_yara.done" ] && yara_lost=true
    # files over -m that nothing opened (listed as "Not scanned"): not clean
    cat "$WORK_DIR/reports"/*.skipped 2>/dev/null | cut -f2- >> "$threat_paths"
    for pool in "$WORK_DIR/reports"/pool_*.txt; do
        [ -f "$pool" ] || continue
        [ "$yara_lost" = false ] && [ -f "${pool%.txt}.done" ] && continue
        bb awk -F'\t' 'NF >= 3 { print $3 }' "$pool" >> "$threat_paths" 2>/dev/null
    done

    local oldcache="$INCREMENTAL_CACHE_FILE"
    _incremental_cache_valid || oldcache=/dev/null

    local new_cache="${INCREMENTAL_CACHE_FILE}.new"
    printf '#orphus-icache\t%s\n' "$(_incremental_sig_stamp)" > "$new_cache" 2>/dev/null
    AV_ROOT="$ROOT_DIR" bb awk -F'\t' -v threatfile="$threat_paths" -v oldcache="$oldcache" "$_AWK_UNDER_ROOT"'
        BEGIN {
            while ((getline line < threatfile) > 0) { threat[line] = 1 }
            close(threatfile)
            while ((getline line < oldcache) > 0) {
                if (line ~ /^#/) continue
                split(line, c, "\t")
                oldval[c[1]] = line
            }
            close(oldcache)
        }
        {
            size=$1; mtime=$3; path=$4
            if (!under_root(path)) next
            seen[path] = 1
            if (!(path in threat)) print path "\t" mtime "\t" size
        }
        END {
            for (p in oldval) if (!(p in seen)) print oldval[p]
        }
    ' "$raw" >> "$new_cache" 2>/dev/null
    mv -f "$new_cache" "$INCREMENTAL_CACHE_FILE" 2>/dev/null
}

collect_files() {
    echo -e "[*] Collecting file tree..."
    # Excluded paths are PRUNED (find never descends into them) instead of
    # walked and filtered with -not -path: same file list, but /proc, /sys,
    # the quarantine dir and big -X trees are no longer traversed. Each path
    # P matches as "P" and "P/*". Built into excl=( \( ... \) -prune -o ).
    # /dev is pruned except /dev/shm: that tmpfs holds regular files, and
    # droppers/miners hide there (".khp", random-named ELF) because it
    # leaves nothing on disk. Other scanner instances' own dirs there and
    # in /tmp are skipped by name.
    local prune=(/proc /sys)

    # Always exclude the scanner's own footprint (install dir, signature
    # dir, quarantine dir, ephemeral work dir, live report file) —
    # otherwise scanning a target that happens to contain the AV's own
    # installation makes every YARA rule/signature file "detect" itself,
    # since it literally contains the patterns being searched for
    # (confirmed in practice: scanning "/" produced hundreds of
    # self-matches against signatures/yara/*.yar). This logic lives here
    # inline, not in a separately-named function — if you're looking for
    # "init_self_exclude()" from an old comment elsewhere, this is it.
    #
    # FIX (real bug reported): WORK_DIR was missing from this list —
    # SCRIPT_DIR and SIGNATURES were covered, but the EPHEMERAL per-run
    # work directory (worker.sh, reports, extracted setup module) was
    # not, so worker.sh itself — which necessarily contains the literal
    # string patterns this scanner looks for, since that's what a copy
    # of its own detection logic looks like — got flagged scanning its
    # own temp file. Confirmed in practice: "/tmp/av_scan_NNNNN/worker.sh
    # pattern=eval(base64_decode". SIG_DIR listed separately too — it's
    # usually WORK_DIR/sigs (already covered), but --sig-in-ram can place
    # it at its own /dev/shm/av_sigs_NNNNN path outside WORK_DIR entirely.
    local self_paths=("$SCRIPT_DIR" "$SIGNATURES" "$WORK_DIR" "$SIG_DIR")
    [ "$QUARANTINE_ENABLED" = true ] && self_paths+=("$QUARANTINE_DIR")
    local p
    # Report files and their -SUID/.slow siblings (they quote matched
    # strings, so a report inside the scanned tree would "detect" itself).
    for p in "$LIVE_REPORT_FILE" "$OUTPUT_FILE"; do
        [ -n "$p" ] && self_paths+=("$p" "$p-SUID" "$p.slow")
    done

    # User-specified extra exclusions (-X/--exclude, repeatable)
    # FIX (real bug reported): a trailing slash in the person's OWN input
    # (e.g. "-X /mnt/home/", a completely natural way to type a directory
    # path) silently broke BOTH generated patterns — "-not -path
    # '/mnt/home/'" can never match a directory (find reports it WITHOUT
    # the trailing slash), and "-not -path '/mnt/home//*'" needs a
    # literal double-slash in the real path to match, which normal
    # filesystem paths never have. Confirmed directly: with the trailing
    # slash, find excluded NOTHING; stripped, it worked correctly.
    # Strip exactly one trailing slash (unless the path IS just "/") before
    # building the pattern.
    self_paths+=("${EXCLUDE_PATHS[@]}")
    local q
    for p in "${self_paths[@]}"; do
        [ -n "$p" ] || continue
        [ "$p" != "/" ] && p="${p%/}"
        prune+=("$p")
        # ROOT_DIR is physical (normalize_args), so find prints physical
        # paths: also prune the path with its PARENT symlink-resolved
        # (scanner under www -> public_html, -X www/cache). The last
        # component stays literal — it may be site-owned, and a -X dir
        # swapped for a symlink to the docroot must not prune the site —
        # and ROOT_DIR itself or anything above it is never pruned this way.
        [ "$p" = "/" ] && continue
        q="${p%/*}"; q=$(_phys_dir "${q:-/}"); [ "$q" = "/" ] && q=""
        q="$q/${p##*/}"
        case "$ROOT_DIR/" in "$q/"*) continue ;; esac
        [ "$q" != "$p" ] && prune+=("$q")
    done
    local excl=(\()
    for p in "${prune[@]}"; do
        [ "${#excl[@]}" -gt 1 ] && excl+=(-o)
        excl+=(-path "$p" -o -path "${p%/}/*")
    done
    excl+=(-o \( -path '/dev/*' ! -path /dev/shm ! -path '/dev/shm/*' \))
    excl+=(-o -path '/dev/shm/av_scan_*' -o -path '/dev/shm/av_sigs_*' -o -path '/tmp/av_scan_*')
    excl+=(\) -prune -o)

    # FIX (real bug found, pre-existing — not introduced by incremental
    # mode): this printf-capability check used to go through bb() (which
    # routes to busybox's find when busybox is bundled/preferred) — but
    # busybox's find does NOT support -printf AT ALL ("unrecognized:
    # -printf"). Since busybox is the preferred path throughout this
    # script, that meant the size/mode-via-printf optimization here had
    # essentially never actually been active in practice: every file fell
    # back to the worker doing individual stat() calls per file instead of
    # getting size+mode for free from the one `find` pass. GNU find (the
    # system one, NOT busybox's) supports -printf properly, so this now
    # explicitly uses `command find` for this specific call, bypassing
    # bb() on purpose — busybox find is still used everywhere else it's
    # actually correct (the plain -print fallback below, and every other
    # find call in the script).
    local sys_find_printf_ok=false
    if [ "$OS" = "linux" ] && command -v find &>/dev/null && command find "$SCRIPT_DIR" -maxdepth 0 -printf "" 2>/dev/null; then
        sys_find_printf_ok=true
    fi

    if [ "$sys_find_printf_ok" = true ]; then
        # Third field is the incremental-cache key: ctime:dev:inode, not
        # mtime — mtime is forgeable with `touch -d/-r` after editing (H4);
        # ctime cannot be set back by an unprivileged user.
        # Records are NUL-terminated and a newline INSIDE a name becomes \001,
        # so a name (or a directory name) with an embedded newline can no
        # longer split into a forged "size<TAB>mode<TAB>key<TAB>/any/path"
        # line. Such records, and names with a TAB (would shift the fields),
        # are set aside as SUSPICIOUS_FILENAME instead of being queued or cached.
        command find -H "$ROOT_DIR" "${excl[@]}" -type f -printf "%s\t%m\t%C@:%D:%i\t%p\0" 2>/dev/null \
            | tr '\n\000' '\001\n' > "$WORK_DIR/all_files_raw.all"
        bb awk -F'\t' -v bad="$WORK_DIR/odd_names.lst" '
            NF != 4 || $4 ~ /\001/ { print > bad; next }
            { print }' "$WORK_DIR/all_files_raw.all" > "$WORK_DIR/all_files_raw.tsv" 2>/dev/null
        rm -f "$WORK_DIR/all_files_raw.all"
        apply_incremental_filter
    else
        # No printf-capable find available (BSD find on macOS, or no
        # system find at all) — incremental mode has no effect on this
        # path, every file is always scanned (correct, just not
        # IOPS-optimized here).
        bb find -H "$ROOT_DIR" "${excl[@]}" -type f -print 2>/dev/null | _under_root > "$WORK_DIR/all_files.tsv"
        SKIPPED_UNCHANGED=0
    fi
    TOTAL_FILES=$(bb wc -l < "$WORK_DIR/all_files.tsv" | tr -d ' ')
    if [ "${SKIPPED_UNCHANGED:-0}" -gt 0 ] 2>/dev/null; then
        echo -e "[*] Files queued: ${C}${TOTAL_FILES}${Z} (skipped ${C}${SKIPPED_UNCHANGED}${Z} unchanged since last clean scan)\n"
    else
        echo -e "[*] Files queued: ${C}${TOTAL_FILES}${Z}\n"
    fi

    # FIX (real gap found in security review): every path above collects
    # files via newline-separated `find -print`/-printf — a filename
    # containing an actual embedded newline byte (unusual, but real and
    # legal on Linux — confirmed directly: `touch` happily creates one)
    # would get SPLIT across two lines there, and the resulting garbage
    # fragments essentially never match a real file, so `[ -f ... ]`-style
    # checks downstream just silently skip it. That means a file named
    # this way could dodge scanning ENTIRELY — a real, if obscure, evasion
    # technique specifically worth caring about in an AV scanner. Fully
    # converting the whole collection/pool-distribution pipeline to
    # NUL-separated records would close this more completely, but it's a
    # substantial rewrite of a heavily-tested core path; this is the
    # narrower, lower-risk fix: a SEPARATE, NUL-safe (-print0) pass whose
    # only job is to catch and flag anomalous filenames directly — no
    # legitimate file has a newline (or other raw control byte) in its
    # name, so the mere existence of one is itself a strong signal, even
    # though this pass doesn't try to hash/YARA-scan its CONTENT.
    # FIX (real bug found in testing): this file used to be named
    # "pool_anomaly.txt" — which matched the SAME "pool_*.txt" glob the
    # worker-launch loop uses to decide what to spawn a worker for! A
    # worker started up treating it as a real work queue, found nothing
    # scannable in it, and overwrote it with its own startup/completion
    # log lines — clobbering the THREAT line before it was ever read.
    # Renamed to a pattern that can't collide with that glob; the
    # aggregation call sites explicitly include it as a second path
    # alongside pool_*.txt instead.
    # FIX (real perf problem reported: ~9 minutes to index 3M files):
    # this used to run a SEPARATE, FULL SECOND `find -print0` traversal
    # of the ENTIRE target tree just to catch anomalous filenames —
    # doubling the filesystem-walk cost on every scan, dominant exactly
    # at the multi-million-file scale where it hurts most. The same
    # detection is derivable from the MAIN find pass's OWN output
    # instead, with zero extra tree-walking: an embedded newline in a
    # filename SPLITS that record across two lines of the -printf output
    # (confirmed directly) — the first half still looks like a normal,
    # well-formed "size\tmode\tmtime\tpath..." line (just with a
    # truncated path), but the second half is an orphaned fragment that
    # does NOT start with the expected "digit\tdigit\tfloat\t" prefix.
    # Grepping the ALREADY-COLLECTED listing for lines that don't match
    # that prefix finds exactly those orphaned fragments — same
    # detection, one tree-walk instead of two. Only applies on the
    # sys_find_printf_ok path (the common case); the plain -print
    # fallback (no GNU find) doesn't have a structured prefix to check
    # against, so this pass is skipped there rather than adding back a
    # separate full traversal for a less-common environment.
    if [ "$sys_find_printf_ok" = true ]; then
        local anomaly_report="$WORK_DIR/reports/anomaly_findings.txt"
        : > "$anomaly_report" 2>/dev/null
        # records set aside by the collection pass above (newline / TAB in
        # a file or directory name): flagged, never scanned or cached
        [ -s "$WORK_DIR/odd_names.lst" ] && while IFS= read -r frag; do
            [ -z "$frag" ] && continue
            frag="${frag#*	*	*	}"
            printf 'THREAT:SUSPICIOUS_FILENAME|%s|newline/TAB byte in the file or directory name -- not scanned by the normal pipeline; investigate directly (find PATH -type f -print0)\n' \
                "$(printf '%s' "$frag" | tr '\001-\037\177' '?' | head -c 300)" >> "$anomaly_report"
        done < "$WORK_DIR/odd_names.lst"
    fi
}

split_pools() {
    bb awk -v w="$WORKERS" -v d="$WORK_DIR/reports" '{ print > (d "/pool_" (NR % w) ".txt") }' "$WORK_DIR/all_files.tsv"
}

# Launches CMD... as its own SESSION/PROCESS GROUP LEADER when setsid is
# available (checked once, cached in HAS_SETSID) — this is what lets
# cleanup() below kill a worker's ENTIRE process tree (including whatever
# yara/grep/etc subprocess it currently has running) with one signal,
# instead of only the worker's own PID while any in-flight child gets
# orphaned and keeps running. Falls back to a plain background launch if
# setsid isn't available (non-Linux, minimal container) — cleanup() then
# falls back too, matching the previous (imperfect but not worse) behavior.
_launch_grouped() {
    if [ "$HAS_SETSID" = true ]; then
        setsid "$@" &
    else
        "$@" &
    fi
}

# --explain FILE: one worker, in the foreground, on this one file, telling
# for every check what it found and why a hit is reported or suppressed
# (ignore_sigs line, built-in noisy rule, vendor allowlist, PUA, ...).
run_explain() {
    local f qdir=""
    f=$(_abs_path "$EXPLAIN_FILE")
    if [ ! -f "$f" ] || [ ! -r "$f" ]; then
        echo -e "${R}[FAIL] --explain: '$EXPLAIN_FILE' is not a readable regular file${Z}" >&2
        return 1
    fi
    [ "$QUARANTINE_ENABLED" = true ] && echo -e "${Y}[*] --explain never quarantines (-q ignored)${Z}"
    printf '%s\t%s\t%s\n' "$(stat -c %s "$f" 2>/dev/null || wc -c < "$f" | tr -d ' ')" "$(stat -c %a "$f" 2>/dev/null || echo 644)" "$f" \
        > "$WORK_DIR/reports/pool_explain.txt"
    echo -e "${B}[*] Explaining: $f${Z}"
    echo -e "    pack '$(_yara_pack_id)', ClamAV groups: ${CLAM_GROUPS:-?}, deep: ${DEEP_MODE}, -m ${MAX_SCAN_MB} MB, media-fast: ${MEDIA_FAST}"
    AV_EXPLAIN=1 "$WORKER_BASH" "$WORKER_FILE" \
        "$WORK_DIR/reports/pool_explain.txt" "explain" "$WORK_DIR/reports" \
        "$SIG_DIR" "$MAX_SCAN_MB" "$OS" \
        "$SHA256_CMD" "$MD5_CMD" "$STRINGS_CMD" "$FILE_CMD" "$YARA_CMD" \
        "$qdir" "$QUARANTINE_PERM" "$BUSYBOX_BIN" \
        "$BATCH_SIZE" "$HEUR_BATCH_SIZE" "$PE_BATCH_SIZE" "" "$IGNORE_SIGS_FILE" "$SCAN_ARCHIVES" "$ARCHIVE_MAX_MB" "$ARCHIVE_MAX_EXTRACT_MB" "$ARCHIVE_MAX_DEPTH" "$ARCHIVE_MAX_FILES" "$USE_RAM" "$GREP_BIN" "$SUID_VERIFY_MODE" "$YARA_TIMEOUT_SEC" "false" "$LONG_TIME_THRESHOLD_SEC" "$ARCHIVE_RAM_MAX_MB" "$ARCHIVE_USE_RAM" "$GENERIC_OBFUSCATION_RULES_FILE" "$KNOWN_VENDOR_OBFUSCATION_FILE" "$SANDBOX_MODE" "$SANDBOX_USER" "$SANDBOX_MEM_KB" "$SANDBOX_CPU_SEC" "$DEEP_MODE" "$SHA1_CMD" "$$" "false" "$QUARANTINE_SKIP_ARCHIVES" ""
    local rc=$?
    rm -rf "$WORK_DIR"
    case "$SIG_DIR" in /dev/shm/av_sigs_*|*/.cache/run.*) rm -rf "$SIG_DIR" 2>/dev/null ;; esac
    return "$rc"
}

launch_workers() {
    echo -e "[*] Launching ${WORKERS} workers (batch hash + YARA)...\n"
    WORKER_PIDS=()
    command -v setsid &>/dev/null && HAS_SETSID=true
    local pool wid qdir=""
    [ "$QUARANTINE_ENABLED" = true ] && qdir="$QUARANTINE_DIR"
    # threads mode: workers queue their YARA batches here (see _yara_ram_cap)
    local yq=""
    if [ "${YARA_MODE:-threads}" = "threads" ] && [ "$YARA_CMD" != "none" ]; then
        yq="$WORK_DIR/reports/.yq"; mkdir -p "$yq"
    fi
    for pool in "$WORK_DIR/reports"/pool_*.txt; do
        [ -f "$pool" ] || continue
        wid=$(basename "$pool" .txt)
        _launch_grouped "$WORKER_BASH" "$WORKER_FILE" \
            "$pool" "$wid" "$WORK_DIR/reports" \
            "$SIG_DIR" "$MAX_SCAN_MB" "$OS" \
            "$SHA256_CMD" "$MD5_CMD" "$STRINGS_CMD" "$FILE_CMD" "$YARA_CMD" \
            "$qdir" "$QUARANTINE_PERM" "$BUSYBOX_BIN" \
            "$BATCH_SIZE" "$HEUR_BATCH_SIZE" "$PE_BATCH_SIZE" "$LIVE_REPORT_FILE" "$IGNORE_SIGS_FILE" "$SCAN_ARCHIVES" "$ARCHIVE_MAX_MB" "$ARCHIVE_MAX_EXTRACT_MB" "$ARCHIVE_MAX_DEPTH" "$ARCHIVE_MAX_FILES" "$USE_RAM" "$GREP_BIN" "$SUID_VERIFY_MODE" "$YARA_TIMEOUT_SEC" "$LONG_TIME_MODE" "$LONG_TIME_THRESHOLD_SEC" "$ARCHIVE_RAM_MAX_MB" "$ARCHIVE_USE_RAM" "$GENERIC_OBFUSCATION_RULES_FILE" "$KNOWN_VENDOR_OBFUSCATION_FILE" "$SANDBOX_MODE" "$SANDBOX_USER" "$SANDBOX_MEM_KB" "$SANDBOX_CPU_SEC" "$DEEP_MODE" "$SHA1_CMD" "$$" "$QUARANTINE_DRY_RUN" "$QUARANTINE_SKIP_ARCHIVES" "$SUID_REPORT_FILE"
        WORKER_PIDS+=($!)
    done
    if [ -n "$yq" ]; then
        # the YARA consumer: same worker script, empty pool, own report
        # (pool_yara.txt, so threats/progress/incremental cache pick it up)
        : > "$WORK_DIR/reports/pool_yara.txt"
        export AV_YARA_ROLE=consumer AV_YARA_WPIDS="${WORKER_PIDS[*]}" AV_YARA_NWORKERS="${#WORKER_PIDS[@]}"
        _launch_grouped "$WORKER_BASH" "$WORKER_FILE" \
            "$WORK_DIR/reports/pool_yara.txt" "pool_yara" "$WORK_DIR/reports" \
            "$SIG_DIR" "$MAX_SCAN_MB" "$OS" \
            "$SHA256_CMD" "$MD5_CMD" "$STRINGS_CMD" "$FILE_CMD" "$YARA_CMD" \
            "$qdir" "$QUARANTINE_PERM" "$BUSYBOX_BIN" \
            "$BATCH_SIZE" "$HEUR_BATCH_SIZE" "$PE_BATCH_SIZE" "$LIVE_REPORT_FILE" "$IGNORE_SIGS_FILE" "$SCAN_ARCHIVES" "$ARCHIVE_MAX_MB" "$ARCHIVE_MAX_EXTRACT_MB" "$ARCHIVE_MAX_DEPTH" "$ARCHIVE_MAX_FILES" "$USE_RAM" "$GREP_BIN" "$SUID_VERIFY_MODE" "$YARA_TIMEOUT_SEC" "$LONG_TIME_MODE" "$LONG_TIME_THRESHOLD_SEC" "$ARCHIVE_RAM_MAX_MB" "$ARCHIVE_USE_RAM" "$GENERIC_OBFUSCATION_RULES_FILE" "$KNOWN_VENDOR_OBFUSCATION_FILE" "$SANDBOX_MODE" "$SANDBOX_USER" "$SANDBOX_MEM_KB" "$SANDBOX_CPU_SEC" "$DEEP_MODE" "$SHA1_CMD" "$$" "$QUARANTINE_DRY_RUN" "$QUARANTINE_SKIP_ARCHIVES" "$SUID_REPORT_FILE"
        WORKER_PIDS+=($!)
        unset AV_YARA_ROLE AV_YARA_WPIDS AV_YARA_NWORKERS
    fi
}

wait_for_workers() {
    local pid
    for pid in "${WORKER_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
    kill "$MONITOR_PID" 2>/dev/null || true
    # threads mode: anything still queued was never YARA-scanned (consumer died)
    local left pool lost=""
    left=$(cat "$WORK_DIR/reports/.yq"/*.lst 2>/dev/null | tr -cd '\0' | wc -c)
    if [ "${left:-0}" -gt 0 ]; then
        echo -e "${R}[WARN] ${left} file(s) were queued for YARA but never scanned (the YARA consumer stopped early) — rerun, or use --yara-mode workers${Z}"
    fi
    # a worker (or the YARA consumer) that ended without finishing: its last
    # files - for the consumer, the batch it was scanning - were not checked
    for pool in "$WORK_DIR/reports"/pool_*.txt; do
        [ -f "$pool" ] || continue
        [ -f "${pool%.txt}.done" ] || lost+=" $(basename "$pool" .txt)"
    done
    if [ -n "$lost" ]; then
        echo -e "${R}[WARN] Scan INCOMPLETE: worker(s)${lost} stopped before finishing (killed / out of memory?) - some files were not fully checked. Rerun the scan.${Z}"
    fi
    tput cnorm 2>/dev/null || true
}

# ============================================================================
# 13. MODULE: progress monitor / cleanup
# ============================================================================
# Last resort of the RAM ceiling: SIGKILL the biggest yara process under the
# given root PIDs. Safe by construction — the worker that owned it sees the
# signal exit and rescans that batch file by file (see process_yara_batch), so
# nothing is silently counted as clean. Echoes "pid mb" of the victim.
_ram_kill_biggest_yara() {
    local out victim
    out=$(ps -eo pid=,ppid=,rss=,comm= 2>/dev/null)
    victim=$(printf '%s\n' "$out" | bb awk -v roots="$*" -v yb="${YARA_CMD##*/}" '
        BEGIN { n=split(roots, r, " "); for(i=1;i<=n;i++) mark[r[i]]=1 }
        { pid[NR]=$1; ppid[NR]=$2; rss[NR]=$3; comm[NR]=$4; cnt=NR }
        END {
            do { ch=0
                for(i=1;i<=cnt;i++) if(!(pid[i] in mark) && (ppid[i] in mark)) { mark[pid[i]]=1; ch=1 }
            } while(ch)
            best=0; bp=""
            for(i=1;i<=cnt;i++) if((pid[i] in mark) && comm[i]==yb && rss[i]>best) { best=rss[i]; bp=pid[i] }
            if (bp != "") print bp, int(best/1024)
        }')
    [ -n "$victim" ] || return 1
    set -- $victim
    kill -KILL "$1" 2>/dev/null || return 1
    echo "$victim"
}

show_progress() {
    local prev=0 prev_ms="$START_MS"
    local over_ticks=0 gate_file="$WORK_DIR/reports/.ram_high" ev_file="$WORK_DIR/reports/.ram_events"
    tput civis 2>/dev/null || true
    printf '\n\n\n\n\n'
    while true; do
        local now elapsed_ms elapsed_s
        now=$(now_ms)
        elapsed_ms=$(( now - START_MS )); elapsed_s=$(( elapsed_ms / 1000 ))

        local tf=0 tt=0 tpm=0 tsu=0
        for f in "$WORK_DIR/reports"/pool_*.progress; do
            [ -f "$f" ] || continue
            local fv tv pv
            fv=$(grep "^FILES=" "$f" 2>/dev/null | cut -d= -f2)
            tv=$(grep "^THREATS=" "$f" 2>/dev/null | cut -d= -f2)
            pv=$(grep "^PERMS=" "$f" 2>/dev/null | cut -d= -f2)
            tf=$(( tf + ${fv:-0} )); tt=$(( tt + ${tv:-0} )); tpm=$(( tpm + ${pv:-0} ))
            pv=$(grep "^SUID=" "$f" 2>/dev/null | cut -d= -f2); tsu=$(( tsu + ${pv:-0} ))
        done

        local dt=$(( now - prev_ms )) fps=0 avg=0
        [ "$dt" -gt 0 ] && fps=$(( (tf - prev) * 1000 / dt ))
        [ "$fps" -lt 0 ] && fps=0
        [ "$elapsed_s" -gt 0 ] && avg=$(( tf / elapsed_s ))
        prev=$tf; prev_ms=$now

        local eta="--:--"
        [ "${avg:-0}" -gt 0 ] && [ "${TOTAL_FILES:-0}" -gt "$tf" ] && {
            local r=$(( (TOTAL_FILES - tf) / avg ))
            eta=$(printf '%02d:%02d' $(( r/60 )) $(( r%60 )))
        }

        local active=0 active_pids=($$ "$MONITOR_PID")
        for pid in "${WORKER_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                active=$(( active + 1 ))
                active_pids+=("$pid")
            fi
        done

        local mem_mb=0
        if [ "${#active_pids[@]}" -gt 0 ]; then
            # FIX (real bug reported, confirmed on a 24-worker scan: htop
            # showed ~5GB in use by ~25 yara processes at 170-350MB each,
            # while this counter said 419MB): this used to sum the workers
            # plus their DIRECT children only (`ps --ppid`). But yara never
            # runs as a direct child — it runs as worker -> $(...) subshell
            # -> timeout -> yara, so every actual yara process (the biggest
            # memory consumer, each one loading the whole compiled rule
            # set) was invisible and only the shared signature DB in
            # /dev/shm was being counted. Walk the FULL descendant tree of
            # every worker instead (reproduced in isolation: a 150MB
            # process under worker->timeout showed as 5MB with the old
            # method, 163MB with this one). One `ps` call per tick, tree
            # closure done in awk, so cost stays flat as workers grow.
            # Caveat: RSS double-counts pages genuinely shared between
            # processes (small for yara — rules are private heap), so this
            # errs slightly high rather than low, the safe direction for
            # a ceiling.
            mem_mb=$(_tree_rss_mb "${active_pids[@]}")
        fi
        # FIX (real bug reported): process RSS is BLIND to /dev/shm
        # (tmpfs) usage — reading a file from tmpfs doesn't inflate the
        # READING process's own RSS the way heap/stack allocations do,
        # even though tmpfs content is unambiguously real system RAM
        # (confirmed directly: a 50MB file in /dev/shm showed 0 in the
        # reading process's RSS). This under-reported real usage
        # specifically whenever WORK_DIR or --sig-in-ram's SIG_DIR live in
        # /dev/shm (~300MB actual vs ~12MB shown, per the report) — add
        # actual tmpfs usage for both paths on top of process RSS.
        local shm_mb=0 _du
        case "$WORK_DIR" in
            /dev/shm/*)
                _du=$(du -sm "$WORK_DIR" 2>/dev/null | cut -f1)
                shm_mb=$(( shm_mb + ${_du:-0} ))
                ;;
        esac
        case "$SIG_DIR" in
            "$WORK_DIR"/*) : ;;  # already counted above, part of WORK_DIR
            /dev/shm/*)
                _du=$(du -sm "$SIG_DIR" 2>/dev/null | cut -f1)
                shm_mb=$(( shm_mb + ${_du:-0} ))
                ;;
        esac
        mem_mb=$(( mem_mb + shm_mb ))
        local ram_pct=0
        [ "$MAX_RAM_MB" -gt 0 ] && ram_pct=$(( mem_mb * 100 / MAX_RAM_MB ))

        # ---- RAM ceiling enforcement (it used to be display-only) ----
        # >= 90%: raise a gate — workers hold back from STARTING new yara
        #   processes (each one loads the whole compiled ruleset), so running
        #   ones finish and memory drains; nothing is lost. Cleared at <= 75%.
        # >= 105% for 4 ticks in a row despite the gate: SIGKILL the biggest
        #   yara; its batch is rescanned file by file by the worker.
        if [ "$MAX_RAM_MB" -gt 0 ]; then
            if [ "$ram_pct" -ge 90 ]; then
                [ -e "$gate_file" ] || { : > "$gate_file"; echo "$(date +%H:%M:%S) gate ON  at ${mem_mb}MB (${ram_pct}%)" >> "$ev_file"; }
            elif [ "$ram_pct" -le 75 ] && [ -e "$gate_file" ]; then
                rm -f "$gate_file"; echo "$(date +%H:%M:%S) gate OFF at ${mem_mb}MB (${ram_pct}%)" >> "$ev_file"
            fi
            if [ "$ram_pct" -ge 105 ]; then
                # a mild overshoot may just be yara loading its ruleset, so give
                # it 4 ticks; a big one (>= 150%) can't wait that long
                local need=4
                [ "$ram_pct" -ge 150 ] && need=2
                over_ticks=$(( over_ticks + 1 ))
                if [ "$over_ticks" -ge "$need" ]; then
                    local vic; vic=$(_ram_kill_biggest_yara "${active_pids[@]}")
                    [ -n "$vic" ] && echo "$(date +%H:%M:%S) KILLED yara pid=${vic% *} (${vic#* } MB) at ${mem_mb}MB (${ram_pct}%)" >> "$ev_file"
                    # still over after this kill? then the NEXT tick may kill
                    # again without waiting out a fresh countdown
                    over_ticks=$(( need - 1 ))
                fi
            else
                over_ticks=0
            fi
        fi

        local cpu_load="0.00"
        if [ -r /proc/loadavg ]; then
            cpu_load=$(awk '{print $1}' /proc/loadavg 2>/dev/null)
        else
            cpu_load=$(uptime 2>/dev/null | awk -F'load averages?:' '{print $2}' | cut -d, -f1 | tr -d ' ')
        fi

        local efmt; efmt=$(printf '%02d:%02d' $(( elapsed_s/60 )) $(( elapsed_s%60 )))
        local tc="$G"; [ "$tt" -gt 0 ] && tc="$R"

        printf '\033[5A'
        printf '\033[K'"${B}Time     :${Z} %-8s ${C}Workers : %d/%d${Z}\n" "$efmt" "$active" "$WORKERS"
        printf '\033[K'"${B}Files    :${Z} %-8d ${tc}${B}Threats : %d${Z}%s\n" "$tf" "$tt" "$([ "$tpm" -gt 0 ] && printf '   Perms : %d' "$tpm"; [ "$tsu" -gt 0 ] && printf '   SUID : %d' "$tsu")"
        printf '\033[K'"${B}Speed    :${Z} %-8s ${C}RAM     : %s / %s MB (%d%%)${Z}\n" "${fps} f/s" "${mem_mb:-0}" "$MAX_RAM_MB" "$ram_pct"
        printf '\033[K'"${B}Avg Speed:${Z} %-8s ${C}CPU Load: %s${Z}\n" "${avg} f/s" "${cpu_load:-0.00}"
        printf '\033[K'"${B}ETA      :${Z} %s\n" "$eta"
        sleep 1
    done
}

# Total RSS (MB) of the given root PIDs plus ALL their descendants,
# not just direct children — see the comment at its one call site in
# start_monitor() for why direct children aren't enough.
_tree_rss_mb() {
    local out res rss_mb anon
    out=$(ps -eo pid=,ppid=,rss= 2>/dev/null)
    [ -z "$out" ] && out=$(ps -o pid=,ppid=,rss= 2>/dev/null)
    res=$(printf '%s\n' "$out" | bb awk -v roots="$*" '
        BEGIN { n=split(roots, r, " "); for(i=1;i<=n;i++) mark[r[i]]=1 }
        { pid[NR]=$1; ppid[NR]=$2; rss[NR]=$3; cnt=NR }
        END {
            do { ch=0
                for(i=1;i<=cnt;i++) if(!(pid[i] in mark) && (ppid[i] in mark)) { mark[pid[i]]=1; ch=1 }
            } while(ch)
            for(i=1;i<=cnt;i++) if(pid[i] in mark) { s+=rss[i]; print "P", pid[i] }
            print "S", int(s/1024)
        }')
    rss_mb=$(printf '%s\n' "$res" | bb awk '$1=="S" {print $2}')
    # The ceiling is about memory that can actually run out, which is the
    # processes' ANONYMOUS memory (RssAnon). Plain RSS also counts file pages
    # a process has mapped — yara maps every file it scans, up to
    # MAX_SCAN_MB each — and those are reclaimable page cache, not pressure
    # (measured: scanning a 150MB file with trivial rules showed RSS=135MB,
    # RssAnon=0). tmpfs (/dev/shm) is added separately by the caller, so
    # RssShmem is deliberately not counted here to avoid counting it twice.
    # Falls back to RSS where the kernel doesn't report RssAnon (< 4.5).
    if grep -q '^RssAnon:' /proc/self/status 2>/dev/null; then
        anon=$(cd /proc 2>/dev/null && printf '%s\n' "$res" | bb awk '$1=="P" {print $2 "/status"}' \
               | xargs grep -hE '^RssAnon:' 2>/dev/null | bb awk '{s+=$2} END {print int(s/1024)}')
        [ -n "$anon" ] && { echo "$anon"; return; }
    fi
    echo "${rss_mb:-0}"
}

start_monitor() {
    show_progress &
    MONITOR_PID=$!
}

cleanup() {
    kill "$MONITOR_PID" 2>/dev/null || true
    local p
    for p in "${WORKER_PIDS[@]}"; do
        # FIX (real bug reported): a worker currently blocked inside a
        # foreground child call (yara/grep/etc via command substitution)
        # does NOT pass a signal on to that child when the worker itself
        # is killed — the child gets orphaned (re-parented to init) and
        # keeps running/using CPU indefinitely, exactly what was observed:
        # stopping the script left yara processes still loading the CPU.
        # -TERM to the NEGATIVE pid signals the whole PROCESS GROUP at
        # once (worker + whatever it currently has running), but that's
        # only safe/correct when the worker was launched with setsid
        # (guarantees its own PID == its own PGID — otherwise a negative
        # PID could coincidentally target an unrelated process group).
        if [ "$HAS_SETSID" = true ]; then
            kill -TERM -"$p" 2>/dev/null || kill "$p" 2>/dev/null || true
        else
            kill "$p" 2>/dev/null || true
        fi
    done
    cleanup_realtime
    tput cnorm 2>/dev/null || true

    local found=0
    if [ -n "$LIVE_REPORT_FILE" ] && [ -f "$LIVE_REPORT_FILE" ]; then
        # NOTE: grep -c legitimately PRINTS "0" on zero matches while also
        # exiting 1 (that's not an error, just "no match") — a "|| echo 0"
        # fallback here would double up and print "0\n0" into $found.
        found=$(bb grep -c "^\[" "$LIVE_REPORT_FILE" 2>/dev/null)
        found="${found:-0}"
    fi

    rm -rf "$WORK_DIR"
    # SIG_DIR lives OUTSIDE WORK_DIR when --sig-in-ram placed it directly
    # under /dev/shm (see init_workdir) — the rm -rf above wouldn't touch
    # a sibling path, so clean it up explicitly too.
    case "$SIG_DIR" in
        "$WORK_DIR"/*) : ;;  # already covered by the rm -rf above
        /dev/shm/av_sigs_*|*/.cache/run.*) rm -rf "$SIG_DIR" 2>/dev/null ;;
    esac
    echo -e "\n${Y}[WARN] Scan aborted${Z}"
    if [ -n "$LIVE_REPORT_FILE" ]; then
        echo -e "${C}[*] ${found} threat(s) found before interruption -> saved to: ${LIVE_REPORT_FILE}${Z}"
    fi
    exit 130
}

# ============================================================================
# 14. MODULE: reporting
# ============================================================================
build_report() {
    ELAPSED_S=$(( (END_MS - START_MS) / 1000 ))
    TF=0; TT=0; SC=0; TPERM=0; TSUID=0
    local r f t
    local th_ms=0 ty_ms=0 tu_ms=0 tp_ms=0 v
    for r in "$WORK_DIR/reports"/pool_*.txt "$WORK_DIR/reports"/anomaly_findings.txt; do
        [ -f "$r" ] || continue
        f=$(bb grep "^FILES_SCANNED:" "$r" 2>/dev/null | cut -d: -f2)
        t=$(bb grep "^THREATS_FOUND:" "$r" 2>/dev/null | cut -d: -f2)
        TF=$(( TF + ${f:-0} )); TT=$(( TT + ${t:-0} ))
        v=$(bb grep "^PERMS_FOUND:" "$r" 2>/dev/null | cut -d: -f2); TPERM=$(( TPERM + ${v:-0} ))
        v=$(bb grep "^SUID_FOUND:" "$r" 2>/dev/null | cut -d: -f2); TSUID=$(( TSUID + ${v:-0} ))
        v=$(bb grep "^TIMING_HASH_MS:" "$r" 2>/dev/null | cut -d: -f2); th_ms=$(( th_ms + ${v:-0} ))
        v=$(bb grep "^TIMING_YARA_MS:" "$r" 2>/dev/null | cut -d: -f2); ty_ms=$(( ty_ms + ${v:-0} ))
        v=$(bb grep "^TIMING_HEUR_MS:" "$r" 2>/dev/null | cut -d: -f2); tu_ms=$(( tu_ms + ${v:-0} ))
        v=$(bb grep "^TIMING_PE_MS:" "$r" 2>/dev/null | cut -d: -f2); tp_ms=$(( tp_ms + ${v:-0} ))
    done
    # FIX (real bug found in testing): anomaly_findings.txt (the
    # suspicious-filename pass — see collect_files()) is written directly
    # by the MAIN script, not by a worker, so it has no "THREATS_FOUND:N"
    # summary line the loop above looks for — its THREAT: lines were
    # correctly present in the file, but never counted, so the console
    # showed "0 threats / CLEAN" despite a real finding sitting right
    # there unreported. Count its THREAT: lines directly.
    if [ -f "$WORK_DIR/reports/anomaly_findings.txt" ]; then
        v=$(bb grep -c "^THREAT:" "$WORK_DIR/reports/anomaly_findings.txt" 2>/dev/null)
        TT=$(( TT + ${v:-0} ))
    fi
    SC=$(count_suppressed)
    SPEED=0; [ "$ELAPSED_S" -gt 0 ] && SPEED=$(( TF / ELAPSED_S ))

    QC=0
    [ "$QUARANTINE_ENABLED" = true ] && QC=$(count_quarantined)
    local quarantine_line=""
    [ "$QUARANTINE_ENABLED" = true ] && quarantine_line="
 Quarantined        : $QC ($QUARANTINE_DIR)"
    local suppressed_line=""
    [ "${SC:-0}" -gt 0 ] 2>/dev/null && suppressed_line="
 Suppressed (ignore_sigs / known vendor obfuscation): $SC"
    local ram_line="" _ev="$WORK_DIR/reports/.ram_events" _ng _nk
    if [ -s "$_ev" ]; then
        _ng=$(grep -c 'gate ON' "$_ev" 2>/dev/null); _nk=$(grep -c 'KILLED' "$_ev" 2>/dev/null)
        ram_line="
 RAM limiter        : held back new yara starts ${_ng:-0}x, killed ${_nk:-0} yara process(es) — ceiling ${MAX_RAM_MB} MB was reached (raise --max-ram or lower -j; killed batches were rescanned per file)"
    fi
    local skipped_line=""
    [ "$INCREMENTAL_MODE" = true ] && skipped_line="
 Skipped (unchanged): $SKIPPED_UNCHANGED (incremental cache: $INCREMENTAL_CACHE_FILE)"
    # files over -m that no check opened (scripts over -m still get hash +
    # YARA, archives go to -A, media to --media-fast): count, size, and a
    # list next to the report, biggest first
    local nskip skipmb skiplist base
    nskip=$(cat "$WORK_DIR/reports"/*.skipped 2>/dev/null | bb wc -l | tr -d ' ')
    if [ "${nskip:-0}" -gt 0 ]; then
        skipmb=$(cat "$WORK_DIR/reports"/*.skipped 2>/dev/null | bb awk -F'\t' '{ s += $1 } END { printf "%d", s / 1048576 }')
        base="${OUTPUT_FILE:-$LIVE_REPORT_FILE}"
        skiplist=""
        if [ -n "$base" ]; then
            skiplist="${base}.skipped"
            rm -f -- "$skiplist" 2>/dev/null
            ( set -C; cat "$WORK_DIR/reports"/*.skipped 2>/dev/null | bb sort -t"$(printf '\t')" -k1,1nr \
                | bb awk -F'\t' '{ printf "%10.1f MB  %s\n", $1 / 1048576, $2 }' > "$skiplist" ) 2>/dev/null || skiplist=""
        fi
        skipped_line="${skipped_line}
 Not scanned (> -m ${MAX_SCAN_MB} MB): ${nskip} file(s), ${skipmb} MB${skiplist:+ (list: ${skiplist})}"
    fi

    # Diagnostic time breakdown: these 4 numbers are SUMMED ACROSS ALL
    # WORKERS (so they can individually exceed wall-clock elapsed time when
    # running with multiple workers in parallel — that's expected, compare
    # them to each other and to elapsed*workers, not to elapsed alone).
    # "unaccounted" is whatever's left: per-file base64/disguised/
    # permission checks, file collection, process/fork overhead, and disk
    # I/O wait not otherwise attributed. A large unaccounted share with all
    # 4 named phases small points at I/O (or per-file base64 scan cost)
    # rather than any single batch subsystem.
    local total_batch_ms=$(( th_ms + ty_ms + tu_ms + tp_ms ))
    local elapsed_ms=$(( ELAPSED_S * 1000 * (WORKERS > 0 ? WORKERS : 1) ))
    local unaccounted_ms=$(( elapsed_ms - total_batch_ms ))
    [ "$unaccounted_ms" -lt 0 ] && unaccounted_ms=0
    local timing_line="
 Time breakdown (ms, summed across ${WORKERS} worker(s)):
   hash=${th_ms} yara=${ty_ms} strings/hex=${tu_ms} pe-sections=${tp_ms}
   other/unaccounted=${unaccounted_ms} (per-file checks, I/O wait, overhead)"

    RPT="
=================================================
 SCAN RESULTS  (Orphus Unified v${VERSION})
=================================================
 OS / Arch          : $OS / $ARCH
 Target             : $ROOT_DIR
 Files Scanned      : $TF
 Threats Found      : $TT$([ "${TSUID:-0}" -gt 0 ] && printf '\n SUID/SGID files    : %s (not counted as threats; list: %s)' "$TSUID" "${SUID_REPORT_FILE:-see -o report}")$([ "${TPERM:-0}" -gt 0 ] && printf '\n Permission issues  : %s (not counted as threats; list: %s)' "$TPERM" "${PERMS_REPORT_FILE:-see -o report}")${quarantine_line}${suppressed_line}${skipped_line}${ram_line}
 Time Elapsed       : $(printf '%02d:%02d' $(( ELAPSED_S/60 )) $(( ELAPSED_S%60 )))
 Avg Speed          : ${SPEED} files/s
 Workers            : $WORKERS${timing_line}
================================================="
}

# Permission findings: counted and listed apart from threats. Console: the
# number and the 10 directories holding most of them (a "chmod -R 777" on
# one site is one line here, not hundreds), the full list goes to -PERMS.
_print_perms_summary() {
    [ "${TPERM:-0}" -gt 0 ] || return 0
    echo -e "\n ${Y}[i]${Z} ${TPERM} file(s) with unsafe permissions (world-writable + executable) — not counted as threats${PERMS_REPORT_FILE:+, full list: ${C}${PERMS_REPORT_FILE}${Z}}"
    bb grep -h "^THREAT:WORLD_WRITABLE_EXEC|" "$WORK_DIR/reports"/pool_*.txt 2>/dev/null | cut -d'|' -f2 \
        | bb sed 's|/[^/]*$||' | bb sort | bb uniq -c | bb sort -rn | head -10 | tr '\001-\011\013-\037\177' '?' \
        | while read -r n d; do printf '     %6s  %s/\n' "$n" "$d"; done
    echo -e "     fix example: find DIR -type f -perm -0002 -exec chmod o-w {} +   (and chmod a-x for non-scripts)"
}

print_report() {
    echo -e "\n"
    if [ "$TT" -gt 0 ]; then
        echo -e "${R}${RPT}${Z}"
        echo -e "\n${R}${B}=== DETECTED THREATS ===${Z}"
        bb grep -h "^THREAT:" "$WORK_DIR/reports"/pool_*.txt "$WORK_DIR/reports"/anomaly_findings.txt 2>/dev/null \
            | bb grep -v "^THREAT:WORLD_WRITABLE_EXEC|" | bb awk '!(/^THREAT:SUID_SGID[|]/ && !/TAMPERED/)' \
            | cut -d: -f2- | bb sort -u | tr '\001-\011\013-\037\177' '?' \
            | while IFS='|' read -r type file info; do
                # printf %s, not echo -e: a name containing a literal "\n"
                # (or "\r", "\033[...") must not become a forged line.
                printf ' %b[!]%b [%b%s%b] %s %b%s%b\n' "$R" "$Z" "$Y" "$type" "$Z" "$file" "$C" "${info:-}" "$Z"
              done
    else
        echo -e "${G}${RPT}${Z}"
        echo -e "\n ${G}[OK] No threats detected [CLEAN]${Z}"
    fi
    local suid_count
    suid_count=$(bb grep -c "^THREAT:SUID_SGID|" "$WORK_DIR/reports"/pool_*.txt "$WORK_DIR/reports"/anomaly_findings.txt 2>/dev/null | bb awk -F: '{s+=$2} END{print s+0}')
    if [ "${suid_count:-0}" -gt 0 ]; then
        echo -e "\n ${Y}[i]${Z} ${suid_count} SUID/SGID finding(s) written separately to: ${C}${SUID_REPORT_FILE}${Z} (TAMPERED ones are also listed above as threats)"
    fi
    _print_perms_summary
}

save_report() {
    [ -n "$LIVE_REPORT_FILE" ] || return 0
    # Recreated with noclobber (O_EXCL), not truncated with ">": if the path
    # was swapped for a symlink during the scan, nothing is written through it.
    rm -f -- "$LIVE_REPORT_FILE" 2>/dev/null
    ( set -C; { exec 3> "$LIVE_REPORT_FILE"; } 2>/dev/null || exit 1
    {
        echo "$RPT"
        [ "$TT" -gt 0 ] && {
            echo -e "\n=== DETECTED THREATS ==="
            # FIX (real bug found in testing): grep given MULTIPLE file
            # arguments prefixes every matched line with "filename:" —
            # meaning the SECOND grep's "^THREAT:SUID_SGID|" anchor never
            # matched (the line actually started with the pool file's own
            # path, not literally "THREAT:"), so the SUID exclusion
            # silently did nothing despite looking correct. "-h"
            # suppresses that filename prefix.
            bb grep -h "^THREAT:" "$WORK_DIR/reports"/pool_*.txt "$WORK_DIR/reports"/anomaly_findings.txt 2>/dev/null \
                | bb grep -v "^THREAT:WORLD_WRITABLE_EXEC|" | bb awk '!(/^THREAT:SUID_SGID[|]/ && !/TAMPERED/)' \
                | cut -d: -f2- | bb sort -u | tr '\001-\011\013-\037\177' '?'
        }
    } >&3; exit 0 ) || { echo -e "${Y}[WARN] Can't create ${LIVE_REPORT_FILE} -> report not saved${Z}"; return 0; }
    echo -e "\n[*] Report saved: ${C}${LIVE_REPORT_FILE}${Z}"

    # SUID/SGID findings, same source data, separate file — see the
    # comment in init_live_report() for why. Only written if there's
    # actually anything to put in it (no empty companion file otherwise).
    if bb grep -q "^THREAT:SUID_SGID|" "$WORK_DIR/reports"/pool_*.txt "$WORK_DIR/reports"/anomaly_findings.txt 2>/dev/null; then
        rm -f -- "$SUID_REPORT_FILE" 2>/dev/null
        ( set -C; { exec 3> "$SUID_REPORT_FILE"; } 2>/dev/null || exit 1
        {
            echo "# Orphus AV Scanner — SUID/SGID findings (split out from the main report)"
            echo "# Target: $ROOT_DIR"
            echo ""
            bb grep -h "^THREAT:SUID_SGID|" "$WORK_DIR/reports"/pool_*.txt "$WORK_DIR/reports"/anomaly_findings.txt 2>/dev/null | cut -d: -f2- | bb sort -u | tr '\001-\011\013-\037\177' '?'
        } >&3 ) 2>/dev/null
        echo -e "[*] SUID/SGID report saved: ${C}${SUID_REPORT_FILE}${Z}"
    fi
    if [ -n "$PERMS_REPORT_FILE" ] && bb grep -q "^THREAT:WORLD_WRITABLE_EXEC|" "$WORK_DIR/reports"/pool_*.txt 2>/dev/null; then
        rm -f -- "$PERMS_REPORT_FILE" 2>/dev/null
        ( set -C; { exec 3> "$PERMS_REPORT_FILE"; } 2>/dev/null || exit 1
        {
            echo "# Orphus AV Scanner — files with unsafe permissions (world-writable + executable)"
            echo "# Not counted as threats. Target: $ROOT_DIR"
            echo ""
            bb grep -h "^THREAT:WORLD_WRITABLE_EXEC|" "$WORK_DIR/reports"/pool_*.txt 2>/dev/null | cut -d: -f2- | bb sort -u | tr '\001-\011\013-\037\177' '?'
        } >&3 ) 2>/dev/null
        echo -e "[*] Permissions report saved: ${C}${PERMS_REPORT_FILE}${Z}"
    fi
}

# ============================================================================
# 15. MODULE: real-time watch (background daemon)
#
#     Runs a single instance of the same worker (same WORKER_FILE, same
#     hashing/YARA/heuristics/quarantine code), but reads paths from a FIFO
#     instead of a static pool file. "while read ... done < FIFO" already
#     blocks and waits for new lines, so the worker is inherently a
#     long-running real-time process without extra code.
#
#     The main script just feeds new file paths into the FIFO:
#       - inotifywait if available -> instant, event-driven
#       - otherwise -> polling (find + diff against previous snapshot)
#         every WATCH_INTERVAL seconds
# ============================================================================
start_realtime_worker() {
    REALTIME_FIFO="$WORK_DIR/realtime.fifo"
    mkfifo "$REALTIME_FIFO" 2>/dev/null || {
        echo -e "${R}[FAIL] Could not create FIFO for real-time mode${Z}"
        return 1
    }

    local qdir=""
    [ "$QUARANTINE_ENABLED" = true ] && qdir="$QUARANTINE_DIR"

    REALTIME_REPORT="$WORK_DIR/reports/rt.txt"
    : > "$REALTIME_REPORT"

    # The worker opens the FIFO for reading and blocks inside its usual
    # run_scan_loop(), waiting for new path lines.
    command -v setsid &>/dev/null && HAS_SETSID=true
    _launch_grouped "$WORKER_BASH" "$WORKER_FILE" \
        "$REALTIME_FIFO" "rt" "$WORK_DIR/reports" \
        "$SIG_DIR" "$MAX_SCAN_MB" "$OS" \
        "$SHA256_CMD" "$MD5_CMD" "$STRINGS_CMD" "$FILE_CMD" "$YARA_CMD" \
        "$qdir" "$QUARANTINE_PERM" "$BUSYBOX_BIN" \
        "$BATCH_SIZE" "$HEUR_BATCH_SIZE" "$PE_BATCH_SIZE" "$LIVE_REPORT_FILE" "$IGNORE_SIGS_FILE" "$SCAN_ARCHIVES" "$ARCHIVE_MAX_MB" "$ARCHIVE_MAX_EXTRACT_MB" "$ARCHIVE_MAX_DEPTH" "$ARCHIVE_MAX_FILES" "$USE_RAM" "$GREP_BIN" "$SUID_VERIFY_MODE" "$YARA_TIMEOUT_SEC" "$LONG_TIME_MODE" "$LONG_TIME_THRESHOLD_SEC" "$ARCHIVE_RAM_MAX_MB" "$ARCHIVE_USE_RAM" "$GENERIC_OBFUSCATION_RULES_FILE" "$KNOWN_VENDOR_OBFUSCATION_FILE" "$SANDBOX_MODE" "$SANDBOX_USER" "$SANDBOX_MEM_KB" "$SANDBOX_CPU_SEC" "$DEEP_MODE" "$SHA1_CMD" "$$" "$QUARANTINE_DRY_RUN" "$QUARANTINE_SKIP_ARCHIVES" "$SUID_REPORT_FILE"
    REALTIME_WORKER_PID=$!

    # Keep the write fd (3) open permanently — opening/closing per event
    # would block until a reader shows up each time.
    exec 3> "$REALTIME_FIFO"
}

# The scanner's own footprint, as collect_files excludes it: without this
# the watch rescans its own live log (it holds matched patterns) each time
# a threat is appended to it, which re-matches, forever.
# -X exclusions for the watch, prepared once: each path as given (absolute,
# see normalize_args) and with its parent resolved, like collect_files.
RT_EXCL=()
_rt_build_excl() {
    local e pd
    RT_EXCL=()
    for e in "${EXCLUDE_PATHS[@]}"; do
        [ -n "$e" ] || continue
        e="${e%/}"; RT_EXCL+=("$e")
        pd=$(_phys_dir "$(dirname "$e")" 2>/dev/null) && [ -n "$pd" ] && RT_EXCL+=("${pd%/}/$(basename "$e")")
    done
    RT_EXCL_READY=1
}
_rt_is_self() {
    local p
    [ -n "${RT_EXCL_READY:-}" ] || _rt_build_excl
    for p in "${RT_EXCL[@]}"; do
        case "$1" in "$p"|"$p"/*) return 0 ;; esac
    done
    for p in "$SCRIPT_DIR" "$SIGNATURES" "$WORK_DIR" "$SIG_DIR"; do
        [ -n "$p" ] && [ "$p" != "/" ] || continue
        p="${p%/}"
        case "$1" in "$p"|"$p"/*) return 0 ;; esac
    done
    [ "$QUARANTINE_ENABLED" = true ] && [ -n "$QUARANTINE_DIR" ] && case "$1" in "${QUARANTINE_DIR%/}"|"${QUARANTINE_DIR%/}"/*) return 0 ;; esac
    for p in "$LIVE_REPORT_FILE" "$OUTPUT_FILE" "$SUID_REPORT_FILE" "$PERMS_REPORT_FILE"; do
        [ -n "$p" ] && [ "$1" = "$p" ] && return 0
    done
    return 1
}

feed_realtime_path() {
    local path="$1" f
    _rt_is_self "$path" && return 0
    # A directory moved in (mv, WordPress renaming upgrade/x into plugins/)
    # is ONE inotify event / one new path; feed every file inside it.
    if [ -d "$path" ] && [ ! -L "$path" ]; then
        while IFS= read -r -d '' f; do
            feed_realtime_path "$f"
        done < <(command find "$path" -type f -print0 2>/dev/null)
        return 0
    fi
    [ -f "$path" ] || return 0
    case "$path" in
        *$'\n'*|*$'\t'*)
            # Same verdict as collect_files' anomaly pass. Never sent to the
            # worker: a newline splits the FIFO line, a TAB is a field
            # separator in the worker's "size<TAB>mode<TAB>path" protocol.
            f=$(printf '%s' "$path" | tr '\n\t' '??')
            printf 'THREAT:SUSPICIOUS_FILENAME|%s|contains embedded newline/tab byte in the filename itself -- not scanned via the normal pipeline, which splits on these; investigate directly\n' "$f" >> "$REALTIME_REPORT"
            [ -n "$LIVE_REPORT_FILE" ] && printf '[%s] [SUSPICIOUS_FILENAME] %s contains embedded newline/tab byte in the filename itself\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$f" >> "$LIVE_REPORT_FILE" 2>/dev/null
            return 0 ;;
    esac
    printf '%s\n' "$path" >&3 2>/dev/null || true
}

# One sorted line per regular file, "<ctime><TAB><path>": a new path OR a
# changed ctime (edited in place, even with mtime reset by touch -r) gives a
# line that comm -13 reports. GNU find prints NUL-terminated records; tr turns
# embedded newlines into \001 so they survive the line-based sort/comm.
_rt_snapshot() {
    local ex=(-not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*")
    if [ "$OS" = "linux" ] && command find "$WORK_DIR" -maxdepth 0 -printf "" 2>/dev/null; then
        command find "$ROOT_DIR" -type f "${ex[@]}" -printf '%C@\t%p\0' 2>/dev/null | tr '\n\0' '\001\n'
    elif stat -c '%Z' "$WORK_DIR" >/dev/null 2>&1; then
        # busybox find: no -printf
        find "$ROOT_DIR" -type f "${ex[@]}" -exec stat -c $'%Z\t%n' {} + 2>/dev/null
    else
        # BSD stat (macOS): new paths only, as before
        find "$ROOT_DIR" -type f "${ex[@]}" 2>/dev/null | awk '{ print "0\t" $0 }'
    fi | LC_ALL=C sort
}

# Feed what changed since the snapshot in $WORK_DIR/rt_known.tsv, then make
# the new snapshot the reference.
_rt_poll_once() {
    local known="$WORK_DIR/rt_known.tsv" cur="$WORK_DIR/rt_current.tsv" line p
    _rt_snapshot > "$cur"
    LC_ALL=C comm -13 "$known" "$cur" | uniq | while IFS= read -r line; do
        # no TAB = tail of a newline-split name (busybox stat output)
        [[ "$line" == *$'\t'* ]] || continue
        p="${line#*$'\t'}"
        [ -n "$p" ] || continue
        feed_realtime_path "$p"
        # \001 may be an encoded newline or a literal byte; a planted literal
        # twin must not hide the newline-named file, so feed both (a path
        # that doesn't exist is dropped by feed_realtime_path).
        [[ "$p" == *$'\001'* ]] && feed_realtime_path "${p//$'\001'/$'\n'}"
    done
    mv -f "$cur" "$known"
}

# Called before the base scan's file collection, so whatever is created or
# modified while the base scan runs shows up in the first comparison.
realtime_baseline() {
    _rt_snapshot > "$WORK_DIR/rt_known.tsv"
}

# Streams new THREAT lines from the worker's live report to the console
tail_realtime_report() {
    # $! must be tail itself (not the reader), so cleanup_realtime kills it
    tail -n0 -F "$REALTIME_REPORT" 2>/dev/null > >(while IFS= read -r line; do
        case "$line" in
            THREAT:*)
                echo -e "${R}${B}[RT-THREAT]${Z} ${line#THREAT:}"
                ;;
        esac
    done) &
    REALTIME_TAIL_PID=$!
}

_rt_read_events() {
    local path
    if [ "$1" = nul ]; then
        while IFS= read -r -d '' path; do feed_realtime_path "$path"; done
    else
        while IFS= read -r path; do feed_realtime_path "$path"; done
    fi
}

# Returns only if inotifywait exits (e.g. "upper limit on inotify watches
# reached", or killed); its stderr is shown then.
watch_inotify() {
    echo -e "${C}[*] Real-time: using inotifywait (instant reaction)${Z}"
    local err="$WORK_DIR/rt_inotify.err" fmt=(--format '%w%f') mode=line
    # NUL-terminated events keep a newline in a filename intact (3.20+).
    # Not "--help | grep": --help exits non-zero, which pipefail propagates.
    case "$(inotifywait --help 2>&1)" in
        *--no-newline*) fmt=(--no-newline --format '%w%f%0'); mode=nul ;;
    esac
    : > "$err"
    inotifywait -m -r -e create -e moved_to -e close_write "${fmt[@]}" \
        "$ROOT_DIR" 2> "$err" > >(_rt_read_events "$mode") &
    REALTIME_WATCH_PID=$!
    while kill -0 "$REALTIME_WATCH_PID" 2>/dev/null && ! grep -q 'Watches established' "$err"; do
        sleep 1
    done
    # Catch-up for the gap between the pre-scan snapshot and the watches
    # being in place (files created/changed during the base scan).
    kill -0 "$REALTIME_WATCH_PID" 2>/dev/null && _rt_poll_once
    wait "$REALTIME_WATCH_PID"
    REALTIME_WATCH_PID=""
    echo -e "${R}[FAIL] inotifywait exited — real-time watch via inotify ended:${Z}"
    grep -v -e '^Setting up watches' -e '^Watches established' "$err" >&2
    return 1
}

watch_poll() {
    echo -e "${Y}[WARN] Real-time: polling every ${WATCH_INTERVAL}s (install inotify-tools for instant reaction)${Z}"
    while true; do
        _rt_poll_once
        sleep "$WATCH_INTERVAL"
    done
}

cleanup_realtime() {
    [ -n "$REALTIME_WATCH_PID" ] && kill "$REALTIME_WATCH_PID" 2>/dev/null
    exec 3>&- 2>/dev/null || true
    if [ -n "$REALTIME_WORKER_PID" ]; then
        if [ "$HAS_SETSID" = true ]; then
            kill -TERM -"$REALTIME_WORKER_PID" 2>/dev/null || kill "$REALTIME_WORKER_PID" 2>/dev/null || true
        else
            kill "$REALTIME_WORKER_PID" 2>/dev/null || true
        fi
    fi
    [ -n "$REALTIME_TAIL_PID" ] && kill "$REALTIME_TAIL_PID" 2>/dev/null || true
    [ -n "$REALTIME_FIFO" ] && rm -f "$REALTIME_FIFO" 2>/dev/null || true
}

run_realtime_watch() {
    echo -e "\n${B}=================================================${Z}"
    echo -e "${B} REAL-TIME MODE${Z} — base scan done, watching ${C}${ROOT_DIR}${Z}"
    echo -e " Ctrl+C to stop"
    echo -e "${B}=================================================${Z}\n"

    start_realtime_worker || return 1
    tail_realtime_report

    # inotifywait dying (watch limit, killed) falls back to polling instead
    # of silently watching nothing: the limit doesn't go away on restart,
    # polling has none.
    if command -v inotifywait &>/dev/null; then
        watch_inotify
        echo -e "${Y}[WARN] Real-time: falling back to polling${Z}"
    fi
    watch_poll
}

# ============================================================================
# 16. main() — single entry point; enforces init order so no module runs
#     before its required globals are set.
# ============================================================================
main() {
    detect_platform
    parse_args "$@"
    normalize_args
    setup_colors
    # --audit is a self-contained read-only module (no signatures, no workers):
    # run it and leave before any of the scan machinery is initialised.
    if [ "$AUDIT_MODE" = true ]; then
        enforce_readonly
        run_audit_main
        exit $?
    fi
    apply_low_priority

    # -I is implied by -w unless the person explicitly said --no-incremental
    # — real-time mode's whole point is running the base scan repeatedly
    # (service restarts, periodic re-supervision), and that's exactly the
    # case where NOT re-reading every unchanged file every time matters
    # most on an IOPS-capped host.
    if [ "$REALTIME_MODE" = true ] && [ -z "$INCREMENTAL_EXPLICIT_OFF" ]; then
        INCREMENTAL_MODE=true
    fi

    # --deep/--paranoid overrides incremental caching off regardless of
    # how it got turned on — deep mode means every file gets a full,
    # fresh check, never trusting a cached "was clean before" verdict.
    if [ "$DEEP_MODE" = true ]; then
        INCREMENTAL_MODE=false
    fi

    # SUID_VERIFY_MODE is true by default now (see its declaration) — this
    # block is effectively a no-op today, kept only so --no-verify-suid
    # (which sets SUID_VERIFY_EXPLICIT_OFF) still wins over -w if someone
    # explicitly wants raw/unverified SUID reporting even in real-time mode.
    if [ "$REALTIME_MODE" = true ] && [ -z "$SUID_VERIFY_EXPLICIT_OFF" ]; then
        SUID_VERIFY_MODE=true
    fi

    if [ "$DO_SETUP" = true ]; then
        # Runs through the extracted standalone module (not the inline
        # function directly) — this is the actual, meaningful benefit of
        # having it as a separate file: it's not just "the same code
        # somewhere else", every real --setup run exercises the EXACT
        # file a person would use to debug it standalone, so the two
        # never drift apart.
        extract_setup_module
        local setup_args=()
        [ "${SETUP_FORCE:-false}" = true ] && setup_args+=(--force)
        [ "${DEBUG_MODE:-false}" = true ] && setup_args+=(--debug)
        # The module is a separate bash process and reads these from its
        # environment — without them --yara-url/--compile/--no-busybox/
        # -b/--busybox-url were silently ignored by --setup.
        YARA_URL_ARG="$YARA_URL_ARG" SETUP_FORCE="$SETUP_FORCE" \
        SETUP_COMPILE_ONLY="$SETUP_COMPILE_ONLY" ALLOW_BUSYBOX="$ALLOW_BUSYBOX" \
        BUSYBOX_URL_ARG="$BUSYBOX_URL_ARG" BUSYBOX_PATH_ARG="$BUSYBOX_PATH_ARG" \
        DEBUG_MODE="$DEBUG_MODE" \
            "$WORKER_BASH" "$SCRIPT_DIR/setup_module.sh" "${setup_args[@]}"
        exit $?
    fi

    if [ "$DO_CHECK_DEPS" = true ]; then
        check_dependencies_report
        exit 0
    fi

    # BusyBox bootstrap must happen before everything else — the signature
    # updater, compiler, and scanning all depend on BUSYBOX_BIN/SHA256_CMD/
    # MD5_CMD/STRINGS_CMD/FILE_CMD set here.
    init_toolchain
    YARA_CMD=$(detect_yara)
    detect_yarac
    [ -x "$SCRIPT_DIR/bin/grep" ] && GREP_BIN="$SCRIPT_DIR/bin/grep"

    # --packs without -u selects the ONE pack to scan with (default: server)
    if [ "$DO_UPDATE" != true ]; then
        case "$PACKS_SPEC" in
            *,*) echo -e "${R}[FAIL] A scan uses one pack; join items with + (e.g. --packs hosting+pe). Several packs (a,b) are for -u.${Z}" >&2; exit 1 ;;
        esac
        [ -n "$PACKS_SPEC" ] && _pack_apply "$PACKS_SPEC"
        [ "$YARA_ALL" = true ] && [ -z "$PACKS_SPEC" ] && PACK_ID="full"
    fi

    # --update is a standalone action (like typical AV tools separate
    # update from scan): update signatures, then exit, no auto-scan.
    if [ "$DO_UPDATE" = true ]; then
        update_signatures "$SIGNATURES" "$MB_KEY"

        # Compile right away (not a scan — no target files touched) so the
        # persistent cache is fresh immediately and the printed SHA256/MD5/
        # HexERE/Strings/YARA counts reflect exactly what the next scan
        # will use, as a sanity check that nothing broke in the update.
        local tmp_compile_dir
        tmp_compile_dir=$(mktemp -d "${TMPDIR:-/tmp}/av_update_compile.XXXXXX" 2>/dev/null || mktemp -d)
        if [ -n "$PACKS_SPEC" ]; then
            # --packs hosting,server,all : one pack per comma-separated entry
            # (each entry may itself be a category: --packs hosting,webshell).
            # All of them end up side by side in .cache/packs/ — one archive.
            local pk first=true
            for pk in $(printf '%s' "$PACKS_SPEC" | tr ',' ' '); do
                YARA_ALL=false; _pack_apply "$pk"
                echo -e "${B}[*] ===== pack '$pk' =====${Z}"
                [ "$first" = true ] || DO_UPDATE=false   # only the first pack invalidates the others
                compile_signatures "$SIGNATURES" "$tmp_compile_dir"
                first=false
                rm -rf "$tmp_compile_dir"; mkdir -p "$tmp_compile_dir"
            done
            echo -e "${G}[OK] Packs in $SIGNATURES/.cache/packs/: $(ls "$SIGNATURES/.cache/packs" 2>/dev/null | tr '\n' ' ')${Z}"
        else
            compile_signatures "$SIGNATURES" "$tmp_compile_dir"
        fi
        rm -rf "$tmp_compile_dir"

        echo -e "${C}[*] Update finished. Auto-scan after --update is disabled — run a scan as a separate command.${Z}"
        exit 0
    fi

    init_workers

    enforce_readonly
    init_workdir
    check_deps
    init_quarantine

    extract_worker
    compile_signatures "$SIGNATURES" "$SIG_DIR"
    # workers: are ClamAV PUA.* hash hits wanted (pack has the "pua" group)?
    case " $CLAM_GROUPS " in *" pua "*) export AV_CLAM_PUA=true ;; *) export AV_CLAM_PUA=false ;; esac
    export AV_MEDIA_FAST="$MEDIA_FAST"
    export AV_IOC_PATH_ANY_RE="$IOC_PATH_ANY_RE" AV_IOC_PATH_TMP_RE="$IOC_PATH_TMP_RE"
    if [ -n "$(_ignore_sigs_upstream_url)" ] && [ -s "${SIGNATURES}/ignore_sigs.upstream" ]; then
        export AV_IGNORE_UPSTREAM="${SIGNATURES}/ignore_sigs.upstream"
    else
        export AV_IGNORE_UPSTREAM=""
    fi
    _yara_ram_cap "$SIG_DIR/yara/rules.yarc"
    yara_self_test

    if [ "$SCAN_PROCESSES" = true ]; then
        if [ -n "$OFFLINE_ROOT" ]; then
            echo -e "${Y}[WARN] -P/--scan-processes doesn't make sense with --offline-root${Z}"
            echo -e "${Y}       (there are no running processes to inspect on a mounted, not-booted disk) — skipping.${Z}"
        else
            scan_processes
            # -P without an explicit -d means "just check processes" —
            # skip the whole file-tree scan entirely rather than
            # defaulting to scanning /mnt, which the person never asked for.
            if [ -z "$ROOT_DIR_EXPLICIT" ] && [ "$CHECK_KERNEL" != true ]; then
                exit 0
            fi
            echo ""
        fi
    fi

    if [ "$CHECK_KERNEL" = true ]; then
        scan_kernel_integrity
        if [ -z "$ROOT_DIR_EXPLICIT" ]; then
            exit 0
        fi
        echo ""
    fi

    # FIX (real bug reported): these two used to run BEFORE
    # compile_signatures. Both auto-create a file DIRECTLY inside
    # $SIGNATURES the first time they're used (ignore_sigs,
    # .incremental_cache.tsv) — creating a new direct child bumps the
    # PARENT directory's own mtime. compile_signatures' cache-freshness
    # check compares its compiled flag against exactly that parent mtime,
    # so on the very first run after either feature's file didn't exist
    # yet, the freshly-written cache would look "stale" on the VERY NEXT
    # invocation even though nothing about the actual signature data had
    # changed — forcing a full, unnecessary recompile every time (this is
    # what caused "-u finishes, cache is fresh, but the next plain scan
    # recompiles everything anyway"). Running them after compile_signatures
    # sidesteps this entirely — neither has any dependency on running
    # earlier (ignore_sigs is only consulted per-threat during scanning;
    # the incremental cache is only consulted in collect_files(), which
    # itself runs after this point).
    init_ignore_sigs
    init_incremental_cache
    init_vendor_obfuscation_allowlist

    if [ -n "$EXPLAIN_FILE" ]; then
        run_explain
        exit $?
    fi

    init_live_report

    START_MS=$(now_ms)
    print_banner

    [ "$REALTIME_MODE" = true ] && realtime_baseline
    collect_files
    split_pools
    launch_workers

    start_monitor
    # HUP added alongside INT/TERM: closing the terminal/session (not just
    # Ctrl+C) sends SIGHUP to the foreground process group — without
    # trapping it too, the script (and its workers) would die without
    # cleanup running at all, leaving the same kind of orphaned processes
    # this whole fix is about.
    trap cleanup INT TERM HUP

    wait_for_workers

    END_MS=$(now_ms)
    update_incremental_cache
    build_report
    print_report
    save_report

    # Real-time watch starts AFTER the base scan (the same trap cleanup is
    # already active and covers this phase too — Ctrl+C/SIGTERM stops both
    # the worker daemon and the FIFO cleanly).
    if [ "$REALTIME_MODE" = true ]; then
        run_realtime_watch
    fi

    rm -rf "$WORK_DIR"
    case "$SIG_DIR" in
        "$WORK_DIR"/*) : ;;
        /dev/shm/av_sigs_*|*/.cache/run.*) rm -rf "$SIG_DIR" 2>/dev/null ;;
    esac
    exit 0
}

main "$@"

# =============================================================================
# 17. EMBEDDED WORKER (self-contained, also modular)
# =============================================================================
#__WORKER_START__
#!/bin/bash
set -uo pipefail
export LC_ALL=C

# Tracks archive-extraction directories currently in use by scan_archive()
# — see the trap below and the array-append in scan_archive() itself. If
# this worker gets TERM'd/INT'd while mid-extraction (e.g. the main
# script's cleanup() killing workers on Ctrl+C), it would otherwise die
# outright without ever reaching scan_archive()'s own end-of-function
# rm -rf, leaking the directory (confirmed in practice — a real leftover
# extraction sat in /dev/shm for two days after an interrupted archive
# scan). This is defense-in-depth for the common graceful-interrupt case;
# it cannot catch SIGKILL/a hard crash, which is what the startup sweep
# in the main script's init_workdir() exists for instead — the two
# together cover both the common case and the case nothing can trap.
declare -a _ACTIVE_EXTRACT_DIRS=()
_cleanup_active_extractions() {
    local d
    for d in "${_ACTIVE_EXTRACT_DIRS[@]:-}"; do
        # FIX (real bug found in testing): this array tracks BOTH archive
        # extraction DIRECTORIES and the three filtered pattern FILES
        # (ignore_sigs/generic_obfuscation_rules/known_vendor_obfuscation
        # copies) — but this check was "-d" (directory) only, a leftover
        # from when the array was archive-dirs-only. For the file
        # entries, "-d" is always false, so "&&" short-circuited and
        # rm -rf NEVER ran for them — confirmed directly: the trap fired
        # with the exact correct paths logged, yet the files remained on
        # disk untouched afterward. "-e" (exists, either type) covers both.
        [ -n "$d" ] && [ -e "$d" ] && rm -rf "$d" 2>/dev/null
    done
    exit 143
}
trap _cleanup_active_extractions TERM INT

# ----------------------------------------------------------------------------
# GLOBALS — all worker variables defined once here, before any function
# uses them.
# ----------------------------------------------------------------------------
POOL_FILE="${1:?}"
WORKER_ID="${2:?}"
REPORT_DIR="${3:?}"
SIG_DIR="${4:?}"
MAX_SCAN_MB="${5:-10}"
OS="${6:-linux}"
SHA256_CMD="${7:-none}"
MD5_CMD="${8:-none}"
STRINGS_CMD="${9:-bash}"
FILE_CMD="${10:-bash}"
YARA_CMD="${11:-none}"
QUARANTINE_DIR="${12:-}"      # empty = quarantine disabled
QUARANTINE_PERM="${13:-0400}"
BUSYBOX_BIN="${14:-}"         # inherited from the main script (same binary)
BATCH_SIZE="${15:-200}"       # files per hash/YARA batch
HEUR_BATCH_SIZE="${16:-200}"  # files per strings/hex heuristic batch
PE_BATCH_SIZE="${17:-100}"    # files per PE-section (.mdb) batch
LIVE_REPORT_FILE="${18:-}"    # persistent live threat log (outside the
                               # ephemeral WORK_DIR) — written to immediately
                               # as each threat is found, see threat() below
IGNORE_SIGS_FILE="${19:-}"    # ERE patterns that suppress noisy detections
                               # entirely — see init_ignore_sigs in the main
                               # script
SCAN_ARCHIVES="${20:-false}"
ARCHIVE_MAX_MB="${21:-200}"
ARCHIVE_MAX_EXTRACT_MB="${22:-500}"
ARCHIVE_MAX_DEPTH="${23:-2}"
ARCHIVE_MAX_FILES="${24:-2000}"
ARCHIVE_DEPTH_CUR=0            # current recursion depth, tracked at runtime
USE_RAM="${25:-true}"          # prefer /dev/shm for archive extraction too
GREP_BIN="${26:-}"             # bundled static grep — see MODULE below
SUID_VERIFY_MODE="${27:-false}" # dpkg/rpm checksum verify for SUID/SGID —
                                 # off by default, on for -w (real-time)
YARA_TIMEOUT_SEC="${28:-300}"    # abort a single yara call after this long
                                 # (yara's own -a flag) — see global comment
LONG_TIME_MODE="${29:-false}"   # -L/--long-time: log slow batches
LONG_TIME_THRESHOLD_SEC="${30:-20}"
ARCHIVE_RAM_MAX_MB="${31:-50}"  # extract archives up to this compressed
                                 # size straight into RAM — see global note
ARCHIVE_USE_RAM="${32:-true}"   # explicit --no-ram choice, NOT auto-tuned
                                 # by the low-RAM-profile logic — see main
                                 # script comment where it's captured
GENERIC_OBFUSCATION_RULES_FILE="${33:-}"
KNOWN_VENDOR_OBFUSCATION_FILE="${34:-}"
SANDBOX_MODE="${35:-auto}"
SANDBOX_USER="${36:-nobody}"
SANDBOX_MEM_KB="${37:-1048576}"
SANDBOX_CPU_SEC="${38:-60}"
DEEP_MODE="${39:-false}"       # --deep/--paranoid: bypass ALL automatic
                                 # suppression (ignore_sigs, vendor
                                 # obfuscation allowlist) — the whole
                                 # point of deep mode is showing
                                 # everything and letting the person
                                 # decide, not trusting our own filters.
SHA1_CMD="${40:-none}"          # recovers ClamAV .hsb SHA1 entries that
                                 # used to be silently dropped — see
                                 # detect_sha1() in the main script.
MAIN_SCRIPT_PID="${41:-$PPID}"  # PID of the top-level av.sh instance that
                                 # launched this worker — embedded into
                                 # every ephemeral resource name this
                                 # worker creates (archive extraction
                                 # dirs, chroot sandbox dirs, filtered
                                 # pattern files) so a DIFFERENT,
                                 # concurrently-running scan instance's
                                 # startup sweep can tell "orphaned from a
                                 # dead run" apart from "still in active
                                 # use by a live one" — see
                                 # _sweep_stale_shm_dirs in the main
                                 # script for why this matters: it used to
                                 # match purely by name pattern, which
                                 # could not tell two instances apart at
                                 # all (a real risk: cron + a manual scan
                                 # running at the same time, or -w in the
                                 # background plus a one-off audit).
QUARANTINE_DRY_RUN="${42:-false}"  # --quarantine-dry-run: report what
                                 # WOULD be quarantined without touching
                                 # any file — see quarantine_file() below.
QUARANTINE_SKIP_ARCHIVES="${43:-false}"  # --no-quarantine-archives
SUID_REPORT_FILE="${44:-}"     # companion file for SUID_SGID live-stream
PERMS_REPORT_FILE=""; [ -n "$SUID_REPORT_FILE" ] && PERMS_REPORT_FILE="${SUID_REPORT_FILE%-SUID}-PERMS"
                                 # writes — see threat() for why this needs
                                 # to exist here too, not just in save_report()

REPORT="$REPORT_DIR/${WORKER_ID}.txt"
PROGRESS="$REPORT_DIR/${WORKER_ID}.progress"
FILES_SCANNED=0
THREATS_FOUND=0
SUPPRESSED_FOUND=0
PERMS_FOUND=0      # permission findings: separate counter, not THREATS_FOUND
SUID_FOUND=0       # SUID/SGID (not TAMPERED): separate counter as well
# Coarse per-phase timing (ms), accumulated across all batches this worker
# processes — reported at the end so a slow scan can be diagnosed (CPU/fork
# overhead vs disk I/O vs a specific subsystem) instead of guessed at.
T_HASH_MS=0
T_YARA_MS=0
T_HEUR_MS=0
T_PE_MS=0
T_CHECK_MS=0
_now_ms() {
    date +%s%3N 2>/dev/null || echo $(( $(date +%s) * 1000 ))
}

# FIX (real bug found — not just in the new vendor-obfuscation feature,
# but a LATENT bug in the pre-existing ignore_sigs mechanism too): grep -f
# treats EVERY line of a pattern file as a literal pattern, including
# comment lines starting with "#" — and this script's own auto-generated
# template comments contain unbalanced parentheses (e.g. explaining
# "eval(base64_decode" as prose), which makes grep -f error out entirely
# ("Unmatched ( or \(") on the untouched default template. Strips
# comment/blank lines ONCE per file at worker startup (not on every
# check) into a filtered copy, used for all pattern-file grep -f lookups
# from here on.
_filter_patterns_file() {
    local src="$1" dst="$2"
    [ -n "$src" ] && [ -s "$src" ] || { : > "$dst" 2>/dev/null; return; }
    bb grep -v '^[[:space:]]*#' "$src" 2>/dev/null | bb grep -v '^[[:space:]]*$' > "$dst" 2>/dev/null
}
_IGNORE_SIGS_FILTERED="$(mktemp "${TMPDIR:-/tmp}/av_filtered_${MAIN_SCRIPT_PID}_XXXXXX" 2>/dev/null || echo "$REPORT_DIR/.filtered_${WORKER_ID}_ignore_sigs")"
_GENERIC_OBFUSCATION_FILTERED="$(mktemp "${TMPDIR:-/tmp}/av_filtered_${MAIN_SCRIPT_PID}_XXXXXX" 2>/dev/null || echo "$REPORT_DIR/.filtered_${WORKER_ID}_generic_obf")"
_KNOWN_VENDOR_OBFUSCATION_FILTERED="$(mktemp "${TMPDIR:-/tmp}/av_filtered_${MAIN_SCRIPT_PID}_XXXXXX" 2>/dev/null || echo "$REPORT_DIR/.filtered_${WORKER_ID}_vendor_obf")"
# FIX (real leak found in practice — Ctrl+C during a scan left these
# behind, growing by 3-per-worker on every subsequent interrupted run):
# these three live for the worker's WHOLE lifetime (created once here at
# startup, only removed in finalize_worker() on NORMAL completion) — a
# bare, unprefixed mktemp meant an interrupt anywhere in between leaked
# an unidentifiable "tmp.XXXXXXXXXX" file, same class of bug as the
# archive-extraction directories fixed earlier. Now prefixed (sweepable
# by _sweep_stale_shm_dirs at the next run's startup) AND tracked in the
# same active-resource array the TERM/INT trap already cleans up below.
_ACTIVE_EXTRACT_DIRS+=("$_IGNORE_SIGS_FILTERED" "$_GENERIC_OBFUSCATION_FILTERED" "$_KNOWN_VENDOR_OBFUSCATION_FILTERED")
# NOTE: the actual _filter_patterns_file CALLS happen further down, after
# this worker's own bb() is defined — bb() is a function, and top-level
# code in a bash script runs sequentially as it's reached, so calling
# anything that uses bb() from here (before its definition further below)
# would silently fail (bb not yet a recognized command), leaving the
# filtered files empty. Confirmed exactly this way via direct debug trace.

# "Real" (non-busybox) grep, for the specific searches that need correct
# binary-safe (-a) handling — busybox's grep confirmed to silently miss
# matches in NUL-containing files even with -a. Prefers the bundled static
# build (see --setup / build_grep_from_source), falls back to whatever
# system grep is on PATH, since either is a real GNU/POSIX grep unlike
# busybox's minimal reimplementation.
_real_grep() {
    if [ -n "$GREP_BIN" ] && [ -x "$GREP_BIN" ]; then
        "$GREP_BIN" "$@"
    else
        command grep "$@"
    fi
}
_has_real_grep() {
    { [ -n "$GREP_BIN" ] && [ -x "$GREP_BIN" ]; } || command -v grep &>/dev/null
}
MAX_SIZE=$(( MAX_SCAN_MB * 1024 * 1024 ))
# Images with a valid JPEG/PNG/GIF header used to skip YARA entirely, so a
# classic polyglot (GIF89a... followed by <?php eval ...) was never checked by
# any YARA rule — including Yara-Rules' own WShell_PHP_in_images. They now go
# through one cheap grep per batch for script markers (a real image has no
# reason to contain any; every one of these is >= 5 bytes, so chance hits in
# random pixel data are negligible) and only the files that hit are handed to
# YARA. --deep skips the prefilter and runs YARA on every image.
# PHP, plus ASP/ASPX/JSP (classic China Chopper "<%eval request(..)%>" in a
# real JPEG was missed) and the usual PHP exec/assert family.
IMG_SCRIPT_RE='<\?php|<\?= *\$|<script|eval *\(|base64_decode *\(|gzinflate *\(|\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[|<%[@=]? *(eval|execute|response|request|server|dim|set |page)|eval[ (]+request|request\.(item|form|querystring)|<jsp:|runtime\.getruntime|(assert|system|passthru|shell_exec|proc_open|popen|create_function|str_rot13) *\('
_flush_image_batch() {
    [ "${#BATCH_IMG[@]}" -eq 0 ] && return
    local hit
    while IFS= read -r -d '' hit; do
        [ -z "$hit" ] && continue
        BATCH_YARA+=("$hit")
        YARA_BATCH_CNT=$(( YARA_BATCH_CNT + 1 ))
        if [ "$YARA_BATCH_CNT" -ge "$BATCH_SIZE" ]; then
            _timed_yara_batch "${BATCH_YARA[@]}"
            BATCH_YARA=(); YARA_BATCH_CNT=0
        fi
    done < <(_real_grep -l -Z -a -i -E -e "$IMG_SCRIPT_RE" -- "${BATCH_IMG[@]}" 2>/dev/null)
    BATCH_IMG=()
}

HAS_SHA256=false
HAS_SHA1=false
HAS_MD5=false
HAS_B64=false
HAS_STRINGS=false
HAS_HEX_ERE=false
HAS_YARA=false
HAS_MDB=false
HAS_STR_SIG_MAP=false
YARA_HAS_SCAN_LIST=false
YARA_TARGET=""
BB_APPLETS=""

declare -a BATCH_SHA=()
declare -a BATCH_SHA1=()
declare -a BATCH_MD5=()
declare -a BATCH_YARA=()
declare -a BATCH_IMG=()
declare -a BATCH_HEUR=()
declare -a BATCH_PE=()
SHA_BATCH_CNT=0
SHA1_BATCH_CNT=0
MD5_BATCH_CNT=0
YARA_BATCH_CNT=0
HEUR_BATCH_CNT=0
PE_BATCH_CNT=0
# All batch sizes come from the main script (--batch-size/--heur-batch-size/
# --pe-batch-size), defaulting to 50. Smaller batches mean smoother/more
# incremental progress (threats appear as they're found instead of jumping
# when a big batch completes) at some cost to throughput, since the fixed
# per-call cost (building a grep/YARA match set) is amortized over fewer
# files.

# ----------------------------------------------------------------------------
# MODULE: busybox wrapper (own copy — the worker runs as a separate bash
# process, so it cannot share the main script's function)
# ----------------------------------------------------------------------------
if [ -n "$BUSYBOX_BIN" ] && [ -x "$BUSYBOX_BIN" ]; then
    while IFS= read -r _a; do
        [ -n "$_a" ] && BB_APPLETS="${BB_APPLETS}${_a} "
    done < <("$BUSYBOX_BIN" --list 2>/dev/null)
    BB_APPLETS=" ${BB_APPLETS}"
fi

bb() {
    local applet="$1"; shift
    case "$BB_APPLETS" in
        *" $applet "*) "$BUSYBOX_BIN" "$applet" "$@" ;;
        *) command "$applet" "$@" ;;
    esac
}

# ----------------------------------------------------------------------------
# MODULE: init
# ----------------------------------------------------------------------------
init_worker_state() {
    [ -s "$SIG_DIR/sha256.tsv" ] && HAS_SHA256=true
    [ -s "$SIG_DIR/sha1.tsv" ] && HAS_SHA1=true
    [ -s "$SIG_DIR/md5.tsv" ] && HAS_MD5=true
    [ -s "$SIG_DIR/b64_payloads.tsv" ] && HAS_B64=true
    [ -s "$SIG_DIR/strings.txt" ] && HAS_STRINGS=true
    [ -s "$SIG_DIR/hex_ere.txt" ] && HAS_HEX_ERE=true
    [ -s "$SIG_DIR/mdb.tsv" ] && HAS_MDB=true
    [ -s "$SIG_DIR/str_sig_map.tsv" ] && HAS_STR_SIG_MAP=true

    # Rule files without a yara binary are no YARA coverage: HAS_YARA=true
    # here also switched off the grep string pass below (strings "folded
    # into YARA"), so without yara the built-in strings matched nothing.
    if [ "$YARA_CMD" = "none" ]; then
        :
    elif [ -f "$SIG_DIR/yara/rules.yarc" ]; then
        HAS_YARA=true; YARA_TARGET="$SIG_DIR/yara/rules.yarc"
    elif [ -f "$SIG_DIR/yara/index.yar" ]; then
        HAS_YARA=true; YARA_TARGET="$SIG_DIR/yara/index.yar"
    fi

    # YARA 4.0+ / YARA-X support --scan-list for batch scanning; older
    # builds don't and need the symlink-directory fallback in
    # process_yara_batch(). Probed once per worker, not once per batch.
    YARA_HAS_SCAN_LIST=false
    if [ "$HAS_YARA" = true ] && "$YARA_CMD" --help 2>&1 | bb grep -q -- "--scan-list"; then
        YARA_HAS_SCAN_LIST=true
    fi

    # String signatures are folded into the YARA ruleset (one rule per
    # pattern, see compile_signatures) whenever both YARA and the
    # name->pattern map are available — that covers the string search in
    # the SAME pass as YARA_MATCH, instead of a separate grep -a read of
    # every file. Only fall back to the standalone grep -a pass in
    # process_heuristic_batch when YARA isn't usable.
    if [ "$HAS_YARA" = true ] && [ "$HAS_STR_SIG_MAP" = true ]; then
        HAS_STRINGS=false
    fi

    # Now safe to filter the pattern files (bb() is defined by this point
    # in the worker — see the NOTE further up where these get declared).
    _filter_patterns_file "$IGNORE_SIGS_FILE" "$_IGNORE_SIGS_FILTERED"
    # shared list from the repository (see update_ignore_sigs_upstream)
    if [ -n "${AV_IGNORE_UPSTREAM:-}" ] && [ -s "$AV_IGNORE_UPSTREAM" ]; then
        bb grep -v '^[[:space:]]*#' "$AV_IGNORE_UPSTREAM" 2>/dev/null | bb grep -v '^[[:space:]]*$' >> "$_IGNORE_SIGS_FILTERED" 2>/dev/null
    fi
    _filter_patterns_file "$GENERIC_OBFUSCATION_RULES_FILE" "$_GENERIC_OBFUSCATION_FILTERED"
    _filter_patterns_file "$KNOWN_VENDOR_OBFUSCATION_FILE" "$_KNOWN_VENDOR_OBFUSCATION_FILTERED"
}

# ----------------------------------------------------------------------------
# MODULE: low-level helpers (stat / hash / decode / strings / file-type)
# ----------------------------------------------------------------------------
# Translates a "strsig_*" YARA rule name (generated in compile_signatures
# from strings.txt) back into the original pattern text, so results still
# read as "SIG_STRING_MATCH pattern=..." instead of a raw internal rule
# name. Returns empty if the rule isn't a string-signature rule (i.e. a
# real YARA rule from NDB/LDB or an external ruleset).
_resolve_str_sig() {
    local rule="$1"
    [ "$HAS_STR_SIG_MAP" = true ] || return 1
    case "$rule" in
        strsig_*) ;;
        *) return 1 ;;
    esac
    local pat
    pat=$(bb grep -m1 "^${rule}"$'\t' "$SIG_DIR/str_sig_map.tsv" 2>/dev/null | cut -f2-)
    [ -z "$pat" ] && return 1
    echo "$pat"
    return 0
}

# Returns success (0) if the given YARA rule name is a built-in,
# hardcoded reject — rules confirmed (direct, real-world testing: two
# separate whole-disk scans) to be too generically-written to ever carry
# useful signal, not situationally-ambiguous like vendor obfuscation.
# Unlike _is_vendor_obfuscation() below, this does NOT require a second,
# content-based condition — these rule names alone are reason enough,
# and unlike ignore_sigs/vendor-obfuscation, DEEP_MODE does NOT bypass
# this: there is no "maybe worth a human glance during paranoid review"
# value here the way there can be for a suppressed vendor-obfuscation
# match, just noise, so --deep gets the same quiet rejection as normal
# mode. Intentionally built into the script itself, not left to
# ignore_sigs, so every install gets this by default without needing to
# know to add it by hand.
#
# First batch — one real scan, 96.8% of ALL findings (38,679 of 39,356):
# "domain"/"contains_base64"/"url"/"IP" are generic indicator-style rules
# that fire on nearly any binary/config file's byte content, and
# "android_meterpreter" matched GRUB's module-dependency list, php.ini,
# an Exim mail-server ACL, and ImageMagick's policy.xml — files with no
# conceivable connection to each other or to actual Android malware.
#
# Second batch — a later scan, same signature set, 89.9% of that run's
# findings (12,250 of 13,627), every single one sample-checked by hand:
# Big_Numbers0/1/3 and CRC32_poly_Constant/CRC32_table/MD5_Constants/
# SHA2_BLAKE2_IVs/BASE64_table all just mean "this file contains a
# well-known, PUBLICLY STANDARDIZED algorithm constant table" — matched
# GRUB's own gcry_md5.mod/gcry_sha256.mod (modules literally named after
# the algorithm), libphp5.so (the PHP interpreter itself), phar.so, and
# libetpan.so (a mail library using base64 for MIME, as mail libraries
# legitimately do). vmdetect/vmdetect_misc/VMWare_Detection/
# Qemu_Detection/VirtualBox_Detection matched completely ordinary files
# on a target that is itself a QEMU guest (confirmed via qemu-ga running)
# — this is what legitimate guest-tools code checking its own hypervisor
# looks like, not malware evading analysis. powershell matched vim,
# Python's own venv/__init__.py and its .pyc cache — on a Linux box, no
# less. maldoc_getEIP_method_1 matched ZendGuardLoader.so (itself a
# legitimate PHP code-protection tool), dom.so, and the "cksum" utility.
# PM_Email_Sent_By_PHP_Script matched php.ini — a config file, not a
# script. without_attachments/without_images matched fail2ban's own
# stock sendmail notification templates. spyeye matched a kernel
# System.map symbol listing and the standard btrfs-convert/
# btrfs-find-root tools. Misc_Suspicious_Strings is a generic catch-all
# by design, same problem as the first batch's "domain"/"url"/etc.
# Third batch — a third scan, same signature set, 701 of that run's 946
# rule-tagged findings (74%), every rule sample-checked by hand again:
# rootkit/exploit matched /usr/include/.../unistd.h and syscall.h (the
# STANDARD C headers defining syscall numbers — every compiled C program
# on the system includes these) plus linux-headers-* kernel build files
# (Module.symvers, syscalls_64.h) — a "detects syscall-table tampering"
# rule inevitably matches the files that DEFINE the syscall table in the
# first place. RIPEMD160/SHA1/SHA512/BLOWFISH/RijnDael_AES(_CHAR)/
# SipHash/CRC32b/CRC32c_Constants are the same "contains a well-known
# algorithm constant table" problem as the second batch, just more
# algorithms — and Big_Numbers2/4 are the same rule FAMILY as
# Big_Numbers0/1/3 below, just two more variants. Antivirus matched
# Ansible's own Windows-management PowerShell helper scripts and
# compiled Python bytecode. PoetRat_Python (a real malware family name)
# matched PHP's gd.so/imagick.so image libraries. memory_shylock (also a
# real trojan name) matched Ubuntu's OWN autoinstall.yaml and cloud-init
# installer logs. Browsers matched more Ansible Windows modules.
# php_uname matched PHP's own build/test tooling (run-tests.php,
# pearcmd.php) — part of the standard PHP distribution, not a webshell
# fingerprinting itself. with_sqlite/with_urls/without_urls are the same
# paired with/without-indicator family as without_attachments/
# without_images below, matching fail2ban's own stock templates again.
# spyeye_plugins is the same rule family as spyeye below.
# Fourth batch — a fourth scan (549 findings, 427 YARA matches, ~398 of
# them from these 28 rules), sample-checked by hand: Cerberus matched
# /etc/apache2/magic (the libmagic file-type database, a config file);
# Rooter/RooterStrings matched perf and lto-dump; Warp matched gettext
# .mo translation files; Dropper_Strings matched php's run-tests.php and
# containerd; System_Tools/WMI_strings matched Ansible's Windows-
# management modules. anti_dbg/SEH_*/DebuggerException__* are Windows PE
# rules that matched pip's own t32.exe/w32.exe launcher stubs.
# invalid_trailer_structure/ppaction are PDF-malware rules that matched
# stock PDF documentation; maldoc_OLE_file_magic_number matched the php
# binaries themselves. Email_Generic_Phishing matched exim4's and
# manpages' documentation; possible_exploit matched libgs.so, glib NEWS
# and web-server ACCESS LOGS (logs naturally contain visitors' attack
# strings — that's a log-scanning job, not a file infection). The rest
# (SHA3/WHIRLPOOL/Chacha/DES/CRC16/ecc_order/OpenSSL_DSA/Big_Numbers5/
# with_images) are the same "contains a well-known algorithm constant
# table" family as the earlier batches. NOT sample-checked individually,
# added by family membership: WarpStrings, SEH_Init,
# DebuggerException__SetConsoleCtrl, DES_Long, OpenSSL_DSA.
_is_builtin_noisy_rule() {
    case "$1" in
        domain|contains_base64|url|IP|android_meterpreter| \
        Big_Numbers0|Big_Numbers1|Big_Numbers2|Big_Numbers3|Big_Numbers4| \
        Misc_Suspicious_Strings| \
        vmdetect|vmdetect_misc|VMWare_Detection|Qemu_Detection|VirtualBox_Detection| \
        powershell|spyeye|spyeye_plugins|BASE64_table| \
        CRC32_poly_Constant|CRC32_table|CRC32b_poly_Constant|CRC32c_poly_Constant| \
        maldoc_getEIP_method_1|without_attachments|without_images| \
        without_urls|with_urls|with_sqlite| \
        SHA2_BLAKE2_IVs|MD5_Constants|SHA1_Constants|SHA512_Constants| \
        RIPEMD160_Constants|BLOWFISH_Constants|RijnDael_AES|RijnDael_AES_CHAR| \
        SipHash_big_endian_constants| \
        PM_Email_Sent_By_PHP_Script|Antivirus|Browsers|php_uname| \
        PoetRat_Python|memory_shylock|rootkit|exploit| \
        SHA3_constants|WHIRLPOOL_Constants|Chacha_256_constant|Big_Numbers5| \
        DES_sbox|DES_Long|CRC16_table|ecc_order|OpenSSL_DSA|with_images| \
        Cerberus|Rooter|RooterStrings|Warp|WarpStrings|Dropper_Strings| \
        System_Tools|WMI_strings| \
        anti_dbg|SEH_Save|SEH_Init|DebuggerException__SetConsoleCtrl| \
        DebuggerException__ConsoleCtrl| \
        invalid_trailer_structure|ppaction|maldoc_OLE_file_magic_number| \
        Email_Generic_Phishing|possible_exploit) return 0 ;;
        *) return 1 ;;
    esac
}

# Returns success (0) if a YARA match should be auto-suppressed as known,
# legitimate vendor code-obfuscation (e.g. a CMS encoding its own core
# files for license protection) rather than reported — see
# init_vendor_obfuscation_allowlist in the main script for the two files
# this reads. BOTH conditions must hold, checked cheapest-first: the rule
# that fired has to be in the "too broad to tell obfuscation apart from a
# real backdoor" list, AND the file's own content has to match a known
# vendor's specific fingerprint — a rule-name match alone never suppresses
# anything by itself.
_is_vendor_obfuscation() {
    local rule="$1" file="$2"
    # DEEP_MODE bypasses this too — same reasoning as threat()'s
    # ignore_sigs bypass: --deep means show everything, don't trust any
    # automatic filter, including our own vendor-obfuscation allowlist.
    [ "$DEEP_MODE" = "true" ] && return 1
    [ -s "$_GENERIC_OBFUSCATION_FILTERED" ] || return 1
    [ -s "$_KNOWN_VENDOR_OBFUSCATION_FILTERED" ] || return 1
    echo "$rule" | bb grep -qE -f "$_GENERIC_OBFUSCATION_FILTERED" 2>/dev/null || return 1
    if _has_real_grep; then
        _real_grep -qE -f "$_KNOWN_VENDOR_OBFUSCATION_FILTERED" "$file" 2>/dev/null && return 0
    else
        bb grep -qE -f "$_KNOWN_VENDOR_OBFUSCATION_FILTERED" "$file" 2>/dev/null && return 0
    fi
    return 1
}

_stat_size() {
    if [ "$OS" = "macos" ]; then bb stat -f '%z' "$1" 2>/dev/null
    else bb stat -c '%s' "$1" 2>/dev/null; fi
}
_stat_mode() {
    if [ "$OS" = "macos" ]; then
        local m; m=$(bb stat -f '%Op' "$1" 2>/dev/null) && printf '%s' "${m: -4}"
    else
        bb stat -c '%a' "$1" 2>/dev/null
    fi
}
# Worker copy of the main script's _hash_each (openssl / BSD md5 fallback
# printed in coreutils "<hash>  <name>" format; see there).
_hash_each() {
    local tool="$1" f out
    shift
    local -a c
    case "$tool" in
        bsd-md5)   c=(md5 -q) ;;
        openssl-*) c=(openssl dgst "-${tool#openssl-}") ;;
        *) return 1 ;;
    esac
    if [ $# -eq 0 ]; then
        out=$("${c[@]}") || return 1
        printf '%s  -\n' "${out##* }"; return
    fi
    for f in "$@"; do
        out=$("${c[@]}" < "$f" 2>/dev/null) || continue
        out="${out##* }"
        [[ "$out" =~ ^[0-9a-f]+$ ]] || continue
        case "$f" in
            *\\*|*$'\n'*) f="${f//\\/\\\\}"; printf '\\%s  %s\n' "$out" "${f//$'\n'/\\n}" ;;
            *) printf '%s  %s\n' "$out" "$f" ;;
        esac
    done
}
_sha256_stdin() {
    [ "$SHA256_CMD" = "none" ] && { cat >/dev/null; echo ""; return; }
    $SHA256_CMD 2>/dev/null | bb grep -oE '[0-9a-f]{64}' | head -1
}
_b64decode() {
    if [ "$OS" = "macos" ]; then base64 -D 2>/dev/null
    else base64 -d 2>/dev/null; fi
}

# ----------------------------------------------------------------------------
# MODULE: PE section parsing (for .mdb ClamAV signatures — PE section hashes)
#
# Parses just enough of the PE/COFF header to find each section's raw
# offset and raw size within the file: DOS header -> e_lfanew -> PE
# signature -> COFF header (NumberOfSections, SizeOfOptionalHeader) ->
# section table (40 bytes/entry, PointerToRawData @ +20, SizeOfRawData
# @ +16). Only the first 4096 bytes are read, which covers the header of
# virtually every real-world PE file.
# ----------------------------------------------------------------------------
_hex_byte() {
    local h="${1:$(( $2 * 2 )):2}"
    [ -z "$h" ] && { echo 0; return; }
    echo $((16#$h))
}
_hex_le16() {
    echo $(( $(_hex_byte "$1" "$2") + $(_hex_byte "$1" $(($2+1))) * 256 ))
}
_hex_le32() {
    echo $(( $(_hex_byte "$1" "$2") \
             + $(_hex_byte "$1" $(($2+1))) * 256 \
             + $(_hex_byte "$1" $(($2+2))) * 65536 \
             + $(_hex_byte "$1" $(($2+3))) * 16777216 ))
}

# Prints "offset\tsize" per PE section, one per line. Returns non-zero (no
# output) if the file isn't a well-formed PE within the first 4096 bytes.
_pe_section_table() {
    local file="$1"
    local hexdump
    hexdump=$(bb dd if="$file" bs=4096 count=1 2>/dev/null | bb od -An -tx1 -v | tr -d ' \n')
    [ -z "$hexdump" ] && return 1
    local hexlen=${#hexdump}

    [ "${hexdump:0:4}" != "4d5a" ] && return 1

    local e_lfanew
    e_lfanew=$(_hex_le32 "$hexdump" 60)
    [ "$e_lfanew" -le 0 ] 2>/dev/null && return 1
    [ $(( (e_lfanew + 24) * 2 )) -gt "$hexlen" ] && return 1
    [ "${hexdump:$((e_lfanew*2)):8}" != "50450000" ] && return 1

    local num_sections opt_hdr_size sec_table_off
    num_sections=$(_hex_le16 "$hexdump" $((e_lfanew+6)))
    opt_hdr_size=$(_hex_le16 "$hexdump" $((e_lfanew+20)))
    sec_table_off=$((e_lfanew + 24 + opt_hdr_size))

    local i off ptr rawsize
    for ((i = 0; i < num_sections && i < 96; i++)); do
        off=$((sec_table_off + i * 40))
        [ $(( (off + 40) * 2 )) -gt "$hexlen" ] && break
        rawsize=$(_hex_le32 "$hexdump" $((off+16)))
        ptr=$(_hex_le32 "$hexdump" $((off+20)))
        [ "$rawsize" -gt 0 ] 2>/dev/null && printf '%s\t%s\n' "$ptr" "$rawsize"
    done
}

# Timed wrappers around each batch-processing function — accumulate coarse
# per-phase timing (T_*_MS) so a slow scan can be diagnosed by WHERE time
# actually goes (reported in the final summary) instead of guessed at.
# Deliberately NOT applied to per-file calls (check_file_heuristics) — the
# timing itself forks `date`, and doing that thousands of times would add
# real overhead to exactly what we're trying to measure.
#
# -L/--long-time: when a SINGLE batch call takes longer than
# LONG_TIME_THRESHOLD_SEC, log it immediately (batch type, elapsed time,
# and the exact file list) — pure observability, no behavior change to
# the scan itself. This is the direct "what got stuck" answer requested:
# instead of inferring from a hung-looking process, the log shows exactly
# which batch (and which files in it) was slow, the moment it happens,
# while the scan keeps going.
#
# NOTE: written to a DEDICATED file (LIVE_REPORT_FILE + ".slow"), not
# LIVE_REPORT_FILE itself — on a normal (non-interrupted) finish,
# save_report() in the main script OVERWRITES LIVE_REPORT_FILE with the
# clean final summary, which would silently wipe out every slow-batch
# entry logged during a scan that ultimately completed successfully. A
# separate file survives that regardless of how the scan ends.
_log_if_long() {
    local kind="$1" elapsed_ms="$2"; shift 2
    [ "$LONG_TIME_MODE" = "true" ] || return
    [ $(( elapsed_ms / 1000 )) -ge "$LONG_TIME_THRESHOLD_SEC" ] || return
    [ -n "$LIVE_REPORT_FILE" ] || return
    printf '[%s] [SLOW_BATCH] type=%s elapsed_ms=%d files=%s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$kind" "$elapsed_ms" "$*" \
        >> "${LIVE_REPORT_FILE}.slow" 2>/dev/null
}
_timed_hash_batch() {
    local _t0; _t0=$(_now_ms)
    process_hash_batch "$@"
    local _t1; _t1=$(_now_ms)
    T_HASH_MS=$(( T_HASH_MS + _t1 - _t0 ))
    _log_if_long "hash" $(( _t1 - _t0 )) "$@"
}
# threads mode (see _yara_ram_cap in the main script): ordinary workers do
# not run yara themselves, they hand each batch (NUL-separated paths) to the
# consumer's queue. The consumer, the real-time worker ("rt") and the
# workers mode scan directly.
YQ_SEQ=0
_yara_enqueue() {
    local q="$REPORT_DIR/.yq" f
    YQ_SEQ=$(( YQ_SEQ + 1 ))
    f="$q/${WORKER_ID}.$(printf '%06d' "$YQ_SEQ")"
    printf '%s\0' "$@" > "$f.tmp" && mv -f "$f.tmp" "$f.lst"
}
_yara_queued_mode() {
    [ "${YARA_MODE:-workers}" = "threads" ] && [ "${AV_YARA_ROLE:-}" != "consumer" ] \
        && [ "$WORKER_ID" != "rt" ] && [ -d "$REPORT_DIR/.yq" ] && [ "$HAS_YARA" = true ]
}
_timed_yara_batch() {
    if _yara_queued_mode; then _yara_enqueue "$@"; return 0; fi
    local _t0; _t0=$(_now_ms)
    process_yara_batch "$@"
    local _t1; _t1=$(_now_ms)
    T_YARA_MS=$(( T_YARA_MS + _t1 - _t0 ))
    _log_if_long "yara" $(( _t1 - _t0 )) "$@"
}
_timed_heur_batch() {
    local _t0; _t0=$(_now_ms)
    process_heuristic_batch "$@"
    local _t1; _t1=$(_now_ms)
    T_HEUR_MS=$(( T_HEUR_MS + _t1 - _t0 ))
    _log_if_long "heur" $(( _t1 - _t0 )) "$@"
}
_timed_pe_batch() {
    local _t0; _t0=$(_now_ms)
    process_pe_batch "$@"
    local _t1; _t1=$(_now_ms)
    T_PE_MS=$(( T_PE_MS + _t1 - _t0 ))
    _log_if_long "pe" $(( _t1 - _t0 )) "$@"
}

# Batched (size, md5) lookup for a set of candidate PE files' sections
# against mdb.tsv. Same rationale as the other batch functions: mdb.tsv can
# be millions of lines for a real ClamAV database, so the per-call cost is
# paid once for the whole batch, not once per file.
process_pe_batch() {
    [ $# -eq 0 ] || [ "$HAS_MDB" = false ] && return

    local tmp_candidates
    tmp_candidates=$(mktemp 2>/dev/null) || return
    local -a cand_file=() cand_off=() cand_sz=() cand_md5=()
    local idx=0 f sections off sz sec_md5

    for f in "$@"; do
        sections=$(_pe_section_table "$f" 2>/dev/null) || continue
        [ -z "$sections" ] && continue
        while IFS=$'\t' read -r off sz; do
            [ -z "$sz" ] || [ "$sz" -le 0 ] 2>/dev/null && continue
            [ "$sz" -gt 20971520 ] && continue   # 20MB/section sanity cap
            sec_md5=$(tail -c "+$((off+1))" "$f" 2>/dev/null | head -c "$sz" | $MD5_CMD 2>/dev/null | bb grep -oE '[0-9a-f]{32}' | head -1)
            [ -z "$sec_md5" ] && continue
            printf '%s\t%s\n' "$sz" "$sec_md5" >> "$tmp_candidates"
            cand_file[$idx]="$f"; cand_off[$idx]="$off"; cand_sz[$idx]="$sz"; cand_md5[$idx]="$sec_md5"
            idx=$((idx + 1))
        done <<< "$sections"
    done

    if [ -s "$tmp_candidates" ]; then
        local hits
        hits=$(bb grep -F -f "$tmp_candidates" "$SIG_DIR/mdb.tsv" 2>/dev/null)
        if [ -n "$hits" ]; then
            local hsz hhash hname i
            while IFS=$'\t' read -r hsz hhash hname; do
                [ -z "$hhash" ] && continue
                for ((i = 0; i < idx; i++)); do
                    if [ "${cand_sz[$i]}" = "$hsz" ] && [ "${cand_md5[$i]}" = "$hhash" ]; then
                        threat "KNOWN_MALWARE_SECTION" "${cand_file[$i]}" "name=${hname:-Section.Malware}|size=$hsz|md5=$hhash"
                    fi
                done
            done <<< "$hits"
        fi
    fi
    rm -f "$tmp_candidates"
}

_bash_strings() {
    local file="$1" min_len="${2:-6}" max_bytes="${3:-524288}"
    bb dd if="$file" bs="$max_bytes" count=1 2>/dev/null \
    | bb od -An -tx1 -v | tr -s ' ' '\n' | bb grep -v '^\s*$' \
    | bb awk -v min="$min_len" '
        function h2d(h, v,i,c) {
            v=0; h=tolower(h)
            for(i=1;i<=length(h);i++){ c=substr(h,i,1); v=v*16+(c~/[0-9]/?c+0:index("abcdef",c)+9) }
            return v
        }
        {
            b = h2d($0)
            if (b >= 32 && b <= 126) buf = buf sprintf("%c", b)
            else { if (length(buf) >= min) print buf; buf = "" }
        }
        END { if (length(buf) >= min) print buf }
    '
}

# ----------------------------------------------------------------------------
# MODULE: package-manager integrity check (dpkg/rpm)
#
# Verifies a file against the distro's own package checksum database.
# Result cached per-worker: dpkg -S/-V calls aren't free, but SUID/SGID
# files are rare (dozens, not thousands) so per-file cost is negligible.
# ----------------------------------------------------------------------------
declare -A _PKG_VERIFY_CACHE 2>/dev/null
_verify_package_file() {
    local file="$1"
    [ -n "${_PKG_VERIFY_CACHE[$file]:-}" ] && { echo "${_PKG_VERIFY_CACHE[$file]}"; return; }

    # FIX (real slowdown found and measured): `dpkg -S` on a file that's
    # NOT package-owned takes over a SECOND (confirmed: 1.18s) — it has to
    # linearly scan every installed package's file list before it can
    # conclude there's no match. Package managers only ever install into a
    # known, fixed set of system directories — a SUID/SGID file under a
    # web root or home directory (exactly where this kept firing on a real
    # scan) is essentially guaranteed not to be package-owned, so skip the
    # lookup ENTIRELY for paths outside that set instead of paying ~1s+ to
    # confirm the obvious on every such hit in a content tree. This is
    # what was silently turning "average 8-9 files/s" into "3 files/s" —
    # peak throughput (the batched hash/YARA path) was unaffected, but
    # every SUID/SGID file outside /usr,/bin,/sbin,/lib,/opt added a
    # second-plus synchronous stall outside any batching.
    case "$file" in
        /usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/opt/*) : ;;
        *)
            _PKG_VERIFY_CACHE[$file]="unowned"
            echo "unowned"
            return
            ;;
    esac

    local result="unowned"
    if command -v dpkg &>/dev/null; then
        local pkg
        # timeout as defense in depth: even within a system dir, an
        # unowned file (manually installed software, etc.) hits the same
        # slow "confirm the negative" path — cap the worst case instead of
        # letting a single lookup stall a whole batch.
        local dpath="$file" alt=""
        pkg=$(timeout 2 dpkg -S "$file" 2>/dev/null | head -1 | cut -d: -f1)
        # Merged /usr (/bin -> usr/bin): the scan finds /usr/bin/fusermount3,
        # dpkg recorded /bin/fusermount3 (or the reverse on Debian 13), so a
        # stock SUID binary came out "unowned". Retry the other name, only
        # if both names are the same file.
        if [ -z "$pkg" ]; then
            case "$file" in
                /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*) alt="${file#/usr}" ;;
                /bin/*|/sbin/*|/lib/*|/lib64/*) alt="/usr$file" ;;
            esac
            if [ -n "$alt" ] && [ "$alt" -ef "$file" ]; then
                pkg=$(timeout 2 dpkg -S "$alt" 2>/dev/null | head -1 | cut -d: -f1)
                [ -n "$pkg" ] && dpath="$alt"
            fi
        fi
        if [ -n "$pkg" ]; then
            local md5file="/var/lib/dpkg/info/${pkg}.md5sums"
            [ -f "$md5file" ] || md5file="/var/lib/dpkg/info/${pkg%:*}.md5sums"
            if [ -f "$md5file" ]; then
                local relpath="${dpath#/}"
                local expected
                # Exact path (md5 + 2 spaces = column 35): a substring match
                # took e.g. usr/bin/fooX's sum for usr/bin/foo.
                expected=$(awk -v p="$relpath" 'substr($0, 35) == p { print $1; exit }' "$md5file" 2>/dev/null)
                if [ -n "$expected" ]; then
                    local actual
                    actual=$(bb md5sum "$file" 2>/dev/null | bb grep -oE '[0-9a-f]{32}' | head -1)
                    if [ "$expected" = "$actual" ]; then
                        result="verified"
                    else
                        result="tampered"
                    fi
                fi
            fi
        fi
    elif command -v rpm &>/dev/null; then
        if timeout 2 rpm -qf "$file" &>/dev/null; then
            local vout rc l mine=""
            # rpm -Vf checks the WHOLE package: an edited /etc/pam.d/su made
            # /usr/bin/su "tampered". Keep only the line for this same file
            # (-ef: rpm prints /usr/bin/su for /bin/su); a timeout (124) or
            # a failure without output stays unverified (was "verified").
            vout=$(timeout 2 rpm -Vf "$file" 2>/dev/null); rc=$?
            if [ "$rc" -eq 0 ] || { [ "$rc" -ne 124 ] && [ -n "$vout" ]; }; then
                while IFS= read -r l; do
                    case "$l" in */*) [ "/${l#*/}" -ef "$file" ] && mine+="$l"$'\n' ;; esac
                done <<< "$vout"
                if [ -z "$mine" ]; then
                    result="verified"
                elif echo "$mine" | bb grep -q "^..5"; then
                    result="tampered"
                fi
            fi
        fi
    fi

    _PKG_VERIFY_CACHE[$file]="$result"
    echo "$result"
}

_bash_file_type() {
    # PERFORMANCE: this is called on essentially every scanned file (YARA
    # skip_deep decision). The old dd+od pipeline forks 2 external
    # processes per call — on millions of files that overhead adds up
    # fast, especially on weaker/shared-CPU hosts. Read the first 8 bytes
    # via bash's own `read` builtin and convert to hex in pure bash — zero
    # forks. Falls back to the dd+od path if the pure-bash read comes up
    # empty for any reason (e.g. exotic filesystem edge cases), so this
    # can't silently lose detection coverage.
    local bytes="" hex="" i c ord
    { IFS= read -r -d '' -n 8 bytes < "$1"; } 2>/dev/null
    if [ -n "$bytes" ]; then
        for (( i=0; i<${#bytes}; i++ )); do
            c="${bytes:$i:1}"
            printf -v ord '%02x' "'$c"
            hex+="$ord"
        done
    fi
    if [ -z "$hex" ]; then
        hex=$(bb dd if="$1" bs=8 count=1 2>/dev/null | bb od -An -tx1 -v | tr -d ' \n')
    fi
    [ -z "$hex" ] && { echo "EMPTY"; return; }
    case "$hex" in
        7f454c46*) echo "ELF" ;;
        4d5a*)     echo "PE_MZ" ;;
        25504446*) echo "PDF" ;;
        504b0304*) echo "ZIP" ;;
        89504e470d0a*) echo "PNG" ;;
        ffd8ff*)   echo "JPEG" ;;
        47494638*) echo "GIF" ;;
        1f8b*)     echo "GZIP" ;;
        425a68*)   echo "BZIP2" ;;
        377abcaf*) echo "7ZIP" ;;
        2321*)     echo "SCRIPT" ;;
        *)         echo "UNKNOWN";;
    esac
}

# ----------------------------------------------------------------------------
# MODULE: archive scanning (-A/--scan-archives, opt-in)
#
# Extracts supported archive types into a throwaway directory and runs each
# extracted member through the SAME hash/YARA/string checks used for real
# files. Detections are reported against the ARCHIVE FILE itself (not the
# transient extracted path — that stops existing once the scan ends), with
# the internal member path in the info field, so the user always has a
# real, persistent file to act on. If quarantine is enabled, the WHOLE
# ARCHIVE gets quarantined (moving just the extracted copy would leave the
# infected archive sitting right where it was).
#
# Safety limits (all overridable via CLI flags — see usage):
#   - skip archives bigger than ARCHIVE_MAX_MB compressed
#   - abort extraction past ARCHIVE_MAX_EXTRACT_MB decompressed (bomb guard)
#   - only look at the first ARCHIVE_MAX_FILES members
#   - only recurse ARCHIVE_MAX_DEPTH levels into nested archives
#   - every extraction command runs under `timeout`, so a malformed/hostile
#     archive can't hang a worker indefinitely
# ----------------------------------------------------------------------------
_archive_type() {
    case "${1,,}" in
        *.tar.gz|*.tgz)   echo "targz" ;;
        *.tar.bz2|*.tbz2) echo "tarbz2" ;;
        *.tar.xz|*.txz)   echo "tarxz" ;;
        *.tar)            echo "tar" ;;
        *.zip|*.jar|*.war|*.apk|*.ear) echo "zip" ;;
        *.gz)             echo "gz" ;;
        *.bz2)            echo "bz2" ;;
        *.xz)             echo "xz" ;;
        *.7z)             command -v 7z &>/dev/null && echo "7z" ;;
        *.rar)            { command -v unrar &>/dev/null || command -v 7z &>/dev/null; } && echo "rar" ;;
        *) ;;
    esac
}

# ----------------------------------------------------------------------------
# MODULE: sandboxed extraction (optional, --sandbox-mode)
#
# Archive extraction is the highest-risk operation in this whole script:
# it parses an ATTACKER-CONTROLLED file format (zip/tar/7z/rar) with
# external tools that have historically had real vulnerabilities (path
# traversal / "zip slip", decompression bombs, parser buffer overflows).
# This wraps that extraction in an isolation layer as defense-in-depth —
# a bug in unzip/tar/7z exploited by a malicious archive is far less
# dangerous running as an unprivileged, network-less, filesystem-isolated
# process than running as whatever this scanner itself runs as (often
# root, to reach protected files).
#
# Off by default (SANDBOX_MODE=none) — this changes nothing unless
# explicitly requested via --sandbox-mode, and even then only wraps
# archive extraction, not the rest of the scan.
#
# Rewritten from a person's own draft (credited to a suggestion from
# another AI) after finding two real, serious bugs in it during review:
#   1. bwrap mode had "2>/dev/null || true" INSIDE a backslash-continued
#      argument list — that's not a per-argument fallback, it's a real
#      shell "||", so bwrap's later arguments (--proc, --tmpfs, --uid,
#      --gid, and the command to actually run) were silently NEVER
#      passed at all. Confirmed by reproducing the exact pattern: only
#      the arguments before the first "|| true" ever reached the command.
#   2. chroot mode bind-mounted 5 directories but only ever `rm -rf`'d the
#      chroot dir afterward — never unmounted them. Every archive
#      processed would leak 5 more stale bind mounts, accumulating for
#      the life of a long-running scan.
# Both fixed below: conditional binds are built into an ARGS ARRAY with
# separate statements before bwrap ever runs (no inline "|| true" inside
# its argument list), and chroot mode unmounts everything (in reverse
# order) in a trap before removing the directory.
#
# SANDBOX_MODE/SANDBOX_USER/SANDBOX_MEM_KB/SANDBOX_CPU_SEC are already set
# from positional params above (33-38) — no re-declaration needed here.

_sandbox_has() { command -v "$1" &>/dev/null; }

_sandbox_run_bwrap() {
    local target_dir="$1" archive_src="$2"; shift 2
    local args=(
        --unshare-all --new-session --die-with-parent
        --ro-bind /usr /usr
        --proc /proc --dev /dev
        --tmpfs /home --tmpfs /root
        # /tmp BEFORE the binds below: mounted after them it hid a
        # target_dir / staged archive under /tmp (disk fallback when
        # /dev/shm is small or --no-ram).
        --tmpfs /tmp
        --chdir /tmp
        --setenv HOME /tmp --setenv USER nobody
        --uid 65534 --gid 65534
    )
    # bind /bin, /lib, /lib64, /sbin only if they exist as real entries —
    # checked as SEPARATE statements before the call, not inline in it.
    [ -d /bin ]   && args+=(--ro-bind /bin /bin)
    [ -d /lib ]   && args+=(--ro-bind /lib /lib)
    [ -d /lib64 ] && args+=(--ro-bind /lib64 /lib64)
    [ -d /sbin ]  && args+=(--ro-bind /sbin /sbin)
    # The extraction target dir needs to be WRITABLE inside the sandbox
    # (that's the whole point — the extracted files have to land
    # somewhere this worker can then read back out).
    args+=(--bind "$target_dir" "$target_dir")
    # FIX (real bug found in testing): the ARCHIVE FILE ITSELF lives
    # somewhere else entirely (wherever it was found on the scanned
    # tree) — --unshare-all + explicit binds means NOTHING outside those
    # binds is visible at all, so the extraction tool couldn't even open
    # its own input file ("cannot find or open ..."). Bind its containing
    # directory read-only too, same real path as outside, so the
    # extraction command's own "$archive" argument still resolves.
    if [ -n "$archive_src" ]; then
        local archive_dir; archive_dir=$(dirname "$archive_src")
        args+=(--ro-bind "$archive_dir" "$archive_dir")
    fi
    # FIX (second, separate instance of the SAME bug — found right after
    # fixing the first): the extraction tool ITSELF is very often our own
    # bundled busybox (e.g. "$BUSYBOX_BIN unzip"), installed somewhere
    # under this scanner's OWN directory tree — NOT under /bin or /usr, so
    # it was ALSO invisible inside the sandbox, and extraction failed
    # silently for the exact same "can't find the binary" reason.
    if [ -n "$BUSYBOX_BIN" ] && [ -x "$BUSYBOX_BIN" ]; then
        local bb_dir; bb_dir=$(dirname "$BUSYBOX_BIN")
        args+=(--ro-bind "$bb_dir" "$bb_dir")
    fi
    bwrap "${args[@]}" -- "$@"
}

_sandbox_run_unshare() {
    local target_dir="$1" archive_src="$2"; shift 2
    # --user needs unprivileged user namespaces enabled in the kernel —
    # not universal (disabled on some hardened kernels/containers). Falls
    # through to the caller's own fallback chain if this exits non-zero.
    # NOTE: unlike bwrap/chroot, this does NOT pivot/chroot the root
    # filesystem — it only gets its own independent mount table, so the
    # archive's original path stays visible without any extra binding.
    unshare --user --map-root-user --pid --mount --ipc --uts --fork --kill-child -- \
        bash -c 'mount -t proc proc /proc 2>/dev/null || true; cd "$1"; shift; exec "$@"' \
        _ "$target_dir" "$@"
}

_sandbox_run_chroot() {
    local target_dir="$1" archive_src="$2"; shift 2
    [ "$(id -u)" = "0" ] || { "$@"; return; }  # chroot needs root
    local chroot_dir
    chroot_dir=$(mktemp -d "/tmp/av_chroot.${MAIN_SCRIPT_PID}.XXXXXX" 2>/dev/null) || { "$@"; return; }
    mkdir -p "$chroot_dir"/{bin,lib,lib64,usr,proc,dev,sbin} 2>/dev/null

    # FIX (real bug found in testing): binding target_dir to "$chroot_dir/tmp"
    # and cd-ing to /tmp inside the jail looked reasonable, but the
    # extraction COMMAND itself (built in _archive_extract, which has no
    # idea it might run inside a chroot) still references target_dir by
    # its ORIGINAL absolute path (e.g. "-d /dev/shm/av_arch_XXXXXX") — a
    # path that doesn't exist inside a jail that only knows it as /tmp.
    # Confirmed: extraction silently found nothing (0 threats) with the
    # old /tmp remap. Recreate target_dir at its OWN real path inside the
    # jail instead, matching what bwrap mode already does with --bind.
    mkdir -p "${chroot_dir}${target_dir}" 2>/dev/null

    local -a mounted=()
    local _bind_failed=false
    # FIX (CRITICAL, found in review — a real "our own busybox disappeared
    # mid-scan" report led here): _cbind() used to be a PLAIN mount --bind
    # with no read-only step at all for /bin,/lib,/lib64,/usr,/sbin — the
    # entire point of this sandbox is to contain a potentially HOSTILE,
    # attacker-crafted archive during extraction, and it was binding real
    # system directories into that jail WRITABLE. Separately, the archive_dir
    # and busybox binds DID attempt a read-only remount, but never checked
    # whether it actually succeeded (`2>/dev/null` swallows the failure) —
    # confirmed directly that `mount --bind` alone is read-write and the
    # follow-up `remount,ro` is a genuinely separate step that can fail on
    # its own, silently leaving a writable bind mount of OUR OWN tools
    # directory (where busybox/yara/grep/bash live) inside the jail. Every
    # bind here is now read-only AND VERIFIED; if read-only can't be
    # confirmed for ANY of them, the whole chroot attempt aborts and falls
    # back to unsandboxed extraction rather than silently running with a
    # writable hole in the isolation it exists to provide.
    _cbind() {
        mount --bind "$1" "$2" 2>/dev/null || return 1
        mounted+=("$2")
        mount -o remount,ro,bind "$2" 2>/dev/null
        mountpoint -q "$2" 2>/dev/null && [ ! -w "$2" ] 2>/dev/null
    }
    [ -d /bin ]   && { _cbind /bin   "$chroot_dir/bin"   || _bind_failed=true; }
    [ -d /lib ]   && { _cbind /lib   "$chroot_dir/lib"   || _bind_failed=true; }
    [ -d /lib64 ] && { _cbind /lib64 "$chroot_dir/lib64" || _bind_failed=true; }
    [ -d /usr ]   && { _cbind /usr   "$chroot_dir/usr"   || _bind_failed=true; }
    [ -d /sbin ]  && { _cbind /sbin  "$chroot_dir/sbin"  || _bind_failed=true; }
    mount -t proc proc "$chroot_dir/proc" 2>/dev/null && mounted+=("$chroot_dir/proc")
    # target_dir (the extraction destination) legitimately needs to stay
    # writable — that's where the archive's own contents get written —
    # so it deliberately does NOT go through the read-only _cbind above.
    mount --bind "$target_dir" "${chroot_dir}${target_dir}" 2>/dev/null && mounted+=("${chroot_dir}${target_dir}")

    # The archive file itself lives OUTSIDE target_dir — bind its
    # containing directory too (read-only), same real path, so the
    # extraction command can still open its own input file inside the jail.
    if [ -n "$archive_src" ]; then
        local archive_dir; archive_dir=$(dirname "$archive_src")
        mkdir -p "${chroot_dir}${archive_dir}" 2>/dev/null
        _cbind "$archive_dir" "${chroot_dir}${archive_dir}" || _bind_failed=true
    fi

    # The extraction tool itself is very often our own bundled busybox,
    # installed under this scanner's OWN directory — not /bin or /usr —
    # so it was ALSO invisible inside the jail. Bind that in too, read-only.
    if [ -n "$BUSYBOX_BIN" ] && [ -x "$BUSYBOX_BIN" ]; then
        local bb_dir; bb_dir=$(dirname "$BUSYBOX_BIN")
        mkdir -p "${chroot_dir}${bb_dir}" 2>/dev/null
        _cbind "$bb_dir" "${chroot_dir}${bb_dir}" || _bind_failed=true
    fi

    # FIX: unmount everything (reverse order — last mounted, first
    # unmounted, matters when one mount is nested under another) BEFORE
    # removing the directory, not just rm -rf on top of active mounts.
    # FIX (CRITICAL — real risk confirmed by direct testing): if umount
    # AND umount -l BOTH fail for some mount (a hung process inside the
    # jail, or the worker getting SIGKILL'd at exactly the wrong moment),
    # the old code fell through to "rm -rf $chroot_dir" regardless. That
    # is genuinely destructive: rm -rf CAN recurse INTO an active bind
    # mount and delete its CONTENTS even though it cannot remove the
    # mountpoint directory itself (the kernel blocks that specific
    # rmdir, "Device or resource busy" — but everything *inside* is
    # fair game to rm first). Confirmed directly: a bind-mounted test
    # file was deleted this way even though the mountpoint directory
    # "survived". Since these mounts are real system paths (/bin, /usr,
    # /lib, /lib64, /sbin), a failed cleanup here could otherwise delete
    # the ACTUAL system's own binaries. Now: verify every mount is
    # actually gone (mountpoint -q) before ever calling rm -rf; if even
    # one remains stuck, leave the directory in place untouched and log
    # a warning instead of guessing it's safe to recurse through it.
    _cleanup_chroot() {
        local i still_mounted=false
        for (( i=${#mounted[@]}-1; i>=0; i-- )); do
            umount "${mounted[$i]}" 2>/dev/null || umount -l "${mounted[$i]}" 2>/dev/null || true
        done
        for i in "${mounted[@]}"; do
            if mountpoint -q "$i" 2>/dev/null; then
                still_mounted=true
                echo "[WARN] chroot sandbox cleanup: '$i' is still mounted after umount + umount -l both failed -- refusing to rm -rf '$chroot_dir' (would risk deleting through the live mount). Left in place for manual cleanup: umount it, then remove the directory by hand." >&2
            fi
        done
        [ "$still_mounted" = false ] && rm -rf "$chroot_dir" 2>/dev/null
    }
    # Called directly, not via "trap ... RETURN": that trap is global and
    # outlives this call (fires on every later function return in the same
    # shell), and a bomb kill of the jailed command must still unmount.
    local rc

    if [ "$_bind_failed" = true ]; then
        echo "[WARN] chroot sandbox: at least one bind mount could not be verified read-only -- refusing to run the extraction inside a jail with an unconfirmed writable hole in it. Falling back to unsandboxed extraction for this archive." >&2
        _cleanup_chroot
        "$@"
        return
    fi

    chroot "$chroot_dir" /bin/bash -c 'cd "$1"; shift; exec "$@"' _ "$target_dir" "$@"
    rc=$?
    _cleanup_chroot
    return $rc
}

_sandbox_run_simple() {
    local target_dir="$1" archive_src="$2"; shift 2
    # NOTE: simple mode doesn't isolate the filesystem view at all (just
    # drops privileges + resource limits), so the archive's own read
    # permissions still apply as-is after the UID switch — if it's only
    # readable by root (protected directory), extraction under "nobody"
    # can still fail for that reason. Known, documented limitation of
    # this specific mode; bwrap/chroot don't have it since they instead
    # explicitly bind the archive's directory in.
    #
    # FIX: sudo often isn't installed at all on minimal VPS images
    # (confirmed missing in testing) — setpriv (util-linux, near-universal
    # on Linux) drops privileges without needing sudo configured at all.
    local dropper=() owner=""
    if [ "$(id -u)" = "0" ]; then
        # mktemp -d creates directories mode 0700, root-owned: the dropped
        # user must be able to write target_dir (else extraction produces
        # nothing, silently) and read the staged archive copy. chown to
        # exactly the uid/gid we drop to -- NOT chmod 0777: a world-writable
        # dir lets any other local user plant/swap files in it mid-scan.
        if _sandbox_has setpriv; then
            dropper=(setpriv --reuid 65534 --regid 65534 --clear-groups)
            owner="65534:65534"
        elif _sandbox_has runuser; then
            dropper=(runuser -u "$SANDBOX_USER" --)
            owner="$SANDBOX_USER:$(id -gn "$SANDBOX_USER" 2>/dev/null || echo "$SANDBOX_USER")"
        fi
        if [ -n "$owner" ]; then
            chown "$owner" "$target_dir" 2>/dev/null
            # Only our own private staging copy (scan_archive), never a site file.
            case "$archive_src" in
                */av_arch_*_in.*/*) chown "$owner" "$(dirname "$archive_src")" "$archive_src" 2>/dev/null ;;
            esac
        fi
    fi
    # FIX: ulimit -v (virtual memory) routinely breaks legitimate binaries
    # that reserve large address space upfront (thread stacks, mmap'd
    # shared libs) even when actual RSS usage is modest — using -m (RSS,
    # where the OS enforces it) instead avoids killing extraction tools
    # that were never actually going to use that much real memory.
    (
        ulimit -t "$SANDBOX_CPU_SEC" 2>/dev/null
        ulimit -f 512000 2>/dev/null
        ulimit -n 256 2>/dev/null
        ulimit -u 128 2>/dev/null
        cd "$target_dir" 2>/dev/null || true
        # exec: the bomb guard in scan_archive signals this process tree;
        # as a plain subshell it could die and leave timeout+tar running.
        if [ ${#dropper[@]} -gt 0 ]; then
            exec "${dropper[@]}" "$@"
        else
            exec "$@"
        fi
    )
}

# run_sandboxed TARGET_DIR ARCHIVE_SRC CMD...
# TARGET_DIR is the extraction destination — needs to stay reachable
# (writable) inside whichever isolation mode runs. ARCHIVE_SRC is the
# archive file's own path — filesystem-isolating modes (bwrap/chroot)
# need read access to it explicitly bound in too, since it normally lives
# somewhere else entirely on the scanned tree, not under TARGET_DIR.
# Falls all the way through to running CMD un-sandboxed only for
# SANDBOX_MODE=none (explicit opt-out, not a silent fallback).
#
# _sandbox_resolve: a mode that can't start here (no user namespaces in a
# container / CloudLinux / user.max_user_namespaces=0, bwrap not setuid...)
# made EVERY extraction produce nothing and the archive went unscanned,
# silently. Probe the chosen mode once per worker with `true` (in a
# subshell, so nothing it sets leaks) and fall back to "simple" with a log
# line if it fails.
_SANDBOX_CHECKED=false
declare -A _ARCH_NL_ORIG=()   # plain-named link -> newline-named member (scan_archive)
_sandbox_resolve() {
    [ "$_SANDBOX_CHECKED" = true ] && return
    _SANDBOX_CHECKED=true
    local want="$SANDBOX_MODE" m d
    local -a cand=()
    case "$want" in
        none|simple) return ;;
        auto) cand=(bwrap unshare) ;;
        bwrap|unshare|chroot) cand=("$want") ;;
        *) return ;;
    esac
    SANDBOX_MODE=simple
    d=$(mktemp -d "${TMPDIR:-/tmp}/av_arch_${MAIN_SCRIPT_PID}_probe.XXXXXX" 2>/dev/null) || d=""
    for m in "${cand[@]}"; do
        [ -n "$d" ] || break
        _sandbox_has "$m" || continue
        if ( "_sandbox_run_$m" "$d" "" true ) &>/dev/null; then SANDBOX_MODE="$m"; break; fi
    done
    [ -n "$d" ] && rm -rf "$d"
    if [ "$SANDBOX_MODE" = simple ]; then
        log "Sandbox mode '$want' (${cand[*]}) does not work here -- archives are extracted in 'simple' mode"
        [ "$want" != auto ] && echo "[WARN] --sandbox-mode $want does not work here -- archives are extracted in 'simple' mode" >&2
    fi
}

run_sandboxed() {
    local target_dir="$1" archive_src="$2"; shift 2
    local mode="$SANDBOX_MODE"
    if [ "$mode" = "auto" ]; then
        if _sandbox_has bwrap; then mode="bwrap"
        elif _sandbox_has unshare; then mode="unshare"
        else mode="simple"; fi
    fi
    case "$mode" in
        bwrap)    _sandbox_has bwrap    && { _sandbox_run_bwrap "$target_dir" "$archive_src" "$@"; return; } ;;
        unshare)  _sandbox_has unshare  && { _sandbox_run_unshare "$target_dir" "$archive_src" "$@"; return; } ;;
        chroot)   _sandbox_has chroot   && { _sandbox_run_chroot "$target_dir" "$archive_src" "$@"; return; } ;;
        simple)   { _sandbox_run_simple "$target_dir" "$archive_src" "$@"; return; } ;;
        none|*)   "$@"; return ;;
    esac
    # Requested mode's tool isn't actually available -> run unsandboxed
    # rather than silently fail extraction entirely.
    "$@"
}

_archive_extract() {
    local archive="$1" atype="$2" extract_dir="$3"
    # FIX: `timeout CMD` execs CMD as a real process — it cannot see shell
    # FUNCTIONS like bb(), so "timeout 30 bb unzip ..." failed with "bb:
    # command not found" (exit 127) every time, silently (stderr
    # discarded), extracting nothing. Resolve the real command (busybox
    # binary + applet, or the system tool) into a plain string BEFORE
    # handing it to timeout, same lookup bb() does internally. Same
    # reasoning applies to run_sandboxed below — it's also a shell
    # function, so `timeout` has to wrap the REAL command being passed
    # INTO it, not run_sandboxed itself.
    local unzip_c="unzip" tar_c="tar" gunzip_c="gunzip"
    case "$BB_APPLETS" in *" unzip "*)  unzip_c="$BUSYBOX_BIN unzip" ;; esac
    case "$BB_APPLETS" in *" tar "*)    tar_c="$BUSYBOX_BIN tar" ;; esac
    case "$BB_APPLETS" in *" gunzip "*) gunzip_c="$BUSYBOX_BIN gunzip" ;; esac
    case "$atype" in
        zip)    run_sandboxed "$extract_dir" "$archive" timeout 30 $unzip_c -qq -o "$archive" -d "$extract_dir" 2>/dev/null ;;
        tar)    run_sandboxed "$extract_dir" "$archive" timeout 30 $tar_c -xf "$archive" -C "$extract_dir" 2>/dev/null ;;
        targz)  run_sandboxed "$extract_dir" "$archive" timeout 30 $tar_c -xzf "$archive" -C "$extract_dir" 2>/dev/null ;;
        tarbz2) run_sandboxed "$extract_dir" "$archive" timeout 30 $tar_c -xjf "$archive" -C "$extract_dir" 2>/dev/null ;;
        tarxz)  run_sandboxed "$extract_dir" "$archive" timeout 30 $tar_c -xJf "$archive" -C "$extract_dir" 2>/dev/null ;;
        gz)     run_sandboxed "$extract_dir" "$archive" timeout 30 $gunzip_c -c "$archive" > "$extract_dir/$(basename "${archive%.gz}")" 2>/dev/null ;;
        bz2)    run_sandboxed "$extract_dir" "$archive" timeout 30 bunzip2 -c "$archive" > "$extract_dir/$(basename "${archive%.bz2}")" 2>/dev/null ;;
        xz)     run_sandboxed "$extract_dir" "$archive" timeout 30 unxz -c "$archive" > "$extract_dir/$(basename "${archive%.xz}")" 2>/dev/null ;;
        7z)     run_sandboxed "$extract_dir" "$archive" timeout 30 7z x -y -o"$extract_dir" "$archive" &>/dev/null ;;
        rar)
            if command -v unrar &>/dev/null; then
                run_sandboxed "$extract_dir" "$archive" timeout 30 unrar x -y "$archive" "$extract_dir/" &>/dev/null
            else
                run_sandboxed "$extract_dir" "$archive" timeout 30 7z x -y -o"$extract_dir" "$archive" &>/dev/null
            fi
            ;;
    esac
}

_archive_tmpdir() {
    local compressed_size_mb="${1:-0}"
    # Extract into RAM (/dev/shm) when it makes sense, same reasoning as
    # the main WORK_DIR: much less I/O-bound than disk, which matters most
    # on exactly the kind of low-end/IOPS-capped VPS where every bit of
    # speed counts. Two conditions, both must hold:
    #   1. the ARCHIVE's own compressed size is under ARCHIVE_RAM_MAX_MB
    #      (default 50) — bounds how much RAM one archive can claim,
    #      independent of the (much larger) ARCHIVE_MAX_EXTRACT_MB bomb
    #      guard, which is about the DECOMPRESSED size instead.
    #   2. /dev/shm actually has that much free right now.
    # Respects --no-ram (USE_RAM=false); falls back to disk for archives
    # over the threshold, or when /dev/shm doesn't have room.
    if [ "$ARCHIVE_USE_RAM" = "true" ] && [ "$compressed_size_mb" -le "$ARCHIVE_RAM_MAX_MB" ] && [ -d /dev/shm ] && [ -w /dev/shm ]; then
        local avail
        avail=$(df -m /dev/shm 2>/dev/null | awk 'NR==2{print $4}')
        if [ "${avail:-0}" -ge "$ARCHIVE_MAX_EXTRACT_MB" ]; then
            mktemp -d "/dev/shm/av_arch_${MAIN_SCRIPT_PID}_XXXXXX" 2>/dev/null && return
        fi
    fi
    # FIX (real bug found in practice): this fallback used to be a bare
    # `mktemp -d` with no template — every large/disk-fallback archive
    # extraction got an UNPREFIXED "tmp.XXXXXXXXXX" name indistinguishable
    # from any other random system tmp dir. That meant these directories
    # were invisible to both the startup stale-dir sweep (which matches
    # on the "av_*" prefix) and self-exclusion — confirmed in practice: a
    # "/" scan re-discovered its OWN old leftover extractions sitting in
    # /tmp as if they were regular target files, re-reporting the same
    # DLE content a second time under a path that looked unrelated to
    # this scanner at all. Prefixed now, matching every other tmp dir
    # this script creates.
    mktemp -d "${TMPDIR:-/tmp}/av_arch_${MAIN_SCRIPT_PID}_XXXXXX" 2>/dev/null
}

# Batched hash check across ALL members of one archive at once — computing
# each member's hash is inherently per-file (unavoidable), but the lookup
# itself uses the same fast grep -qF path the main scan uses.
_archive_batch_hash_check() {
    local top_archive="$1" extract_dir="$2" cur_rel="$3"; shift 3

    # FIX (real hang reported: an 18MB DLE zip "hanging" for over a
    # minute): despite the name, this used to loop per-member, calling
    # sha256sum/md5sum AND a busybox-grep lookup against sha256.tsv/
    # md5.tsv SEPARATELY FOR EVERY FILE inside the archive — exactly the
    # same per-file overhead problem already fixed for the main scan
    # pipeline (busybox grep against the 632k-line md5.tsv alone measured
    # ~1.5s/call), just never applied here. A few hundred files inside one
    # archive meant a few hundred seconds. Now genuinely batched, same
    # pattern as process_hash_batch(): hash the whole member set in ONE
    # command, look up ALL hashes in ONE grep call, via the fast
    # bundled/system grep (_real_grep), not busybox's.
    local -a valid=()
    local m msize
    for m in "$@"; do
        msize=$(_stat_size "$m" 2>/dev/null) || continue
        { [ "${msize:-0}" -eq 0 ] || [ "${msize:-0}" -gt "$MAX_SIZE" ]; } && continue
        valid+=("$m")
    done
    [ ${#valid[@]} -eq 0 ] && return

    # Same parsing rules as process_hash_batch, for sha256, sha1 and md5
    # (the same hash types normal files get):
    #  - only hex hashes go to the grep: an empty/garbage first column (an
    #    unreadable member, a name fragment) became an empty -F pattern that
    #    matched EVERY line of the .tsv, then the loop below ran per line;
    #  - coreutils prints "\<hash>  <escaped name>" for names with "\" --
    #    the "\" is stripped and the name decoded (back\slash.php was missed);
    #  - EVERY member with a matching hash is reported, not just the first.
    # Members with a newline in the name arrive here as plain-named hard
    # links (see scan_archive); _ARCH_NL_ORIG maps them back for the report.
    local htype cmd sig_file out hits hit_hash tname ln h f rel
    for htype in sha256 sha1 md5; do
        case "$htype" in
            sha256) [ "$HAS_SHA256" = true ] || continue; cmd="$SHA256_CMD" ;;
            sha1)   [ "$HAS_SHA1" = true ]   || continue; cmd="$SHA1_CMD" ;;
            md5)    [ "$HAS_MD5" = true ]    || continue; cmd="$MD5_CMD" ;;
        esac
        [ "$cmd" = "none" ] && continue
        sig_file="$SIG_DIR/$htype.tsv"
        out=$($cmd "${valid[@]}" 2>/dev/null)
        [ -z "$out" ] && continue
        hits=$(printf '%s\n' "$out" | cut -d' ' -f1 | sed 's/^\\//' | bb grep -E '^[0-9a-fA-F]+$' | _real_grep -F -f - "$sig_file" 2>/dev/null | cut -f1 | sort -u)
        [ -z "$hits" ] && continue
        while IFS= read -r hit_hash; do
            [ -z "$hit_hash" ] && continue
            tname=$(_real_grep -m 1 "^${hit_hash}" "$sig_file" 2>/dev/null | cut -f2)
            while IFS= read -r ln; do
                h="${ln%% *}"; f="${ln:${#h}+2}"
                if [ "${h:0:1}" = '\' ]; then h="${h:1}"; f=$(printf '%b' "$f"); fi
                [ "${h,,}" = "${hit_hash,,}" ] && [ -n "$f" ] || continue
                f="${_ARCH_NL_ORIG[$f]:-$f}"
                rel="${f#$extract_dir/}"
                [ -n "$cur_rel" ] && rel="${cur_rel}!${rel}"
                threat "KNOWN_MALWARE" "$top_archive" "archive_member=${rel//$'\n'/?}|name=${tname:-Malware}|$htype=$hit_hash"
            done <<< "$out"
        done <<< "$hits"
    done
}

# Batched YARA check across ALL members of one archive in ONE call. This is
# the fix for the real slowdown reported: the old per-member design called
# $YARA_CMD separately for EVERY file inside the archive, reloading/
# compiling the whole ruleset each time — on an archive with dozens of
# members that alone made a single zip take minutes. Same --scan-list (or
# symlink+-r fallback) technique already used for the main file batches.
_archive_batch_yara_check() {
    local top_archive="$1" extract_dir="$2" cur_rel="$3"; shift 3
    [ $# -eq 0 ] && return

    # FIX (real bug found — confirmed via YARA CLI source: `static int
    # threads = YR_MAX_THREADS;`): without an explicit -p, yara defaults to
    # its MAXIMUM allowed thread count, not something sane like nproc. That
    # meant EVERY single yara invocation — and we already run one PER
    # WORKER PROCESS, i.e. our own -j-controlled parallelism — was ALSO
    # spawning its own large internal thread pool, all fighting over the
    # same CPU cores as every other worker's yara call. Confirmed on a
    # real 2-CPU box: 7+ concurrent yara threads/processes, load average
    # ~5 on 2 cores — severe oversubscription that tanks throughput
    # despite high CPU%, not genuine parallel speedup. -p 1 makes each
    # yara call single-threaded; the worker-process level (-j) is where
    # parallelism should live, not duplicated inside every yara call too.
    local yflags=(-d filename= -d filepath= -d extension= -p "${YARA_THREADS:-1}" -a "$YARA_TIMEOUT_SEC")
    case "$YARA_TARGET" in *.yarc) yflags+=(-C) ;; esac

    local yara_out
    if [ "$YARA_HAS_SCAN_LIST" = true ]; then
        local listfile
        listfile=$(mktemp 2>/dev/null) || return
        printf '%s\n' "$@" > "$listfile"
        _yslot_acq
        yara_out=$(timeout $(( YARA_TIMEOUT_SEC + 3 )) $YARA_CMD "${yflags[@]}" --scan-list "$YARA_TARGET" "$listfile" 2>/dev/null)
        _yslot_rel
        rm -f "$listfile"
    else
        local tmpdir2
        tmpdir2=$(mktemp -d 2>/dev/null) || return
        local f
        for f in "$@"; do
            ln -sf "$f" "$tmpdir2/$(basename "$f")_$RANDOM" 2>/dev/null
        done
        local raw
        _yslot_acq
        raw=$(timeout $(( YARA_TIMEOUT_SEC + 3 )) $YARA_CMD "${yflags[@]}" -r "$YARA_TARGET" "$tmpdir2" 2>/dev/null)
        _yslot_rel
        if [ -n "$raw" ]; then
            yara_out=$(while IFS= read -r l; do
                [ -z "$l" ] && continue
                local r p real
                r=$(echo "$l" | awk '{print $1}')
                p=$(echo "$l" | cut -d' ' -f2-)
                real=$(readlink -f "$p" 2>/dev/null || echo "$p")
                echo "$r $real"
            done <<< "$raw")
        fi
        rm -rf "$tmpdir2"
    fi

    [ -z "$yara_out" ] && return
    local yline yrule yfile rel spat
    while IFS= read -r yline; do
        [ -z "$yline" ] && continue
        yrule=$(echo "$yline" | awk '{print $1}')
        yfile=$(echo "$yline" | cut -d' ' -f2-)
        # Newline-named members were scanned via a plain-named hard link
        # (see scan_archive) -- map back to the real member name.
        [ -n "$yfile" ] && yfile="${_ARCH_NL_ORIG[$yfile]:-$yfile}"
        rel="${yfile#$extract_dir/}"
        [ -n "$cur_rel" ] && rel="${cur_rel}!${rel}"
        rel="${rel//$'\n'/?}"
        if _is_builtin_noisy_rule "$yrule"; then
            SUPPRESSED_FOUND=$(( SUPPRESSED_FOUND + 1 ))
        elif spat=$(_resolve_str_sig "$yrule"); then
            threat "SIG_STRING_MATCH" "$top_archive" "archive_member=${rel}|pattern=${spat:0:50}"
        elif _is_vendor_obfuscation "$yrule" "$yfile"; then
            SUPPRESSED_FOUND=$(( SUPPRESSED_FOUND + 1 ))
        else
            threat "YARA_MATCH" "$top_archive" "archive_member=${rel}|rule=$yrule"
        fi
    done <<< "$yara_out"
}

# scan_archive TOP_ARCHIVE [CURRENT_FILE] [CURRENT_REL]
# TOP_ARCHIVE is always the real, original archive file to report against.
# CURRENT_FILE/CURRENT_REL are set when called recursively for a nested
# archive found inside an already-extracted one.
scan_archive() {
    local top_archive="$1" cur="${2:-$1}" cur_rel="${3:-}"
    [ "$SCAN_ARCHIVES" = "true" ] || return

    # Type first (this runs for every file): only real archives get a
    # "skipped" log line, so a skipped archive is never silent.
    local where="$top_archive${cur_rel:+ (member $cur_rel)}"
    local atype
    atype=$(_archive_type "$cur")
    if [ -z "$atype" ]; then
        case "${cur,,}" in
            *.7z|*.rar) log "Archive NOT scanned (7z/unrar not installed): $where" ;;
        esac
        return
    fi

    local asize
    asize=$(_stat_size "$cur" 2>/dev/null) || return
    if [ "${asize:-0}" -gt $(( ARCHIVE_MAX_MB * 1024 * 1024 )) ]; then
        log "Archive NOT scanned (larger than --archive-max-mb ${ARCHIVE_MAX_MB}MB): $where"
        return
    fi

    local extract_dir
    extract_dir=$(_archive_tmpdir $(( asize / 1024 / 1024 ))) || { log "Archive NOT scanned (no temp dir for extraction): $where"; return; }
    # Tracked so a graceful interrupt (TERM/INT — see trap near the top of
    # this worker script) can still clean this up even if the worker gets
    # killed mid-extraction, before reaching this function's own rm -rf at
    # the end. Trimmed back to n_tracked after the rm -rf (nested calls
    # finish first), so a long -w -A run doesn't grow it forever.
    local n_tracked=${#_ACTIVE_EXTRACT_DIRS[@]}
    _ACTIVE_EXTRACT_DIRS+=("$extract_dir")

    # Extract from a root-made PRIVATE copy, not the site's file: a
    # privilege-dropped sandbox can't read a 0600 archive owned by the site
    # user, and bwrap/chroot then bind only this copy's dir, not the
    # site's directory. cp -P + checks on the copy: the file may have been
    # swapped for a symlink (/etc/shadow, /dev/zero) or a FIFO since it was
    # listed -- never follow it.
    local stage_dir staged
    stage_dir=$(mktemp -d "${extract_dir}_in.XXXXXX" 2>/dev/null) || {
        rm -rf "$extract_dir"; _ACTIVE_EXTRACT_DIRS=("${_ACTIVE_EXTRACT_DIRS[@]:0:n_tracked}")
        log "Archive NOT scanned (no temp dir for staging copy): $where"; return; }
    _ACTIVE_EXTRACT_DIRS+=("$stage_dir")
    staged="$stage_dir/${cur##*/}"
    timeout 30 cp -P -- "$cur" "$staged" 2>/dev/null
    if [ -L "$staged" ] || [ ! -f "$staged" ] || \
       [ "$(_stat_size "$staged" 2>/dev/null || echo 0)" -gt $(( ARCHIVE_MAX_MB * 1024 * 1024 )) ]; then
        rm -rf "$extract_dir" "$stage_dir"; _ACTIVE_EXTRACT_DIRS=("${_ACTIVE_EXTRACT_DIRS[@]:0:n_tracked}")
        log "Archive NOT scanned (not a regular file / unreadable / too big when copied): $where"
        return
    fi
    chmod 0400 "$staged" 2>/dev/null
    _sandbox_resolve

    # FIX (real gap found in security review): this used to let
    # _archive_extract run to full completion, ONLY checking the total
    # size AFTERWARD — for a genuine decompression bomb (a small archive
    # that expands to gigabytes), the damage (disk fill / RAM exhaustion
    # in the /dev/shm case) would already be done by the time anything
    # noticed. Now runs extraction in the background and polls the
    # directory's growing size WHILE it's still running, killing it
    # immediately once it crosses the cap instead of after. A ~1s poll
    # interval means some overshoot is still possible (whatever gets
    # written in that window), but this bounds it to roughly one second's
    # worth of writes instead of "however big the bomb actually is".
    _archive_extract "$staged" "$atype" "$extract_dir" &
    local extract_pid=$! bomb_killed=false extracted_kb=0
    while kill -0 "$extract_pid" 2>/dev/null; do
        extracted_kb=$(du -sk "$extract_dir" 2>/dev/null | awk '{print $1}')
        if [ -n "$extracted_kb" ] && [ "$extracted_kb" -gt $(( ARCHIVE_MAX_EXTRACT_MB * 1024 )) ]; then
            bomb_killed=true
            # Signal EVERY descendant, not just the extract subshell and
            # its direct children: that orphaned timeout+tar in some modes
            # (they kept writing past the cap), and `unshare --fork` /
            # bwrap sit between us and the extractor. Descendants are
            # collected first, then all get TERM, then KILL if still alive.
            # The subshell itself then returns normally, so chroot mode
            # still unmounts its binds.
            local lvl="$extract_pid" desc="" p w
            while [ -n "$lvl" ]; do
                lvl=$(for p in $lvl; do pgrep -P "$p"; done 2>/dev/null)
                desc="$desc $lvl"
            done
            [ -n "${desc// /}" ] && kill -TERM $desc 2>/dev/null
            for w in 1 2 3 4 5 6; do
                kill -0 "$extract_pid" 2>/dev/null || break
                sleep 0.5
            done
            # KILL whatever is STILL in the tree (re-collected, not the old
            # PID list -- those PIDs may have been reused by now).
            lvl="$extract_pid"; desc=""
            while [ -n "$lvl" ]; do
                lvl=$(for p in $lvl; do pgrep -P "$p"; done 2>/dev/null)
                desc="$desc $lvl"
            done
            [ -n "${desc// /}" ] && kill -KILL $desc 2>/dev/null
            pkill -KILL -P "$extract_pid" 2>/dev/null
            kill -KILL "$extract_pid" 2>/dev/null
            break
        fi
        sleep 1
    done
    wait "$extract_pid" 2>/dev/null
    rm -rf "$stage_dir"

    extracted_kb=$(du -sk "$extract_dir" 2>/dev/null | awk '{print $1}')
    if [ "$bomb_killed" = true ]; then
        # FIX (real gap found in testing): the abort itself worked
        # correctly (confirmed: extraction stopped around 110MB against a
        # 50MB cap on a real 300MB decompression bomb, instead of letting
        # it run to completion), but log() alone writes to this worker's
        # EPHEMERAL internal report file, deleted with WORK_DIR at the
        # end — an operator would see "0 threats, clean" with zero
        # visibility that a bomb was even encountered. A decompression
        # bomb is itself a strong signal worth surfacing prominently, not
        # a detail to quietly protect against and stay silent about.
        threat "ARCHIVE_BOMB_SUSPECTED" "$top_archive" "extracted>=${extracted_kb}KB before abort, cap=${ARCHIVE_MAX_EXTRACT_MB}MB"
        log "Archive extraction ABORTED mid-extraction (exceeded ${ARCHIVE_MAX_EXTRACT_MB}MB decompressed cap -- possible decompression bomb): $top_archive"
    elif [ -n "$extracted_kb" ] && [ "$extracted_kb" -gt $(( ARCHIVE_MAX_EXTRACT_MB * 1024 )) ]; then
        log "Archive extraction exceeded ${ARCHIVE_MAX_EXTRACT_MB}MB cap, scan may be incomplete: $top_archive"
    fi

    local -a members=()
    local inner n=0
    while IFS= read -r -d '' inner; do
        n=$(( n + 1 ))
        if [ "$n" -gt "$ARCHIVE_MAX_FILES" ]; then
            log "Archive partly scanned (only first ${ARCHIVE_MAX_FILES} members, --archive-max-files): $where"
            break
        fi
        members+=("$inner")
    done < <(find "$extract_dir" -type f -print0 2>/dev/null)

    # A newline in a member name splits the hasher's output line and the
    # yara --scan-list entry / "rule path" output line, so such a member
    # went unscanned (or produced a bogus match). Hash/YARA it through a
    # hard link (copy if that fails) with a plain name; the batch checks
    # map it back via _ARCH_NL_ORIG (local: nested calls get their own).
    local -A _ARCH_NL_ORIG=()
    local -a checked=()
    local nl_dir="" k=0 s
    for s in "${members[@]}"; do
        case "$s" in
            *$'\n'*)
                [ -n "$nl_dir" ] || nl_dir=$(mktemp -d "$extract_dir/.nl.XXXXXX" 2>/dev/null) || continue
                k=$(( k + 1 ))
                ln -- "$s" "$nl_dir/$k" 2>/dev/null || cp -- "$s" "$nl_dir/$k" 2>/dev/null || continue
                _ARCH_NL_ORIG["$nl_dir/$k"]="$s"
                checked+=("$nl_dir/$k")
                ;;
            *) checked+=("$s") ;;
        esac
    done

    if [ ${#members[@]} -gt 0 ]; then
        [ ${#checked[@]} -gt 0 ] && _archive_batch_hash_check "$top_archive" "$extract_dir" "$cur_rel" "${checked[@]}"
        [ "$HAS_YARA" = true ] && [ ${#checked[@]} -gt 0 ] && _archive_batch_yara_check "$top_archive" "$extract_dir" "$cur_rel" "${checked[@]}"

        # Strings + nested-archive recursion stay per-member: grep -F is
        # cheap enough not to need batching, and nested archives are rare.
        local m rel msize
        for m in "${members[@]}"; do
            msize=$(_stat_size "$m" 2>/dev/null) || continue
            { [ "${msize:-0}" -eq 0 ] || [ "${msize:-0}" -gt "$MAX_SIZE" ]; } && continue
            rel="${m#$extract_dir/}"
            [ -n "$cur_rel" ] && rel="${cur_rel}!${rel}"
            rel="${rel//$'\n'/?}"

            if [ "$HAS_STRINGS" = true ]; then
                local sm
                sm=$(do_strings "$m" 6 524288 | bb grep -F -i -f "$SIG_DIR/strings.txt" 2>/dev/null | head -1)
                [ -n "$sm" ] && threat "SIG_STRING_MATCH" "$top_archive" "archive_member=${rel}|pattern=${sm:0:50}"
            fi

            if [ "$ARCHIVE_DEPTH_CUR" -lt "$ARCHIVE_MAX_DEPTH" ]; then
                local atype2
                atype2=$(_archive_type "$m")
                if [ -n "$atype2" ]; then
                    ARCHIVE_DEPTH_CUR=$(( ARCHIVE_DEPTH_CUR + 1 ))
                    scan_archive "$top_archive" "$m" "$rel"
                    ARCHIVE_DEPTH_CUR=$(( ARCHIVE_DEPTH_CUR - 1 ))
                fi
            fi
        done
    fi

    rm -rf "$extract_dir"
    _ACTIVE_EXTRACT_DIRS=("${_ACTIVE_EXTRACT_DIRS[@]:0:n_tracked}")
}

do_strings() {
    local file="$1" min="${2:-6}" maxb="${3:-524288}"
    if [ "$STRINGS_CMD" = "bash" ]; then
        _bash_strings "$file" "$min" "$maxb"
    else
        bb dd if="$file" bs="$maxb" count=1 2>/dev/null | $STRINGS_CMD -n "$min" 2>/dev/null
    fi
}

do_file_type() {
    local file="$1"
    if [ "$FILE_CMD" = "bash" ]; then
        _bash_file_type "$file"
    else
        local out
        out=$($FILE_CMD -b "$file" 2>/dev/null | head -1)
        case "$out" in
            ELF*) echo "ELF" ;;
            PE32*|MS-DOS*|MZ*) echo "PE_MZ" ;;
            PDF*) echo "PDF" ;;
            Zip*|Java*archive*) echo "ZIP" ;;
            PNG*) echo "PNG" ;;
            JPEG*) echo "JPEG" ;;
            GIF*) echo "GIF" ;;
            gzip*) echo "GZIP" ;;
            bzip2*) echo "BZIP2" ;;
            *7-zip*) echo "7ZIP" ;;
            *shell*script*|*Python*|*Perl*|*Ruby*|*PHP*) echo "SCRIPT" ;;
            *) echo "UNKNOWN" ;;
        esac
    fi
}

# ----------------------------------------------------------------------------
# MODULE: logging
# ----------------------------------------------------------------------------
# Control chars (CR/LF/ESC...) masked: messages carry file / archive member
# names, and a raw newline could forge a "THREAT:" line in the report.
log() { local m="$*"; printf '[%s] %s\n' "$WORKER_ID" "${m//[$'\001'-$'\037'$'\177']/?}" >> "$REPORT"; }

# threat() — single entry point for any finding: checks ignore_sigs first
# (a match suppresses the detection entirely — no log, no quarantine), then
# logs it, streams it immediately to the persistent live report (so
# Ctrl+C/SIGTERM mid-scan doesn't lose already-found results — see
# init_live_report in the main script), and quarantines the file if
# enabled. Report line format ("TYPE|file|info") is unchanged so
# build_report/print_report still work.
threat() {
    local type="$1" file="$2" info="${3:-}"

    # ClamAV PUA.* ("potentially unwanted": adware, packers, hack tools) are
    # off unless the pack has them (--clam-pua / +pua). Their YARA part is
    # left out at compile time; hash tables are shared by every pack, so a
    # PUA hash hit is dropped here. --deep shows it anyway.
    if [ "${type#KNOWN_MALWARE}" != "$type" ] && [ "${AV_CLAM_PUA:-false}" != true ] && [ "$DEEP_MODE" != "true" ]; then
        case "$info" in name=PUA.*|*"|name=PUA."*)
            SUPPRESSED_FOUND=$(( SUPPRESSED_FOUND + 1 ))
            [ "$EXPLAIN_MODE" = true ] && { EXPLAIN_SUPPRESSED=$(( EXPLAIN_SUPPRESSED + 1 )); _xp "  suppressed  $type | $info  <- ClamAV PUA signature, off unless --clam-pua / +pua"; }
            return ;;
        esac
    fi

    # NOTE: matched string includes the file PATH too (not just type+info)
    # — lets ignore_sigs patterns be scoped to specific paths, e.g.
    # suppress a noisy rule only under a known-legitimate directory
    # instead of everywhere it might ever fire. Old simple patterns (no
    # anchors) keep working unchanged, since they just match as a
    # substring regardless of what else is on the line.
    #
    # DEEP_MODE bypasses this entirely — the whole point of --deep is
    # maximum precision with no automatic suppression at all; the person
    # reviews and dismisses findings themselves rather than trusting the
    # tool's own filters, which is exactly what a deep/paranoid pass is
    # for.
    if [ "$DEEP_MODE" != "true" ] && [ -n "$IGNORE_SIGS_FILE" ] && [ -s "$_IGNORE_SIGS_FILTERED" ]; then
        if printf '%s|%s|%s\n' "$type" "$info" "$file" | bb grep -qE -f "$_IGNORE_SIGS_FILTERED" 2>/dev/null; then
            SUPPRESSED_FOUND=$(( SUPPRESSED_FOUND + 1 ))
            if [ "$EXPLAIN_MODE" = true ]; then
                local _pat _which=""
                while IFS= read -r _pat; do
                    [ -n "$_pat" ] || continue
                    printf '%s|%s|%s\n' "$type" "$info" "$file" | bb grep -qE -e "$_pat" 2>/dev/null && { _which="$_pat"; break; }
                done < "$_IGNORE_SIGS_FILTERED"
                EXPLAIN_SUPPRESSED=$(( EXPLAIN_SUPPRESSED + 1 ))
                _xp "  suppressed  $type | $info  <- ignore_sigs line: $_which"
            fi
            return
        fi
    fi

    # A newline in a name/info would forge extra "THREAT:" lines: masked.
    # CR is kept in this internal line on purpose (the incremental cache
    # matches its path against find's raw output); every human-facing copy
    # (live report below, save_report/print_report) masks all control chars.
    printf 'THREAT:%s|%s|%s\n' "${type//$'\n'/?}" "${file//$'\n'/?}" "${info//$'\n'/?}" >> "$REPORT"
    # Permission findings keep the THREAT: line (so -I rescans the file and
    # the report can list it) but count separately and never quarantine.
    # SUID/SGID: own counter too, unless the package checksum says the
    # binary was TAMPERED with (that one is a threat). Neither kind is ever
    # quarantined: moving sudo/passwd/mount away can lock the admin out.
    local _perm=false _suid=false
    case "$type" in
        WORLD_WRITABLE_EXEC) _perm=true ;;
        SUID_SGID) _suid=true ;;
    esac
    if [ "$_perm" = true ]; then PERMS_FOUND=$(( PERMS_FOUND + 1 ))
    elif [ "$_suid" = true ] && [ "${info#*TAMPERED}" = "$info" ]; then SUID_FOUND=$(( SUID_FOUND + 1 ))
    else THREATS_FOUND=$(( THREATS_FOUND + 1 )); fi
    [ "$EXPLAIN_MODE" = true ] && { EXPLAIN_REPORTED=$(( EXPLAIN_REPORTED + 1 )); _xp "  REPORTED    $type | $info"; }
    local _ct=$'\001'-$'\037'
    local m_type="${type//[$_ct$'\177']/?}" m_file="${file//[$_ct$'\177']/?}" m_info="${info//[$_ct$'\177']/?}"
    # FIX (real gap reported): this used to unconditionally append EVERY
    # threat, SUID_SGID included, to the main LIVE_REPORT_FILE — the
    # split into a separate SUID_REPORT_FILE only happened in
    # save_report() at the very END of a scan (which truncates and
    # rewrites the live file cleanly). That left a real gap: anyone
    # watching the live file DURING a scan (tail -f, or just checking
    # progress), or a scan that gets interrupted before reaching
    # save_report(), would still see SUID_SGID lines mixed into the main
    # file — exactly what this feature exists to avoid. Routed to the
    # SAME companion file live now, not just at the end.
    if [ "$type" = "SUID_SGID" ]; then
        if [ -n "$SUID_REPORT_FILE" ]; then
            printf '[%s] [%s] %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$m_type" "$m_file" "$m_info" >> "$SUID_REPORT_FILE" 2>/dev/null
        fi
        # a TAMPERED one is a threat: also in the main live log
        if [ "${info#*TAMPERED}" != "$info" ] && [ -n "$LIVE_REPORT_FILE" ]; then
            printf '[%s] [%s] %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$m_type" "$m_file" "$m_info" >> "$LIVE_REPORT_FILE" 2>/dev/null
        fi
    elif [ "$_perm" = true ]; then
        [ -n "$PERMS_REPORT_FILE" ] && printf '[%s] [%s] %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$m_type" "$m_file" "$m_info" >> "$PERMS_REPORT_FILE" 2>/dev/null
    elif [ -n "$LIVE_REPORT_FILE" ]; then
        # Single printf = single write() syscall = atomic append even with
        # multiple worker processes writing the same file concurrently, as
        # long as the line stays under PIPE_BUF (a few KB) — safe here.
        printf '[%s] [%s] %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$m_type" "$m_file" "$m_info" >> "$LIVE_REPORT_FILE" 2>/dev/null
    fi
    [ -n "$QUARANTINE_DIR" ] || return 0
    [ "$_perm" = true ] && return 0   # wrong mode is not malware: fix it, don't move it
    [ "$_suid" = true ] && { log "QUARANTINE_SKIPPED (SUID/SGID binary, report only): $file"; return 0; }
    if [ "$QUARANTINE_SKIP_ARCHIVES" = "true" ]; then
        case "$info" in
            archive_member=*) log "QUARANTINE_SKIPPED (archive container, --no-quarantine-archives): $file"; return 0 ;;
        esac
    fi
    quarantine_file "$file" "$type"
}

progress() {
    printf 'FILES=%d\nTHREATS=%d\nPERMS=%d\nSUID=%d\nCURRENT=%s\n' \
        "$FILES_SCANNED" "$THREATS_FOUND" "$PERMS_FOUND" "$SUID_FOUND" "${1:-}" > "$PROGRESS"
}

# ----------------------------------------------------------------------------
# MODULE: quarantine
# ----------------------------------------------------------------------------
quarantine_file() {
    local src="$1" type="${2:-UNKNOWN}"
    [ -n "$QUARANTINE_DIR" ] || return 0
    [ -f "$src" ] || return 0

    # --quarantine-dry-run: report what would happen, touch nothing. The
    # real value here is -w (real-time) running unattended in production
    # — a single overly-broad YARA rule or a bad signature update could
    # otherwise move a batch of legitimate site files before a person
    # notices. Dry-run lets someone validate a rule/signature change is
    # safe before ever letting it actually move anything.
    if [ "$QUARANTINE_DRY_RUN" = "true" ]; then
        log "QUARANTINE_DRY_RUN (would move): $src ($type)"
        return 0
    fi

    mkdir -p "$QUARANTINE_DIR" 2>/dev/null
    chmod 700 "$QUARANTINE_DIR" 2>/dev/null

    # Quarantine filename = sha256(original path) + original basename —
    # unique even for same-name files from different directories, without
    # recreating the original directory tree inside quarantine.
    local path_hash qfile ts
    ts=$(date +%s)
    path_hash=$(printf '%s' "$src" | bb sha256sum 2>/dev/null | bb grep -oE '[0-9a-f]{64}' | head -1)
    [ -z "$path_hash" ] && path_hash="$(date +%s%N)_$$"
    qfile="${QUARANTINE_DIR}/${path_hash}_$(basename -- "$src")"

    if mv -f -- "$src" "$qfile" 2>/dev/null; then
        chmod "$QUARANTINE_PERM" "$qfile" 2>/dev/null
        # Manifest for restore: original_path <TAB> quarantined_file <TAB>
        # threat_type <TAB> unix_time. Restore = mv "$qfile" "$src".
        printf '%s\t%s\t%s\t%s\n' "$src" "$qfile" "$type" "$ts" >> "${QUARANTINE_DIR}/manifest.tsv"
        log "QUARANTINED: $src -> $qfile ($type)"
    else
        log "QUARANTINE_FAILED (mv error): $src ($type)"
    fi
}

# ----------------------------------------------------------------------------
# MODULE: hash matching
# ----------------------------------------------------------------------------
process_hash_batch() {
    local htype="$1" sig_file="$2"
    shift 2
    [ $# -eq 0 ] && return
    local cmd="$SHA256_CMD"
    [ "$htype" = "md5" ] && cmd="$MD5_CMD"
    [ "$htype" = "sha1" ] && cmd="$SHA1_CMD"
    [ "$cmd" = "none" ] && return

    local out
    out=$($cmd "$@" 2>/dev/null)
    [ -z "$out" ] && return

    # "grep -F -f - sig_file" returns full "hash<TAB>name" lines, not just
    # the hash — the trailing "cut -f1" extracts the clean hash.
    #
    # FIX (real bottleneck found and measured on a live scan — hash
    # lookups were 69% of total scan time): this used to go through
    # busybox's grep, which measured ~2.2x slower than a real grep for
    # exactly this shape of query (-F -f - against a 632k-line hash
    # database — confirmed 1528ms vs 701ms per call on a realistic
    # benchmark). Same fix already applied to the string-signature search
    # — use _real_grep (bundled/system grep) here too.
    #
    # coreutils prints "\<hash>  <escaped name>" for names containing "\" or
    # a newline: the leading "\" is stripped before the lookup (such files
    # were never matched). Only hex hashes go to grep: busybox does not
    # escape newlines, so a name with an empty line became an EMPTY pattern
    # that matched every database line.
    local hits
    hits=$(printf '%s\n' "$out" | cut -d' ' -f1 | sed 's/^\\//' | bb grep -E '^[0-9a-fA-F]{32,64}$' \
        | _real_grep -F -f - "$sig_file" 2>/dev/null | cut -f1 | sort -u)
    if [ -n "$hits" ]; then
        local hit_hash tname ln h f
        while IFS= read -r hit_hash; do
            [ -z "$hit_hash" ] && continue
            tname=$(_real_grep -m 1 "^${hit_hash}" "$sig_file" 2>/dev/null | cut -f2)
            # EVERY file with this hash is reported, not only the first one.
            while IFS= read -r ln; do
                # "<hash><space><mode: space or *><name>"
                h="${ln%% *}"; f="${ln:${#h}+2}"
                if [ "${h:0:1}" = '\' ]; then h="${h:1}"; f=$(printf '%bX' "$f"); f="${f%X}"; fi
                [ "${h,,}" = "${hit_hash,,}" ] && [ -n "$f" ] && \
                    threat "KNOWN_MALWARE" "$f" "name=${tname:-Malware}|$htype=$hit_hash"
            done <<< "$out"
        done <<< "$hits"
    fi
}

# ----------------------------------------------------------------------------
# MODULE: yara matching
# ----------------------------------------------------------------------------
# Called when a --scan-list batch hit (or nearly hit) the -a timeout —
# retries the SAME batch one file at a time with a short per-file timeout,
# so a single pathological file doesn't cost the whole batch's results and
# gets identified by name instead of just "the scan is stuck".
_yara_bisect_slow_batch() {
    # FIX (real bug reported — "дуже багато файлів скіпнуло, сканувало
    # занадто довго"): short_timeout used to be STUCK at a fixed 5s for
    # any YARA_TIMEOUT_SEC >= 20 — completely ignoring how generously the
    # person actually configured the main timeout. Compounded by --deep
    # raising MAX_SCAN_MB to 200MB without touching this at all: a large,
    # perfectly legitimate file now gets scanned for the first time under
    # --deep (previously skipped by the size cap), but still only gets
    # 5 bisect seconds to do it in — the opposite of --deep's "maximum
    # thoroughness" intent, silently skipping exactly the large files
    # --deep exists to no longer skip. Now always proportional, same 1/4
    # ratio regardless of how high YARA_TIMEOUT_SEC is set (so raising
    # --yara-timeout, or --deep's own bump below, actually helps here too).
    # Per-file retry gets the FULL configured timeout (default 300s): a
    # 1/4 ratio gave ~7s and produced masses of SCAN_TIMEOUT on big but
    # legitimate files. Only the one slow file pays, never the batch.
    local short_timeout=$YARA_TIMEOUT_SEC
    [ "$short_timeout" -lt 2 ] && short_timeout=2

    local yflags2=(-d filename= -d filepath= -d extension= -p "${YARA_THREADS:-1}" -a "$short_timeout")
    case "$YARA_TARGET" in *.yarc) yflags2+=(-C) ;; esac

    local f t0 t1 out
    for f in "$@"; do
        t0=$(_now_ms)
        _yslot_acq
        out=$(timeout $(( short_timeout + 2 )) $YARA_CMD "${yflags2[@]}" "$YARA_TARGET" "$f" 2>/dev/null)
        _yslot_rel
        local frc=$?
        t1=$(_now_ms)
        if [ "$frc" -ge 128 ]; then
            # killed again, now on its own: this file is the one that needs
            # more memory than the ceiling allows. Report it, don't hide it.
            threat "SCAN_ABORTED" "${MEDIA_MAP[$f]:-$f}" "yara killed (rc=${frc}) by the RAM ceiling (--max-ram) or the OOM killer|note=file was NOT scanned"
            continue
        fi
        if [ $(( (t1 - t0) / 1000 )) -ge "$short_timeout" ]; then
            # This is the (or a) culprit — report it as a diagnostic entry
            # (not necessarily malicious — pathologically slow-to-scan
            # files are usually just unusual content, e.g. one enormous
            # minified line — but worth the person's attention either way)
            # and move on instead of hanging the whole scan on it.
            threat "SCAN_TIMEOUT" "${MEDIA_MAP[$f]:-$f}" "yara_timeout_sec=${short_timeout}|note=file took too long to scan, skipped"
            continue
        fi
        [ -z "$out" ] && continue
        # every matching rule, like the batch path (was: only the first one)
        local yrule yfile spat yl
        yfile="$f"
        [ -n "${MEDIA_MAP[$yfile]:-}" ] && yfile="${MEDIA_MAP[$yfile]}"
        while IFS= read -r yl; do
            [ -z "$yl" ] && continue
            yrule="${yl%% *}"
            if _is_builtin_noisy_rule "$yrule"; then
                SUPPRESSED_FOUND=$(( SUPPRESSED_FOUND + 1 ))
            elif spat=$(_resolve_str_sig "$yrule"); then
                threat "SIG_STRING_MATCH" "$yfile" "pattern=${spat:0:50}"
            elif _is_vendor_obfuscation "$yrule" "$yfile"; then
                SUPPRESSED_FOUND=$(( SUPPRESSED_FOUND + 1 ))
            else
                threat "YARA_MATCH" "$yfile" "rule=$yrule"
            fi
        done <<< "$out"
    done
}

# Worker side of the RAM ceiling: while the monitor's gate is up, don't start
# another yara process (each loads the full ruleset). Waits at most 20s, and
# after one timeout stops waiting for 60s — so a ceiling that is simply too
# low for even one worker slows the scan down instead of stalling it.
RAM_GATE_SKIP_UNTIL=0
_ram_gate() {
    # the threads-mode consumer IS the one yara process: making it wait for
    # memory to drop would only stall the whole scan
    [ "${AV_YARA_ROLE:-}" = "consumer" ] && return 0
    [ -e "$REPORT_DIR/.ram_high" ] || return 0
    [ "$(date +%s)" -lt "$RAM_GATE_SKIP_UNTIL" ] && return 0
    local waited=0
    while [ -e "$REPORT_DIR/.ram_high" ] && [ "$waited" -lt 20 ]; do
        sleep 1; waited=$(( waited + 1 ))
    done
    [ -e "$REPORT_DIR/.ram_high" ] && RAM_GATE_SKIP_UNTIL=$(( $(date +%s) + 60 ))
    return 0
}

# Counting semaphore for concurrent yara processes (see _yara_ram_cap).
# mkdir is atomic; the owner PID is stored so slots of dead workers are reclaimed.
_YSLOT=""
_yslot_acq() {
    local n="${YARA_SLOTS:-0}" i d pid
    [ "${AV_YARA_ROLE:-}" = "consumer" ] && return 0
    [ "$n" -ge 1 ] 2>/dev/null || return 0
    [ "$n" -ge "${WORKERS:-$n}" ] 2>/dev/null && [ "${YARA_THREADS:-1}" -le 1 ] && return 0
    mkdir -p "$REPORT_DIR/.yslots" 2>/dev/null
    while :; do
        i=1
        while [ "$i" -le "$n" ]; do
            d="$REPORT_DIR/.yslots/$i"
            if mkdir "$d" 2>/dev/null; then echo $$ > "$d/pid"; _YSLOT="$d"; return 0; fi
            pid=$(cat "$d/pid" 2>/dev/null)
            if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then rm -rf "$d" 2>/dev/null; continue; fi
            i=$(( i + 1 ))
        done
        sleep 0.1 2>/dev/null || sleep 1
    done
}
_yslot_rel() {
    local rc=$?
    [ -n "$_YSLOT" ] && { rm -rf "$_YSLOT" 2>/dev/null; _YSLOT=""; }
    return $rc
}

process_yara_batch() {
    [ $# -eq 0 ] || [ "$HAS_YARA" = false ] || [ "$YARA_CMD" = "none" ] && return
    _ram_gate

    local yara_out yrc yara_flags=(-d filename= -d filepath= -d extension= -p "${YARA_THREADS:-1}" -a "$YARA_TIMEOUT_SEC")
    # A compiled ruleset (.yarc) MUST be loaded with -C, or yara tries to
    # parse the binary as rule *source* and fails outright.
    case "$YARA_TARGET" in
        *.yarc) yara_flags+=(-C) ;;
    esac

    if [ "$YARA_HAS_SCAN_LIST" = true ]; then
        # YARA 4.0+/YARA-X: --scan-list takes a plain text file of paths
        # (one per line) and scans them in one call with the ruleset
        # loaded/compiled ONCE for the whole batch — this is what LMD's own
        # docs point to for exactly this problem ("YARA CLI can't take a
        # list of arbitrary files directly"). Simpler and a bit faster
        # end-to-end than the symlink-directory fallback below, since it
        # skips one filesystem syscall (symlink create) per file.
        local listfile
        listfile=$(mktemp 2>/dev/null) || return
        printf '%s\n' "$@" > "$listfile"
        local t0; t0=$(_now_ms)
        # FIX (real bug reported — "goes into infinity"): yara's own -a
        # flag was measured NOT reliably capping --scan-list duration (a
        # real batch took 74-113 SECONDS despite the configured 30s
        # limit). Relying only on -a meant the elapsed-time check below
        # would only ever fire AFTER yara eventually finished on its own,
        # however long that took — defeating the whole point of a
        # timeout. Wrap with the shell's own `timeout` (SIGTERM then
        # SIGKILL at the OS level) as a HARD guarantee that doesn't depend
        # on yara's internal timeout logic working correctly at all.
        _yslot_acq
        yara_out=$(timeout $(( YARA_TIMEOUT_SEC + 3 )) $YARA_CMD "${yara_flags[@]}" --scan-list "$YARA_TARGET" "$listfile" 2>/dev/null)
        _yslot_rel
        yrc=$?
        local t1; t1=$(_now_ms)
        rm -f "$listfile"

        # yara died from a signal (>= 128; a plain timeout is 124): killed by
        # the RAM limiter or by the kernel's OOM killer. Its output is empty
        # and would read as "clean" — instead rescan this batch one file at a
        # time, which also pins down the file responsible.
        if [ "$yrc" -ge 128 ]; then
            _yara_bisect_slow_batch "$@"
            return
        fi

        # FIX (real hang reported): a batch call that hits -a's timeout
        # aborts the WHOLE --scan-list operation, losing results for every
        # OTHER file in the batch too — not just the slow one. Detect a
        # likely timeout by comparing actual elapsed time against the
        # configured limit (yara doesn't give a clean distinct exit code
        # for this), and if so, fall back to checking this SAME batch's
        # files ONE AT A TIME with a much shorter per-file timeout: fast
        # files still get scanned normally (nothing lost), and whichever
        # file(s) also blow the short timeout get identified and reported
        # instead of silently swallowing the whole batch or hanging again.
        if [ $(( (t1 - t0) / 1000 )) -ge "$YARA_TIMEOUT_SEC" ]; then
            _yara_bisect_slow_batch "$@"
            return
        fi
    else
        # Fallback for older yara builds without --scan-list: the CLI only
        # accepts ONE scan target (a file, or a directory with -r), so
        # symlink the whole batch into a throwaway directory and scan that.
        local tmpdir
        tmpdir=$(mktemp -d 2>/dev/null) || return
        local f
        for f in "$@"; do
            ln -sf "$f" "$tmpdir/$(bb basename "$f" 2>/dev/null || basename "$f")_$RANDOM" 2>/dev/null
        done
        _yslot_acq
        yara_out=$(timeout $(( YARA_TIMEOUT_SEC + 3 )) $YARA_CMD "${yara_flags[@]}" -r "$YARA_TARGET" "$tmpdir" 2>/dev/null)
        _yslot_rel
        # Symlink names don't map back to real paths 1:1 in this fallback
        # path (RANDOM-suffixed to avoid collisions) — resolve via readlink.
        if [ -n "$yara_out" ]; then
            yara_out=$(echo "$yara_out" | while IFS= read -r l; do
                [ -z "$l" ] && continue
                r=$(echo "$l" | awk '{print $1}')
                p=$(echo "$l" | cut -d' ' -f2-)
                real=$(readlink -f "$p" 2>/dev/null || echo "$p")
                echo "$r $real"
            done)
        fi
        rm -rf "$tmpdir"
    fi

    if [ -n "$yara_out" ]; then
        while IFS= read -r yline; do
            [ -z "$yline" ] && continue
            # "RULE PATH": split with parameter expansion, not echo|awk +
            # echo|cut (3 forks per match line add up to seconds on noisy batches)
            local yrule="${yline%% *}"
            local yfile="${yline#* }"
            [ -n "${MEDIA_MAP[$yfile]:-}" ] && yfile="${MEDIA_MAP[$yfile]}"
            local spat
            if [ "$EXPLAIN_MODE" = true ]; then
                if _is_builtin_noisy_rule "$yrule"; then
                    EXPLAIN_SUPPRESSED=$(( EXPLAIN_SUPPRESSED + 1 )); _xp "  suppressed  YARA_MATCH | rule=$yrule  <- built-in list of rules too generic to report"
                elif ! _resolve_str_sig "$yrule" >/dev/null && _is_vendor_obfuscation "$yrule" "$yfile"; then
                    EXPLAIN_SUPPRESSED=$(( EXPLAIN_SUPPRESSED + 1 )); _xp "  suppressed  YARA_MATCH | rule=$yrule  <- known vendor obfuscation fingerprint (generic_obfuscation_rules + known_vendor_obfuscation)"
                fi
            fi
            if _is_builtin_noisy_rule "$yrule"; then
                SUPPRESSED_FOUND=$(( SUPPRESSED_FOUND + 1 ))
            elif spat=$(_resolve_str_sig "$yrule"); then
                threat "SIG_STRING_MATCH" "$yfile" "pattern=${spat:0:50}"
            elif _is_vendor_obfuscation "$yrule" "$yfile"; then
                SUPPRESSED_FOUND=$(( SUPPRESSED_FOUND + 1 ))
            else
                threat "YARA_MATCH" "$yfile" "rule=$yrule"
            fi
        done <<< "$yara_out"
    fi
}

# ----------------------------------------------------------------------------
# MODULE: heuristics (batched strings/hex matching)
#
# grep -E -f builds its match automaton FROM SCRATCH on every invocation.
# With a realistic ClamAV .ndb+.ldb signature set that's tens/hundreds of
# thousands of patterns, that build alone can take seconds — calling it
# once PER FILE (as before) made a scan of 20k+ files effectively hang.
# Same fix pattern as hashes/YARA: batch many files into one grep call so
# the automaton is built once per batch, not once per file.
# ----------------------------------------------------------------------------
process_heuristic_batch() {
    [ $# -eq 0 ] && return
    { [ "$HAS_STRINGS" = true ] || [ "$HAS_HEX_ERE" = true ]; } || return

    # PERFORMANCE FIX: this used to fork dd+strings (do_strings) for EVERY
    # file before the batched search even ran — batching only combined the
    # SEARCH step, not this per-file preparation step, so it never actually
    # eliminated the dominant cost (~2 forks/file, e.g. ~5000 forks for
    # 2485 files). strings.txt patterns are literal readable text, which
    # already appears as a substring in a file's raw bytes whether the
    # file is genuine text or binary — no separate "extract printable
    # runs" step is actually needed. GNU grep -a searches binary files as
    # text directly, AND (unlike yara) accepts many files as plain
    # arguments in one call, so the whole batch can be searched with zero
    # per-file preparation forks.
    #
    # CAVEAT: busybox's grep does NOT handle -a / binary content
    # correctly (verified: silently finds nothing in files containing NUL
    # bytes, matched or not) — this path requires real GNU grep. Falls
    # back to the slower do_strings-based per-file extraction (the
    # previous behavior) if system grep isn't available.
    if [ "$HAS_STRINGS" = true ]; then
        if _has_real_grep; then
            local mf pat
            while IFS= read -r mf; do
                [ -z "$mf" ] && continue
                pat=$(_real_grep -F -a -i -o -f "$SIG_DIR/strings.txt" "$mf" 2>/dev/null | head -1)
                threat "SIG_STRING_MATCH" "$mf" "pattern=${pat:0:50}"
            done < <(_real_grep -F -a -i -l -f "$SIG_DIR/strings.txt" "$@" 2>/dev/null)
        else
            local tmpdir_s f i=0
            tmpdir_s=$(mktemp -d 2>/dev/null) && {
                local -a idx_s=()
                for f in "$@"; do
                    idx_s[$i]="$f"
                    do_strings "$f" 6 524288 > "$tmpdir_s/${i}.str" 2>/dev/null
                    i=$((i + 1))
                done
                local mf mi orig pat
                while IFS= read -r mf; do
                    [ -z "$mf" ] && continue
                    mi="${mf##*/}"; mi="${mi%.str}"
                    orig="${idx_s[$mi]:-}"
                    [ -z "$orig" ] && continue
                    pat=$(bb grep -F -i -o -f "$SIG_DIR/strings.txt" "$mf" 2>/dev/null | head -1)
                    threat "SIG_STRING_MATCH" "$orig" "pattern=${pat:0:50}"
                done < <(bb grep -F -i -l -f "$SIG_DIR/strings.txt" "$tmpdir_s"/*.str 2>/dev/null)
                rm -rf "$tmpdir_s"
            }
        fi
    fi

    # hex_ere.txt patterns are hex-DIGIT TEXT meant to match a hex-encoded
    # dump of the file's bytes, not the raw bytes themselves — this still
    # needs the per-file hex-dump preparation (can't skip it the way
    # strings could). In practice HAS_HEX_ERE is false for most setups
    # now that .ndb/.ldb signatures compile to YARA instead (see MODULE:
    # ClamAV format support), so this path is rarely exercised.
    if [ "$HAS_HEX_ERE" = true ]; then
        local tmpdir_h f i=0
        tmpdir_h=$(mktemp -d 2>/dev/null) && {
            local -a idx_h=()
            for f in "$@"; do
                idx_h[$i]="$f"
                bb dd if="$f" bs=524288 count=1 2>/dev/null | bb od -An -tx1 -v | tr -d ' \n' > "$tmpdir_h/${i}.hex" 2>/dev/null
                i=$((i + 1))
            done
            local mf mi orig hx
            while IFS= read -r mf; do
                [ -z "$mf" ] && continue
                mi="${mf##*/}"; mi="${mi%.hex}"
                orig="${idx_h[$mi]:-}"
                [ -z "$orig" ] && continue
                hx=$(bb grep -E -o -i -f "$SIG_DIR/hex_ere.txt" "$mf" 2>/dev/null | head -1)
                [ -n "$hx" ] && threat "HEX_SIG_MATCH" "$orig" "hex=${hx:0:40}..."
            done < <(bb grep -E -l -i -f "$SIG_DIR/hex_ere.txt" "$tmpdir_h"/*.hex 2>/dev/null)
            rm -rf "$tmpdir_h"
        }
    fi
}

# Decodes and checks candidate base64 chunks in ONE file: hash-lookup
# against known payloads, then (if still unmatched) a follow-up YARA scan
# of the DECODED content for anything ELF/PE/script-shaped. Runs directly
# per-file (via check_file_heuristics) — NOT gated behind a YARA screening
# rule anymore. That WAS tried (an embedded "__av_b64_screen__" regex rule,
# to save one read per file), but caused a real regression: YARA's regex
# engine scales badly against a very long single-line base64-ish blob —
# confirmed on real DLE installations, whose own license-obfuscated engine
# files are exactly that shape, making specific files take 74-113+
# SECONDS each. A plain `grep -oE` call handles the same content fine.
_check_b64_payload() {
    local file="$1"
    while IFS= read -r chunk; do
        [ -z "$chunk" ] && continue
        local b64tmp
        b64tmp=$(mktemp 2>/dev/null) || continue
        printf '%s' "$chunk" | _b64decode > "$b64tmp" 2>/dev/null
        [ -s "$b64tmp" ] || { rm -f "$b64tmp"; continue; }

        local magic
        magic=$(bb od -An -tx1 -v "$b64tmp" 2>/dev/null | head -1 | tr -d ' \n')
        case "$magic" in
            7f454c46*|4d5a*|2321*) : ;;
            *) rm -f "$b64tmp"; continue ;;
        esac

        if [ "$HAS_B64" = true ] && [ "$SHA256_CMD" != "none" ]; then
            local dh
            dh=$($SHA256_CMD "$b64tmp" 2>/dev/null | bb grep -oE '[0-9a-f]{64}' | head -1)
            if [ -n "$dh" ] && bb grep -qF "$dh" "$SIG_DIR/b64_payloads.tsv" 2>/dev/null; then
                local bname
                bname=$(bb grep -m 1 "^$dh" "$SIG_DIR/b64_payloads.tsv" | cut -f2)
                threat "KNOWN_B64_PAYLOAD" "$file" "name=${bname:-B64.Malware}|b64=${chunk:0:20}..."
                rm -f "$b64tmp"
                continue
            fi
        fi

        local dtype="SCRIPT"
        case "$magic" in 7f454c46*) dtype="ELF" ;; 4d5a*) dtype="PE_MZ" ;; esac
        if [ "$HAS_YARA" = true ]; then
            local yara_flags3=(-d filename= -d filepath= -d extension= -p "${YARA_THREADS:-1}" -a "$YARA_TIMEOUT_SEC") yhit
            case "$YARA_TARGET" in *.yarc) yara_flags3+=(-C) ;; esac
            _yslot_acq
            yhit=$(timeout $(( YARA_TIMEOUT_SEC + 3 )) $YARA_CMD "${yara_flags3[@]}" "$YARA_TARGET" "$b64tmp" 2>/dev/null | head -1 | awk '{print $1}')
            _yslot_rel
            [ -n "$yhit" ] && threat "SUSPICIOUS_B64_PAYLOAD" "$file" "decoded=${dtype}|yara=${yhit}|b64=${chunk:0:20}..."
        else
            threat "SUSPICIOUS_B64_PAYLOAD" "$file" "decoded=${dtype}|b64=${chunk:0:20}..."
        fi
        rm -f "$b64tmp"
    done < <(if _has_real_grep; then _real_grep -oE '[A-Za-z0-9+/]{200,}={0,2}' "$file" 2>/dev/null; else bb grep -oE '[A-Za-z0-9+/]{200,}={0,2}' "$file" 2>/dev/null; fi | head -8)
}

check_file_heuristics() {
    local file="$1" size="$2" oct="$3"

    if [ "$size" -lt "$MAX_SIZE" ]; then
        # REVERTED to always running this own grep-based pass (see the
        # REVERTED comment in compile_signatures for why) — no longer
        # gated on HAS_YARA / a screening rule.
        _check_b64_payload "$file"
    fi

    # Disguised
    local ext="${file##*.}"
    ext="${ext,,}"
    case "$ext" in
        jpg|jpeg|png|gif|bmp|webp|pdf|doc|docx|xls|xlsx)
            local real_type
            real_type=$(do_file_type "$file")
            case "$real_type" in
                ELF|PE_MZ|SCRIPT) threat "DISGUISED_FILE" "$file" "ext=.$ext|real=$real_type" ;;
            esac
            ;;
    esac

    # Known miner/botnet file names (IOC lists defined in the main script)
    if [ -n "${AV_IOC_PATH_ANY_RE:-}" ] && [[ "$file" =~ $AV_IOC_PATH_ANY_RE ]]; then
        threat "KNOWN_MALWARE_PATH" "$file" "ioc=${BASH_REMATCH[1]}|miner/botnet file name"
    elif [ -n "${AV_IOC_PATH_TMP_RE:-}" ] && [[ "$file" =~ $AV_IOC_PATH_TMP_RE ]]; then
        threat "KNOWN_MALWARE_PATH" "$file" "ioc=${file##*/}|miner/botnet file name (temp or bin dir)"
    fi

    # Executables in temp dirs (/tmp, /var/tmp, /dev/shm and per-site tmp/,
    # also inside an offline copy such as /mnt/x/var/tmp): botnet droppers
    # and miners live there as hidden files (".X11R6", ".khp",
    # ".cache-jd/javad") or random-named ELF binaries. Reported when
    #   - any path part below the temp dir starts with "." and the file is
    #     executable (x bit) or a binary/script (ELF / "#!"), or
    #   - the file is an ELF binary at all (hidden or not).
    case "$file" in
        */tmp/*|*/dev/shm/*)
            local _tr="${file##*/tmp/}" _ts="${file##*/dev/shm/}" _tt _tx=false _th=false
            [ "${#_ts}" -lt "${#_tr}" ] && _tr="$_ts"
            case "/$_tr" in */.*) _th=true ;; esac
            _tt=$(_bash_file_type "$file")
            local _to="0000${oct:-0}"; _to="${_to: -4}"
            (( 8#$_to & 8#0111 )) 2>/dev/null && _tx=true
            if [ "$_tt" = ELF ] || { [ "$_th" = true ] && { [ "$_tx" = true ] || [ "$_tt" = SCRIPT ]; }; }; then
                threat "SUSPICIOUS_TMP_EXEC" "$file" "type=${_tt}|hidden=$([ "$_th" = true ] && echo yes || echo no)|perms=${_to}"
            fi
            ;;
    esac

    # Permissions
    # stat/find usually return a 3-digit octal mode ("644") with no
    # setuid/setgid bit. "${oct: -4}" on a string shorter than 4 chars
    # returns EMPTY in bash, so pad with zeros first.
    if [ -n "$oct" ] && [ "$oct" != "0" ]; then
        oct="0000${oct}"
        oct="${oct: -4}"
        if (( 8#$oct & 8#6000 )) 2>/dev/null; then
            # SUID/SGID on standard system binaries (sudo, su, mount, passwd,
            # ...) is EXPECTED — every Linux install has these, so flagging
            # them on every scan of a system directory is pure noise. But a
            # virus/rootkit REPLACING one of those binaries is exactly what
            # we want to still catch. The distro package manager already
            # keeps a checksum database for this — use it: if the file is
            # package-owned AND its checksum matches the package's record,
            # it is verified legitimate and suppressed; if it's unowned,
            # unverifiable, or the checksum DOESN'T match, it's reported
            # (with 'unverified' or 'TAMPERED' noted, since a checksum
            # mismatch on a package-owned SUID binary is a strong compromise
            # indicator, not a minor discrepancy).
            #
            # SUID_VERIFY_MODE is on by default now (see its declaration)
            # — this just gates whether verification runs at all
            # (--no-verify-suid skips it entirely, e.g. if dpkg isn't
            # trusted/available). DEEP_MODE separately controls whether a
            # VERIFIED-clean file still gets suppressed — consistent with
            # --deep's "no automatic filtering" rule elsewhere, a person
            # running a deep/paranoid pass sees every SUID/SGID file
            # regardless of verification status, with that status noted
            # as context rather than used to hide anything.
            if [ "$SUID_VERIFY_MODE" = "true" ]; then
                local suid_status
                suid_status=$(_verify_package_file "$file")
                case "$suid_status" in
                    verified)
                        [ "$DEEP_MODE" = "true" ] && threat "SUID_SGID" "$file" "perms=$oct|verified (package checksum matches)"
                        ;;
                    tampered) threat "SUID_SGID" "$file" "perms=$oct|TAMPERED (fails package checksum verification)" ;;
                    *)        threat "SUID_SGID" "$file" "perms=$oct" ;;
                esac
            else
                threat "SUID_SGID" "$file" "perms=$oct"
            fi
        fi
        (( 8#$oct & 8#0002 )) 2>/dev/null && (( 8#$oct & 8#0111 )) 2>/dev/null && threat "WORLD_WRITABLE_EXEC" "$file" "perms=$oct"
    fi
}

# ----------------------------------------------------------------------------
# MODULE: scan loop (lives inside a function so "local" is valid)
# ----------------------------------------------------------------------------
# Run every partially filled batch and reset it. Used by the -w worker
# (WORKER_ID=rt), whose FIFO never ends: without it a new file waited for
# BATCH_SIZE-1 more files before hash/YARA/strings ever ran.
# --media-fast: big video/audio files (recognised by magic bytes, not by
# extension) are checked by YARA on their first and last MEDIA_FAST_MB only,
# with no full-file hash: that is where an appended or metadata-embedded
# script would sit, and it spares reading hundreds of GB of uploads.
MEDIA_FAST_MB=2
MEDIA_BATCH_MAX=8        # extracts per yara call (8 x 4 MB): they sit in the work dir, maybe /dev/shm
declare -A MEDIA_MAP=()
declare -a BATCH_MEDIA=()
MEDIA_SEQ=0
_is_script_ext() {
    case "${1##*.}" in
        [pP][hH][pP]*|[pP][hH][tT][mM][lL]|[pP][hH][aA][rR]|[iI][nN][cC]|[jJ][sS]|[pP][lL]|[pP][yY]|[sS][hH]|[cC][gG][iI]|[aA][sS][pP]|[aA][sS][pP][xX]|[jJ][sS][pP]) return 0 ;;
    esac
    return 1
}
_is_media_magic() {
    local h
    h=$(head -c 12 "$1" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
    case "$h" in
        ????????66747970*) return 0 ;;            # ISO-BMFF: mp4 m4a mov 3gp ("ftyp" at 4)
        1a45dfa3*) return 0 ;;                    # matroska / webm
        52494646????????41564920*) return 0 ;;    # RIFF....AVI
        52494646????????57415645*) return 0 ;;    # RIFF....WAVE
        494433*|fffb*|fff3*|fff2*) return 0 ;;    # mp3 (ID3 tag / frame sync)
        664c6143*|4f676753*|464c56*) return 0 ;;  # flac, ogg, flv
        3026b2758e66cf11*) return 0 ;;            # asf: wmv / wma
        000001ba*|000001b3*) return 0 ;;          # mpeg program / video stream
    esac
    return 1
}
# $1 file -> queues a head+tail extract for YARA; the result is reported
# against the original file (MEDIA_MAP)
_media_fast_queue() {
    local f="$1" d="$REPORT_DIR/.media_${WORKER_ID}" t n
    n=$(( MEDIA_FAST_MB * 1024 * 1024 ))
    mkdir -p "$d" 2>/dev/null || return 1
    MEDIA_SEQ=$(( MEDIA_SEQ + 1 )); t="$d/m${MEDIA_SEQ}"
    { head -c "$n" "$f"; tail -c "$n" "$f"; } > "$t" 2>/dev/null || { rm -f "$t"; return 1; }
    MEDIA_MAP["$t"]="$f"
    BATCH_MEDIA+=("$t")
    [ "${#BATCH_MEDIA[@]}" -ge "$MEDIA_BATCH_MAX" ] && _flush_media_batch
    return 0
}
# scanned right here (not via the threads-mode queue: the path map lives in
# this worker); one extra yara process at most, like the other side checks
_flush_media_batch() {
    [ "${#BATCH_MEDIA[@]}" -eq 0 ] && return 0
    local t
    if [ "$HAS_YARA" = true ]; then
        local _t0; _t0=$(_now_ms)
        process_yara_batch "${BATCH_MEDIA[@]}"
        T_YARA_MS=$(( T_YARA_MS + $(_now_ms) - _t0 ))
    fi
    for t in "${BATCH_MEDIA[@]}"; do rm -f "$t"; unset 'MEDIA_MAP[$t]'; done
    BATCH_MEDIA=()
}
# over -m and not checked at all: listed for the report (see main)
_note_size_skip() {
    printf '%s\t%s\n' "$2" "${1//$'\n'/?}" >> "$REPORT_DIR/${WORKER_ID}.skipped" 2>/dev/null
}

# ---------------------------------------------------------------- --explain
EXPLAIN_MODE=false
EXPLAIN_REPORTED=0
EXPLAIN_SUPPRESSED=0
_xp() { [ "$EXPLAIN_MODE" = true ] && printf '%s\n' "$*"; return 0; }
explain_file_header() {
    local f="$1" sz mt h algo cmd tbl hit lines
    sz=$(_stat_size "$f" 2>/dev/null || wc -c < "$f")
    mt=$(_bash_file_type "$f")
    echo "  size ${sz} bytes, mode $(_stat_mode "$f" 2>/dev/null), magic: ${mt:-unknown}"
    echo "--- which checks run for this file with these settings"
    if [ "${AV_MEDIA_FAST:-false}" = true ] && [ "$sz" -gt $(( MEDIA_FAST_MB * 2 * 1048576 )) ] && _is_media_magic "$f"; then
        echo "  media (magic bytes) + --media-fast: YARA on the first and last ${MEDIA_FAST_MB} MB only, no hash"
    elif [ "$sz" -ge "$MAX_SIZE" ]; then
        case "${f##*.}" in
            [pP][hH][pP]*|[pP][hH][tT][mM][lL]|[pP][hH][aA][rR]|[iI][nN][cC]|[jJ][sS]|[pP][lL]|[pP][yY]|[sS][hH]|[cC][gG][iI])
                echo "  over -m ${MAX_SCAN_MB} MB, but a script: hash + YARA still run (no heuristics)" ;;
            *)  echo "  over -m ${MAX_SCAN_MB} MB: NOT scanned (listed as 'Not scanned' in a normal scan)" ;;
        esac
    else
        echo "  hash tables: sha256$( [ "$HAS_SHA1" = true ] && echo ", sha1"), md5; YARA; strings/hex heuristics; per-file checks"
        case "$mt" in JPEG|PNG|GIF)
            case "${f##*.}" in [jJ][pP][gG]|[jJ][pP][eE][gG]|[jJ][pP][eE]|[pP][nN][gG]|[gG][iI][fF])
                if [ "$DEEP_MODE" = true ]; then echo "  real image: --deep, full YARA"
                elif _real_grep -q -a -i -E -e "$IMG_SCRIPT_RE" -- "$f" 2>/dev/null; then echo "  real image: the script-marker prefilter HIT -> full YARA"
                else echo "  real image: no script markers -> YARA is skipped for it (--deep forces it)"; fi ;;
            esac ;;
        esac
    fi
    echo "--- hashes"
    for algo in sha256 sha1 md5; do
        case "$algo" in
            sha256) cmd="$SHA256_CMD"; tbl="$SIG_DIR/sha256.tsv" ;;
            sha1)   cmd="$SHA1_CMD";   tbl="$SIG_DIR/sha1.tsv" ;;
            md5)    cmd="$MD5_CMD";    tbl="$SIG_DIR/md5.tsv" ;;
        esac
        [ "$cmd" = "none" ] || [ -z "$cmd" ] && continue
        # SHA256_CMD & co are a tool ("sha256sum", "busybox sha256sum") or
        # "_hash_each openssl-sha256": same call as the hash batches use
        h=$($cmd "$f" 2>/dev/null | head -1 | cut -d' ' -f1 | sed 's/^\\//')
        [ -n "$h" ] || continue
        hit=$(_real_grep -m1 -i "^${h}"$'\t' "$tbl" 2>/dev/null | cut -f2)
        printf '  %-6s %s  %s\n' "$algo" "$h" "${hit:+IN SIGNATURES: $hit}"
        [ -z "$hit" ] && [ -s "$tbl" ] && echo "         not in the $(bb wc -l < "$tbl" | tr -d ' ') ${algo} signature(s)"
    done
    echo "--- YARA: every rule that matches, before any filtering"
    if [ "$HAS_YARA" = true ]; then
        local yf=(-s -d filename= -d filepath= -d extension= -a "$YARA_TIMEOUT_SEC")
        case "$YARA_TARGET" in *.yarc) yf+=(-C) ;; esac
        lines=$(timeout $(( YARA_TIMEOUT_SEC + 3 )) $YARA_CMD "${yf[@]}" "$YARA_TARGET" "$f" 2>/dev/null)
        if [ -z "$lines" ]; then echo "  no rule matches"
        else
            printf '%s\n' "$lines" | bb awk '
                /^0x/ { if (++k[r] <= 3) { s = $0; if (length(s) > 110) s = substr(s, 1, 110) "..."; print "      " s } ; next }
                { r = $1; print "  rule " r }'
        fi
    else
        echo "  YARA is not available (no yara binary or no ruleset)"
    fi
    echo "--- what the scanner does with the hits (reported / suppressed and why)"
}
explain_file_footer() {
    echo "--- result: ${EXPLAIN_REPORTED} finding(s) reported, ${EXPLAIN_SUPPRESSED} suppressed"
    [ "$EXPLAIN_REPORTED" -eq 0 ] && [ "$EXPLAIN_SUPPRESSED" -eq 0 ] && echo "    nothing matched: the file is clean for this signature set"
    [ "$EXPLAIN_SUPPRESSED" -gt 0 ] && [ "$DEEP_MODE" != true ] && echo "    (--deep shows what ignore_sigs / allowlists / PUA hide)"
    return 0
}

_flush_batches() {
    if [ "$SHA_BATCH_CNT" -gt 0 ]; then _timed_hash_batch "sha256" "$SIG_DIR/sha256.tsv" "${BATCH_SHA[@]}"; BATCH_SHA=(); SHA_BATCH_CNT=0; fi
    if [ "$SHA1_BATCH_CNT" -gt 0 ]; then _timed_hash_batch "sha1" "$SIG_DIR/sha1.tsv" "${BATCH_SHA1[@]}"; BATCH_SHA1=(); SHA1_BATCH_CNT=0; fi
    if [ "$MD5_BATCH_CNT" -gt 0 ]; then _timed_hash_batch "md5" "$SIG_DIR/md5.tsv" "${BATCH_MD5[@]}"; BATCH_MD5=(); MD5_BATCH_CNT=0; fi
    _flush_image_batch
    if [ "$YARA_BATCH_CNT" -gt 0 ]; then _timed_yara_batch "${BATCH_YARA[@]}"; BATCH_YARA=(); YARA_BATCH_CNT=0; fi
    if [ "$HEUR_BATCH_CNT" -gt 0 ]; then _timed_heur_batch "${BATCH_HEUR[@]}"; BATCH_HEUR=(); HEUR_BATCH_CNT=0; fi
    if [ "$PE_BATCH_CNT" -gt 0 ]; then _timed_pe_batch "${BATCH_PE[@]}"; BATCH_PE=(); PE_BATCH_CNT=0; fi
    _flush_media_batch
    return 0
}

run_scan_loop() {
    local col1 col2 col3 file size oct magic_type skip_deep ext
    local rc line pending="" t0=""

    while :; do
        if [ "$WORKER_ID" != "rt" ]; then
            IFS=$'\t' read -r col1 col2 col3 || break
        else
            # -w: the FIFO carries plain paths only (feed_realtime_path
            # never sends names with TAB/newline). Flush on 2 s idle, and
            # also once the oldest queued path is 2 s old, since a steady
            # trickle of events would never let the read time out.
            IFS= read -r -t 2 line; rc=$?
            # >128 = timed out: keep any partial line (bash stores it in
            # $line), flush batches, keep waiting.
            if [ "$rc" -gt 128 ]; then pending+="$line"; _flush_batches; t0=""; continue; fi
            line="$pending$line"; pending=""
            if [ -n "$t0" ] && [ $(( SECONDS - t0 )) -ge 2 ]; then _flush_batches; t0=""; fi
            [ "$rc" -ne 0 ] && [ -z "$line" ] && break
            [ -z "$t0" ] && t0=$SECONDS
            col1="$line"; col2=""; col3=""
        fi
        file=""; size=""; oct=""
        if [ -n "${col3:-}" ]; then
            size="$col1"; oct="$col2"; file="$col3"
        else
            file="$col1"
            [ -z "$file" ] || [ ! -f "$file" ] || [ ! -r "$file" ] && continue
            size=$(_stat_size "$file") || continue
            oct=$(_stat_mode "$file")
        fi

        [ -z "$file" ] || [ ! -f "$file" ] || [ ! -r "$file" ] && continue
        FILES_SCANNED=$(( FILES_SCANNED + 1 ))
        [ "$size" -eq 0 ] && continue

        # --media-fast: a big video/audio file -> head+tail YARA only. Never
        # for a script extension: "ID3" + padding + <?php ... saved as .php
        # still runs in PHP and must get the full checks.
        if [ "${AV_MEDIA_FAST:-false}" = true ] && [ "$size" -gt $(( MEDIA_FAST_MB * 2 * 1048576 )) ] \
           && ! _is_script_ext "$file" && _is_media_magic "$file" && _media_fast_queue "$file"; then
            # disguised extension / permissions (no full read: size as if over -m)
            check_file_heuristics "$file" "$MAX_SIZE" "${oct:-0}"
            [ $(( FILES_SCANNED % 50 )) -eq 0 ] && progress "$file"
            continue
        fi

        if [ "$size" -lt "$MAX_SIZE" ]; then
            # Hash batches
            if [ "$HAS_SHA256" = true ] && [ "$SHA256_CMD" != "none" ]; then
                BATCH_SHA+=("$file")
                SHA_BATCH_CNT=$(( SHA_BATCH_CNT + 1 ))
                if [ "$SHA_BATCH_CNT" -ge "$BATCH_SIZE" ]; then
                    _timed_hash_batch "sha256" "$SIG_DIR/sha256.tsv" "${BATCH_SHA[@]}"
                    BATCH_SHA=(); SHA_BATCH_CNT=0
                fi
            fi
            if [ "$HAS_MD5" = true ] && [ "$MD5_CMD" != "none" ]; then
                BATCH_MD5+=("$file")
                MD5_BATCH_CNT=$(( MD5_BATCH_CNT + 1 ))
                if [ "$MD5_BATCH_CNT" -ge "$BATCH_SIZE" ]; then
                    _timed_hash_batch "md5" "$SIG_DIR/md5.tsv" "${BATCH_MD5[@]}"
                    BATCH_MD5=(); MD5_BATCH_CNT=0
                fi
            fi
            # SHA1 gated the same way — only queued at all when the
            # compiled signature set actually HAS sha1.tsv entries (a
            # real ClamAV .hsb file with none would leave this HAS_SHA1
            # false, and this whole extra per-file read never happens —
            # no IOPS cost paid for a hash type nobody's database uses).
            if [ "$HAS_SHA1" = true ] && [ "$SHA1_CMD" != "none" ]; then
                BATCH_SHA1+=("$file")
                SHA1_BATCH_CNT=$(( SHA1_BATCH_CNT + 1 ))
                if [ "$SHA1_BATCH_CNT" -ge "$BATCH_SIZE" ]; then
                    _timed_hash_batch "sha1" "$SIG_DIR/sha1.tsv" "${BATCH_SHA1[@]}"
                    BATCH_SHA1=(); SHA1_BATCH_CNT=0
                fi
            fi

            # Magic filter + YARA decision
            magic_type=$(_bash_file_type "$file")
            skip_deep=false
            # Skip full YARA only when BOTH magic and extension say "image":
            # "GIF89a;<?php ..." saved as .php must still get YARA.
            case "$magic_type" in
                JPEG|PNG|GIF)
                    case "${file##*.}" in
                        [jJ][pP][gG]|[jJ][pP][eE][gG]|[jJ][pP][eE]|[pP][nN][gG]|[gG][iI][fF]) skip_deep=true ;;
                    esac ;;
            esac

            # Extension/magic mismatch override: force full YARA scanning
            # even for image extensions that would otherwise skip_deep, so
            # a real executable disguised as a .jpg still gets checked.
            # The actual DISGUISED_FILE report happens once, in
            # check_file_heuristics() below (which covers more extensions
            # — bmp/webp/pdf/doc/xls too) — reporting it here TOO used to
            # double-count every disguised-file hit (threats displayed
            # once due to dedup, but counted twice).
            ext="${file##*.}"
            case "${ext,,}" in
                jpg|jpeg|png|gif)
                    if [ "$magic_type" = "ELF" ] || [ "$magic_type" = "PE_MZ" ]; then
                        skip_deep=false
                    fi
                    ;;
            esac

            if [ "$skip_deep" = true ] && [ "$HAS_YARA" = true ]; then
                if [ "$DEEP_MODE" = "true" ]; then
                    skip_deep=false
                else
                    BATCH_IMG+=("$file")
                    [ "${#BATCH_IMG[@]}" -ge "$BATCH_SIZE" ] && _flush_image_batch
                fi
            fi

            if [ "$skip_deep" = false ] && [ "$HAS_YARA" = true ]; then
                BATCH_YARA+=("$file")
                YARA_BATCH_CNT=$(( YARA_BATCH_CNT + 1 ))
                if [ "$YARA_BATCH_CNT" -ge "$BATCH_SIZE" ]; then
                    _timed_yara_batch "${BATCH_YARA[@]}"
                    BATCH_YARA=(); YARA_BATCH_CNT=0
                fi
            fi

            # Batched strings/hex heuristic matching (see process_heuristic_batch)
            if [ "$HAS_STRINGS" = true ] || [ "$HAS_HEX_ERE" = true ]; then
                BATCH_HEUR+=("$file")
                HEUR_BATCH_CNT=$(( HEUR_BATCH_CNT + 1 ))
                if [ "$HEUR_BATCH_CNT" -ge "$HEUR_BATCH_SIZE" ]; then
                    _timed_heur_batch "${BATCH_HEUR[@]}"
                    BATCH_HEUR=(); HEUR_BATCH_CNT=0
                fi
            fi

            # Batched PE-section hash matching (.mdb signatures) — only for
            # files whose magic bytes actually look like a PE/MZ executable.
            if [ "$HAS_MDB" = true ] && [ "$magic_type" = "PE_MZ" ]; then
                BATCH_PE+=("$file")
                PE_BATCH_CNT=$(( PE_BATCH_CNT + 1 ))
                if [ "$PE_BATCH_CNT" -ge "$PE_BATCH_SIZE" ]; then
                    _timed_pe_batch "${BATCH_PE[@]}"
                    BATCH_PE=(); PE_BATCH_CNT=0
                fi
            fi
        else
            # Over MAX_SIZE (H1): a webshell padded past -m skipped every
            # check. Script files still get hash + YARA; big media/backups
            # stay skipped to spare disk I/O.
            case "${file##*.}" in
                [pP][hH][pP]*|[pP][hH][tT][mM][lL]|[pP][hH][aA][rR]|[iI][nN][cC]|[jJ][sS]|[pP][lL]|[pP][yY]|[sS][hH]|[cC][gG][iI])
                    if [ "$HAS_SHA256" = true ] && [ "$SHA256_CMD" != "none" ]; then
                        BATCH_SHA+=("$file"); SHA_BATCH_CNT=$(( SHA_BATCH_CNT + 1 ))
                        if [ "$SHA_BATCH_CNT" -ge "$BATCH_SIZE" ]; then
                            _timed_hash_batch "sha256" "$SIG_DIR/sha256.tsv" "${BATCH_SHA[@]}"
                            BATCH_SHA=(); SHA_BATCH_CNT=0
                        fi
                    fi
                    if [ "$HAS_MD5" = true ] && [ "$MD5_CMD" != "none" ]; then
                        BATCH_MD5+=("$file"); MD5_BATCH_CNT=$(( MD5_BATCH_CNT + 1 ))
                        if [ "$MD5_BATCH_CNT" -ge "$BATCH_SIZE" ]; then
                            _timed_hash_batch "md5" "$SIG_DIR/md5.tsv" "${BATCH_MD5[@]}"
                            BATCH_MD5=(); MD5_BATCH_CNT=0
                        fi
                    fi
                    if [ "$HAS_YARA" = true ]; then
                        BATCH_YARA+=("$file"); YARA_BATCH_CNT=$(( YARA_BATCH_CNT + 1 ))
                        if [ "$YARA_BATCH_CNT" -ge "$BATCH_SIZE" ]; then
                            _timed_yara_batch "${BATCH_YARA[@]}"
                            BATCH_YARA=(); YARA_BATCH_CNT=0
                        fi
                    fi
                    ;;
                *)
                    # archives are still opened by -A (own size limit)
                    case "${file,,}" in
                        *.zip|*.jar|*.tar|*.tgz|*.gz|*.bz2|*.xz|*.7z|*.rar)
                            [ "$SCAN_ARCHIVES" = "true" ] || _note_size_skip "$file" "$size" ;;
                        *) _note_size_skip "$file" "$size" ;;
                    esac ;;
            esac
        fi

        # Archive scanning (-A/--scan-archives) — deliberately OUTSIDE the
        # MAX_SIZE gate above: archives are checked against their own,
        # separate ARCHIVE_MAX_MB limit (typically larger than MAX_SIZE,
        # since compressed archives commonly exceed the deep-inspection
        # size cutoff for regular files). scan_archive() itself is a fast
        # no-op for non-archive extensions and when -A wasn't passed.
        [ "$SCAN_ARCHIVES" = "true" ] && scan_archive "$file"

        # Cheap per-file checks (base64 payloads, disguised ext, perms)
        check_file_heuristics "$file" "$size" "${oct:-0}"

        [ $(( FILES_SCANNED % 50 )) -eq 0 ] && progress "$file"
    done < "$POOL_FILE"

    # Flush remaining batches
    [ "$SHA_BATCH_CNT" -gt 0 ] && _timed_hash_batch "sha256" "$SIG_DIR/sha256.tsv" "${BATCH_SHA[@]}"
    [ "$SHA1_BATCH_CNT" -gt 0 ] && _timed_hash_batch "sha1" "$SIG_DIR/sha1.tsv" "${BATCH_SHA1[@]}"
    [ "$MD5_BATCH_CNT" -gt 0 ] && _timed_hash_batch "md5" "$SIG_DIR/md5.tsv" "${BATCH_MD5[@]}"
    _flush_image_batch
    [ "$YARA_BATCH_CNT" -gt 0 ] && _timed_yara_batch "${BATCH_YARA[@]}"
    [ "$HEUR_BATCH_CNT" -gt 0 ] && _timed_heur_batch "${BATCH_HEUR[@]}"
    [ "$PE_BATCH_CNT" -gt 0 ] && _timed_pe_batch "${BATCH_PE[@]}"
    _flush_media_batch
}

# ----------------------------------------------------------------------------
# MODULE: YARA consumer (threads mode): one yara process with -p YARA_THREADS
# scans what the workers queued, in batches of BATCH_SIZE x threads (so one
# call takes about as long as one single-thread batch: same timeout meaning).
# Ends when every worker has finished (.done marker or process gone) and the
# queue is empty.
# ----------------------------------------------------------------------------
_yq_workers_running() {
    local p n=0
    n=$(ls "$REPORT_DIR"/pool_*.done 2>/dev/null | grep -vc '/pool_yara\.done$')
    [ "${n:-0}" -ge "${AV_YARA_NWORKERS:-0}" ] && return 1
    for p in ${AV_YARA_WPIDS:-}; do kill -0 "$p" 2>/dev/null && return 0; done
    return 1
}
run_yara_consumer() {
    local q="$REPORT_DIR/.yq" f p maxb batch=() finishing=false
    maxb=$(( BATCH_SIZE * ${YARA_THREADS:-1} ))
    [ "$maxb" -lt "$BATCH_SIZE" ] && maxb=$BATCH_SIZE
    log "YARA consumer: 1 process x ${YARA_THREADS:-1} thread(s), up to $maxb files per call"
    while :; do
        batch=()
        for f in "$q"/*.lst; do
            [ -f "$f" ] || continue
            while IFS= read -r -d '' p; do batch+=("$p"); done < "$f"
            rm -f "$f"
            [ "${#batch[@]}" -ge "$maxb" ] && break
        done
        if [ "${#batch[@]}" -gt 0 ]; then
            _timed_yara_batch "${batch[@]}"
            progress "yara"
            continue
        fi
        [ "$finishing" = true ] && break
        # the last lists are written before a worker's .done / exit, so one
        # more pass after "all finished" catches everything
        _yq_workers_running || { finishing=true; continue; }
        sleep 0.2 2>/dev/null || sleep 1
    done
}

# ----------------------------------------------------------------------------
# MODULE: finalize
# ----------------------------------------------------------------------------
finalize_worker() {
    progress "done"
    printf 'FILES_SCANNED:%d\nTHREATS_FOUND:%d\nSUPPRESSED:%d\nPERMS_FOUND:%d\nSUID_FOUND:%d\n' "$FILES_SCANNED" "$THREATS_FOUND" "$SUPPRESSED_FOUND" "$PERMS_FOUND" "$SUID_FOUND" >> "$REPORT"
    printf 'TIMING_HASH_MS:%d\nTIMING_YARA_MS:%d\nTIMING_HEUR_MS:%d\nTIMING_PE_MS:%d\n' "$T_HASH_MS" "$T_YARA_MS" "$T_HEUR_MS" "$T_PE_MS" >> "$REPORT"
    log "Completed - files: $FILES_SCANNED, threats: $THREATS_FOUND, suppressed: $SUPPRESSED_FOUND"
    rm -f "$_IGNORE_SIGS_FILTERED" "$_GENERIC_OBFUSCATION_FILTERED" "$_KNOWN_VENDOR_OBFUSCATION_FILTERED" 2>/dev/null
    touch "${REPORT_DIR}/${WORKER_ID}.done"
}

# ----------------------------------------------------------------------------
# worker main()
# ----------------------------------------------------------------------------
main() {
    log "Worker started PID=$$ OS=$OS yara=$YARA_CMD"
    progress "init"
    init_worker_state
    if [ "${AV_YARA_ROLE:-}" = "consumer" ]; then
        run_yara_consumer
    elif [ -n "${AV_EXPLAIN:-}" ]; then
        EXPLAIN_MODE=true
        explain_file_header "$(cut -f3- "$POOL_FILE" | head -1)"
        run_scan_loop
        explain_file_footer
        rm -f "$_IGNORE_SIGS_FILTERED" "$_GENERIC_OBFUSCATION_FILTERED" "$_KNOWN_VENDOR_OBFUSCATION_FILTERED" 2>/dev/null
        rm -rf "$REPORT_DIR/.media_${WORKER_ID}" 2>/dev/null
        exit 0
    else
        run_scan_loop
    fi
    finalize_worker
}

main "$@"
#__WORKER_END__
