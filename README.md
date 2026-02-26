# Unix Performance Forensic Tools

<a id="overview"></a>
## Overview

A comprehensive Bash-based diagnostic tool for Unix servers that automatically detects performance bottlenecks and can create AWS Support cases with detailed forensic data. Originally created for AWS DMS migrations - run this on your SOURCE DATABASE SERVER. Now useful for any Unix performance troubleshooting scenario. Supports AIX, HP-UX, Solaris, and Illumos with graceful degradation when tools are unavailable.

Key Features:
- Performance forensics: CPU, memory, disk, network, database (vmstat, iostat, sar, prstat, etc.)
- Storage profiling (disk labeling, partition schemes, boot configuration)
- AWS DMS source database diagnostics (binary logging, replication lag, connection analysis)
- Automated bottleneck detection
- **Multi-Unix support** (AIX, HP-UX, Solaris, Illumos)
- Graceful degradation when tools unavailable
- Database forensics: DBA-level query analysis and DMS readiness checks
- Automatic AWS Support case creation with diagnostic data
- Works on-premises and in cloud environments

TL;DR - Run it now
```bash
git clone https://github.com/arsanmiguel/unix-forensics.git && cd unix-forensics
chmod +x invoke-unix-forensics.sh
./invoke-unix-forensics.sh
```
(Run as root or with system administrator privileges.) Then read on for Solaris, AWS Support, or troubleshooting.

Quick links: [Install](#installation) · [Usage](#available-tool) · [Solaris](#solaris) · [Troubleshooting](#troubleshooting)

Contents
- [Overview](#overview)
- [Quick Start](#quick-start)
- [Solaris](#solaris)
- [Solaris 9 vs 10/11](#appendix-solaris)
- [AIX](#aix)
- [HP-UX](#hp-ux)
- [Installation](#installation)
- [Examples](#examples)
- [Use Cases](#use-cases)
- [What Bottlenecks Can Be Found](#what-bottlenecks-can-be-found)
- [Troubleshooting](#troubleshooting)
- [Configuration (AWS Support)](#configuration)
- [Support](#support)
- [Important Notes & Performance](#important-notes-and-performance)
- [Version History](#version-history)

---

<a id="quick-start"></a>
## Quick Start

### Prerequisites
- Unix server (see supported OS list below)
- Root or system administrator privileges
- Bash or Korn shell
- AWS CLI (optional, for support case creation)

### Supported Operating Systems

Designed For:
- AIX 7.1, 7.2, 7.3
- HP-UX 11i v3
- Solaris 9, 10, 11 (see Solaris notes below)
- OpenIndiana / OmniOS / Illumos

I've put together an updated VirtualBox image of Solaris 9. Why? You may need to pull repositories from GitHub and it's too much of a hassle to get your systems connected. You could also just take binaries from it for non-internet connected networks. It is available on the [Releases](https://github.com/arsanmiguel/unix-forensics/releases) page (tag: `solaris9-rescue-v1.0`).

Note: Solaris has been validated on 9, 10, and 11 (x86); illumos validated on OpenIndiana and OmniOS (r151056). SPARC not yet validated. AIX and HP-UX are syntactically validated but not yet tested on actual hardware; the script uses standard Unix commands and graceful degradation for missing tools. If you have access to these systems and would like to help test, please contact: adrianr.sanmiguel@gmail.com

---

<a id="solaris"></a>
## Solaris

<a id="solaris-critical"></a>
<details>
<summary><strong>Solaris: CRITICAL - Patch Before You Run</strong></summary>

Do not run this tool on a Solaris box until the system is patched as current as you can get it.

Solaris (especially 9 and 10) ships with ancient, often vulnerable versions of OpenSSL, curl, wget, and git. Out-of-date builds can break TLS, fail on HTTPS, or expose you to known CVEs. The script and your sanity both assume a minimally modern toolchain.

Before you even attempt this on Solaris:

1. Patch the OS - Apply the latest recommended patch clusters / updates for your release (SunOS 5.9, 5.10, or 5.11).
2. OpenSSL - Ensure OpenSSL (or the platform’s TLS stack) is updated and supports current TLS. Many older Solaris builds are stuck on 0.9.x/1.0.x and are unsafe for anything network-facing.
3. curl and wget - Update to versions that support HTTPS and modern TLS. The script and any follow-up (e.g. AWS CLI, support bundles) may need them.
4. git - If you clone the repo on the box, use a recent enough git that works with HTTPS and doesn’t choke on modern servers.

The script tries to be compatible with old Solaris; it does not fix an unpatched, 20-year-old userland. If you're a bench admin still touching this OS: patch fully and then give it a shot.

Note - for bench admins

> To the bench admins: My sweet summer child. I fought the Old Gods so you wouldn't have to. Proceed with utmost caution. Here be dragons of the absolute highest order. Not Puff. Think *Reign of Fire*'s Bull Dragon, *Slime*'s Veldora (IYKYK), *Game of Thrones*' Drogon.
>
> Do you have a patch disk? If not, STOP. Do you have a week to spend mucking through the wayback machine, even with an AI agent to help you munge through broken mirrors and bad packages? PLEASE STOP.
>
> There is no substitute for a patch disk, a known-good internal patch mirror, or a healthier system with these binaries. I have a known-good, QEMU-based Solaris 9 image [available here](https://github.com/arsanmiguel/unix-forensics/releases/tag/solaris9-rescue-v1.0). Trust me: you don't want to have to go through what I did to get somewhere useful.

</details>

<a id="appendix-solaris"></a>
<details>
<summary><strong>Solaris 9 vs 10/11: version differences and getting each running</strong></summary>

Version differences (what the script does)

The script detects Solaris by OS/release and adjusts automatically. You don't have to pick a "mode" for 9 vs 10 vs 11.

| Item | Solaris 9 (SunOS 5.9) | Solaris 10 / 11, Illumos |
|------|------------------------|---------------------------|
| ZFS | Not available (introduced in 10). Script reports zpool/zfs as N/A and does not require or recommend installing them (they are not in OpenCSW for 9). | ZFS is checked and used when present (pool status, ashift, capacity, etc.). All `zpool` output commands are guarded with `|| true` so the script survives `set -eu` + `pipefail` when no pools are configured. |
| Bash / shell | Very old bash; no `pipefail`, no `=~`, no `<<<`, no `${!array[@]}`, no array `+=`. Script uses portable constructs (e.g. `case`, here-docs, scalar lists, index loops) and skips `set -o pipefail` on 5.9. | Modern enough; script uses full strictness and normal Bash-isms. |
| date | `date +%s` (epoch seconds) is not supported; script falls back so duration may show 0 seconds. | Epoch time works; analysis duration is reported normally. |
| grep | Solaris 9 `/usr/bin/grep` does not support `-q` (quiet) or `-i` with `-q`. All quiet-match patterns use `>/dev/null 2>&1` instead. `egrep` is used everywhere (no `grep -E`). | `grep -q` works but the script uses `>/dev/null 2>&1` universally for portability. |
| tail | `tail -n +2` is not supported on Solaris 9. Script uses `awk 'NR>1'` everywhere. | `tail -n +2` works but the script uses `awk 'NR>1'` universally for portability. |
| sed | Solaris 9 `sed` does not support POSIX `[[:space:]]` character classes (they silently consume input). OS detection uses `tr -d ' \t\r\n'` instead. | `[[:space:]]` works in `sed`, but `tr` is used for the critical `UNAME_S` detection to stay portable. |
| Disk enumeration | `iostat -En` does not exist; `format` hangs without a controlling tty (same as all Solaris). Script enumerates `/dev/rdsk/c*s2` and uses `iostat -e` for disk summaries. | `iostat -En` provides full device details. `format` is never called (hangs without a tty in background/SSH). CD-ROM devices are filtered via `iostat -En` grep. |
| du (directory sizes) | `du -sk /*` hangs scanning `/dev` and `/devices` (massive pseudo-fs trees). Script explicitly lists real directories (`/bin /etc /usr /var` etc.), skipping `/dev`, `/devices`, `/proc`. | Same explicit directory list used for consistency and safety. |
| Storage tools | Only `iostat` (with `-e` flag) is used for disk info. `zpool`/`zfs` are listed as "N/A (ZFS not available on Solaris 9)". | `iostat -En`, `zpool`, and `zfs` are checked; missing ones are reported and install hints given where applicable. |
| Forensics summary | Same as 10/11: bottleneck list, duration, and summary at the end. | Same. |

Solaris 9 is supported in the sense that the script runs and produces a useful report without assuming ZFS or a modern shell. It does not mean running on an unpatched 9 box is a good idea; see [Solaris: CRITICAL - Patch Before You Run](#solaris-critical) above.

What the script does on all Solaris (9, 10, 11):  
The script sets `IS_SOLARIS` from `/etc/release` and `uname` (and does not rely on `/proc` or Linux-only tools). It uses `egrep` everywhere instead of `grep -E` (Solaris `/usr/bin/grep` doesn't support `-E`). It never runs `free` or reads `/proc/cpuinfo` on Solaris; it uses `swap -s`, `vmstat`, `prstat`, and similar native commands. So 10 and 11 are treated the same as 9 for detection and command choice; the only differences are ZFS availability and shell age (see the table above).

What was done for Solaris 9:  
Solaris 9 (SunOS 5.9) ships with very old bash that doesn't support `pipefail`, `=~`, `<<<`, `${!array[@]}`, or array `+=`. Its core utilities (`grep`, `sed`, `tail`) also lack features found on Solaris 10+ and illumos. To get the script running on 9 we:

- Skip `set -o pipefail` on 5.9 (detect via `uname -r`); use `set -o pipefail 2>/dev/null || true` elsewhere so unsupported shells don't exit.
- Avoid Bash-isms: use `case` for regex-style checks instead of `=~`; use here-docs instead of `<<<`; use scalar variables (e.g. `to_install_list`, `missing_tools_list`) and index loops instead of array `+=` and `${!array[@]}`; declare variables at function top where needed to avoid unbound variable under `set -u`.
- `grep -q` / `egrep -qi`: Not supported on Solaris 9. All quiet-match patterns replaced with `>/dev/null 2>&1` (works everywhere).
- `tail -n +2`: Not supported on Solaris 9. Replaced with `awk 'NR>1'` universally.
- `sed` with `[[:space:]]`: Silently breaks on Solaris 9 (consumes the entire input). The critical `UNAME_S` detection now uses `tr -d ' \t\r\n'` instead, which fixed `SOLARIS_9` always being 0 on actual Solaris 9.
- `iostat -En`: Does not exist on Solaris 9. Disk enumeration uses `ls /dev/rdsk/c*s2` with `sed` parsing; disk summaries use `iostat -e`. On Solaris 10+/illumos, `iostat -En` is used instead.
- `format`: Hangs without a controlling tty on ALL Solaris/illumos (not just illumos as originally thought). Removed all `echo | format` calls on every platform; replaced with `iostat -En` (10+/illumos) or `/dev/rdsk` enumeration (9).
- `du -sk /*`: Hangs on Solaris scanning `/dev` and `/devices` (massive device pseudo-filesystems). Replaced with an explicit directory list skipping pseudo-fs mounts.
- ZFS: Don't require or recommend zpool/zfs on 9 (they're not in OpenCSW); report them as "N/A (ZFS not available on Solaris 9)" and guard any `zfs list` usage so we never call it when `zfs` isn't present.
- `date +%s`: Not supported on 9; script validates the output and uses 0 for start/end time when invalid, so `duration=$((end_time - start_time))` never sees a literal `%s` and doesn't trigger an arithmetic error.

What was done for Solaris 10 (also benefits 11 and illumos):
- `zpool` commands with `set -eu` + `pipefail`: Commands like `zpool iostat -v`, `zpool status`, and `zpool list` exit non-zero when no pools are configured. With `set -e` enabled, this killed the script silently. All `zpool` output commands now have `|| true` guards.

With these changes the script runs end-to-end on Solaris 9, 10, 11, OpenIndiana, and OmniOS and produces a full forensics summary on all five.

Getting Solaris 10 and 11 running:  
Validation on 10 and 11 (x86) was done on patched systems with a current-ish userland. Recommended before running the script:

1. Patch the OS and key userland (OpenSSL, curl, wget, git) as in "Patch Before You Run" above.
2. Use bash from the package manager so you get a version that supports `pipefail` and normal Bash-isms. On Solaris 11: `pkg install shell/bash`. On 10, install bash from OpenCSW or equivalent if the stock shell is too old.
3. Optional but useful: Install `system/sar` (Solaris 11: `pkg install system/sar`) so the script can collect SAR-based CPU, memory, and disk analysis. Without it, the script still runs and uses vmstat, iostat, swap, prstat, etc.
4. ZFS: On 10/11, if ZFS is present the script will report pool status, ashift, and capacity. No extra steps needed beyond a normal Solaris install.

If the script fails on 10/11, check: (a) running with a proper bash (e.g. `bash ./invoke-unix-forensics.sh` or ensure `#!/bin/bash` resolves to pkg-installed bash), (b) missing utilities (see Troubleshooting --> Missing Utilities), and (c) that the system is patched so that any optional tools (e.g. curl for AWS) work.

What was done for illumos (OpenIndiana, OmniOS, SmartOS):  
illumos derivatives share the Solaris 10+ codebase but have their own quirks that were discovered during validation on OpenIndiana and OmniOS (r151056). The fixes applied benefit all illumos distributions:

- `echo | format` hangs without a tty: Same as all Solaris. The `format` command is interactive and blocks when there's no controlling terminal (common in SSH remote commands and background processes). Replaced with `iostat -En` for disk enumeration on illumos/Solaris 10+.
- `sort -rh` (human-readable sort): illumos `sort` does not support the `-h` flag. Replaced `du -sh | sort -rh` with `du -sk | sort -rn`.
- `netstat` flags: Linux-style `netstat -ant` and `-tuln` are not supported. Replaced with `netstat -an -f inet -P tcp` and `netstat -an -f inet`. Port matching also changed from colon-separated (`:22`) to dot-separated (`[.]22[[:space:]]`) to match illumos output format.
- `grep -c ... || echo "0"` pattern: When `grep -c` finds 0 matches it outputs "0" but exits with code 1, causing `|| echo "0"` to fire and produce "0\n0", breaking bash arithmetic. Replaced all instances with `|| true`.
- `((count++))` arithmetic: In bash, `((0))` returns exit code 1, so `((var++))` when var=0 can cause script termination under `set -e`. Replaced with `var=$((var + 1))`.
- CD-ROM device filtering: Disk scanning loops were including CD-ROMs, leading to `prtvtoc` errors. Added `iostat -En` checks to skip CD-ROM devices on illumos/Solaris 10+.

These fixes are transparent -- the script detects the OS at startup and uses the appropriate code path. No user configuration is needed.

</details>

---

<a id="aix"></a>
## AIX

Workin' on it.

---

<a id="hp-ux"></a>
## HP-UX

Workin' on it.

---

<a id="installation"></a>
### Installation

1. Clone the repository:
```bash
git clone https://github.com/arsanmiguel/unix-forensics.git
cd unix-forensics
```

2. Make executable:
```bash
chmod +x invoke-unix-forensics.sh
```

3. Run diagnostics (as root or a user with system administrator privileges):
```bash
./invoke-unix-forensics.sh
```

---

<a id="available-tool"></a>
The script runs system diagnostics and writes a report to a timestamped file; optional AWS Support case creation when issues are found. Usage: Run as root or with system administrator privileges: `./invoke-unix-forensics.sh [-m mode] [-s] [-v severity] [-o dir]`.

---

<a id="examples"></a>
## Examples

Run all script commands as root or with system administrator privileges.

<details>
<summary><strong>Example 1: Quick Health Check</strong></summary>

```bash
./invoke-unix-forensics.sh -m quick
```
Output: 3-minute assessment with automatic bottleneck detection

</details>

<details>
<summary><strong>Example 2: Production Issue with Auto-Ticket</strong></summary>

```bash
./invoke-unix-forensics.sh -m deep -s -v urgent
```
Output: Comprehensive diagnostics + AWS Support case with all data attached

</details>

<details>
<summary><strong>Example 3: Disk Performance Testing</strong></summary>

```bash
./invoke-unix-forensics.sh -m disk
```
Output: Detailed disk I/O testing and analysis

</details>

### Use Cases

<a id="use-cases"></a>
<details>
<summary><strong>Use Cases</strong> (DMS, DB perf, web server, EC2, incident response)</summary>

<details>
<summary><strong>AWS DMS Migrations</strong></summary>

This tool is designed to run on your SOURCE DATABASE SERVER, not on the DMS replication instance (which is AWS-managed).

What it checks for DMS by database type:

<details>
<summary><strong>MySQL/MariaDB</strong></summary>

- Binary logging enabled (log_bin=ON, required for CDC)
- Binlog format set to ROW (required for DMS)
- Binary log retention configured (expire_logs_days >= 1)
- Replication lag (if source is a replica)

</details>

<details>
<summary><strong>PostgreSQL</strong></summary>

- WAL level set to 'logical' (required for CDC)
- Replication slots configured (max_replication_slots >= 1)
- Replication lag (if standby server)

</details>

<details>
<summary><strong>Oracle</strong></summary>

- ARCHIVELOG mode enabled (required for CDC)
- Supplemental logging enabled (required for DMS)
- Data Guard apply lag (if standby)

</details>

<details>
<summary><strong>SQL Server</strong></summary>

- SQL Server Agent running (required for CDC)
- Database recovery model set to FULL (required for CDC)
- AlwaysOn replica lag (if applicable)

</details>

<details>
<summary><strong>All Databases</strong></summary>

- CloudWatch Logs Agent running
- Database connection health
- Network connectivity to database ports
- Connection churn that could impact DMS
- Source database performance issues
- Long-running queries/sessions
- High connection counts

</details>

Run this when:
- Planning a DMS migration (pre-migration assessment)
- DMS replication is slow or stalling
- Source database performance issues
- High replication lag
- Connection errors in DMS logs
- CDC not capturing changes

Usage:
```bash
./invoke-unix-forensics.sh -m deep -s -v high
```

</details>

<details>
<summary><strong>Database Server Performance Issues</strong></summary>

Diagnose MySQL, PostgreSQL, or other database performance problems:
```bash
./invoke-unix-forensics.sh -m deep -s
```

</details>

<details>
<summary><strong>Web Server Troubleshooting</strong></summary>

Identify bottlenecks affecting web application performance:
```bash
./invoke-unix-forensics.sh -m standard
```

</details>

<details>
<summary><strong>EC2 Instance Right-Sizing</strong></summary>

Gather baseline performance data for capacity planning:
```bash
./invoke-unix-forensics.sh -m quick
```

</details>

<details>
<summary><strong>Production Incident Response</strong></summary>

When things go wrong:
```bash
./invoke-unix-forensics.sh -m deep -s -v urgent
```

</details>

</details>

### What Bottlenecks Can Be Found

<a id="what-bottlenecks-can-be-found"></a>
<details>
<summary><strong>What Bottlenecks Can Be Found?</strong> (What the script can detect)</summary>

The tool automatically detects:

<details>
<summary><strong>CPU Issues</strong></summary>

- High load average (>1.0 per core)
- High CPU utilization (>80%)
- Excessive context switches (>15,000/sec)
- High CPU steal time (>10% - indicates hypervisor/VM contention)

</details>

<details>
<summary><strong>Memory Issues</strong></summary>

- Low available memory (<10%)
- High swap usage (>50%)
- High page fault rate (>1,000/sec)
- OOM (Out of Memory) killer invocations
- Memory leak candidates (high virtual, low resident memory)

</details>

<details>
<summary><strong>Disk Issues</strong></summary>

- Filesystem nearly full (>90%)
- High I/O wait time (>20ms average)
- Poor read/write performance

</details>

<details>
<summary><strong>Database Issues</strong></summary>

- High connection count (MySQL/PostgreSQL/Oracle/SQL Server: >500, MongoDB/Cassandra: >1000, Redis: >10,000)
- Slow queries detected (MySQL: >100 slow query log entries)
- High connection churn (>1,000 TIME_WAIT connections on database ports)
- Excessive resource usage by database processes
- Top 5 queries by CPU/time, long-running queries (>30s), blocking detection
- SQL Server/MySQL/PostgreSQL: DMV/performance schema queries, active sessions, wait states
- MongoDB: currentOp() and profiler analysis for slow operations
- Redis: SLOWLOG, ops/sec metrics, connection rejection tracking
- Oracle: v$session and v$sql analysis, blocking session detection
- Elasticsearch: Tasks API for long-running searches, thread pool monitoring

Supported Databases:
- MySQL / MariaDB
- PostgreSQL
- MongoDB
- Cassandra
- Redis
- Oracle Database
- Microsoft SQL Server (where applicable)
- Elasticsearch

</details>

<details>
<summary><strong>Network Issues</strong></summary>

- Excessive TIME_WAIT connections (>5,000)
- Excessive CLOSE_WAIT connections (>1,000)
- High TCP retransmissions (>100)
- High RX/TX errors (>100)
- Network packet drops

</details>

</details>

---

<a id="troubleshooting"></a>
## Troubleshooting

<details>
<summary><strong>Missing Utilities</strong></summary>

The script automatically handles missing utilities on supported Unix variants (e.g. Solaris 11 IPS).

If automatic installation fails, install manually:

Solaris 11:
```bash
pkg install system/sar   # for sar; vmstat, iostat, swap, prstat are usually in base (run as root)
```

Solaris 10 / 9 (OpenCSW if available):
- Use `pkgutil` or OpenCSW packages for sysstat/bc where applicable. ZFS/zpool are not available on Solaris 9.

AIX:
- Install from AIX Toolbox: https://www.ibm.com/support/pages/aix-toolbox-linux-applications
- Or use: `rpm -ivh <package>.rpm`

HP-UX:
- Install from HP-UX Software Depot
- Use: `swinstall -s /path/to/depot <package>`

Note: The script will continue with limited functionality if some tools are unavailable, using fallback methods where possible.

</details>

<details>
<summary><strong>Bash Not Available</strong></summary>

If you see "bash not found" error:

Solaris 11:
```bash
pkg install shell/bash
```

Solaris 10 / 9 (OpenCSW):
- Install bash from OpenCSW if available.

AIX:
- Install bash.rte from AIX Toolbox

HP-UX:
- Install bash from HP-UX Software Depot

</details>

<details>
<summary><strong>Permission Denied</strong></summary>

The script requires root privileges:
```bash
./invoke-unix-forensics.sh
```

Or run as root:
```bash
su -
./invoke-unix-forensics.sh
```

</details>

<details>
<summary><strong>AWS Support Case Creation Fails</strong></summary>

- Verify AWS CLI: `aws --version`
- Check credentials: `aws sts get-caller-identity`
- Ensure Support plan is active (Business or Enterprise)
- Verify IAM permissions for support:CreateCase

</details>

<details>
<summary><strong>Package Installation Fails</strong></summary>

The script provides detailed diagnostics when package installation fails, including:
- Repository configuration status
- Disk space availability
- Manual installation commands

Check the output for specific guidance based on your system.

</details>

---

<a id="configuration"></a>
## Configuration

### AWS Support Integration

The tool can automatically create AWS Support cases when performance issues are detected.

<details>
<summary><strong>Setup Instructions</strong></summary>

Setup:
1. Install AWS CLI:
```bash
# Solaris 11 (IPS) - run as root
pkg install aws-cli

# Or use pip (if available on your Unix)
pip3 install awscli
```
On AIX, HP-UX, or older Solaris you may need to install AWS CLI from source or a port; ensure OpenSSL and Python are patched first.

2. Configure AWS credentials:
```bash
aws configure
```

3. Verify Support API access:
```bash
aws support describe-services
```

Required IAM Permissions:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "support:CreateCase",
        "support:AddAttachmentsToSet",
        "support:AddCommunicationToCase"
      ],
      "Resource": "*"
    }
  ]
}
```

</details>

---

<a id="support"></a>
## Support

### Contact
- Report bugs and feature requests: [adrianr.sanmiguel@gmail.com](mailto:adrianr.sanmiguel@gmail.com)

### AWS Support
For AWS-specific issues, the tool can automatically create support cases with diagnostic data attached.

---

<a id="important-notes-and-performance"></a>
<details>
<summary><strong>Important Notes & Performance</strong></summary>

Important Notes
- This tool requires root or system administrator privileges
- Testing Status: Solaris 9-11 x86 tested; illumos tested on OpenIndiana and OmniOS (r151056). SPARC should work (not yet validated). AIX/HP-UX syntactically validated only.
- Script uses graceful degradation - continues with available tools if some are missing
- Uses only native Unix commands (vmstat, iostat, sar, etc.)
- Works on-premises and in cloud environments
- No warranty or official support provided - use at your own discretion
- Community testing welcome - contact adrianr.sanmiguel@gmail.com if you can help test on legacy Unix systems

Expected Performance Impact

Quick Mode (3 minutes):
- CPU: <5% overhead - mostly reading system stats (and /proc where available, e.g. Linux)
- Memory: <50MB - lightweight data collection
- Disk I/O: Minimal - no performance testing, only stat collection
- Network: None - passive monitoring only
- Safe for production - read-only operations

Standard Mode (5-10 minutes):
- CPU: 5-10% overhead - includes sampling and process analysis
- Memory: <100MB - additional process tree analysis
- Disk I/O: Minimal - no write testing, only extended stat collection
- Network: None - passive monitoring only
- Safe for production - read-only operations

Deep Mode (15-20 minutes):
- CPU: 10-20% overhead - includes dd tests and extended sampling
- Memory: <150MB - comprehensive process and memory analysis
- Disk I/O: Moderate impact - performs dd read/write tests (1GB writes)
- Network: None - passive monitoring only
- Use caution in production - disk tests may cause temporary I/O spikes
- Recommendation: Run during maintenance windows or low-traffic periods

Database Query Analysis (all modes):
- CPU: <2% overhead per database - lightweight queries to system tables
- Memory: <20MB per database - result set caching
- Database Load: Minimal - uses performance schema/DMVs/system views
- Safe for production - read-only queries, no table locks

General Guidelines:
- The tool is read-only except for disk write tests in deep mode
- No application restarts or configuration changes
- Monitoring tools (mpstat, iostat, vmstat) run for 10-second intervals
- Database queries target system/performance tables only, not user data
- All operations are non-blocking and use minimal system resources

</details>


---

<a id="version-history"></a>
<details>
<summary><strong>Version History</strong></summary>

- v1.2 (February 2026)
  - OS-aware portability: Script now detects Solaris 9 vs 10+/illumos at runtime and branches disk enumeration, grep flags, tail syntax, and sed usage per platform.
  - Solaris 9 fixes: `grep -q`/`egrep -qi` replaced with `>/dev/null 2>&1`; `tail -n +2` replaced with `awk 'NR>1'`; `sed` `[[:space:]]` replaced with `tr` for OS detection (was silently breaking `SOLARIS_9` flag); disk enumeration uses `/dev/rdsk` + `iostat -e` instead of `iostat -En`.
  - All Solaris: Removed all `echo | format` calls (hangs without a tty on every Solaris/illumos variant, not just illumos); `du -sk /*` replaced with explicit directory list to avoid hanging on `/dev`/`/devices` pseudo-fs.
  - Solaris 10+: `zpool` output commands guarded with `|| true` so `set -eu` + `pipefail` doesn't kill the script when no pools are configured.
  - Validated end-to-end (deep mode) on Solaris 9, 10, 11 (x86), OpenIndiana, and OmniOS (r151056). All five produce a complete forensics summary.
  - README: Updated compatibility table with grep, tail, sed, disk enumeration, du differences; expanded "What was done" sections.

- v1.1 (February 2026)
  - Solaris (all versions): `IS_SOLARIS` and file-based detection; `egrep` everywhere (no `grep -E`); no `free`/`/proc` on Solaris; use native commands (swap -s, vmstat, prstat, etc.). README documents how 9, 10, and 11 were validated and how to get each running.
  - Solaris 9 compatibility: Skip `pipefail` on SunOS 5.9; portable shell (case instead of `=~`, here-doc instead of `<<<`, scalar lists instead of array `+=`, index loops for `${!array[@]}`); ZFS/zpool reported as N/A on 9; guard `date +%s` so duration never triggers arithmetic error. README “Solaris troubleshooting” section describes what was done for 9.
  - Solaris 10/11: Validation on x86 with patched systems; README “Getting Solaris 10 and 11 running” covers patch, bash from pkg, optional sar, ZFS usage, and failure checks.
  - README: Solaris patch requirements; 9 vs 10/11 differences table; full “Solaris troubleshooting and how 9, 10, and 11 were validated” (all-Solaris behavior, what was done for 9, how 10/11 were got going); Unix-focused troubleshooting and setup; testing status (x86 tested, SPARC expected); contact email.

- v1.0 (January 2026)
  - Initial release: AIX, HP-UX, Solaris, Illumos.
  - Disk labeling and boot configuration (SMI/VTOC, EFI, LVM).
  - Partition alignment analysis (AIX PP, HP-UX PE, Solaris VTOC/EFI/ZFS ashift).
  - SAR/sysstat analysis (CPU, memory, disk, network).
  - Testing status disclaimer; time estimates and performance impact notes.

</details>

---

Note: This tool is provided as-is for diagnostic purposes. If you successfully use this on AIX, HP-UX, or Solaris, please share feedback!
