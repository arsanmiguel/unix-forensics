# Unix Performance Forensic Tools

## Overview

A comprehensive Bash-based diagnostic tool for Unix servers that automatically detects performance bottlenecks and can create AWS Support cases with detailed forensic data. **Originally created for AWS DMS migrations - run this on your SOURCE DATABASE SERVER.** Now useful for any Unix performance troubleshooting scenario. Supports AIX, HP-UX, Solaris, and Illumos with graceful degradation when tools are unavailable.

**Key Features:**
- ✅ Comprehensive performance forensics (CPU, Memory, Disk, Network, Database)
- ✅ **Storage profiling** (disk labeling, partition schemes, boot configuration)
- ✅ **AWS DMS SOURCE DATABASE diagnostics** (binary logging, replication lag, connection analysis)
- ✅ Automated bottleneck detection
- ✅ **Multi-Unix support** (AIX, HP-UX, Solaris, Illumos)
- ✅ Graceful degradation when tools unavailable
- ✅ CPU forensics (load average, vmstat, sar, mpstat, prstat)
- ✅ Memory forensics (svmon, swapinfo, swap analysis, paging space)
- ✅ Disk I/O testing (iostat, ZFS pools, LVM, volume groups)
- ✅ **Database forensics** - DBA-level query analysis + DMS readiness checks
- ✅ Network analysis (connection states, database connectivity)
- ✅ **Automatic AWS Support case creation** with diagnostic data
- ✅ Works on-premises and in cloud environments

> **Note on Enhanced Profiling Tools:** Unlike the Linux and macOS versions of this utility, the Unix version does not include htop, btop, or glances support. These modern interactive profilers are typically not available in standard AIX, HP-UX, or Solaris package repositories, and their compilation requirements make them impractical for enterprise Unix environments. The Unix utility relies on native tools (vmstat, iostat, sar, prstat, svmon, etc.) which are well-suited for these platforms.

---

## 🚀 **Quick Start**

### **Prerequisites**
- Unix server (see supported OS list below)
- Root or sudo privileges
- Bash or Korn shell
- AWS CLI (optional, for support case creation)

### **Supported Operating Systems**

**Designed For:**
- AIX 7.1, 7.2, 7.3
- HP-UX 11i v3
- Solaris 9, 10, 11 (see Solaris notes below)
- OpenIndiana / Illumos

**Testing Status:**
⚠️ **Solaris:** Tested on Solaris 9, 10, and 11 (x86). Should work on SPARC; not yet validated on that architecture. **AIX / HP-UX:** Syntactically validated but not tested on actual hardware due to limited access; the script uses standard Unix commands and graceful degradation for missing tools.

**If you have access to these systems and would like to help test, please contact:** adrianr.sanmiguel@gmail.com

**Note:** The script uses native Unix commands that are typically pre-installed. For database diagnostics, database client tools (mysql, psql, sqlplus, etc.) must be installed separately.

---

<details>
<summary><strong>Solaris: CRITICAL – Patch Before You Run</strong></summary>

**Do not run this tool on a Solaris box until the system is patched as current as you can get it.**

Solaris (especially 9 and 10) ships with ancient, often vulnerable versions of OpenSSL, curl, wget, and git. Out-of-date builds can break TLS, fail on HTTPS, or expose you to known CVEs. The script and your sanity both assume a minimally modern toolchain.

**Before you even attempt this on Solaris:**

1. **Patch the OS** – Apply the latest recommended patch clusters / updates for your release (SunOS 5.9, 5.10, or 5.11).
2. **OpenSSL** – Ensure OpenSSL (or the platform’s TLS stack) is updated and supports current TLS. Many older Solaris builds are stuck on 0.9.x/1.0.x and are unsafe for anything network-facing.
3. **curl and wget** – Update to versions that support HTTPS and modern TLS. The script and any follow-up (e.g. AWS CLI, support bundles) may need them.
4. **git** – If you clone the repo on the box, use a recent enough git that works with HTTPS and doesn’t choke on modern servers.

If you’re a bench admin still touching this OS: get the box patched and the toolchain updated first. Otherwise you’re one bad TLS handshake or one missing option away from flipping a table. The script tries to be compatible with old Solaris; it does **not** fix an unpatched, 20-year-old userland. Patch first, then run.

> **To the bench admins:** My sweet summer child. I fought the Old Gods so you wouldn't have to. Proceed with **utmost caution**. Here be dragons of the absolute highest order. Not Puff. Think *Reign of Fire*'s Bull Dragon, *Slime*'s Veldora (IYKYK), *Game of Thrones*' Drogon.
>
> Do you have a patch disk? If not, **STOP**. Do you have a week to spend mucking through the wayback machine, even with an AI agent to help you munge through broken mirrors and bad packages? **PLEASE STOP**.
>
> There is no substitute for a patch disk, a known-good internal patch mirror, or a healthier system with these binaries. I have a known-good, QEMU-based Solaris 9 image available here. Trust me: you don't want to have to go through what I did to get somewhere useful.

</details>

---

### **Solaris version differences (what the script does)**

The script detects Solaris by OS/release and adjusts automatically. You don’t have to pick a “mode” for 9 vs 10 vs 11.

| Item | Solaris 9 (SunOS 5.9) | Solaris 10 / 11, Illumos |
|------|------------------------|---------------------------|
| **ZFS** | Not available (introduced in 10). Script reports zpool/zfs as N/A and does not require or recommend installing them (they are not in OpenCSW for 9). | ZFS is checked and used when present (pool status, ashift, capacity, etc.). |
| **Bash / shell** | Very old bash; no `pipefail`, no `=~`, no `<<<`, no `${!array[@]}`, no array `+=`. Script uses portable constructs (e.g. `case`, here-docs, scalar lists, index loops) and skips `set -o pipefail` on 5.9. | Modern enough; script uses full strictness and normal Bash-isms. |
| **date** | `date +%s` (epoch seconds) is not supported; script falls back so duration may show 0 seconds. | Epoch time works; analysis duration is reported normally. |
| **Storage tools** | Only iostat and format are required. zpool/zfs are listed as “N/A (ZFS not available on Solaris 9)”. | iostat, format, zpool, and zfs are checked; missing ones are reported and install hints given where applicable. |
| **Forensics summary** | Same as 10/11: bottleneck list, duration, and summary at the end. | Same. |

Solaris 9 is supported in the sense that the script runs and produces a useful report without assuming ZFS or a modern shell. It does **not** mean running on an unpatched 9 box is a good idea; see the patch requirements above.

---

<details>
<summary><strong>Solaris troubleshooting and how 9, 10, and 11 were validated</strong></summary>

**What the script does on all Solaris (9, 10, 11):**  
The script sets `IS_SOLARIS` from `/etc/release` and `uname` (and does not rely on `/proc` or Linux-only tools). It uses `egrep` everywhere instead of `grep -E` (Solaris `/usr/bin/grep` doesn’t support `-E`). It never runs `free` or reads `/proc/cpuinfo` on Solaris; it uses `swap -s`, `vmstat`, `prstat`, and similar native commands. So 10 and 11 are treated the same as 9 for detection and command choice; the only differences are ZFS availability and shell age (see the table above).

**What was done for Solaris 9:**  
Solaris 9 (SunOS 5.9) ships with very old bash that doesn’t support `pipefail`, `=~`, `<<<`, `${!array[@]}`, or array `+=`. To get the script running on 9 we:

- **Skip `set -o pipefail`** on 5.9 (detect via `uname -r`); use `set -o pipefail 2>/dev/null || true` elsewhere so unsupported shells don’t exit.
- **Avoid Bash-isms:** use `case` for regex-style checks instead of `=~`; use here-docs instead of `<<<`; use scalar variables (e.g. `to_install_list`, `missing_tools_list`) and index loops instead of array `+=` and `${!array[@]}`; declare variables at function top where needed to avoid unbound variable under `set -u`.
- **ZFS:** Don’t require or recommend zpool/zfs on 9 (they’re not in OpenCSW); report them as “N/A (ZFS not available on Solaris 9)” and guard any `zfs list` usage so we never call it when `zfs` isn’t present.
- **`date +%s`:** Not supported on 9; script validates the output and uses 0 for start/end time when invalid, so `duration=$((end_time - start_time))` never sees a literal `%s` and doesn’t trigger an arithmetic error.

With these changes the script runs end-to-end on Solaris 9 and produces a full forensics summary.

**Getting Solaris 10 and 11 running:**  
Validation on 10 and 11 (x86) was done on patched systems with a current-ish userland. Recommended before running the script:

1. **Patch the OS** and key userland (OpenSSL, curl, wget, git) as in “Patch Before You Run” above.
2. **Use bash from the package manager** so you get a version that supports `pipefail` and normal Bash-isms. On Solaris 11: `pkg install shell/bash`. On 10, install bash from OpenCSW or equivalent if the stock shell is too old.
3. **Optional but useful:** Install `system/sar` (Solaris 11: `pkg install system/sar`) so the script can collect SAR-based CPU, memory, and disk analysis. Without it, the script still runs and uses vmstat, iostat, swap, prstat, etc.
4. **ZFS:** On 10/11, if ZFS is present the script will report pool status, ashift, and capacity. No extra steps needed beyond a normal Solaris install.

If the script fails on 10/11, check: (a) running with a proper bash (e.g. `bash ./invoke-unix-forensics.sh` or ensure `#!/bin/bash` resolves to pkg-installed bash), (b) missing utilities (see **Troubleshooting → Missing Utilities** below), and (c) that the system is patched so that any optional tools (e.g. curl for AWS) work.

</details>

---

### **Installation**

1. **Clone the repository:**
```bash
git clone https://github.com/arsanmiguel/unix-forensics.git
cd unix-forensics
```

2. **Make executable:**
```bash
chmod +x invoke-unix-forensics.sh
```

3. **Run diagnostics:**
```bash
sudo ./invoke-unix-forensics.sh
```

---

## 📊 **Available Tool**

### **invoke-unix-forensics.sh**
**A complete Unix performance diagnostic tool** - comprehensive forensics with automatic issue detection.

<details>
<summary><strong>What it does</strong></summary>

**System Detection & Setup:**
- Automatically detects OS distribution and version
- Identifies available package manager (pkg/IPS on Solaris, rpm on AIX, swinstall on HP-UX)
- Checks for required utilities (mpstat, iostat, vmstat, netstat, bc)
- **Automatically installs missing packages** on supported distros
- Provides manual installation instructions for AIX/HP-UX
- Continues with graceful degradation if tools unavailable

**CPU Forensics:**
- Load average analysis (per-core calculation)
- CPU utilization sampling (10-second average)
- Context switch rate monitoring
- CPU steal time detection (hypervisor contention)
- Top CPU-consuming processes
- **SAR CPU analysis:** Real-time sampling (sar -u, sar -q)
- **Historical CPU data:** Automatic detection of /var/adm/sa data

**Memory Forensics:**
- Memory usage and availability analysis
- Swap usage monitoring
- Page fault rate detection
- Memory pressure indicators (PSI)
- Slab memory usage analysis
- OOM (Out of Memory) killer detection
- Memory leak candidate identification
- Huge pages status
- Top memory-consuming processes
- **SAR memory analysis:** Real-time sampling (sar -r, sar -p/sar -g)
- **Historical memory data:** Automatic detection of /var/adm/sa data

**Storage Profiling:**
- Disk labeling/partition scheme detection:
  - **AIX**: LVM-only architecture (no MBR/GPT concept)
  - **HP-UX**: LVM, EFI (Itanium) vs PDC (PA-RISC) boot detection
  - **Solaris/Illumos**: SMI (VTOC) vs EFI (GPT) with >2TB warnings
- **Partition alignment analysis:**
  - **AIX**: LVM Physical Partition (PP) size analysis (optimal >= 64MB for SAN)
  - **HP-UX**: LVM Physical Extent (PE) size and first PE offset alignment
  - **Solaris**: VTOC slice alignment, EFI partition alignment, ZFS ashift analysis
- Boot configuration (UEFI vs BIOS/OBP)
- Filesystem type analysis (ZFS, UFS, JFS, VxFS)
- Storage topology (LVM, VxVM, SVM, ZFS)

**Disk I/O Forensics:**
- Filesystem usage monitoring
- I/O wait time analysis
- Read/write performance testing (dd-based)
- Dropped I/O detection
- Per-device statistics
- **SAR disk analysis:** Real-time sampling (sar -d, sar -b)
- **Historical disk data:** Automatic detection of /var/adm/sa data

**Database Forensics:**
- Automatic detection of running databases
- Supported: MySQL/MariaDB, PostgreSQL, MongoDB, Cassandra, Redis, Oracle, SQL Server, Elasticsearch
- **DBA-level query analysis:**
  - Top 5 queries by CPU time and resource consumption (all platforms)
  - Long-running queries/operations (>30 seconds)
  - Blocking and wait state analysis (SQL Server, Oracle)
  - Connection pool exhaustion and rejection tracking (all platforms)
  - Thread pool monitoring (Elasticsearch)
  - Slow operation profiling (MongoDB, Redis)
- Connection count monitoring
- Process resource usage (CPU, memory)
- Connection churn analysis (TIME_WAIT)

**Network Forensics:**
- Interface status and statistics
- TCP connection state analysis
- Retransmission detection
- RX/TX error monitoring
- Dropped packet analysis
- Socket memory usage
- Network throughput analysis
- Buffer/queue settings
- **SAR network analysis:** Real-time sampling (sar -n DEV, sar -n EDEV, sar -n TCP)
- **Historical network data:** Automatic detection of /var/adm/sa data

**Bottleneck Detection:**
- Automatically identifies performance issues
- Categorizes by severity (Critical, High, Medium, Low)
- Provides threshold comparisons
- **Creates AWS Support case** with all diagnostic data

**Storage Issues Detected:**
- **Misaligned partitions/extents** (LVM PP/PE size, slice alignment, ZFS ashift)
- **SMI (VTOC) label on >2TB disk** (Solaris - only 2TB usable)
- ZFS pool degraded or faulted
- SMART drive failures (where smartctl available)
- AIX Volume Group quorum issues
- Suboptimal LVM extent sizes for SAN environments

</details>

<details>
<summary><strong>Usage</strong></summary>

```bash
# Quick diagnostics (3 minutes)
sudo ./invoke-unix-forensics.sh -m quick

# Standard diagnostics (5-10 minutes) - recommended
sudo ./invoke-unix-forensics.sh -m standard

# Deep diagnostics with I/O testing (15-20 minutes)
sudo ./invoke-unix-forensics.sh -m deep

# Auto-create support case if issues found (3 minutes)
sudo ./invoke-unix-forensics.sh -m standard -s -v high

# Disk-only diagnostics
sudo ./invoke-unix-forensics.sh -m disk

# CPU-only diagnostics
sudo ./invoke-unix-forensics.sh -m cpu

# Memory-only diagnostics
sudo ./invoke-unix-forensics.sh -m memory

# Custom output directory
sudo ./invoke-unix-forensics.sh -m standard -o /var/log
```

**Options:**
- `-m, --mode` - Diagnostic mode: quick, standard, deep, disk, cpu, memory
- `-s, --support` - Create AWS Support case if issues found
- `-v, --severity` - Support case severity: low, normal, high, urgent, critical
- `-o, --output` - Output directory (default: current directory)
- `-h, --help` - Show help message

</details>

<details>
<summary><strong>Output Example</strong></summary>

```
BOTTLENECKS DETECTED: 3 performance issue(s) found

  CRITICAL ISSUES (1):
    • Memory: Low available memory

  HIGH PRIORITY (2):
    • Disk: High I/O wait time
    • CPU: High load average

Detailed report saved to: unix-forensics-20260114-070000.txt
AWS Support case created: case-123456789
```

</details>

---

## 📖 **Examples**

<details>
<summary><strong>Example 1: Quick Health Check</strong></summary>

```bash
sudo ./invoke-unix-forensics.sh -m quick
```
Output: 3-minute assessment with automatic bottleneck detection

</details>

<details>
<summary><strong>Example 2: Production Issue with Auto-Ticket</strong></summary>

```bash
sudo ./invoke-unix-forensics.sh -m deep -s -v urgent
```
Output: Comprehensive diagnostics + AWS Support case with all data attached

</details>

<details>
<summary><strong>Example 3: Disk Performance Testing</strong></summary>

```bash
sudo ./invoke-unix-forensics.sh -m disk
```
Output: Detailed disk I/O testing and analysis

</details>

---

## 🎯 **Use Cases**

<details>
<summary><strong>AWS DMS Migrations</strong></summary>

**This tool is designed to run on your SOURCE DATABASE SERVER**, not on the DMS replication instance (which is AWS-managed).

**What it checks for DMS by database type:**

<details>
<summary><strong>MySQL/MariaDB</strong></summary>

- ✅ Binary logging enabled (log_bin=ON, required for CDC)
- ✅ Binlog format set to ROW (required for DMS)
- ✅ Binary log retention configured (expire_logs_days >= 1)
- ✅ Replication lag (if source is a replica)

</details>

<details>
<summary><strong>PostgreSQL</strong></summary>

- ✅ WAL level set to 'logical' (required for CDC)
- ✅ Replication slots configured (max_replication_slots >= 1)
- ✅ Replication lag (if standby server)

</details>

<details>
<summary><strong>Oracle</strong></summary>

- ✅ ARCHIVELOG mode enabled (required for CDC)
- ✅ Supplemental logging enabled (required for DMS)
- ✅ Data Guard apply lag (if standby)

</details>

<details>
<summary><strong>SQL Server</strong></summary>

- ✅ SQL Server Agent running (required for CDC)
- ✅ Database recovery model set to FULL (required for CDC)
- ✅ AlwaysOn replica lag (if applicable)

</details>

<details>
<summary><strong>All Databases</strong></summary>

- ✅ CloudWatch Logs Agent running
- ✅ Database connection health
- ✅ Network connectivity to database ports
- ✅ Connection churn that could impact DMS
- ✅ Source database performance issues
- ✅ Long-running queries/sessions
- ✅ High connection counts

</details>

**Run this when:**
- Planning a DMS migration (pre-migration assessment)
- DMS replication is slow or stalling
- Source database performance issues
- High replication lag
- Connection errors in DMS logs
- CDC not capturing changes

**Usage:**
```bash
sudo ./invoke-unix-forensics.sh -m deep -s -v high
```

</details>

<details>
<summary><strong>Database Server Performance Issues</strong></summary>

Diagnose MySQL, PostgreSQL, or other database performance problems:
```bash
sudo ./invoke-unix-forensics.sh -m deep -s
```

</details>

<details>
<summary><strong>Web Server Troubleshooting</strong></summary>

Identify bottlenecks affecting web application performance:
```bash
sudo ./invoke-unix-forensics.sh -m standard
```

</details>

<details>
<summary><strong>EC2 Instance Right-Sizing</strong></summary>

Gather baseline performance data for capacity planning:
```bash
sudo ./invoke-unix-forensics.sh -m quick
```

</details>

<details>
<summary><strong>Production Incident Response</strong></summary>

When things go wrong:
```bash
sudo ./invoke-unix-forensics.sh -m deep -s -v urgent
```

</details>

---

## **What Bottlenecks Can Be Found?**

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
- **SQL Server/MySQL/PostgreSQL**: DMV/performance schema queries, active sessions, wait states
- **MongoDB**: currentOp() and profiler analysis for slow operations
- **Redis**: SLOWLOG, ops/sec metrics, connection rejection tracking
- **Oracle**: v$session and v$sql analysis, blocking session detection
- **Elasticsearch**: Tasks API for long-running searches, thread pool monitoring

**Supported Databases:**
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

---

## 🔧 **Configuration**

### **AWS Support Integration**

The tool can automatically create AWS Support cases when performance issues are detected.

<details>
<summary><strong>Setup Instructions</strong></summary>

**Setup:**
1. **Install AWS CLI:**
```bash
# Solaris 11 (IPS)
sudo pkg install aws-cli

# Or use pip (if available on your Unix)
pip3 install awscli
```
On AIX, HP-UX, or older Solaris you may need to install AWS CLI from source or a port; ensure OpenSSL and Python are patched first.

2. **Configure AWS credentials:**
```bash
aws configure
```

3. **Verify Support API access:**
```bash
aws support describe-services
```

**Required IAM Permissions:**
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

## 🛠️ **Troubleshooting**

<details>
<summary><strong>Missing Utilities</strong></summary>

**The script automatically handles missing utilities on supported Unix variants (e.g. Solaris 11 IPS).**

If automatic installation fails, install manually:

**Solaris 11:**
```bash
sudo pkg install system/sar   # for sar; vmstat, iostat, swap, prstat are usually in base
```

**Solaris 10 / 9 (OpenCSW if available):**
- Use `pkgutil` or OpenCSW packages for sysstat/bc where applicable. ZFS/zpool are not available on Solaris 9.

**AIX:**
- Install from AIX Toolbox: https://www.ibm.com/support/pages/aix-toolbox-linux-applications
- Or use: `rpm -ivh <package>.rpm`

**HP-UX:**
- Install from HP-UX Software Depot
- Use: `swinstall -s /path/to/depot <package>`

**Note:** The script will continue with limited functionality if some tools are unavailable, using fallback methods where possible.

</details>

<details>
<summary><strong>Bash Not Available</strong></summary>

If you see "bash not found" error:

**Solaris 11:**
```bash
pkg install shell/bash
```

**Solaris 10 / 9 (OpenCSW):**
- Install bash from OpenCSW if available.

**AIX:**
- Install bash.rte from AIX Toolbox

**HP-UX:**
- Install bash from HP-UX Software Depot

</details>

<details>
<summary><strong>Permission Denied</strong></summary>

The script requires root privileges:
```bash
sudo ./invoke-unix-forensics.sh
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

## 📦 **What's Included**

- `invoke-unix-forensics.sh` - Comprehensive forensics tool with bottleneck detection
- `README.md` - This documentation

---

## 🤝 **Support**

### **Contact**
- **Report bugs and feature requests:** [adrianr.sanmiguel@gmail.com](mailto:adrianr.sanmiguel@gmail.com)

### **AWS Support**
For AWS-specific issues, the tool can automatically create support cases with diagnostic data attached.

---

<details>
<summary><strong>Important Notes & Performance</strong></summary>

**Important Notes**
- This tool requires root/sudo privileges
- **Testing Status:** Solaris 9–11 x86 tested; SPARC should work (not yet validated). AIX/HP-UX syntactically validated only.
- Script uses **graceful degradation** - continues with available tools if some are missing
- Uses only native Unix commands (vmstat, iostat, sar, etc.)
- Works on-premises and in cloud environments
- **No warranty or official support provided** - use at your own discretion
- **Community testing welcome** - contact adrianr.sanmiguel@gmail.com if you can help test on legacy Unix systems

**Expected Performance Impact**

**Quick Mode (3 minutes):**
- CPU: <5% overhead - mostly reading system stats (and /proc where available, e.g. Linux)
- Memory: <50MB - lightweight data collection
- Disk I/O: Minimal - no performance testing, only stat collection
- Network: None - passive monitoring only
- **Safe for production** - read-only operations

**Standard Mode (5-10 minutes):**
- CPU: 5-10% overhead - includes sampling and process analysis
- Memory: <100MB - additional process tree analysis
- Disk I/O: Minimal - no write testing, only extended stat collection
- Network: None - passive monitoring only
- **Safe for production** - read-only operations

**Deep Mode (15-20 minutes):**
- CPU: 10-20% overhead - includes dd tests and extended sampling
- Memory: <150MB - comprehensive process and memory analysis
- Disk I/O: **Moderate impact** - performs dd read/write tests (1GB writes)
- Network: None - passive monitoring only
- **Use caution in production** - disk tests may cause temporary I/O spikes
- Recommendation: Run during maintenance windows or low-traffic periods

**Database Query Analysis (all modes):**
- CPU: <2% overhead per database - lightweight queries to system tables
- Memory: <20MB per database - result set caching
- Database Load: Minimal - uses performance schema/DMVs/system views
- **Safe for production** - read-only queries, no table locks

**General Guidelines:**
- The tool is **read-only** except for disk write tests in deep mode
- No application restarts or configuration changes
- Monitoring tools (mpstat, iostat, vmstat) run for 10-second intervals
- Database queries target system/performance tables only, not user data
- All operations are non-blocking and use minimal system resources

</details>

---

## 📝 **Version History**

- **v1.1** (February 2026)
  - **Solaris (all versions):** `IS_SOLARIS` and file-based detection; `egrep` everywhere (no `grep -E`); no `free`/`/proc` on Solaris; use native commands (swap -s, vmstat, prstat, etc.). README documents how 9, 10, and 11 were validated and how to get each running.
  - **Solaris 9 compatibility:** Skip `pipefail` on SunOS 5.9; portable shell (case instead of `=~`, here-doc instead of `<<<`, scalar lists instead of array `+=`, index loops for `${!array[@]}`); ZFS/zpool reported as N/A on 9; guard `date +%s` so duration never triggers arithmetic error. README “Solaris troubleshooting” section describes what was done for 9.
  - **Solaris 10/11:** Validation on x86 with patched systems; README “Getting Solaris 10 and 11 running” covers patch, bash from pkg, optional sar, ZFS usage, and failure checks.
  - **README:** Solaris patch requirements; 9 vs 10/11 differences table; full “Solaris troubleshooting and how 9, 10, and 11 were validated” (all-Solaris behavior, what was done for 9, how 10/11 were got going); Unix-focused troubleshooting and setup; testing status (x86 tested, SPARC expected); contact email.

- **v1.0** (January 2026)
  - Initial release: AIX, HP-UX, Solaris, Illumos.
  - Disk labeling and boot configuration (SMI/VTOC, EFI, LVM).
  - Partition alignment analysis (AIX PP, HP-UX PE, Solaris VTOC/EFI/ZFS ashift).
  - SAR/sysstat analysis (CPU, memory, disk, network).
  - Testing status disclaimer; time estimates and performance impact notes.

---

**Note:** This tool is provided as-is for diagnostic purposes. If you successfully use this on AIX, HP-UX, or Solaris, please share feedback!
