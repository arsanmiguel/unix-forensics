# Unix Performance Forensic Tools

## Overview

A comprehensive Bash-based diagnostic tool for Unix servers that automatically detects performance bottlenecks and can create AWS Support cases with detailed forensic data. **Originally created for AWS DMS migrations - run this on your SOURCE DATABASE SERVER.** Now useful for any Unix performance troubleshooting scenario. Supports AIX, HP-UX, Solaris, and Illumos with graceful degradation when tools are unavailable.

**Key Features:**
- ✅ Comprehensive performance forensics (CPU, Memory, Disk, Network, Database)
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

---

## 🚀 **Quick Start**

### **Prerequisites**
- Unix server (see supported OS list below)
- Root or sudo privileges
- Bash or Korn shell
- AWS CLI (optional, for support case creation)

### **Supported Operating Systems**

**Fully Supported:**
- AIX 7.1, 7.2, 7.3
- HP-UX 11i v3
- Solaris 10, 11
- OpenIndiana / Illumos

**Note:** The script uses native Unix commands (vmstat, iostat, sar, etc.) that are typically pre-installed. For database diagnostics, database client tools (mysql, psql, sqlplus, etc.) must be installed separately.

### **Installation**

1. **Clone the repository:**
```bash
git clone https://github.com/arsanmiguel/linux-performance-forensic-tools.git
cd linux-performance-forensic-tools
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
- Identifies available package manager (apt, yum, dnf, zypper)
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

**Disk I/O Forensics:**
- Filesystem usage monitoring
- I/O wait time analysis
- Read/write performance testing (dd-based)
- Dropped I/O detection
- Per-device statistics

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

**Bottleneck Detection:**
- Automatically identifies performance issues
- Categorizes by severity (Critical, High, Medium, Low)
- Provides threshold comparisons
- **Creates AWS Support case** with all diagnostic data

</details>

<details>
<summary><strong>Usage</strong></summary>

```bash
# Quick diagnostics (1-2 minutes)
sudo ./invoke-unix-forensics.sh -m quick

# Standard diagnostics (3-5 minutes) - recommended
sudo ./invoke-unix-forensics.sh -m standard

# Deep diagnostics with I/O testing (5-10 minutes)
sudo ./invoke-unix-forensics.sh -m deep

# Auto-create support case if issues found
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
Output: 1-2 minute assessment with automatic bottleneck detection

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
- Microsoft SQL Server (Linux)
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
# Amazon Linux / RHEL / CentOS
sudo yum install -y aws-cli

# Ubuntu / Debian
sudo apt-get install -y awscli

# Or use pip
pip3 install awscli
```

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

**The script automatically handles missing utilities on supported distributions.**

If automatic installation fails, install manually:

**RHEL / CentOS / Amazon Linux / Rocky / Alma:**
```bash
sudo yum install -y sysstat net-tools bc
# or
sudo dnf install -y sysstat net-tools bc
```

**Ubuntu / Debian:**
```bash
sudo apt-get update
sudo apt-get install -y sysstat net-tools bc
```

**SUSE:**
```bash
sudo zypper install -y sysstat net-tools bc
```

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

**RHEL / CentOS:**
```bash
yum install bash
```

**Ubuntu / Debian:**
```bash
apt-get install bash
```

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
- **Report bugs and feature requests:** [adrianrs@amazon.com](mailto:adrianrs@amazon.com)

### **AWS Support**
For AWS-specific issues, the tool can automatically create support cases with diagnostic data attached.

---

## ⚠️ **Important Notes**

- This tool requires root/sudo privileges
- Disk testing may impact system performance temporarily
- **Automatic package installation** works on Debian/Ubuntu, RHEL/CentOS/Amazon Linux, and SUSE
- **Manual installation required** for AIX and HP-UX (instructions provided by script)
- Script uses **graceful degradation** - continues with available tools if some are missing
- Tested on Ubuntu 18.04+, RHEL 7+, Amazon Linux 2/2023, CentOS 7+, Debian 9+, Rocky Linux 8+, AlmaLinux 8+
- Works on AWS EC2, Azure VMs, GCP Compute, on-premises, and other cloud providers
- Uses only open-source utilities (no proprietary tools required)
- **No warranty or official support provided** - use at your own discretion

---

## 📝 **Version History**

- **v1.0** (January 2026) - Initial release with comprehensive forensics and AWS Support integration

---

**Note:** This tool is provided as-is for diagnostic purposes. Always test in non-production environments first.
