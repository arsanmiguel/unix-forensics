#!/bin/bash

#############################################################################
# Unix Performance Forensic Tool
# 
# Comprehensive performance diagnostics with automatic bottleneck detection
# and AWS Support integration
#
# Supports: AIX, HP-UX, Solaris, Illumos
#
# Usage: sudo ./invoke-unix-forensics.sh [OPTIONS]
#
# Options:
#   -m, --mode MODE          Diagnostic mode: quick, standard, deep, disk, cpu, memory
#   -s, --support            Create AWS Support case if issues found
#   -v, --severity LEVEL     Support case severity: low, normal, high, urgent, critical
#   -o, --output PATH        Output directory (default: current directory)
#   -h, --help               Show this help message
#
# Requires: root/sudo privileges
# Optional: AWS CLI for support case creation
#############################################################################

# Check if bash is available, if not try to re-execute with bash
if [ -z "$BASH_VERSION" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    else
        echo "ERROR: This script requires bash, but it's not available."
        echo "Please install bash using your system's package manager:"
        echo "  - Debian/Ubuntu: apt-get install bash"
        echo "  - RHEL/CentOS: yum install bash"
        echo "  - AIX: Install from AIX Toolbox (bash.rte)"
        echo "  - HP-UX: Install from HP-UX Software Depot"
        exit 1
    fi
fi

set -euo pipefail

# Default values
MODE="standard"
CREATE_SUPPORT_CASE=false
SEVERITY="normal"
OUTPUT_DIR="$(pwd)"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="${OUTPUT_DIR}/unix-forensics-${TIMESTAMP}.txt"
BOTTLENECKS=()
DISTRO=""
PACKAGE_MANAGER=""
MISSING_PACKAGES=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

#############################################################################
# System Detection
#############################################################################

detect_os() {
    local uname_s=$(uname -s)
    local uname_v=$(uname -v 2>/dev/null || echo "")
    
    # Detect Unix variants
    if [[ "$uname_s" == "AIX" ]]; then
        DISTRO="aix"
        OS_VERSION=$(oslevel 2>/dev/null || echo "unknown")
    elif [[ "$uname_s" == "HP-UX" ]]; then
        DISTRO="hpux"
        OS_VERSION=$(uname -r)
    elif [[ "$uname_s" == "SunOS" ]]; then
        DISTRO="solaris"
        OS_VERSION=$(uname -r)
        # Distinguish Solaris vs OpenSolaris/Illumos
        if [[ -f /etc/release ]]; then
            if grep -qi "openindiana\|illumos" /etc/release; then
                DISTRO="illumos"
            fi
        fi
    elif [[ -f /etc/os-release ]]; then
        # Linux fallback (shouldn't happen, but just in case)
        . /etc/os-release
        DISTRO="$ID"
        OS_VERSION="$VERSION_ID"
    else
        DISTRO="unknown"
        OS_VERSION="unknown"
    fi
    
    # Determine package manager
    case "$DISTRO" in
        aix)
            # AIX uses installp, rpm, or yum (depending on setup)
            if command -v yum >/dev/null 2>&1; then
                PACKAGE_MANAGER="yum"
            elif command -v rpm >/dev/null 2>&1; then
                PACKAGE_MANAGER="rpm"
            else
                PACKAGE_MANAGER="installp"
            fi
            ;;
        hpux)
            # HP-UX uses swinstall/swlist
            PACKAGE_MANAGER="swinstall"
            ;;
        solaris|illumos)
            # Solaris 11+ uses pkg, older uses pkgadd
            if command -v pkg >/dev/null 2>&1; then
                PACKAGE_MANAGER="pkg"
            else
                PACKAGE_MANAGER="pkgadd"
            fi
            ;;
        *)
            PACKAGE_MANAGER="none"
            ;;
    esac
}

diagnose_package_install_failure() {
    local package="$1"
    
    echo "" | tee -a "$OUTPUT_FILE"
    log_error "Failed to install required package: ${package}"
    echo "" | tee -a "$OUTPUT_FILE"
    echo "DIAGNOSTIC INFORMATION:" | tee -a "$OUTPUT_FILE"
    echo "======================" | tee -a "$OUTPUT_FILE"
    
    # Check repository configuration
    case "$PACKAGE_MANAGER" in
        apt-get)
            echo "Repository configuration:" | tee -a "$OUTPUT_FILE"
            if [[ -f /etc/apt/sources.list ]]; then
                echo "  - /etc/apt/sources.list exists" | tee -a "$OUTPUT_FILE"
                local repo_count=$(grep -v "^#" /etc/apt/sources.list | grep -c "^deb" || echo "0")
                echo "  - Active repositories: ${repo_count}" | tee -a "$OUTPUT_FILE"
            fi
            echo "" | tee -a "$OUTPUT_FILE"
            echo "Try updating package cache:" | tee -a "$OUTPUT_FILE"
            echo "  sudo apt-get update" | tee -a "$OUTPUT_FILE"
            ;;
        yum|dnf)
            echo "Repository configuration:" | tee -a "$OUTPUT_FILE"
            local repo_count=$($PACKAGE_MANAGER repolist 2>/dev/null | grep -c "^[^!]" || echo "0")
            echo "  - Active repositories: ${repo_count}" | tee -a "$OUTPUT_FILE"
            echo "" | tee -a "$OUTPUT_FILE"
            echo "Try:" | tee -a "$OUTPUT_FILE"
            echo "  sudo ${PACKAGE_MANAGER} clean all" | tee -a "$OUTPUT_FILE"
            echo "  sudo ${PACKAGE_MANAGER} makecache" | tee -a "$OUTPUT_FILE"
            ;;
    esac
    
    # Check disk space
    echo "" | tee -a "$OUTPUT_FILE"
    local root_usage=$(df -h / 2>/dev/null | tail -1 | awk '{print $5}' | sed 's/%//')
    echo "Disk space on /: ${root_usage}% used" | tee -a "$OUTPUT_FILE"
    if (( root_usage > 90 )); then
        echo "  ⚠️  WARNING: Low disk space may prevent package installation" | tee -a "$OUTPUT_FILE"
    fi
    
    # Manual installation instructions
    echo "" | tee -a "$OUTPUT_FILE"
    echo "MANUAL INSTALLATION:" | tee -a "$OUTPUT_FILE"
    echo "===================" | tee -a "$OUTPUT_FILE"
    
    case "$DISTRO" in
        ubuntu|debian)
            echo "Try installing manually:" | tee -a "$OUTPUT_FILE"
            echo "  sudo apt-get update" | tee -a "$OUTPUT_FILE"
            echo "  sudo apt-get install -y ${package}" | tee -a "$OUTPUT_FILE"
            ;;
        rhel|centos|fedora|amzn|rocky|alma)
            echo "Try installing manually:" | tee -a "$OUTPUT_FILE"
            echo "  sudo ${PACKAGE_MANAGER} install -y ${package}" | tee -a "$OUTPUT_FILE"
            ;;
        aix)
            echo "Install from AIX Toolbox:" | tee -a "$OUTPUT_FILE"
            echo "  1. Download from: https://www.ibm.com/support/pages/aix-toolbox-linux-applications" | tee -a "$OUTPUT_FILE"
            echo "  2. Or use: rpm -ivh ${package}.rpm" | tee -a "$OUTPUT_FILE"
            ;;
        hpux)
            echo "Install from HP-UX Software Depot:" | tee -a "$OUTPUT_FILE"
            echo "  swinstall -s /path/to/depot ${package}" | tee -a "$OUTPUT_FILE"
            ;;
    esac
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "The script will continue with limited functionality..." | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
}

install_package() {
    local package="$1"
    
    log_info "Installing ${package}..."
    
    case "$PACKAGE_MANAGER" in
        apt-get)
            if apt-get update >/dev/null 2>&1 && apt-get install -y "$package" >/dev/null 2>&1; then
                log_success "${package} installed successfully"
                return 0
            fi
            ;;
        yum|dnf)
            if $PACKAGE_MANAGER install -y "$package" >/dev/null 2>&1; then
                log_success "${package} installed successfully"
                return 0
            fi
            ;;
        zypper)
            if zypper install -y "$package" >/dev/null 2>&1; then
                log_success "${package} installed successfully"
                return 0
            fi
            ;;
        aix)
            log_warning "AIX detected - please install ${package} manually from AIX Toolbox"
            MISSING_PACKAGES+=("$package")
            return 1
            ;;
        hpux)
            log_warning "HP-UX detected - please install ${package} manually from Software Depot"
            MISSING_PACKAGES+=("$package")
            return 1
            ;;
        *)
            log_warning "Unknown package manager - cannot auto-install ${package}"
            MISSING_PACKAGES+=("$package")
            return 1
            ;;
    esac
    
    diagnose_package_install_failure "$package"
    MISSING_PACKAGES+=("$package")
    return 1
}

check_and_install_dependencies() {
    log_info "Checking required utilities..."
    
    local required_commands=()
    local package_map=()
    
    # Define required commands and their packages per distro
    case "$DISTRO" in
        aix)
            # AIX - most tools are built-in
            required_commands=("vmstat" "iostat" "netstat" "sar" "svmon" "lsps")
            package_map=("base" "base" "base" "base" "base" "base")
            ;;
        hpux)
            # HP-UX - most tools are built-in
            required_commands=("vmstat" "iostat" "netstat" "sar" "swapinfo")
            package_map=("base" "base" "base" "base" "base")
            ;;
        solaris|illumos)
            # Solaris/Illumos - most tools are built-in
            required_commands=("vmstat" "iostat" "netstat" "sar" "swap" "prstat")
            package_map=("base" "base" "base" "base" "base" "base")
            ;;
        *)
            log_warning "Unknown Unix variant - will attempt to use available tools"
            return
            ;;
    esac
    
    local missing=false
    for i in "${!required_commands[@]}"; do
        local cmd="${required_commands[$i]}"
        local pkg="${package_map[$i]}"
        
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_warning "${cmd} not found"
            
            if [[ "$pkg" != "base" ]]; then
                log_warning "${cmd} package installation not automated for ${DISTRO}"
                missing=true
            else
                log_warning "${cmd} should be part of base system but is missing"
                missing=true
            fi
        fi
    done
    
    if [[ "$missing" == true ]]; then
        log_warning "Some utilities are missing - diagnostics will be limited"
        echo "" | tee -a "$OUTPUT_FILE"
        echo "The script will continue with available tools..." | tee -a "$OUTPUT_FILE"
    else
        log_success "All required utilities are available"
    fi
}

#############################################################################
# Helper Functions
#############################################################################

log_info() {
    local msg="$1"
    echo -e "${CYAN}[$(date +%H:%M:%S)] ${msg}${NC}" | tee -a "$OUTPUT_FILE"
}

log_success() {
    local msg="$1"
    echo -e "${GREEN}[$(date +%H:%M:%S)] ${msg}${NC}" | tee -a "$OUTPUT_FILE"
}

log_warning() {
    local msg="$1"
    echo -e "${YELLOW}[$(date +%H:%M:%S)] ${msg}${NC}" | tee -a "$OUTPUT_FILE"
}

log_error() {
    local msg="$1"
    echo -e "${RED}[$(date +%H:%M:%S)] ${msg}${NC}" | tee -a "$OUTPUT_FILE"
}

log_bottleneck() {
    local category="$1"
    local issue="$2"
    local current="$3"
    local threshold="$4"
    local impact="$5"
    
    BOTTLENECKS+=("${impact}|${category}|${issue}|${current}|${threshold}")
    echo -e "${MAGENTA}[$(date +%H:%M:%S)] BOTTLENECK FOUND: ${category} - ${issue} (Current: ${current}, Threshold: ${threshold})${NC}" | tee -a "$OUTPUT_FILE"
}

print_header() {
    local title="$1"
    echo "" | tee -a "$OUTPUT_FILE"
    echo "================================================================================" | tee -a "$OUTPUT_FILE"
    echo "  ${title}" | tee -a "$OUTPUT_FILE"
    echo "================================================================================" | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo"
        exit 1
    fi
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_warning "Command '$1' not found. Some diagnostics may be limited."
        return 1
    fi
    return 0
}

#############################################################################
# System Information
#############################################################################

collect_system_info() {
    print_header "SYSTEM INFORMATION"
    
    log_info "Gathering system information..."
    
    # Basic system info
    echo "Hostname: $(hostname)" | tee -a "$OUTPUT_FILE"
    echo "Kernel: $(uname -r)" | tee -a "$OUTPUT_FILE"
    echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)" | tee -a "$OUTPUT_FILE"
    echo "Architecture: $(uname -m)" | tee -a "$OUTPUT_FILE"
    echo "Uptime: $(uptime -p)" | tee -a "$OUTPUT_FILE"
    
    # CPU info
    local cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
    local cpu_cores=$(nproc)
    echo "CPU: ${cpu_model}" | tee -a "$OUTPUT_FILE"
    echo "CPU Cores: ${cpu_cores}" | tee -a "$OUTPUT_FILE"
    
    # Memory info
    local total_mem=$(free -h | grep Mem | awk '{print $2}')
    echo "Total Memory: ${total_mem}" | tee -a "$OUTPUT_FILE"
    
    # Check if running on EC2
    if curl -s -m 2 http://169.254.169.254/latest/meta-data/instance-id &>/dev/null; then
        local instance_id=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
        local instance_type=$(curl -s http://169.254.169.254/latest/meta-data/instance-type)
        local az=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
        echo "Instance ID: ${instance_id}" | tee -a "$OUTPUT_FILE"
        echo "Instance Type: ${instance_type}" | tee -a "$OUTPUT_FILE"
        echo "Availability Zone: ${az}" | tee -a "$OUTPUT_FILE"
    else
        echo "Instance ID: Not EC2" | tee -a "$OUTPUT_FILE"
    fi
    
    log_success "System information collected"
}

#############################################################################
# CPU Forensics
#############################################################################

analyze_cpu() {
    print_header "CPU FORENSICS"
    
    if [[ "$MODE" == "disk" ]] || [[ "$MODE" == "memory" ]]; then
        log_info "Skipping CPU forensics in ${MODE} mode"
        return
    fi
    
    log_info "Analyzing CPU performance..."
    
    case "$DISTRO" in
        aix)
            analyze_cpu_aix
            ;;
        hpux)
            analyze_cpu_hpux
            ;;
        solaris|illumos)
            analyze_cpu_solaris
            ;;
        *)
            log_warning "CPU analysis not implemented for ${DISTRO}"
            ;;
    esac
    
    log_success "CPU forensics completed"
}

analyze_cpu_aix() {
    # Load average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    echo "Load Average: ${load_avg}" | tee -a "$OUTPUT_FILE"
    
    # CPU count
    local cpu_count=$(lsdev -Cc processor | grep Available | wc -l)
    echo "CPU Count: ${cpu_count}" | tee -a "$OUTPUT_FILE"
    
    # vmstat for CPU stats
    if command -v vmstat >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== CPU Statistics (vmstat 1 5) ===" | tee -a "$OUTPUT_FILE"
        vmstat 1 5 | tee -a "$OUTPUT_FILE"
    fi
    
    # sar if available
    if command -v sar >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== CPU Usage (sar) ===" | tee -a "$OUTPUT_FILE"
        sar 1 5 | tee -a "$OUTPUT_FILE"
    fi
    
    # Top CPU consumers
    echo "" | tee -a "$OUTPUT_FILE"
    echo "=== Top 10 CPU Consumers ===" | tee -a "$OUTPUT_FILE"
    ps aux | sort -rn -k 3 | head -10 | tee -a "$OUTPUT_FILE"
}

analyze_cpu_hpux() {
    # Load average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    echo "Load Average: ${load_avg}" | tee -a "$OUTPUT_FILE"
    
    # CPU count
    local cpu_count=$(ioscan -kC processor | grep processor | wc -l)
    echo "CPU Count: ${cpu_count}" | tee -a "$OUTPUT_FILE"
    
    # vmstat for CPU stats
    if command -v vmstat >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== CPU Statistics (vmstat 1 5) ===" | tee -a "$OUTPUT_FILE"
        vmstat 1 5 | tee -a "$OUTPUT_FILE"
    fi
    
    # sar if available
    if command -v sar >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== CPU Usage (sar) ===" | tee -a "$OUTPUT_FILE"
        sar 1 5 | tee -a "$OUTPUT_FILE"
    fi
    
    # Top CPU consumers
    echo "" | tee -a "$OUTPUT_FILE"
    echo "=== Top 10 CPU Consumers ===" | tee -a "$OUTPUT_FILE"
    ps -ef | sort -rn -k 4 | head -10 | tee -a "$OUTPUT_FILE"
}

analyze_cpu_solaris() {
    # Load average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    echo "Load Average: ${load_avg}" | tee -a "$OUTPUT_FILE"
    
    # CPU count
    local cpu_count=$(psrinfo | wc -l)
    echo "CPU Count: ${cpu_count}" | tee -a "$OUTPUT_FILE"
    
    # CPU info
    if command -v psrinfo >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== CPU Information ===" | tee -a "$OUTPUT_FILE"
        psrinfo -v | head -20 | tee -a "$OUTPUT_FILE"
    fi
    
    # vmstat for CPU stats
    if command -v vmstat >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== CPU Statistics (vmstat 1 5) ===" | tee -a "$OUTPUT_FILE"
        vmstat 1 5 | tee -a "$OUTPUT_FILE"
    fi
    
    # mpstat if available
    if command -v mpstat >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== Per-CPU Statistics (mpstat) ===" | tee -a "$OUTPUT_FILE"
        mpstat 1 5 | tee -a "$OUTPUT_FILE"
    fi
    
    # Top CPU consumers using prstat
    echo "" | tee -a "$OUTPUT_FILE"
    echo "=== Top 10 CPU Consumers ===" | tee -a "$OUTPUT_FILE"
    if command -v prstat >/dev/null 2>&1; then
        prstat -s cpu -n 10 1 1 | tee -a "$OUTPUT_FILE"
    else
        ps -eo pid,pcpu,comm | sort -rn -k 2 | head -10 | tee -a "$OUTPUT_FILE"
    fi
}

#############################################################################
# Memory Forensics
#############################################################################

analyze_memory() {
    print_header "MEMORY FORENSICS"
    
    if [[ "$MODE" == "disk" ]] || [[ "$MODE" == "cpu" ]]; then
        log_info "Skipping memory forensics in ${MODE} mode"
        return
    fi
    
    log_info "Analyzing memory usage..."
    
    case "$DISTRO" in
        aix)
            analyze_memory_aix
            ;;
        hpux)
            analyze_memory_hpux
            ;;
        solaris|illumos)
            analyze_memory_solaris
            ;;
        *)
            log_warning "Memory analysis not implemented for ${DISTRO}"
            ;;
    esac
}

analyze_memory_aix() {
    # AIX uses svmon for memory stats
    if command -v svmon >/dev/null 2>&1; then
        echo "=== AIX Memory Statistics (svmon) ===" | tee -a "$OUTPUT_FILE"
        svmon -G | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
    fi
    
    # Paging space (swap)
    if command -v lsps >/dev/null 2>&1; then
        echo "=== Paging Space ===" | tee -a "$OUTPUT_FILE"
        lsps -a | tee -a "$OUTPUT_FILE"
        
        local swap_pct=$(lsps -s | tail -1 | awk '{print $2}' | tr -d '%')
        if [[ -n "$swap_pct" ]] && (( swap_pct > 50 )); then
            log_bottleneck "Memory" "High paging space usage" "${swap_pct}%" "50%" "High"
        fi
    fi
    
    # Top memory consumers
    echo "" | tee -a "$OUTPUT_FILE"
    echo "=== Top 10 Memory Consumers ===" | tee -a "$OUTPUT_FILE"
    ps aux | sort -rn -k 4 | head -10 | tee -a "$OUTPUT_FILE"
}

analyze_memory_hpux() {
    # HP-UX uses swapinfo for memory/swap stats
    if command -v swapinfo >/dev/null 2>&1; then
        echo "=== HP-UX Memory and Swap (swapinfo) ===" | tee -a "$OUTPUT_FILE"
        swapinfo -tam | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
        
        # Check swap usage
        local swap_pct=$(swapinfo -t | tail -1 | awk '{print $5}' | tr -d '%')
        if [[ -n "$swap_pct" ]] && (( swap_pct > 50 )); then
            log_bottleneck "Memory" "High swap usage" "${swap_pct}%" "50%" "High"
        fi
    fi
    
    # Top memory consumers
    echo "=== Top 10 Memory Consumers ===" | tee -a "$OUTPUT_FILE"
    ps -ef | sort -rn -k 4 | head -10 | tee -a "$OUTPUT_FILE"
}

analyze_memory_solaris() {
    # Solaris uses swap -s and vmstat
    if command -v swap >/dev/null 2>&1; then
        echo "=== Solaris Swap Statistics ===" | tee -a "$OUTPUT_FILE"
        swap -s | tee -a "$OUTPUT_FILE"
        swap -l | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
    fi
    
    # Memory info from prtconf
    if command -v prtconf >/dev/null 2>&1; then
        echo "=== Physical Memory ===" | tee -a "$OUTPUT_FILE"
        prtconf | grep "Memory size" | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
    fi
    
    # Top memory consumers using prstat
    if command -v prstat >/dev/null 2>&1; then
        echo "=== Top 10 Memory Consumers ===" | tee -a "$OUTPUT_FILE"
        prstat -s rss -n 10 1 1 | tee -a "$OUTPUT_FILE"
    else
        # Fallback to ps
        ps -eo pid,rss,comm | sort -rn -k 2 | head -10 | tee -a "$OUTPUT_FILE"
    fi
}

#############################################################################
# Disk Forensics
#############################################################################

analyze_disk() {
    print_header "DISK I/O FORENSICS"
    
    if [[ "$MODE" == "cpu" ]] || [[ "$MODE" == "memory" ]]; then
        log_info "Skipping disk forensics in ${MODE} mode"
        return
    fi
    
    log_info "Analyzing disk I/O performance..."
    
    case "$DISTRO" in
        aix)
            analyze_disk_aix
            ;;
        hpux)
            analyze_disk_hpux
            ;;
        solaris|illumos)
            analyze_disk_solaris
            ;;
        *)
            log_warning "Disk analysis not implemented for ${DISTRO}"
            ;;
    esac
    
    log_success "Disk forensics completed"
}

analyze_disk_aix() {
    # Disk usage
    echo "=== Filesystem Usage ===" | tee -a "$OUTPUT_FILE"
    df -g | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    
    # Check for full filesystems
    while IFS= read -r line; do
        local usage=$(echo "$line" | awk '{print $4}' | sed 's/%//')
        local mount=$(echo "$line" | awk '{print $7}')
        if [[ -n "$usage" ]] && (( usage > 90 )); then
            log_bottleneck "Disk" "Filesystem nearly full: ${mount}" "${usage}%" "90%" "High"
        fi
    done < <(df -g | tail -n +2)
    
    # I/O statistics
    if command -v iostat >/dev/null 2>&1; then
        echo "=== I/O Statistics (iostat) ===" | tee -a "$OUTPUT_FILE"
        iostat 1 5 | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
    fi
    
    # Disk information
    if command -v lspv >/dev/null 2>&1; then
        echo "=== Physical Volumes ===" | tee -a "$OUTPUT_FILE"
        lspv | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
    fi
    
    # LVM information
    if command -v lsvg >/dev/null 2>&1; then
        echo "=== Volume Groups ===" | tee -a "$OUTPUT_FILE"
        lsvg | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
    fi
}

analyze_disk_hpux() {
    # Disk usage
    echo "=== Filesystem Usage ===" | tee -a "$OUTPUT_FILE"
    df -k | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    
    # Check for full filesystems
    while IFS= read -r line; do
        local usage=$(echo "$line" | awk '{print $5}' | sed 's/%//')
        local mount=$(echo "$line" | awk '{print $6}')
        if [[ -n "$usage" ]] && (( usage > 90 )); then
            log_bottleneck "Disk" "Filesystem nearly full: ${mount}" "${usage}%" "90%" "High"
        fi
    done < <(df -k | tail -n +2)
    
    # I/O statistics
    if command -v iostat >/dev/null 2>&1; then
        echo "=== I/O Statistics (iostat) ===" | tee -a "$OUTPUT_FILE"
        iostat 1 5 | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
    fi
    
    # Disk information
    if command -v ioscan >/dev/null 2>&1; then
        echo "=== Disk Devices ===" | tee -a "$OUTPUT_FILE"
        ioscan -funC disk | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
    fi
    
    # LVM information
    if command -v vgdisplay >/dev/null 2>&1; then
        echo "=== Volume Groups ===" | tee -a "$OUTPUT_FILE"
        vgdisplay | head -50 | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
    fi
}

analyze_disk_solaris() {
    # Disk usage
    echo "=== Filesystem Usage ===" | tee -a "$OUTPUT_FILE"
    df -h | tee -a "$OUTPUT_FILE"
    echo "" | tee -a "$OUTPUT_FILE"
    
    # Check for full filesystems
    while IFS= read -r line; do
        local usage=$(echo "$line" | awk '{print $5}' | sed 's/%//')
        local mount=$(echo "$line" | awk '{print $6}')
        if [[ -n "$usage" ]] && (( usage > 90 )); then
            log_bottleneck "Disk" "Filesystem nearly full: ${mount}" "${usage}%" "90%" "High"
        fi
    done < <(df -h | tail -n +2)
    
    # I/O statistics
    if command -v iostat >/dev/null 2>&1; then
        echo "=== I/O Statistics (iostat -xn) ===" | tee -a "$OUTPUT_FILE"
        iostat -xn 1 5 | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
    fi
    
    # ZFS pools if available
    if command -v zpool >/dev/null 2>&1; then
        echo "=== ZFS Pool Status ===" | tee -a "$OUTPUT_FILE"
        zpool status | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
        
        echo "=== ZFS Pool I/O Stats ===" | tee -a "$OUTPUT_FILE"
        zpool iostat -v | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
    fi
    
    # Disk information
    if command -v format >/dev/null 2>&1; then
        echo "=== Disk Devices ===" | tee -a "$OUTPUT_FILE"
        echo | format 2>/dev/null | grep "^[0-9]" | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
    fi
}
analyze_network() {
    print_header "NETWORK FORENSICS"
    
    log_info "Analyzing network performance..."
    
    # Network interfaces and status
    echo "Network Interfaces:" | tee -a "$OUTPUT_FILE"
    if command -v ip >/dev/null 2>&1; then
        ip -br addr 2>/dev/null | tee -a "$OUTPUT_FILE"
    else
        ifconfig 2>/dev/null | grep -E "^[a-z]|inet " | tee -a "$OUTPUT_FILE" || \
        log_warning "Unable to list network interfaces"
    fi
    
    # Network statistics and connection states
    if command -v netstat >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "TCP Connection States:" | tee -a "$OUTPUT_FILE"
        netstat -ant 2>/dev/null | awk '{print $6}' | sort | uniq -c | sort -rn | tee -a "$OUTPUT_FILE"
        
        # Check for excessive connections
        local established=$(netstat -ant 2>/dev/null | grep -c ESTABLISHED || echo "0")
        local time_wait=$(netstat -ant 2>/dev/null | grep -c TIME_WAIT || echo "0")
        local close_wait=$(netstat -ant 2>/dev/null | grep -c CLOSE_WAIT || echo "0")
        
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Established Connections: ${established}" | tee -a "$OUTPUT_FILE"
        echo "TIME_WAIT Connections: ${time_wait}" | tee -a "$OUTPUT_FILE"
        echo "CLOSE_WAIT Connections: ${close_wait}" | tee -a "$OUTPUT_FILE"
        
        if (( time_wait > 5000 )); then
            log_bottleneck "Network" "Excessive TIME_WAIT connections" "${time_wait}" "5000" "Medium"
        fi
        
        if (( close_wait > 1000 )); then
            log_bottleneck "Network" "Excessive CLOSE_WAIT connections" "${close_wait}" "1000" "Medium"
        fi
        
        # Listening ports
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Top 10 listening ports:" | tee -a "$OUTPUT_FILE"
        netstat -tuln 2>/dev/null | grep LISTEN | awk '{print $4}' | sed 's/.*://' | sort -n | uniq -c | sort -rn | head -10 | tee -a "$OUTPUT_FILE"
    elif command -v ss >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "TCP Connection States:" | tee -a "$OUTPUT_FILE"
        ss -ant 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | tee -a "$OUTPUT_FILE"
        
        local established=$(ss -ant 2>/dev/null | grep -c ESTAB || echo "0")
        local time_wait=$(ss -ant 2>/dev/null | grep -c TIME-WAIT || echo "0")
        
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Established Connections: ${established}" | tee -a "$OUTPUT_FILE"
        echo "TIME_WAIT Connections: ${time_wait}" | tee -a "$OUTPUT_FILE"
        
        if (( time_wait > 5000 )); then
            log_bottleneck "Network" "Excessive TIME_WAIT connections" "${time_wait}" "5000" "Medium"
        fi
    else
        log_warning "netstat and ss not available - skipping connection state analysis"
    fi
    
    # TCP retransmissions and errors
    if command -v ss >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "TCP Retransmission Analysis:" | tee -a "$OUTPUT_FILE"
        local retrans_info=$(ss -ti 2>/dev/null | grep -oP 'retrans:\d+/\d+' | head -20)
        if [[ -n "$retrans_info" ]]; then
            echo "$retrans_info" | tee -a "$OUTPUT_FILE"
            local total_retrans=$(echo "$retrans_info" | cut -d: -f2 | cut -d/ -f1 | awk '{sum+=$1} END {print sum}')
            if [[ -n "$total_retrans" ]] && (( total_retrans > 100 )); then
                log_bottleneck "Network" "High TCP retransmissions detected" "${total_retrans}" "100" "Medium"
            fi
        else
            echo "  No significant retransmissions detected" | tee -a "$OUTPUT_FILE"
        fi
    fi
    
    # Network interface statistics and errors
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Network Interface Statistics:" | tee -a "$OUTPUT_FILE"
    if command -v ip >/dev/null 2>&1; then
        ip -s link 2>/dev/null | grep -E "^\d+:|RX:|TX:|errors" | tee -a "$OUTPUT_FILE"
        
        # Check for errors
        local rx_errors=$(ip -s link 2>/dev/null | grep "RX:" -A 1 | grep errors | awk '{sum+=$2} END {print sum}')
        local tx_errors=$(ip -s link 2>/dev/null | grep "TX:" -A 1 | grep errors | awk '{sum+=$2} END {print sum}')
        
        if [[ -n "$rx_errors" ]] && (( rx_errors > 100 )); then
            log_bottleneck "Network" "High RX errors detected" "${rx_errors}" "100" "Medium"
        fi
        
        if [[ -n "$tx_errors" ]] && (( tx_errors > 100 )); then
            log_bottleneck "Network" "High TX errors detected" "${tx_errors}" "100" "Medium"
        fi
    else
        netstat -i 2>/dev/null | tee -a "$OUTPUT_FILE" || \
        ifconfig 2>/dev/null | grep -E "RX|TX" | tee -a "$OUTPUT_FILE" || \
        log_warning "Unable to get network interface statistics"
    fi
    
    # Network throughput (if sar available)
    if command -v sar >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Network Throughput (last 5 samples):" | tee -a "$OUTPUT_FILE"
        sar -n DEV 1 5 2>/dev/null | grep -v "^$" | grep -v "Linux" | tail -20 | tee -a "$OUTPUT_FILE" || \
        log_warning "sar network statistics not available"
    fi
    
    # Socket statistics
    if command -v ss >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Socket Memory Usage:" | tee -a "$OUTPUT_FILE"
        ss -m 2>/dev/null | grep -A 1 "skmem:" | head -20 | tee -a "$OUTPUT_FILE"
    fi
    
    # Check for dropped packets
    if [[ -f /proc/net/dev ]]; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Dropped Packets by Interface:" | tee -a "$OUTPUT_FILE"
        awk 'NR>2 {print $1, "RX dropped:", $5, "TX dropped:", $13}' /proc/net/dev | column -t | tee -a "$OUTPUT_FILE"
    fi
    
    # Network buffer/queue statistics
    if [[ -f /proc/sys/net/core/netdev_max_backlog ]]; then
        local max_backlog=$(cat /proc/sys/net/core/netdev_max_backlog)
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Network Queue Settings:" | tee -a "$OUTPUT_FILE"
        echo "  Max backlog: ${max_backlog}" | tee -a "$OUTPUT_FILE"
    fi
    
    # Database connectivity checks (useful for DMS migrations)
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Database Port Connectivity:" | tee -a "$OUTPUT_FILE"
    
    # Check for active database connections
    local mysql_conns=$(netstat -ant 2>/dev/null | grep ":3306" | grep ESTABLISHED | wc -l || echo "0")
    local pg_conns=$(netstat -ant 2>/dev/null | grep ":5432" | grep ESTABLISHED | wc -l || echo "0")
    local oracle_conns=$(netstat -ant 2>/dev/null | grep ":1521" | grep ESTABLISHED | wc -l || echo "0")
    local mssql_conns=$(netstat -ant 2>/dev/null | grep ":1433" | grep ESTABLISHED | wc -l || echo "0")
    local mongo_conns=$(netstat -ant 2>/dev/null | grep ":27017" | grep ESTABLISHED | wc -l || echo "0")
    
    echo "  MySQL (3306): ${mysql_conns} connections" | tee -a "$OUTPUT_FILE"
    echo "  PostgreSQL (5432): ${pg_conns} connections" | tee -a "$OUTPUT_FILE"
    echo "  Oracle (1521): ${oracle_conns} connections" | tee -a "$OUTPUT_FILE"
    echo "  SQL Server (1433): ${mssql_conns} connections" | tee -a "$OUTPUT_FILE"
    echo "  MongoDB (27017): ${mongo_conns} connections" | tee -a "$OUTPUT_FILE"
    
    # Check for connection churn (high TIME_WAIT on database ports)
    local db_time_wait=$(netstat -ant 2>/dev/null | grep -E ":3306|:5432|:1521|:1433|:27017" | grep TIME_WAIT | wc -l || echo "0")
    echo "  Database TIME_WAIT: ${db_time_wait}" | tee -a "$OUTPUT_FILE"
    
    if (( db_time_wait > 1000 )); then
        log_bottleneck "Network" "High connection churn on database ports (DMS impact)" "${db_time_wait}" "1000" "Medium"
    fi
    
    log_success "Network forensics completed"
}

#############################################################################
# AWS Support Integration
#############################################################################

create_support_case() {
    print_header "AWS SUPPORT CASE CREATION"
    
    if [[ ${#BOTTLENECKS[@]} -eq 0 ]]; then
        log_info "No bottlenecks detected - skipping support case creation"
        return
    fi
    
    # Check AWS CLI
    if ! check_command aws; then
        log_error "AWS CLI not found. Install from: https://aws.amazon.com/cli/"
        return
    fi
    
    log_info "Creating AWS Support case with severity: ${SEVERITY}"
    
    # Build bottleneck summary
    local bottleneck_summary=""
    for bottleneck in "${BOTTLENECKS[@]}"; do
        IFS='|' read -r impact category issue current threshold <<< "$bottleneck"
        bottleneck_summary+="[${impact}] ${category}: ${issue} (Current: ${current}, Threshold: ${threshold})\n"
    done
    
    # Get system info
    local hostname=$(hostname)
    local os_info=$(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
    local kernel=$(uname -r)
    local instance_id=$(curl -s -m 2 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "")
    
    # Use instance ID for AWS, hostname for non-AWS
    local system_identifier
    if [[ -n "$instance_id" ]]; then
        system_identifier="$instance_id"
    else
        system_identifier="$hostname"
    fi
    
    # Build case description
    local case_description="AUTOMATED UNIX FORENSICS REPORT

EXECUTIVE SUMMARY:
Comprehensive diagnostics detected ${#BOTTLENECKS[@]} performance issue(s) requiring attention.

BOTTLENECKS DETECTED:
${bottleneck_summary}

SYSTEM INFORMATION:
- Hostname: ${hostname}
- OS: ${os_info}
- Kernel: ${kernel}
- Instance ID: ${instance_id:-Not EC2}
- Diagnostic Mode: ${MODE}
- Timestamp: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

Detailed forensics data is attached in the diagnostic report file.

Generated by: invoke-unix-forensics.sh v1.0"
    
    local case_subject="Unix Performance Issues Detected - ${system_identifier}"
    
    # Create case JSON
    local case_json=$(cat <<EOF
{
  "subject": "${case_subject}",
  "serviceCode": "amazon-ec2-linux",
  "severityCode": "${SEVERITY}",
  "categoryCode": "performance",
  "communicationBody": "${case_description}",
  "language": "en",
  "issueType": "technical"
}
EOF
)
    
    # Create the case
    local case_result=$(aws support create-case --cli-input-json "$case_json" 2>&1)
    
    if [[ $? -eq 0 ]]; then
        local case_id=$(echo "$case_result" | grep -oP '"caseId":\s*"\K[^"]+')
        log_success "Support case created successfully!"
        log_success "Case ID: ${case_id}"
        
        # Attach diagnostic file
        log_info "Attaching diagnostic report..."
        
        local attachment_content=$(base64 -w 0 "$OUTPUT_FILE")
        local attachment_json=$(cat <<EOF
{
  "attachments": [
    {
      "fileName": "$(basename "$OUTPUT_FILE")",
      "data": "${attachment_content}"
    }
  ]
}
EOF
)
        
        local attachment_result=$(aws support add-attachments-to-set --cli-input-json "$attachment_json" 2>&1)
        
        if [[ $? -eq 0 ]]; then
            local attachment_set_id=$(echo "$attachment_result" | grep -oP '"attachmentSetId":\s*"\K[^"]+')
            
            aws support add-communication-to-case \
                --case-id "$case_id" \
                --communication-body "Complete forensics diagnostic report attached." \
                --attachment-set-id "$attachment_set_id" &>/dev/null
            
            log_success "Diagnostic report attached successfully"
        fi
        
        echo "" | tee -a "$OUTPUT_FILE"
        log_info "View your case: https://console.aws.amazon.com/support/home#/case/?displayId=${case_id}"
        
    else
        log_error "Failed to create support case: ${case_result}"
        log_info "Ensure you have:"
        log_info "  1. AWS CLI configured (aws configure)"
        log_info "  2. Active AWS Support plan (Business or Enterprise)"
        log_info "  3. IAM permissions for support:CreateCase"
    fi
}

#############################################################################
# Main Execution
#############################################################################

show_banner() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                               ║"
    echo "║                UNIX PERFORMANCE FORENSICS TOOL v1.0                          ║"
    echo "║                                                                               ║"
    echo "║                    Comprehensive System Diagnostics                           ║"
    echo "║                    with AWS Support Integration                               ║"
    echo "║                                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
}

show_help() {
    cat << EOF
Unix Performance Forensic Tool

Usage: sudo $0 [OPTIONS]

Options:
  -m, --mode MODE          Diagnostic mode: quick, standard, deep, disk, cpu, memory
                          (default: standard)
  -s, --support            Create AWS Support case if issues found
  -v, --severity LEVEL     Support case severity: low, normal, high, urgent, critical
                          (default: normal)
  -o, --output PATH        Output directory (default: current directory)
  -h, --help               Show this help message

Modes:
  quick      - Fast assessment (CPU, memory, disk usage only)
  standard   - Comprehensive diagnostics (recommended)
  deep       - Extended diagnostics with I/O testing
  disk       - Disk-only diagnostics
  cpu        - CPU-only diagnostics
  memory     - Memory-only diagnostics

Examples:
  sudo $0 -m quick
  sudo $0 -m deep -s -v high
  sudo $0 -m standard -o /var/log

Requires: root/sudo privileges
Optional: AWS CLI for support case creation
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -m|--mode)
                MODE="$2"
                shift 2
                ;;
            -s|--support)
                CREATE_SUPPORT_CASE=true
                shift
                ;;
            -v|--severity)
                SEVERITY="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                OUTPUT_FILE="${OUTPUT_DIR}/unix-forensics-${TIMESTAMP}.txt"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

main() {
    parse_args "$@"
    
    check_root
    
    # Detect OS and package manager
    detect_os
    
    show_banner
    
    log_info "Detected OS: ${DISTRO}"
    log_info "Package Manager: ${PACKAGE_MANAGER}"
    log_info "Starting forensics analysis in ${MODE} mode..."
    log_info "Output file: ${OUTPUT_FILE}"
    echo ""
    
    # Check and install dependencies
    check_and_install_dependencies
    echo ""
    
    local start_time=$(date +%s)
    
    # Execute diagnostics based on mode
    collect_system_info
    
    case "$MODE" in
        quick)
            analyze_cpu
            analyze_memory
            ;;
        standard)
            analyze_cpu
            analyze_memory
            analyze_disk
            analyze_databases
            analyze_network
            ;;
        deep)
            analyze_cpu
            analyze_memory
            analyze_disk
            analyze_databases
            analyze_network
            ;;
        disk)
            analyze_disk
            ;;
        cpu)
            analyze_cpu
            ;;
        memory)
            analyze_memory
            ;;
        *)
            log_error "Invalid mode: ${MODE}"
            show_help
            exit 1
            ;;
    esac
    
    # Summary
    print_header "FORENSICS SUMMARY"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_success "Analysis completed in ${duration} seconds"
    
    if [[ ${#BOTTLENECKS[@]} -eq 0 ]]; then
        echo ""
        echo -e "${GREEN}NO BOTTLENECKS FOUND! System performance looks healthy.${NC}"
    else
        echo ""
        echo -e "${MAGENTA}BOTTLENECKS DETECTED: ${#BOTTLENECKS[@]} performance issue(s) found${NC}"
        echo ""
        
        # Group by impact
        local critical=()
        local high=()
        local medium=()
        local low=()
        
        for bottleneck in "${BOTTLENECKS[@]}"; do
            IFS='|' read -r impact category issue current threshold <<< "$bottleneck"
            case "$impact" in
                Critical) critical+=("${category}: ${issue}") ;;
                High) high+=("${category}: ${issue}") ;;
                Medium) medium+=("${category}: ${issue}") ;;
                Low) low+=("${category}: ${issue}") ;;
            esac
        done
        
        if [[ ${#critical[@]} -gt 0 ]]; then
            echo -e "${RED}  CRITICAL ISSUES (${#critical[@]}):${NC}"
            for issue in "${critical[@]}"; do
                echo "    • ${issue}"
            done
        fi
        
        if [[ ${#high[@]} -gt 0 ]]; then
            echo -e "${YELLOW}  HIGH PRIORITY (${#high[@]}):${NC}"
            for issue in "${high[@]}"; do
                echo "    • ${issue}"
            done
        fi
        
        if [[ ${#medium[@]} -gt 0 ]]; then
            echo -e "${YELLOW}  MEDIUM PRIORITY (${#medium[@]}):${NC}"
            for issue in "${medium[@]}"; do
                echo "    • ${issue}"
            done
        fi
        
        if [[ ${#low[@]} -gt 0 ]]; then
            echo "  LOW PRIORITY (${#low[@]}):"
            for issue in "${low[@]}"; do
                echo "    • ${issue}"
            done
        fi
    fi
    
    echo ""
    log_info "Detailed report saved to: ${OUTPUT_FILE}"
    
    # Create AWS Support case if requested
    if [[ "$CREATE_SUPPORT_CASE" == true ]] && [[ ${#BOTTLENECKS[@]} -gt 0 ]]; then
        echo ""
        create_support_case
    elif [[ ${#BOTTLENECKS[@]} -gt 0 ]] && [[ "$CREATE_SUPPORT_CASE" == false ]]; then
        echo ""
        log_info "Tip: Run with --support to automatically open an AWS Support case"
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo "                         Forensics Analysis Complete                            "
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo ""
}

# Run main function
main "$@"
