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
    # Determine package manager
    case "$DISTRO" in
        macos)
            PACKAGE_MANAGER="brew"
            ;;
        ubuntu|debian)
            PACKAGE_MANAGER="apt-get"
            ;;
        rhel|centos|fedora|amzn|rocky|alma)
            if command -v dnf >/dev/null 2>&1; then
                PACKAGE_MANAGER="dnf"
            else
                PACKAGE_MANAGER="yum"
            fi
            ;;
        sles|opensuse*)
            PACKAGE_MANAGER="zypper"
            ;;
        aix)
            PACKAGE_MANAGER="aix"
            ;;
        hpux)
            PACKAGE_MANAGER="hpux"
            ;;
        *)
            PACKAGE_MANAGER="unknown"
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
        fi
    else
        echo "Swap: Not configured" | tee -a "$OUTPUT_FILE"
    fi
    
    # Page faults
    if command -v vmstat >/dev/null 2>&1; then
        log_info "Sampling page faults (5 seconds)..."
        local page_faults=$(vmstat 1 5 2>/dev/null | tail -1 | awk '{print $7}')
        if [[ -n "$page_faults" ]]; then
            echo "Page Faults: ${page_faults}/sec" | tee -a "$OUTPUT_FILE"
            
            if (( page_faults > 1000 )); then
                log_bottleneck "Memory" "High page fault rate" "${page_faults}/sec" "1000/sec" "Medium"
            fi
        fi
    fi
    
    # Memory pressure indicators
    if [[ -f /proc/pressure/memory ]]; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Memory Pressure (PSI):" | tee -a "$OUTPUT_FILE"
        cat /proc/pressure/memory | tee -a "$OUTPUT_FILE"
    fi
    
    # Slab memory usage
    if [[ -f /proc/meminfo ]]; then
        local slab_mem=$(grep "^Slab:" /proc/meminfo | awk '{print $2}')
        local slab_reclaimable=$(grep "^SReclaimable:" /proc/meminfo | awk '{print $2}')
        local slab_unreclaimable=$(grep "^SUnreclaim:" /proc/meminfo | awk '{print $2}')
        
        if [[ -n "$slab_mem" ]]; then
            echo "" | tee -a "$OUTPUT_FILE"
            echo "Slab Memory: $((slab_mem / 1024)) MB" | tee -a "$OUTPUT_FILE"
            echo "  Reclaimable: $((slab_reclaimable / 1024)) MB" | tee -a "$OUTPUT_FILE"
            echo "  Unreclaimable: $((slab_unreclaimable / 1024)) MB" | tee -a "$OUTPUT_FILE"
        fi
    fi
    
    # OOM killer check
    if command -v dmesg >/dev/null 2>&1; then
        if dmesg 2>/dev/null | grep -i "out of memory" | tail -5 | grep -q .; then
            echo "" | tee -a "$OUTPUT_FILE"
            echo "Recent OOM (Out of Memory) events detected:" | tee -a "$OUTPUT_FILE"
            dmesg 2>/dev/null | grep -i "out of memory" | tail -5 | tee -a "$OUTPUT_FILE"
            log_bottleneck "Memory" "OOM killer invoked recently" "Yes" "No" "Critical"
        fi
    fi
    
    # Check for memory leaks - processes with high VSZ but low RSS
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Potential memory leak candidates (high virtual, low resident):" | tee -a "$OUTPUT_FILE"
    ps aux 2>/dev/null | awk '$5 > 2097152 && $6 < ($5 * 0.3) {printf "  %-20s PID: %-8s VSZ: %8d KB RSS: %8d KB\n", $11, $2, $5, $6}' | head -5 | tee -a "$OUTPUT_FILE" || \
    echo "  No significant candidates found" | tee -a "$OUTPUT_FILE"
    
    # Top memory consumers
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Top 10 memory-consuming processes:" | tee -a "$OUTPUT_FILE"
    ps aux --sort=-%mem 2>/dev/null | head -11 | tail -10 | awk '{printf "  %-20s PID: %-8s MEM: %5s%% CPU: %5s%%\n", $11, $2, $4, $3}' | tee -a "$OUTPUT_FILE" || \
    ps -eo comm,pid,pmem,pcpu --sort=-pmem 2>/dev/null | head -11 | tail -10 | tee -a "$OUTPUT_FILE" || \
    log_warning "Unable to list top memory consumers"
    
    # Huge pages status
    if [[ -f /proc/meminfo ]]; then
        local hugepages_total=$(grep "^HugePages_Total:" /proc/meminfo | awk '{print $2}')
        local hugepages_free=$(grep "^HugePages_Free:" /proc/meminfo | awk '{print $2}')
        if [[ -n "$hugepages_total" ]] && (( hugepages_total > 0 )); then
            echo "" | tee -a "$OUTPUT_FILE"
            echo "Huge Pages: ${hugepages_free} free / ${hugepages_total} total" | tee -a "$OUTPUT_FILE"
        fi
    fi
    
    log_success "Memory forensics completed"
}

#############################################################################
# Disk I/O Forensics
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
            log_bottleneck "Disk" "High I/O wait - processes stuck in uninterruptible sleep" "${io_wait_procs}" "5" "High"
        fi
    else
        echo "  No processes in I/O wait" | tee -a "$OUTPUT_FILE"
    fi
    
    # Top I/O consumers using iotop if available
    if command -v iotop >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Top I/O Consumers (iotop):" | tee -a "$OUTPUT_FILE"
        timeout 5 iotop -b -n 2 -o 2>/dev/null | tail -20 | tee -a "$OUTPUT_FILE" || echo "  Unable to run iotop" | tee -a "$OUTPUT_FILE"
    else
        echo "" | tee -a "$OUTPUT_FILE"
        echo "iotop not available - install with package manager for per-process I/O analysis" | tee -a "$OUTPUT_FILE"
    fi
    
    # Disk I/O test (if in disk mode or deep mode)
    if [[ "$MODE" == "disk" ]] || [[ "$MODE" == "deep" ]]; then
        if command -v dd >/dev/null 2>&1; then
            echo "" | tee -a "$OUTPUT_FILE"
            log_info "Running disk write performance test..."
            
            local test_file="/tmp/forensics_disk_test_$$"
            local write_result=$(dd if=/dev/zero of="$test_file" bs=1M count=1024 oflag=direct 2>&1 || echo "failed")
            
            if [[ "$write_result" != "failed" ]]; then
                local write_speed=$(echo "$write_result" | grep -oP '\d+\.?\d* MB/s' | head -1 || echo "N/A")
                echo "Disk Write Speed: ${write_speed}" | tee -a "$OUTPUT_FILE"
                
                log_info "Running disk read performance test..."
                sync && echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
                local read_result=$(dd if="$test_file" of=/dev/null bs=1M 2>&1 || echo "failed")
                
                if [[ "$read_result" != "failed" ]]; then
                    local read_speed=$(echo "$read_result" | grep -oP '\d+\.?\d* MB/s' | head -1 || echo "N/A")
                    echo "Disk Read Speed: ${read_speed}" | tee -a "$OUTPUT_FILE"
                fi
            else
                log_warning "Disk performance test failed"
            fi
            
            rm -f "$test_file"
        else
            log_warning "dd command not available - skipping disk performance test"
        fi
    fi
    
    log_success "Disk forensics completed"
}

#############################################################################
# Database Forensics
#############################################################################

analyze_databases() {
    print_header "DATABASE FORENSICS"
    
    log_info "Scanning for database processes and connections..."
    
    local databases_found=false
    
    # Check for CloudWatch Logs Agent (common in DMS migrations)
    if pgrep -f "amazon-cloudwatch-agent" >/dev/null 2>&1 || pgrep -f "awslogs" >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== CloudWatch Logs Agent Detected ===" | tee -a "$OUTPUT_FILE"
        ps aux | grep -E "[a]mazon-cloudwatch-agent|[a]wslogs" | awk '{printf "  Process: PID %s, CPU: %s%%, MEM: %s%%\n", $2, $3, $4}' | tee -a "$OUTPUT_FILE"
        echo "  Status: Running" | tee -a "$OUTPUT_FILE"
    else
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== CloudWatch Logs Agent ===" | tee -a "$OUTPUT_FILE"
        echo "  Status: Not detected" | tee -a "$OUTPUT_FILE"
        echo "  Note: CloudWatch Logs Agent recommended for DMS migrations" | tee -a "$OUTPUT_FILE"
    fi
    
    # MySQL/MariaDB Detection
    if pgrep -x mysqld >/dev/null 2>&1 || pgrep -x mariadbd >/dev/null 2>&1; then
        databases_found=true
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== MySQL/MariaDB Detected ===" | tee -a "$OUTPUT_FILE"
        
        # Process info
        ps aux | grep -E "[m]ysqld|[m]ariadbd" | awk '{printf "  Process: PID %s, CPU: %s%%, MEM: %s%%\n", $2, $3, $4}' | tee -a "$OUTPUT_FILE"
        
        # Connection count
        local mysql_conns=$(netstat -ant 2>/dev/null | grep :3306 | grep ESTABLISHED | wc -l || echo "0")
        echo "  Active Connections: ${mysql_conns}" | tee -a "$OUTPUT_FILE"
        
        if (( mysql_conns > 500 )); then
            log_bottleneck "Database" "High MySQL connection count" "${mysql_conns}" "500" "Medium"
        fi
        
        # MySQL Query Analysis
        if command -v mysql >/dev/null 2>&1; then
            echo "" | tee -a "$OUTPUT_FILE"
            echo "  MySQL Query Analysis:" | tee -a "$OUTPUT_FILE"
            
            mysql -u root -e "SELECT ID, USER, HOST, DB, COMMAND, TIME, STATE, LEFT(INFO, 100) AS QUERY FROM information_schema.PROCESSLIST WHERE COMMAND != 'Sleep' AND TIME > 30 ORDER BY TIME DESC LIMIT 5;" 2>/dev/null | tee -a "$OUTPUT_FILE" || echo "  Unable to query MySQL (requires authentication)" | tee -a "$OUTPUT_FILE"
            
            mysql -u root -e "SELECT DIGEST_TEXT AS query, COUNT_STAR AS exec_count, ROUND(AVG_TIMER_WAIT/1000000000, 2) AS avg_time_ms, ROUND(SUM_TIMER_WAIT/1000000000, 2) AS total_time_ms, ROUND(SUM_ROWS_EXAMINED/COUNT_STAR, 0) AS avg_rows_examined FROM performance_schema.events_statements_summary_by_digest ORDER BY SUM_TIMER_WAIT DESC LIMIT 5;" 2>/dev/null | tee -a "$OUTPUT_FILE"
            
            # Check for long-running queries
            local long_running=$(mysql -u root -N -e "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE COMMAND != 'Sleep' AND TIME > 30;" 2>/dev/null)
            if [[ -n "$long_running" ]] && (( long_running > 0 )); then
                log_bottleneck "Database" "Long-running MySQL queries detected (>30s)" "Yes" "30s" "High"
            fi
            
            # DMS-specific checks for MySQL
            echo "" | tee -a "$OUTPUT_FILE"
            echo "  DMS Migration Readiness:" | tee -a "$OUTPUT_FILE"
            
            # Check binary logging (required for CDC)
            local binlog_status=$(mysql -u root -N -e "SHOW VARIABLES LIKE 'log_bin';" 2>/dev/null | awk '{print $2}')
            echo "    Binary Logging: ${binlog_status:-Unknown}" | tee -a "$OUTPUT_FILE"
            if [[ "$binlog_status" != "ON" ]]; then
                log_bottleneck "DMS" "MySQL binary logging disabled - required for CDC" "OFF" "ON" "High"
            fi
            
            # Check binlog format (ROW required for DMS)
            local binlog_format=$(mysql -u root -N -e "SHOW VARIABLES LIKE 'binlog_format';" 2>/dev/null | awk '{print $2}')
            echo "    Binary Log Format: ${binlog_format:-Unknown}" | tee -a "$OUTPUT_FILE"
            if [[ "$binlog_format" != "ROW" ]]; then
                log_bottleneck "DMS" "MySQL binlog format not ROW - required for DMS CDC" "${binlog_format}" "ROW" "High"
            fi
            
            # Check binlog retention
            local binlog_retention=$(mysql -u root -N -e "SHOW VARIABLES LIKE 'expire_logs_days';" 2>/dev/null | awk '{print $2}')
            echo "    Binary Log Retention: ${binlog_retention:-0} days" | tee -a "$OUTPUT_FILE"
            if [[ -n "$binlog_retention" ]] && (( $(echo "$binlog_retention < 1" | bc -l 2>/dev/null || echo 1) )); then
                log_bottleneck "DMS" "MySQL binlog retention too low for DMS" "${binlog_retention}d" ">=1d" "Medium"
            fi
            
            # Check for replication lag (if slave)
            local slave_status=$(mysql -u root -e "SHOW SLAVE STATUS\G" 2>/dev/null | grep "Seconds_Behind_Master" | awk '{print $2}')
            if [[ -n "$slave_status" ]] && [[ "$slave_status" != "NULL" ]]; then
                echo "    Replication Lag: ${slave_status} seconds" | tee -a "$OUTPUT_FILE"
                if (( slave_status > 300 )); then
                    log_bottleneck "Database" "High MySQL replication lag" "${slave_status}s" "300s" "High"
                fi
            fi
        fi
    fi
    
    # PostgreSQL Detection
    if pgrep -x postgres >/dev/null 2>&1 || pgrep -x postmaster >/dev/null 2>&1; then
        databases_found=true
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== PostgreSQL Detected ===" | tee -a "$OUTPUT_FILE"
        
        # Process info
        ps aux | grep -E "[p]ostgres|[p]ostmaster" | head -1 | awk '{printf "  Process: PID %s, CPU: %s%%, MEM: %s%%\n", $2, $3, $4}' | tee -a "$OUTPUT_FILE"
        
        # Connection count
        local pg_conns=$(netstat -ant 2>/dev/null | grep :5432 | grep ESTABLISHED | wc -l || echo "0")
        echo "  Active Connections: ${pg_conns}" | tee -a "$OUTPUT_FILE"
        
        if (( pg_conns > 500 )); then
            log_bottleneck "Database" "High PostgreSQL connection count" "${pg_conns}" "500" "Medium"
        fi
        
        # PostgreSQL Query Analysis
        if command -v psql >/dev/null 2>&1; then
            echo "" | tee -a "$OUTPUT_FILE"
            echo "  PostgreSQL Query Analysis:" | tee -a "$OUTPUT_FILE"
            
            psql -U postgres -c "SELECT pid, usename, application_name, state, EXTRACT(EPOCH FROM (now() - query_start)) AS duration_seconds, LEFT(query, 100) AS query FROM pg_stat_activity WHERE state != 'idle' AND query NOT LIKE '%pg_stat_activity%' ORDER BY duration_seconds DESC LIMIT 5;" 2>/dev/null | tee -a "$OUTPUT_FILE" || echo "  Unable to query PostgreSQL (requires authentication)" | tee -a "$OUTPUT_FILE"
            
            psql -U postgres -c "SELECT query, calls, ROUND(total_exec_time::numeric, 2) AS total_time_ms, ROUND(mean_exec_time::numeric, 2) AS avg_time_ms, ROUND((100 * total_exec_time / SUM(total_exec_time) OVER ())::numeric, 2) AS pct_total FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 5;" 2>/dev/null | tee -a "$OUTPUT_FILE"
            
            # Check for long-running queries
            local long_running=$(psql -U postgres -t -c "SELECT COUNT(*) FROM pg_stat_activity WHERE state != 'idle' AND EXTRACT(EPOCH FROM (now() - query_start)) > 30;" 2>/dev/null | tr -d ' ')
            if [[ -n "$long_running" ]] && (( long_running > 0 )); then
                log_bottleneck "Database" "Long-running PostgreSQL queries detected (>30s)" "Yes" "30s" "High"
            fi
            
            # DMS-specific checks for PostgreSQL
            echo "" | tee -a "$OUTPUT_FILE"
            echo "  DMS Migration Readiness:" | tee -a "$OUTPUT_FILE"
            
            # Check WAL level (logical required for DMS)
            local wal_level=$(psql -U postgres -t -c "SHOW wal_level;" 2>/dev/null | tr -d ' ')
            echo "    WAL Level: ${wal_level:-Unknown}" | tee -a "$OUTPUT_FILE"
            if [[ "$wal_level" != "logical" ]]; then
                log_bottleneck "DMS" "PostgreSQL wal_level not 'logical' - required for DMS CDC" "${wal_level}" "logical" "High"
            fi
            
            # Check replication slots
            local repl_slots=$(psql -U postgres -t -c "SELECT COUNT(*) FROM pg_replication_slots;" 2>/dev/null | tr -d ' ')
            echo "    Replication Slots: ${repl_slots:-0}" | tee -a "$OUTPUT_FILE"
            
            # Check for replication lag (if standby)
            local is_standby=$(psql -U postgres -t -c "SELECT pg_is_in_recovery();" 2>/dev/null | tr -d ' ')
            if [[ "$is_standby" == "t" ]]; then
                local lag=$(psql -U postgres -t -c "SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()));" 2>/dev/null | tr -d ' ')
                echo "    Replication Lag: ${lag:-Unknown} seconds" | tee -a "$OUTPUT_FILE"
                if [[ -n "$lag" ]] && (( $(echo "$lag > 300" | bc -l 2>/dev/null || echo 0) )); then
                    log_bottleneck "Database" "High PostgreSQL replication lag" "${lag}s" "300s" "High"
                fi
            fi
            
            # Check max_replication_slots
            local max_slots=$(psql -U postgres -t -c "SHOW max_replication_slots;" 2>/dev/null | tr -d ' ')
            echo "    Max Replication Slots: ${max_slots:-Unknown}" | tee -a "$OUTPUT_FILE"
            if [[ -n "$max_slots" ]] && (( max_slots < 1 )); then
                log_bottleneck "DMS" "PostgreSQL max_replication_slots is 0 - DMS requires at least 1" "${max_slots}" ">=1" "High"
            fi
        fi
    fi
    
    # MongoDB Detection
    if pgrep -x mongod >/dev/null 2>&1; then
        databases_found=true
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== MongoDB Detected ===" | tee -a "$OUTPUT_FILE"
        
        # Process info
        ps aux | grep "[m]ongod" | awk '{printf "  Process: PID %s, CPU: %s%%, MEM: %s%%\n", $2, $3, $4}' | tee -a "$OUTPUT_FILE"
        
        # Connection count
        local mongo_conns=$(netstat -ant 2>/dev/null | grep :27017 | grep ESTABLISHED | wc -l || echo "0")
        echo "  Active Connections: ${mongo_conns}" | tee -a "$OUTPUT_FILE"
        
        if (( mongo_conns > 1000 )); then
            log_bottleneck "Database" "High MongoDB connection count" "${mongo_conns}" "1000" "Medium"
        fi
        
        # MongoDB Query Analysis
        if command -v mongo >/dev/null 2>&1 || command -v mongosh >/dev/null 2>&1; then
            echo "" | tee -a "$OUTPUT_FILE"
            echo "  MongoDB Query Analysis:" | tee -a "$OUTPUT_FILE"
            
            local mongo_cmd="mongo"
            command -v mongosh >/dev/null 2>&1 && mongo_cmd="mongosh"
            
            $mongo_cmd --quiet --eval "db.currentOp({\$or: [{op: {\$in: ['query', 'command']}}, {secs_running: {\$gte: 30}}]}).inprog.forEach(function(op) { print('OpID: ' + op.opid + ' | Duration: ' + op.secs_running + 's | NS: ' + op.ns + ' | Query: ' + JSON.stringify(op.command).substring(0,100)); }); print('---TOP 5 SLOWEST OPERATIONS---'); db.system.profile.find().sort({millis: -1}).limit(5).forEach(function(op) { print('Duration: ' + op.millis + 'ms | Op: ' + op.op + ' | NS: ' + op.ns + ' | Query: ' + JSON.stringify(op.command).substring(0,100)); });" 2>/dev/null | tee -a "$OUTPUT_FILE" || echo "  Unable to query MongoDB (requires authentication or profiling enabled)" | tee -a "$OUTPUT_FILE"
            
            # Check for long-running operations
            local long_running=$($mongo_cmd --quiet --eval "db.currentOp({secs_running: {\$gte: 30}}).inprog.length" 2>/dev/null)
            if [[ -n "$long_running" ]] && (( long_running > 0 )); then
                log_bottleneck "Database" "Long-running MongoDB operations detected (>30s)" "Yes" "30s" "High"
            fi
        fi
    fi
    
    # Cassandra Detection
    if pgrep -f "org.apache.cassandra" >/dev/null 2>&1; then
        databases_found=true
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== Cassandra Detected ===" | tee -a "$OUTPUT_FILE"
        
        # Process info
        ps aux | grep "[o]rg.apache.cassandra" | awk '{printf "  Process: PID %s, CPU: %s%%, MEM: %s%%\n", $2, $3, $4}' | tee -a "$OUTPUT_FILE"
        
        # Connection count (native transport port)
        local cass_conns=$(netstat -ant 2>/dev/null | grep :9042 | grep ESTABLISHED | wc -l || echo "0")
        echo "  Active Connections: ${cass_conns}" | tee -a "$OUTPUT_FILE"
        
        if (( cass_conns > 1000 )); then
            log_bottleneck "Database" "High Cassandra connection count" "${cass_conns}" "1000" "Medium"
        fi
        
        # Check data directory size
        if [[ -d /var/lib/cassandra ]]; then
            local cass_size=$(du -sh /var/lib/cassandra 2>/dev/null | awk '{print $1}')
            echo "  Data Directory Size: ${cass_size}" | tee -a "$OUTPUT_FILE"
        fi
    fi
    
    # Redis Detection
    if pgrep -x redis-server >/dev/null 2>&1; then
        databases_found=true
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== Redis Detected ===" | tee -a "$OUTPUT_FILE"
        
        # Process info
        ps aux | grep "[r]edis-server" | awk '{printf "  Process: PID %s, CPU: %s%%, MEM: %s%%\n", $2, $3, $4}' | tee -a "$OUTPUT_FILE"
        
        # Connection count
        local redis_conns=$(netstat -ant 2>/dev/null | grep :6379 | grep ESTABLISHED | wc -l || echo "0")
        echo "  Active Connections: ${redis_conns}" | tee -a "$OUTPUT_FILE"
        
        if (( redis_conns > 10000 )); then
            log_bottleneck "Database" "High Redis connection count" "${redis_conns}" "10000" "Medium"
        fi
        
        # Redis Performance Analysis
        if command -v redis-cli >/dev/null 2>&1; then
            echo "" | tee -a "$OUTPUT_FILE"
            echo "  Redis Performance Metrics:" | tee -a "$OUTPUT_FILE"
            
            local redis_stats=$(redis-cli INFO stats 2>/dev/null)
            local total_commands=$(echo "$redis_stats" | grep "total_commands_processed:" | cut -d: -f2 | tr -d '\r')
            local ops_per_sec=$(echo "$redis_stats" | grep "instantaneous_ops_per_sec:" | cut -d: -f2 | tr -d '\r')
            local rejected_conns=$(echo "$redis_stats" | grep "rejected_connections:" | cut -d: -f2 | tr -d '\r')
            
            echo "  Total Commands: ${total_commands} | Ops/sec: ${ops_per_sec} | Rejected Connections: ${rejected_conns}" | tee -a "$OUTPUT_FILE"
            
            echo "  Top 5 Slow Commands:" | tee -a "$OUTPUT_FILE"
            redis-cli SLOWLOG GET 5 2>/dev/null | tee -a "$OUTPUT_FILE" || echo "  Unable to query Redis slowlog" | tee -a "$OUTPUT_FILE"
            
            if [[ -n "$rejected_conns" ]] && (( rejected_conns > 0 )); then
                log_bottleneck "Database" "Redis connection rejections detected" "${rejected_conns}" "0" "High"
            fi
        fi
    fi
    
    # Oracle Detection
    if pgrep -x oracle >/dev/null 2>&1 || pgrep -f "ora_pmon" >/dev/null 2>&1; then
        databases_found=true
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== Oracle Database Detected ===" | tee -a "$OUTPUT_FILE"
        
        # Process info
        ps aux | grep "[o]ra_pmon" | awk '{printf "  Process: PID %s, CPU: %s%%, MEM: %s%%\n", $2, $3, $4}' | tee -a "$OUTPUT_FILE"
        
        # Connection count (default listener port)
        local oracle_conns=$(netstat -ant 2>/dev/null | grep :1521 | grep ESTABLISHED | wc -l || echo "0")
        echo "  Active Connections: ${oracle_conns}" | tee -a "$OUTPUT_FILE"
        
        if (( oracle_conns > 500 )); then
            log_bottleneck "Database" "High Oracle connection count" "${oracle_conns}" "500" "Medium"
        fi
        
        # Oracle Query Analysis
        if command -v sqlplus >/dev/null 2>&1; then
            echo "" | tee -a "$OUTPUT_FILE"
            echo "  Oracle Query Analysis:" | tee -a "$OUTPUT_FILE"
            
            # Active sessions query
            echo "SELECT sid, serial#, username, status, ROUND(last_call_et/60, 2) AS duration_min, sql_id, blocking_session, event FROM v\$session WHERE status = 'ACTIVE' AND username IS NOT NULL ORDER BY last_call_et DESC FETCH FIRST 5 ROWS ONLY;" | sqlplus -S / as sysdba 2>/dev/null | tee -a "$OUTPUT_FILE" || echo "  Unable to query Oracle (requires sqlplus and authentication)" | tee -a "$OUTPUT_FILE"
            
            # Top queries by elapsed time
            echo "SELECT sql_id, executions, ROUND(elapsed_time/1000000, 2) AS total_time_sec, ROUND(cpu_time/1000000, 2) AS cpu_time_sec, ROUND(buffer_gets/NULLIF(executions,0), 0) AS avg_buffer_gets FROM v\$sql ORDER BY elapsed_time DESC FETCH FIRST 5 ROWS ONLY;" | sqlplus -S / as sysdba 2>/dev/null | tee -a "$OUTPUT_FILE"
            
            # Check for long-running sessions
            local long_running=$(echo "SELECT COUNT(*) FROM v\$session WHERE status = 'ACTIVE' AND username IS NOT NULL AND last_call_et > 1800;" | sqlplus -S / as sysdba 2>/dev/null | grep -o '[0-9]*' | head -1)
            if [[ -n "$long_running" ]] && (( long_running > 0 )); then
                log_bottleneck "Database" "Long-running Oracle sessions detected (>30min)" "Yes" "30min" "High"
            fi
            
            # DMS-specific checks for Oracle
            echo "" | tee -a "$OUTPUT_FILE"
            echo "  DMS Migration Readiness:" | tee -a "$OUTPUT_FILE"
            
            # Check archive log mode (required for CDC)
            local log_mode=$(echo "SELECT log_mode FROM v\$database;" | sqlplus -S / as sysdba 2>/dev/null | grep -E "ARCHIVELOG|NOARCHIVELOG" | tr -d ' ')
            echo "    Archive Log Mode: ${log_mode:-Unknown}" | tee -a "$OUTPUT_FILE"
            if [[ "$log_mode" != "ARCHIVELOG" ]]; then
                log_bottleneck "DMS" "Oracle not in ARCHIVELOG mode - required for DMS CDC" "${log_mode}" "ARCHIVELOG" "High"
            fi
            
            # Check supplemental logging
            local supp_log=$(echo "SELECT supplemental_log_data_min FROM v\$database;" | sqlplus -S / as sysdba 2>/dev/null | grep -E "YES|NO" | tr -d ' ')
            echo "    Supplemental Logging: ${supp_log:-Unknown}" | tee -a "$OUTPUT_FILE"
            if [[ "$supp_log" != "YES" ]]; then
                log_bottleneck "DMS" "Oracle supplemental logging not enabled - required for DMS CDC" "${supp_log}" "YES" "High"
            fi
            
            # Check for standby lag (if Data Guard)
            local standby_lag=$(echo "SELECT MAX(ROUND((SYSDATE - applied_time) * 24 * 60)) FROM v\$archived_log WHERE applied = 'YES';" | sqlplus -S / as sysdba 2>/dev/null | grep -o '[0-9]*' | head -1)
            if [[ -n "$standby_lag" ]] && (( standby_lag > 0 )); then
                echo "    Standby Apply Lag: ${standby_lag} minutes" | tee -a "$OUTPUT_FILE"
                if (( standby_lag > 30 )); then
                    log_bottleneck "Database" "High Oracle standby apply lag" "${standby_lag}min" "30min" "Medium"
                fi
            fi
        fi
    fi
    
    # Microsoft SQL Server Detection (Linux)
    if pgrep -x sqlservr >/dev/null 2>&1; then
        databases_found=true
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== SQL Server Detected ===" | tee -a "$OUTPUT_FILE"
        
        # Process info
        ps aux | grep "[s]qlservr" | awk '{printf "  Process: PID %s, CPU: %s%%, MEM: %s%%\n", $2, $3, $4}' | tee -a "$OUTPUT_FILE"
        
        # Connection count
        local mssql_conns=$(netstat -ant 2>/dev/null | grep :1433 | grep ESTABLISHED | wc -l || echo "0")
        echo "  Active Connections: ${mssql_conns}" | tee -a "$OUTPUT_FILE"
        
        if (( mssql_conns > 500 )); then
            log_bottleneck "Database" "High SQL Server connection count" "${mssql_conns}" "500" "Medium"
        fi
        
        # SQL Server Query Analysis
        if command -v sqlcmd >/dev/null 2>&1; then
            echo "" | tee -a "$OUTPUT_FILE"
            echo "  SQL Server Query Analysis:" | tee -a "$OUTPUT_FILE"
            
            sqlcmd -S localhost -E -Q "SELECT TOP 5 qs.execution_count AS [Executions], qs.total_worker_time / 1000 AS [Total CPU (ms)], qs.total_worker_time / qs.execution_count / 1000 AS [Avg CPU (ms)], qs.total_elapsed_time / 1000 AS [Total Duration (ms)], SUBSTRING(qt.text, (qs.statement_start_offset/2)+1, ((CASE qs.statement_end_offset WHEN -1 THEN DATALENGTH(qt.text) ELSE qs.statement_end_offset END - qs.statement_start_offset)/2) + 1) AS [Query Text] FROM sys.dm_exec_query_stats qs CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) qt ORDER BY qs.total_worker_time DESC;" -h -1 -W 2>/dev/null | tee -a "$OUTPUT_FILE" || echo "  Unable to query SQL Server DMVs (requires authentication)" | tee -a "$OUTPUT_FILE"
            
            sqlcmd -S localhost -E -Q "SELECT r.session_id, r.status, r.command, r.cpu_time, r.total_elapsed_time, r.wait_type, r.wait_time, r.blocking_session_id, SUBSTRING(qt.text, (r.statement_start_offset/2)+1, ((CASE r.statement_end_offset WHEN -1 THEN DATALENGTH(qt.text) ELSE r.statement_end_offset END - r.statement_start_offset)/2) + 1) AS [Current Query] FROM sys.dm_exec_requests r CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) qt WHERE r.session_id > 50 ORDER BY r.total_elapsed_time DESC;" -h -1 -W 2>/dev/null | tee -a "$OUTPUT_FILE"
            
            # Check for long-running queries
            local long_running=$(sqlcmd -S localhost -E -Q "SELECT COUNT(*) FROM sys.dm_exec_requests WHERE total_elapsed_time > 30000;" -h -1 -W 2>/dev/null | tail -1 | tr -d ' ')
            if [[ -n "$long_running" ]] && (( long_running > 0 )); then
                log_bottleneck "Database" "Long-running SQL queries detected (>30s)" "Yes" "30s" "High"
            fi
            
            # DMS-specific checks for SQL Server
            echo "" | tee -a "$OUTPUT_FILE"
            echo "  DMS Migration Readiness:" | tee -a "$OUTPUT_FILE"
            
            # Check if SQL Server Agent is running (required for CDC)
            local agent_status=$(sqlcmd -S localhost -E -Q "SELECT CASE WHEN EXISTS (SELECT 1 FROM sys.dm_server_services WHERE servicename LIKE '%Agent%' AND status_desc = 'Running') THEN 'Running' ELSE 'Stopped' END AS AgentStatus;" -h -1 -W 2>/dev/null | tail -1 | tr -d ' ')
            echo "    SQL Server Agent: ${agent_status:-Unknown}" | tee -a "$OUTPUT_FILE"
            if [[ "$agent_status" != "Running" ]]; then
                log_bottleneck "DMS" "SQL Server Agent not running - required for DMS CDC" "${agent_status}" "Running" "High"
            fi
            
            # Check if database is in FULL recovery model (required for CDC)
            local recovery_model=$(sqlcmd -S localhost -E -Q "SELECT name, recovery_model_desc FROM sys.databases WHERE name NOT IN ('master','model','msdb','tempdb');" -h -1 -W 2>/dev/null | grep -v "^$" | head -5 | tee -a "$OUTPUT_FILE")
            if echo "$recovery_model" | grep -q "SIMPLE"; then
                log_bottleneck "DMS" "SQL Server database(s) in SIMPLE recovery - DMS CDC requires FULL" "SIMPLE" "FULL" "High"
            fi
            
            # Check for AlwaysOn lag (if replica)
            local replica_lag=$(sqlcmd -S localhost -E -Q "SELECT ar.replica_server_name, drs.synchronization_state_desc, drs.log_send_queue_size, drs.redo_queue_size FROM sys.dm_hadr_database_replica_states drs INNER JOIN sys.availability_replicas ar ON drs.replica_id = ar.replica_id WHERE drs.is_local = 1;" -h -1 -W 2>/dev/null | grep -v "^$" | head -5)
            if [[ -n "$replica_lag" ]]; then
                echo "    AlwaysOn Replica Status:" | tee -a "$OUTPUT_FILE"
                echo "$replica_lag" | tee -a "$OUTPUT_FILE"
            fi
        fi
    fi
    
    # Elasticsearch Detection
    if pgrep -f "org.elasticsearch" >/dev/null 2>&1; then
        databases_found=true
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== Elasticsearch Detected ===" | tee -a "$OUTPUT_FILE"
        
        # Process info
        ps aux | grep "[o]rg.elasticsearch" | awk '{printf "  Process: PID %s, CPU: %s%%, MEM: %s%%\n", $2, $3, $4}' | tee -a "$OUTPUT_FILE"
        
        # Connection count
        local es_conns=$(netstat -ant 2>/dev/null | grep :9200 | grep ESTABLISHED | wc -l || echo "0")
        echo "  Active Connections: ${es_conns}" | tee -a "$OUTPUT_FILE"
        
        # Elasticsearch Query Analysis
        if command -v curl >/dev/null 2>&1; then
            echo "" | tee -a "$OUTPUT_FILE"
            echo "  Elasticsearch Performance Analysis:" | tee -a "$OUTPUT_FILE"
            
            # Get current tasks
            local es_tasks=$(curl -s "http://localhost:9200/_tasks?detailed=true&actions=*search*" 2>/dev/null)
            if [[ -n "$es_tasks" ]]; then
                echo "  Active Search Tasks:" | tee -a "$OUTPUT_FILE"
                echo "$es_tasks" | grep -o '"running_time_in_nanos":[0-9]*' | head -5 | tee -a "$OUTPUT_FILE"
                
                # Check for long-running queries
                local long_running=$(echo "$es_tasks" | grep -o '"running_time_in_nanos":[0-9]*' | awk -F: '{if ($2 > 30000000000) print $2}' | wc -l)
                if (( long_running > 0 )); then
                    log_bottleneck "Database" "Long-running Elasticsearch queries detected (>30s)" "Yes" "30s" "High"
                fi
            fi
            
            # Get thread pool stats
            echo "  Thread Pool Status:" | tee -a "$OUTPUT_FILE"
            curl -s "http://localhost:9200/_cat/thread_pool?v&h=node_name,name,active,queue,rejected" 2>/dev/null | tee -a "$OUTPUT_FILE" || echo "  Unable to query Elasticsearch API (requires HTTP access to localhost:9200)" | tee -a "$OUTPUT_FILE"
            
            # Check for rejections
            local rejections=$(curl -s "http://localhost:9200/_cat/thread_pool?h=rejected" 2>/dev/null | awk '{sum+=$1} END {print sum}')
            if [[ -n "$rejections" ]] && (( rejections > 0 )); then
                log_bottleneck "Database" "Elasticsearch thread pool rejections detected" "${rejections}" "0" "High"
            fi
        fi
    fi
    
    # General database connection analysis
    if [[ "$databases_found" == true ]]; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== Database Connection Summary ===" | tee -a "$OUTPUT_FILE"
        
        # Check for connection pool exhaustion indicators
        local total_db_conns=$(netstat -ant 2>/dev/null | grep -E ":3306|:5432|:27017|:9042|:6379|:1521|:1433|:9200" | grep ESTABLISHED | wc -l || echo "0")
        echo "Total Database Connections: ${total_db_conns}" | tee -a "$OUTPUT_FILE"
        
        # Check for TIME_WAIT on database ports (connection churn)
        local db_time_wait=$(netstat -ant 2>/dev/null | grep -E ":3306|:5432|:27017|:9042|:6379|:1521|:1433|:9200" | grep TIME_WAIT | wc -l || echo "0")
        if (( db_time_wait > 1000 )); then
            echo "  ⚠️  High TIME_WAIT on database ports: ${db_time_wait}" | tee -a "$OUTPUT_FILE"
            log_bottleneck "Database" "High connection churn (TIME_WAIT)" "${db_time_wait}" "1000" "Medium"
        fi
        
        log_success "Database forensics completed"
    else
        log_info "No common database processes detected"
    fi
}

#############################################################################
# Network Forensics
#############################################################################

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
