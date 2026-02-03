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
    
    # Detect Unix variants with detailed version info
    if [[ "$uname_s" == "AIX" ]]; then
        DISTRO="aix"
        OS_VERSION=$(oslevel 2>/dev/null || echo "unknown")
        OS_VERSION_MAJOR=$(echo "$OS_VERSION" | cut -d. -f1)
        # Get TL (Technology Level) for AIX
        OS_TL=$(oslevel -s 2>/dev/null | cut -d- -f2 || echo "unknown")
        OS_NAME="AIX $OS_VERSION (TL $OS_TL)"
        
        # AIX version-specific notes
        log_info "AIX Version Details:"
        log_info "  OS Level: $OS_VERSION"
        log_info "  Technology Level: $OS_TL"
        oslevel -s 2>/dev/null && log_info "  Service Pack: $(oslevel -s)"
        
    elif [[ "$uname_s" == "HP-UX" ]]; then
        DISTRO="hpux"
        OS_VERSION=$(uname -r)
        OS_VERSION_MAJOR=$(echo "$OS_VERSION" | cut -d. -f2)
        OS_NAME="HP-UX $OS_VERSION"
        
        # HP-UX 11.31 (11i v3) vs 11.23 (11i v2) have different tools
        if [[ "$OS_VERSION" == "B.11.31" ]]; then
            OS_VARIANT="11i v3"
        elif [[ "$OS_VERSION" == "B.11.23" ]]; then
            OS_VARIANT="11i v2"
        elif [[ "$OS_VERSION" == "B.11.11" ]]; then
            OS_VARIANT="11i v1"
        else
            OS_VARIANT="unknown"
        fi
        log_info "HP-UX Variant: $OS_VARIANT"
        
    elif [[ "$uname_s" == "SunOS" ]]; then
        OS_VERSION=$(uname -r)
        OS_VERSION_MAJOR=$(echo "$OS_VERSION" | cut -d. -f2)
        
        # Distinguish Solaris versions and derivatives
        if [[ -f /etc/release ]]; then
            local release_info=$(cat /etc/release | head -1)
            
            if grep -qi "openindiana" /etc/release; then
                DISTRO="openindiana"
                OS_NAME="OpenIndiana $(grep -oE '[0-9]+\.[0-9]+' /etc/release | head -1)"
            elif grep -qi "omnios" /etc/release; then
                DISTRO="omnios"
                OS_NAME="OmniOS $(grep -oE 'r[0-9]+' /etc/release | head -1)"
            elif grep -qi "smartos" /etc/release; then
                DISTRO="smartos"
                OS_NAME="SmartOS"
            elif grep -qi "illumos" /etc/release; then
                DISTRO="illumos"
                OS_NAME="Illumos"
            elif grep -qi "Oracle Solaris 11" /etc/release; then
                DISTRO="solaris11"
                OS_NAME="Oracle Solaris 11"
            elif grep -qi "Oracle Solaris 10" /etc/release; then
                DISTRO="solaris10"
                OS_NAME="Oracle Solaris 10"
            else
                DISTRO="solaris"
                OS_NAME="$release_info"
            fi
        else
            DISTRO="solaris"
            OS_NAME="SunOS $OS_VERSION"
        fi
        
        log_info "Solaris/Illumos Details:"
        log_info "  Kernel: SunOS $OS_VERSION"
        log_info "  Distribution: $OS_NAME"
        
    elif [[ -f /etc/os-release ]]; then
        # Linux fallback (shouldn't happen, but just in case)
        . /etc/os-release
        DISTRO="$ID"
        OS_VERSION="$VERSION_ID"
        OS_VERSION_MAJOR=$(echo "$OS_VERSION" | cut -d. -f1)
        OS_NAME="${PRETTY_NAME:-$ID}"
    else
        DISTRO="unknown"
        OS_VERSION="unknown"
        OS_VERSION_MAJOR="0"
        OS_NAME="Unknown Unix"
    fi
    
    # Determine package manager based on distro and version
    case "$DISTRO" in
        aix)
            # AIX 7.2+ often has dnf/yum from AIX Toolbox
            if command -v dnf >/dev/null 2>&1; then
                PACKAGE_MANAGER="dnf"
            elif command -v yum >/dev/null 2>&1; then
                PACKAGE_MANAGER="yum"
            elif command -v rpm >/dev/null 2>&1; then
                PACKAGE_MANAGER="rpm"
            else
                PACKAGE_MANAGER="installp"
            fi
            ;;
        hpux)
            # HP-UX uses swinstall/swlist, or SD-UX
            if command -v swinstall >/dev/null 2>&1; then
                PACKAGE_MANAGER="swinstall"
            else
                PACKAGE_MANAGER="manual"
            fi
            ;;
        solaris11|openindiana|omnios)
            # Solaris 11 and Illumos derivatives use IPS (pkg)
            PACKAGE_MANAGER="pkg"
            ;;
        solaris10|solaris)
            # Solaris 10 and older use pkgadd
            if command -v pkg >/dev/null 2>&1; then
                PACKAGE_MANAGER="pkg"
            else
                PACKAGE_MANAGER="pkgadd"
            fi
            ;;
        smartos)
            # SmartOS uses pkgin
            PACKAGE_MANAGER="pkgin"
            ;;
        *)
            PACKAGE_MANAGER="manual"
            ;;
    esac
}

# Check if a command exists, with OS-specific alternatives
check_unix_tool() {
    local tool="$1"
    local alt_tool=""
    
    # Check primary tool
    if command -v "$tool" >/dev/null 2>&1; then
        echo "$tool"
        return 0
    fi
    
    # OS-specific alternatives
    case "$DISTRO" in
        aix)
            case "$tool" in
                lsblk) alt_tool="lspv" ;;
                smartctl) alt_tool="" ;;  # No direct equivalent
                fdisk) alt_tool="lspv" ;;
                df) alt_tool="df" ;;  # Always available
            esac
            ;;
        hpux)
            case "$tool" in
                lsblk) alt_tool="ioscan" ;;
                smartctl) alt_tool="" ;;
                fdisk) alt_tool="ioscan" ;;
                pvs) alt_tool="pvdisplay" ;;
                vgs) alt_tool="vgdisplay" ;;
                lvs) alt_tool="lvdisplay" ;;
            esac
            ;;
        solaris*|illumos|openindiana|omnios|smartos)
            case "$tool" in
                lsblk) alt_tool="format" ;;
                smartctl) alt_tool="" ;;
                fdisk) alt_tool="format" ;;
                pvs) alt_tool="" ;;  # Use zpool on Solaris
            esac
            ;;
    esac
    
    if [[ -n "$alt_tool" ]] && command -v "$alt_tool" >/dev/null 2>&1; then
        echo "$alt_tool"
        return 0
    fi
    
    return 1
}

# Get installation instructions for a tool on this Unix
get_install_instructions() {
    local tool="$1"
    
    case "$DISTRO" in
        aix)
            case "$tool" in
                smartctl)
                    echo "Download from AIX Toolbox: https://www.ibm.com/support/pages/aix-toolbox-linux-applications"
                    echo "  rpm -ivh smartmontools-*.rpm"
                    ;;
                *)
                    echo "Install from AIX Toolbox or use: installp -aXgd /path/to/package $tool"
                    ;;
            esac
            ;;
        hpux)
            echo "Install from HP-UX Software Depot:"
            echo "  swinstall -s /path/to/depot $tool"
            echo "Or download from HP Software Depot: https://h20392.www2.hpe.com/portal/swdepot/"
            ;;
        solaris11|openindiana|omnios)
            echo "Install using IPS:"
            echo "  pkg install $tool"
            ;;
        solaris10|solaris)
            echo "Install using pkgadd:"
            echo "  pkgadd -d /path/to/package $tool"
            echo "Or use OpenCSW: https://www.opencsw.org/"
            echo "  pkgutil -i $tool"
            ;;
        smartos)
            echo "Install using pkgin:"
            echo "  pkgin install $tool"
            ;;
        *)
            echo "Please install $tool using your system's package manager"
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

#############################################################################
# Storage Profiling
#############################################################################

analyze_storage_profile() {
    print_header "STORAGE PROFILING"
    
    log_info "Performing comprehensive storage analysis..."
    log_info "OS: ${OS_NAME:-$DISTRO} (Version: ${OS_VERSION:-unknown})"
    
    # ==========================================================================
    # CHECK AVAILABLE TOOLS FOR THIS UNIX VARIANT
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- CHECKING STORAGE TOOLS ---" | tee -a "$OUTPUT_FILE"
    
    local missing_tools=()
    
    case "$DISTRO" in
        aix)
            echo "AIX Storage Tools:" | tee -a "$OUTPUT_FILE"
            for tool in lspv lsvg lslv lspath iostat; do
                if command -v "$tool" >/dev/null 2>&1; then
                    echo "  [OK] $tool" | tee -a "$OUTPUT_FILE"
                else
                    echo "  [MISSING] $tool" | tee -a "$OUTPUT_FILE"
                    missing_tools+=("$tool")
                fi
            done
            
            # Check for optional tools
            for tool in fcstat; do
                if command -v "$tool" >/dev/null 2>&1; then
                    echo "  [OK] $tool (optional)" | tee -a "$OUTPUT_FILE"
                else
                    echo "  [N/A] $tool (optional - Fibre Channel)" | tee -a "$OUTPUT_FILE"
                fi
            done
            ;;
        hpux)
            echo "HP-UX Storage Tools:" | tee -a "$OUTPUT_FILE"
            for tool in ioscan pvdisplay vgdisplay lvdisplay bdf iostat; do
                if command -v "$tool" >/dev/null 2>&1; then
                    echo "  [OK] $tool" | tee -a "$OUTPUT_FILE"
                else
                    echo "  [MISSING] $tool" | tee -a "$OUTPUT_FILE"
                    missing_tools+=("$tool")
                fi
            done
            
            # Check for HP-UX 11i v3 specific tools
            if [[ "$OS_VARIANT" == "11i v3" ]]; then
                for tool in scsimgr; do
                    if command -v "$tool" >/dev/null 2>&1; then
                        echo "  [OK] $tool (11i v3)" | tee -a "$OUTPUT_FILE"
                    else
                        echo "  [N/A] $tool (11i v3 only)" | tee -a "$OUTPUT_FILE"
                    fi
                done
            fi
            ;;
        solaris*|illumos|openindiana|omnios|smartos)
            echo "Solaris/Illumos Storage Tools:" | tee -a "$OUTPUT_FILE"
            for tool in zpool zfs iostat format; do
                if command -v "$tool" >/dev/null 2>&1; then
                    echo "  [OK] $tool" | tee -a "$OUTPUT_FILE"
                else
                    echo "  [MISSING] $tool" | tee -a "$OUTPUT_FILE"
                    missing_tools+=("$tool")
                fi
            done
            
            # Check for optional/newer tools
            for tool in fcinfo mpathadm diskinfo; do
                if command -v "$tool" >/dev/null 2>&1; then
                    echo "  [OK] $tool (optional)" | tee -a "$OUTPUT_FILE"
                else
                    echo "  [N/A] $tool (optional)" | tee -a "$OUTPUT_FILE"
                fi
            done
            
            # Solaris 11 specific
            if [[ "$DISTRO" == "solaris11" ]]; then
                for tool in croinfo; do
                    if command -v "$tool" >/dev/null 2>&1; then
                        echo "  [OK] $tool (Solaris 11)" | tee -a "$OUTPUT_FILE"
                    fi
                done
            fi
            ;;
    esac
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo "" | tee -a "$OUTPUT_FILE"
        log_warning "Some storage tools are missing. Install instructions:"
        for tool in "${missing_tools[@]}"; do
            get_install_instructions "$tool" | tee -a "$OUTPUT_FILE"
        done
    fi
    
    # ==========================================================================
    # RUN OS-SPECIFIC STORAGE PROFILING
    # ==========================================================================
    
    case "$DISTRO" in
        aix)
            analyze_storage_profile_aix
            ;;
        hpux)
            analyze_storage_profile_hpux
            ;;
        solaris|illumos)
            analyze_storage_profile_solaris
            ;;
        *)
            log_warning "Storage profiling not implemented for ${DISTRO}"
            ;;
    esac
    
    log_success "Storage profiling completed"
}

analyze_storage_profile_aix() {
    # ==========================================================================
    # DISK LABELING / PARTITION SCHEME - AIX
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- DISK LABELING (AIX) ---" | tee -a "$OUTPUT_FILE"
    
    # AIX uses LVM exclusively - no MBR/GPT concept
    # Disks are Physical Volumes (PVs) managed by LVM
    echo "" | tee -a "$OUTPUT_FILE"
    echo "AIX Disk Management:" | tee -a "$OUTPUT_FILE"
    echo "  AIX uses Logical Volume Manager (LVM) exclusively" | tee -a "$OUTPUT_FILE"
    echo "  Disks are 'Physical Volumes' (PVs) in 'Volume Groups' (VGs)" | tee -a "$OUTPUT_FILE"
    echo "  No MBR/GPT partition table concept - LVM handles all disk layout" | tee -a "$OUTPUT_FILE"
    
    # Check boot device type
    if command -v bootinfo >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Boot Configuration:" | tee -a "$OUTPUT_FILE"
        local boot_type=$(bootinfo -T 2>/dev/null)
        echo "  Boot Type: $boot_type" | tee -a "$OUTPUT_FILE"
        
        local boot_disk=$(bootinfo -b 2>/dev/null)
        echo "  Boot Disk: $boot_disk" | tee -a "$OUTPUT_FILE"
        
        # Check if booted from SAN
        if bootinfo -q 2>/dev/null | grep -qi "san\|fc"; then
            echo "  Boot Source: SAN (Fibre Channel)" | tee -a "$OUTPUT_FILE"
        else
            echo "  Boot Source: Local Disk" | tee -a "$OUTPUT_FILE"
        fi
    fi
    
    # ==========================================================================
    # STORAGE TOPOLOGY - AIX
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- STORAGE TOPOLOGY ---" | tee -a "$OUTPUT_FILE"
    
    # Physical Volumes
    if command -v lspv >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Physical Volumes:" | tee -a "$OUTPUT_FILE"
        lspv | tee -a "$OUTPUT_FILE"
        
        # Detailed PV info
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Physical Volume Details:" | tee -a "$OUTPUT_FILE"
        for pv in $(lspv | awk '{print $1}'); do
            echo "  === $pv ===" | tee -a "$OUTPUT_FILE"
            lspv "$pv" 2>/dev/null | grep -E "PHYSICAL VOLUME|PV STATE|TOTAL PPs|FREE PPs|PP SIZE" | tee -a "$OUTPUT_FILE"
        done
    fi
    
    # Volume Groups
    if command -v lsvg >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Volume Groups:" | tee -a "$OUTPUT_FILE"
        lsvg | tee -a "$OUTPUT_FILE"
        
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Volume Group Details:" | tee -a "$OUTPUT_FILE"
        for vg in $(lsvg); do
            echo "  === $vg ===" | tee -a "$OUTPUT_FILE"
            lsvg "$vg" 2>/dev/null | grep -E "VG STATE|PP SIZE|TOTAL PPs|FREE PPs|QUORUM" | tee -a "$OUTPUT_FILE"
            
            # Check for quorum issues
            local quorum=$(lsvg "$vg" 2>/dev/null | grep "QUORUM" | awk '{print $2}')
            if [[ "$quorum" != "2" ]]; then
                log_bottleneck "Storage" "Volume Group $vg quorum issue" "$quorum" "2" "High"
            fi
        done
        
        # Logical Volumes
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Logical Volumes:" | tee -a "$OUTPUT_FILE"
        for vg in $(lsvg); do
            lsvg -l "$vg" 2>/dev/null | tee -a "$OUTPUT_FILE"
        done
    fi
    
    # ==========================================================================
    # STORAGE TIERING - AIX
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- STORAGE TIERING ---" | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Disk Types and Attributes:" | tee -a "$OUTPUT_FILE"
    
    local ssd_count=0
    local hdd_count=0
    
    for pv in $(lspv | awk '{print $1}'); do
        local disk_type="Unknown"
        local size=""
        
        # Get disk size
        size=$(lspv "$pv" 2>/dev/null | grep "TOTAL PPs" | awk '{print $3}')
        local pp_size=$(lspv "$pv" 2>/dev/null | grep "PP SIZE" | awk '{print $3}')
        
        # Check if SSD (via lsattr if available)
        if command -v lsattr >/dev/null 2>&1; then
            local queue_depth=$(lsattr -El "$pv" 2>/dev/null | grep queue_depth | awk '{print $2}')
            # SSDs typically have higher queue depths configured
            if [[ -n "$queue_depth" ]] && (( queue_depth > 32 )); then
                disk_type="SSD (likely)"
                ((ssd_count++))
            else
                disk_type="HDD (likely)"
                ((hdd_count++))
            fi
        fi
        
        echo "  $pv: $disk_type - ${size:-Unknown} PPs (${pp_size:-Unknown} MB each)" | tee -a "$OUTPUT_FILE"
    done
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Storage Tier Summary: SSD=$ssd_count, HDD=$hdd_count" | tee -a "$OUTPUT_FILE"
    
    # ==========================================================================
    # SAN/MULTIPATH - AIX
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- SAN/MULTIPATH DETECTION ---" | tee -a "$OUTPUT_FILE"
    
    # MPIO/PowerPath detection
    if command -v lspath >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Multipath Configuration:" | tee -a "$OUTPUT_FILE"
        lspath | tee -a "$OUTPUT_FILE"
        
        # Check for failed paths
        local failed_paths=$(lspath 2>/dev/null | grep -c "Failed" || echo "0")
        if (( failed_paths > 0 )); then
            log_bottleneck "Storage" "Failed multipath paths detected" "$failed_paths" "0" "Critical"
        fi
    fi
    
    # Fibre Channel adapters
    if command -v lsdev >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Fibre Channel Adapters:" | tee -a "$OUTPUT_FILE"
        lsdev -Cc adapter | grep -i "fcs\|fscsi" | tee -a "$OUTPUT_FILE" || echo "  No FC adapters found" | tee -a "$OUTPUT_FILE"
    fi
    
    # ==========================================================================
    # CAPACITY PROFILING - AIX
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- CAPACITY PROFILING ---" | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Filesystem Capacity:" | tee -a "$OUTPUT_FILE"
    df -g | tee -a "$OUTPUT_FILE"
    
    # Inode usage
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Inode Usage:" | tee -a "$OUTPUT_FILE"
    df -i | tee -a "$OUTPUT_FILE"
    
    # Large files
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Top 10 Directories by Size (/):" | tee -a "$OUTPUT_FILE"
    du -sg /* 2>/dev/null | sort -rn | head -10 | tee -a "$OUTPUT_FILE"
    
    # ==========================================================================
    # PERFORMANCE BASELINE - AIX
    # ==========================================================================
    if [[ "$MODE" == "deep" ]] || [[ "$MODE" == "disk" ]]; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "--- STORAGE PERFORMANCE BASELINE ---" | tee -a "$OUTPUT_FILE"
        
        log_info "Running I/O performance tests..."
        
        local test_file="/tmp/storage_test_$$"
        
        # Write test
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Sequential Write Test:" | tee -a "$OUTPUT_FILE"
        local write_result=$(dd if=/dev/zero of="$test_file" bs=1M count=512 2>&1)
        echo "$write_result" | grep -E "bytes|MB/s" | tee -a "$OUTPUT_FILE"
        
        # Read test
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Sequential Read Test:" | tee -a "$OUTPUT_FILE"
        sync
        local read_result=$(dd if="$test_file" of=/dev/null bs=1M 2>&1)
        echo "$read_result" | grep -E "bytes|MB/s" | tee -a "$OUTPUT_FILE"
        
        rm -f "$test_file"
    fi
}

analyze_storage_profile_hpux() {
    # ==========================================================================
    # DISK LABELING / PARTITION SCHEME - HP-UX
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- DISK LABELING (HP-UX) ---" | tee -a "$OUTPUT_FILE"
    
    # HP-UX uses LVM similar to AIX, but also supports whole-disk
    echo "" | tee -a "$OUTPUT_FILE"
    echo "HP-UX Disk Management:" | tee -a "$OUTPUT_FILE"
    echo "  HP-UX primarily uses LVM (Logical Volume Manager)" | tee -a "$OUTPUT_FILE"
    echo "  Supports both LVM and whole-disk filesystems" | tee -a "$OUTPUT_FILE"
    
    # Check boot configuration
    if command -v setboot >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Boot Configuration:" | tee -a "$OUTPUT_FILE"
        setboot 2>/dev/null | tee -a "$OUTPUT_FILE"
    fi
    
    # Check for EFI (Itanium) vs PARISC boot
    local arch=$(uname -m)
    echo "" | tee -a "$OUTPUT_FILE"
    if [[ "$arch" == "ia64" ]]; then
        echo "  Architecture: Itanium (IA-64) - EFI Boot" | tee -a "$OUTPUT_FILE"
        # EFI partition info
        if command -v efi >/dev/null 2>&1; then
            echo "  EFI Partitions:" | tee -a "$OUTPUT_FILE"
            efi -l 2>/dev/null | tee -a "$OUTPUT_FILE"
        fi
    else
        echo "  Architecture: PA-RISC - PDC Boot" | tee -a "$OUTPUT_FILE"
    fi
    
    # ==========================================================================
    # STORAGE TOPOLOGY - HP-UX
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- STORAGE TOPOLOGY ---" | tee -a "$OUTPUT_FILE"
    
    # Disk devices
    if command -v ioscan >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Disk Devices:" | tee -a "$OUTPUT_FILE"
        ioscan -funC disk | tee -a "$OUTPUT_FILE"
    fi
    
    # LVM - Physical Volumes
    if command -v pvdisplay >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Physical Volumes:" | tee -a "$OUTPUT_FILE"
        pvdisplay 2>/dev/null | grep -E "PV Name|PV Status|Total PE|Free PE" | tee -a "$OUTPUT_FILE"
    fi
    
    # LVM - Volume Groups
    if command -v vgdisplay >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Volume Groups:" | tee -a "$OUTPUT_FILE"
        vgdisplay 2>/dev/null | grep -E "VG Name|VG Status|Total PE|Free PE|PE Size" | tee -a "$OUTPUT_FILE"
    fi
    
    # LVM - Logical Volumes
    if command -v lvdisplay >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Logical Volumes:" | tee -a "$OUTPUT_FILE"
        lvdisplay 2>/dev/null | grep -E "LV Name|LV Status|LV Size|Current LE" | tee -a "$OUTPUT_FILE"
    fi
    
    # ==========================================================================
    # STORAGE TIERING - HP-UX
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- STORAGE TIERING ---" | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Disk Hardware Info:" | tee -a "$OUTPUT_FILE"
    if command -v ioscan >/dev/null 2>&1; then
        ioscan -fnC disk | while read -r line; do
            echo "  $line" | tee -a "$OUTPUT_FILE"
        done
    fi
    
    # ==========================================================================
    # SAN/MULTIPATH - HP-UX
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- SAN/MULTIPATH DETECTION ---" | tee -a "$OUTPUT_FILE"
    
    # Fibre Channel adapters
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Fibre Channel Adapters:" | tee -a "$OUTPUT_FILE"
    ioscan -fnC fc 2>/dev/null | tee -a "$OUTPUT_FILE" || echo "  No FC adapters found" | tee -a "$OUTPUT_FILE"
    
    # Native Multi-Pathing
    if command -v scsimgr >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Multipath Status:" | tee -a "$OUTPUT_FILE"
        scsimgr lun_map 2>/dev/null | head -50 | tee -a "$OUTPUT_FILE" || echo "  scsimgr not available" | tee -a "$OUTPUT_FILE"
    fi
    
    # ==========================================================================
    # CAPACITY PROFILING - HP-UX
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- CAPACITY PROFILING ---" | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Filesystem Capacity:" | tee -a "$OUTPUT_FILE"
    df -k | tee -a "$OUTPUT_FILE"
    
    # bdf for detailed view
    if command -v bdf >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Filesystem Details (bdf):" | tee -a "$OUTPUT_FILE"
        bdf | tee -a "$OUTPUT_FILE"
    fi
    
    # Large directories
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Top 10 Directories by Size (/):" | tee -a "$OUTPUT_FILE"
    du -sk /* 2>/dev/null | sort -rn | head -10 | awk '{printf "  %s\t%s MB\n", $2, $1/1024}' | tee -a "$OUTPUT_FILE"
    
    # ==========================================================================
    # PERFORMANCE BASELINE - HP-UX
    # ==========================================================================
    if [[ "$MODE" == "deep" ]] || [[ "$MODE" == "disk" ]]; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "--- STORAGE PERFORMANCE BASELINE ---" | tee -a "$OUTPUT_FILE"
        
        log_info "Running I/O performance tests..."
        
        local test_file="/tmp/storage_test_$$"
        
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Sequential Write Test:" | tee -a "$OUTPUT_FILE"
        local write_result=$(dd if=/dev/zero of="$test_file" bs=1048576 count=512 2>&1)
        echo "$write_result" | tail -1 | tee -a "$OUTPUT_FILE"
        
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Sequential Read Test:" | tee -a "$OUTPUT_FILE"
        sync
        local read_result=$(dd if="$test_file" of=/dev/null bs=1048576 2>&1)
        echo "$read_result" | tail -1 | tee -a "$OUTPUT_FILE"
        
        rm -f "$test_file"
    fi
}

analyze_storage_profile_solaris() {
    # ==========================================================================
    # DISK LABELING / PARTITION SCHEME - Solaris/Illumos
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- DISK LABELING (Solaris/Illumos) ---" | tee -a "$OUTPUT_FILE"
    
    # Solaris supports multiple partition schemes
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Solaris Disk Label Types:" | tee -a "$OUTPUT_FILE"
    echo "  SMI (VTOC) - Traditional Solaris label, 2TB limit" | tee -a "$OUTPUT_FILE"
    echo "  EFI (GPT)  - Modern label, >2TB support, required for ZFS on large disks" | tee -a "$OUTPUT_FILE"
    
    # Check disk labels using prtvtoc or format
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Disk Label Analysis:" | tee -a "$OUTPUT_FILE"
    
    local smi_count=0
    local efi_count=0
    
    # Get list of disks
    if command -v format >/dev/null 2>&1; then
        # Parse format output for disk list
        local disk_list=$(echo "" | format 2>/dev/null | grep "^[[:space:]]*[0-9]" | awk '{print $2}')
        
        for disk in $disk_list; do
            local disk_dev="/dev/rdsk/${disk}s2"
            [[ -c "$disk_dev" ]] || disk_dev="/dev/rdsk/${disk}s0"
            [[ -c "$disk_dev" ]] || continue
            
            # Try prtvtoc to determine label type
            local label_type="Unknown"
            local vtoc_output=$(prtvtoc "$disk_dev" 2>&1)
            
            if echo "$vtoc_output" | grep -q "EFI"; then
                label_type="EFI (GPT)"
                ((efi_count++))
            elif echo "$vtoc_output" | grep -q "Dimensions\|sectors/track"; then
                label_type="SMI (VTOC)"
                ((smi_count++))
                
                # Check size - warn if SMI on >2TB
                local disk_size=$(echo "$vtoc_output" | grep "accessible sectors" | awk '{print $1}')
                if [[ -n "$disk_size" ]]; then
                    local size_tb=$((disk_size * 512 / 1024 / 1024 / 1024 / 1024))
                    if (( size_tb > 2 )); then
                        log_bottleneck "Storage" "SMI (VTOC) label on >2TB disk $disk" "SMI on ${size_tb}TB" "EFI" "High"
                    fi
                fi
            fi
            
            echo "  $disk: $label_type" | tee -a "$OUTPUT_FILE"
        done
    fi
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Label Summary: EFI (GPT)=$efi_count, SMI (VTOC)=$smi_count" | tee -a "$OUTPUT_FILE"
    
    # Boot configuration
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Boot Configuration:" | tee -a "$OUTPUT_FILE"
    
    # Check if UEFI or BIOS boot
    if [[ -d /sys/firmware/efi ]]; then
        echo "  Firmware: UEFI" | tee -a "$OUTPUT_FILE"
    else
        # Check for x86 BIOS vs SPARC OBP
        local arch=$(uname -p)
        if [[ "$arch" == "sparc" ]]; then
            echo "  Firmware: OpenBoot PROM (SPARC)" | tee -a "$OUTPUT_FILE"
        else
            echo "  Firmware: BIOS (x86)" | tee -a "$OUTPUT_FILE"
        fi
    fi
    
    # Show boot device
    if command -v prtconf >/dev/null 2>&1; then
        local boot_dev=$(prtconf -vp 2>/dev/null | grep "bootpath" | head -1)
        [[ -n "$boot_dev" ]] && echo "  Boot Path: $boot_dev" | tee -a "$OUTPUT_FILE"
    fi
    
    # ==========================================================================
    # FILESYSTEM TYPES - Solaris
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Filesystem Types:" | tee -a "$OUTPUT_FILE"
    
    # Count filesystem types
    local zfs_count=$(zfs list -H 2>/dev/null | wc -l)
    local ufs_count=$(mount -v 2>/dev/null | grep -c "ufs" || echo "0")
    
    echo "  ZFS: $zfs_count dataset(s) - Modern, recommended" | tee -a "$OUTPUT_FILE"
    if (( ufs_count > 0 )); then
        echo "  UFS: $ufs_count filesystem(s) - Legacy (consider migration to ZFS)" | tee -a "$OUTPUT_FILE"
    fi
    
    # ==========================================================================
    # STORAGE TOPOLOGY - Solaris/Illumos
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- STORAGE TOPOLOGY ---" | tee -a "$OUTPUT_FILE"
    
    # Disk devices
    if command -v format >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Disk Devices:" | tee -a "$OUTPUT_FILE"
        echo "" | format 2>/dev/null | grep -E "^[0-9]|c[0-9]" | tee -a "$OUTPUT_FILE"
    fi
    
    # ZFS Pools (primary storage on modern Solaris/Illumos)
    if command -v zpool >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "ZFS Pool Status:" | tee -a "$OUTPUT_FILE"
        zpool status | tee -a "$OUTPUT_FILE"
        
        echo "" | tee -a "$OUTPUT_FILE"
        echo "ZFS Pool List:" | tee -a "$OUTPUT_FILE"
        zpool list | tee -a "$OUTPUT_FILE"
        
        # Check for degraded pools
        local degraded=$(zpool status 2>/dev/null | grep -c "DEGRADED\|FAULTED" || echo "0")
        if (( degraded > 0 )); then
            log_bottleneck "Storage" "ZFS pool degraded or faulted" "$degraded issues" "0" "Critical"
        fi
        
        # ZFS datasets
        echo "" | tee -a "$OUTPUT_FILE"
        echo "ZFS Datasets:" | tee -a "$OUTPUT_FILE"
        zfs list -o name,used,avail,refer,mountpoint | head -30 | tee -a "$OUTPUT_FILE"
    fi
    
    # Traditional SVM (Solaris Volume Manager) if present
    if command -v metastat >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "SVM Metadevices:" | tee -a "$OUTPUT_FILE"
        metastat 2>/dev/null | head -50 | tee -a "$OUTPUT_FILE" || echo "  No SVM configuration" | tee -a "$OUTPUT_FILE"
    fi
    
    # ==========================================================================
    # STORAGE TIERING - Solaris
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- STORAGE TIERING ---" | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Disk Hardware Info:" | tee -a "$OUTPUT_FILE"
    
    # Use iostat -En for extended disk info
    if command -v iostat >/dev/null 2>&1; then
        iostat -En 2>/dev/null | grep -E "^c|Size|Vendor|Product|Serial" | head -40 | tee -a "$OUTPUT_FILE"
    fi
    
    # NVMe detection on newer systems
    if [[ -d /dev/nvme ]]; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "NVMe Devices:" | tee -a "$OUTPUT_FILE"
        ls -la /dev/nvme* 2>/dev/null | tee -a "$OUTPUT_FILE"
    fi
    
    # ==========================================================================
    # SAN/MULTIPATH - Solaris
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- SAN/MULTIPATH DETECTION ---" | tee -a "$OUTPUT_FILE"
    
    # Fibre Channel ports
    if command -v fcinfo >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Fibre Channel HBA Ports:" | tee -a "$OUTPUT_FILE"
        fcinfo hba-port 2>/dev/null | tee -a "$OUTPUT_FILE" || echo "  No FC HBAs found" | tee -a "$OUTPUT_FILE"
    fi
    
    # MPxIO (native multipathing)
    if command -v mpathadm >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "MPxIO Multipath Status:" | tee -a "$OUTPUT_FILE"
        mpathadm list lu 2>/dev/null | tee -a "$OUTPUT_FILE" || echo "  MPxIO not configured" | tee -a "$OUTPUT_FILE"
    fi
    
    # stmsboot status
    if command -v stmsboot >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "STMS (MPxIO) Status:" | tee -a "$OUTPUT_FILE"
        stmsboot -L 2>/dev/null | tee -a "$OUTPUT_FILE"
    fi
    
    # iSCSI targets
    if command -v iscsiadm >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "iSCSI Targets:" | tee -a "$OUTPUT_FILE"
        iscsiadm list target 2>/dev/null | tee -a "$OUTPUT_FILE" || echo "  No iSCSI targets" | tee -a "$OUTPUT_FILE"
    fi
    
    # ==========================================================================
    # ZFS HEALTH & SMART - Solaris
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- STORAGE HEALTH ---" | tee -a "$OUTPUT_FILE"
    
    if command -v zpool >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "ZFS Pool Health:" | tee -a "$OUTPUT_FILE"
        zpool status -v 2>/dev/null | grep -E "pool:|state:|status:|action:|scan:|errors:" | tee -a "$OUTPUT_FILE"
        
        # Scrub status
        echo "" | tee -a "$OUTPUT_FILE"
        echo "ZFS Scrub Status:" | tee -a "$OUTPUT_FILE"
        zpool status 2>/dev/null | grep -A 2 "scan:" | tee -a "$OUTPUT_FILE"
    fi
    
    # ==========================================================================
    # CAPACITY PROFILING - Solaris
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- CAPACITY PROFILING ---" | tee -a "$OUTPUT_FILE"
    
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Filesystem Capacity:" | tee -a "$OUTPUT_FILE"
    df -h | tee -a "$OUTPUT_FILE"
    
    # ZFS-specific capacity
    if command -v zpool >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "ZFS Pool Capacity:" | tee -a "$OUTPUT_FILE"
        zpool list -o name,size,alloc,free,cap,health | tee -a "$OUTPUT_FILE"
        
        # Check for pools over 80% capacity
        while read -r line; do
            local pool_name=$(echo "$line" | awk '{print $1}')
            local cap=$(echo "$line" | awk '{print $5}' | tr -d '%')
            if [[ "$pool_name" != "NAME" ]] && [[ -n "$cap" ]] && (( cap > 80 )); then
                log_bottleneck "Storage" "ZFS pool $pool_name high capacity" "${cap}%" "80%" "High"
            fi
        done < <(zpool list -o name,cap 2>/dev/null)
    fi
    
    # Large directories
    echo "" | tee -a "$OUTPUT_FILE"
    echo "Top 10 Directories by Size (/):" | tee -a "$OUTPUT_FILE"
    du -sh /* 2>/dev/null | sort -rh | head -10 | tee -a "$OUTPUT_FILE"
    
    # ==========================================================================
    # ZFS PERFORMANCE - Solaris
    # ==========================================================================
    echo "" | tee -a "$OUTPUT_FILE"
    echo "--- ZFS PERFORMANCE STATS ---" | tee -a "$OUTPUT_FILE"
    
    if command -v zpool >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "ZFS Pool I/O Statistics:" | tee -a "$OUTPUT_FILE"
        zpool iostat -v 1 3 2>/dev/null | tee -a "$OUTPUT_FILE"
    fi
    
    # ARC (Adaptive Replacement Cache) stats
    if command -v kstat >/dev/null 2>&1; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "ZFS ARC Statistics:" | tee -a "$OUTPUT_FILE"
        kstat -p zfs:0:arcstats:size 2>/dev/null | tee -a "$OUTPUT_FILE"
        kstat -p zfs:0:arcstats:hits 2>/dev/null | tee -a "$OUTPUT_FILE"
        kstat -p zfs:0:arcstats:misses 2>/dev/null | tee -a "$OUTPUT_FILE"
    fi
    
    # ==========================================================================
    # PERFORMANCE BASELINE - Solaris
    # ==========================================================================
    if [[ "$MODE" == "deep" ]] || [[ "$MODE" == "disk" ]]; then
        echo "" | tee -a "$OUTPUT_FILE"
        echo "--- STORAGE PERFORMANCE BASELINE ---" | tee -a "$OUTPUT_FILE"
        
        log_info "Running I/O performance tests..."
        
        local test_file="/tmp/storage_test_$$"
        
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Sequential Write Test:" | tee -a "$OUTPUT_FILE"
        local write_result=$(dd if=/dev/zero of="$test_file" bs=1M count=512 2>&1)
        echo "$write_result" | tail -1 | tee -a "$OUTPUT_FILE"
        
        echo "" | tee -a "$OUTPUT_FILE"
        echo "Sequential Read Test:" | tee -a "$OUTPUT_FILE"
        sync
        local read_result=$(dd if="$test_file" of=/dev/null bs=1M 2>&1)
        echo "$read_result" | tail -1 | tee -a "$OUTPUT_FILE"
        
        rm -f "$test_file"
    fi
}

#############################################################################
# Database Forensics (placeholder for Unix)
#############################################################################

analyze_databases() {
    print_header "DATABASE FORENSICS"
    
    log_info "Checking for database processes..."
    
    # Basic database detection for Unix systems
    local db_found=false
    
    # Oracle detection (common on Unix)
    if pgrep -x oracle >/dev/null 2>&1 || pgrep -f "ora_pmon" >/dev/null 2>&1; then
        db_found=true
        echo "=== Oracle Database Detected ===" | tee -a "$OUTPUT_FILE"
        ps -ef | grep -E "[o]ra_pmon|[o]racle" | head -5 | tee -a "$OUTPUT_FILE"
        
        # Connection count
        local oracle_conns=$(netstat -an 2>/dev/null | grep ":1521" | grep -c ESTABLISHED || echo "0")
        echo "  Active Connections (port 1521): ${oracle_conns}" | tee -a "$OUTPUT_FILE"
    fi
    
    # DB2 detection (common on AIX)
    if pgrep -f "db2sysc" >/dev/null 2>&1; then
        db_found=true
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== IBM DB2 Detected ===" | tee -a "$OUTPUT_FILE"
        ps -ef | grep -E "[d]b2sysc" | head -5 | tee -a "$OUTPUT_FILE"
        
        # Connection count
        local db2_conns=$(netstat -an 2>/dev/null | grep ":50000" | grep -c ESTABLISHED || echo "0")
        echo "  Active Connections (port 50000): ${db2_conns}" | tee -a "$OUTPUT_FILE"
    fi
    
    # MySQL detection
    if pgrep -x mysqld >/dev/null 2>&1; then
        db_found=true
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== MySQL Detected ===" | tee -a "$OUTPUT_FILE"
        ps -ef | grep "[m]ysqld" | head -3 | tee -a "$OUTPUT_FILE"
        
        local mysql_conns=$(netstat -an 2>/dev/null | grep ":3306" | grep -c ESTABLISHED || echo "0")
        echo "  Active Connections (port 3306): ${mysql_conns}" | tee -a "$OUTPUT_FILE"
    fi
    
    # PostgreSQL detection
    if pgrep -x postgres >/dev/null 2>&1; then
        db_found=true
        echo "" | tee -a "$OUTPUT_FILE"
        echo "=== PostgreSQL Detected ===" | tee -a "$OUTPUT_FILE"
        ps -ef | grep "[p]ostgres" | head -3 | tee -a "$OUTPUT_FILE"
        
        local pg_conns=$(netstat -an 2>/dev/null | grep ":5432" | grep -c ESTABLISHED || echo "0")
        echo "  Active Connections (port 5432): ${pg_conns}" | tee -a "$OUTPUT_FILE"
    fi
    
    if [[ "$db_found" == false ]]; then
        echo "No common database processes detected" | tee -a "$OUTPUT_FILE"
    fi
    
    log_success "Database forensics completed"
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
    
    log_info "Detected OS: ${OS_NAME:-$DISTRO}"
    log_info "OS Version: ${OS_VERSION:-unknown}"
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
            analyze_storage_profile
            analyze_databases
            analyze_network
            ;;
        deep)
            analyze_cpu
            analyze_memory
            analyze_disk
            analyze_storage_profile
            analyze_databases
            analyze_network
            ;;
        disk)
            analyze_disk
            analyze_storage_profile
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
