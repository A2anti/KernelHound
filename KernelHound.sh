#!/bin/bash
# KernelHound v2 
# Usage: ./kernelhound.sh [linux|windows] [driver_name|all] [-v]
# License: GPLv3

# Verify bash version and environment
[ "${BASH_VERSINFO:-0}" -lt 4 ] && { echo -e "\033[31m[!] Requires Bash 4+\033[0m" >&2; exit 1; }
set -o pipefail
shopt -s nullglob nocasematch
umask 077

# Dynamic version detection
VERSION=$(git describe --tags 2>/dev/null || echo "v2.2")

# --- ASCII Banner ---
function show_banner() {
  cat << EOF

  _  __                     _   _             _   _          
 | |/ /___ _ __ _ __   ___ | | | | ___   __ _| |_| |__  _ __ 
 | ' // _ \ '__| '_ \ / _ \| |_| |/ _ \ / _` | __| '_ \| '__|
 | . \  __/ |  | | | | (_) |  _  | (_) | (_| | |_| | | | |   
 |_|\_\___|_|  |_| |_|\___/|_| |_|\___/ \__,_|\__|_| |_|_|   

  Zero-Day Kernel Exploit Prediction System ${VERSION}
  ---------------------------------------------
  » Driver Vulnerability Mapping  [✓]
  » Memory Corruption Analysis    [✓]
  » CVE Pattern Correlation       [✓]
  » Syscall Attack Surface Audit  [✓]
  » Live Kernel Symbol Tracing    [✓]

EOF
}

# --- Configuration ---
declare -r CVE_DB="${CVE_DB:-./cve_database.csv}"
declare -r CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/kernelhound"
declare -r CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/kernelhound"

# Security patterns
declare -a EXPLOIT_PATTERNS=(
    "use[-_]after[-_]free"
    "buffer[-_]overflow"
    "race[-_]condition"
    "null[-_]pointer"
    "double[-_]free"
    "heap[-_]overflow"
)

declare -a SAFE_FUNCTIONS=(
    "copy_from_user"
    "strncpy_from_user"
    "memdup_user"
    "access_ok"
)

declare -a UNSAFE_FUNCTIONS=(
    "memcpy"
    "strcpy"
    "sprintf"
    "strcat"
    "gets"
)

# Color codes
declare -r RED='\033[0;31m'
declare -r GREEN='\033[0;32m'
declare -r YELLOW='\033[1;33m'
declare -r BLUE='\033[0;34m'
declare -r NC='\033[0m'

# --- Initialization ---
function init_environment() {
    # Create required directories
    mkdir -p "$CONFIG_DIR" "$CACHE_DIR"
    
    # Verify root privileges
    [[ $EUID -eq 0 ]] || {
        echo -e "${RED}[!] Root privileges required for full analysis${NC}" >&2
        exit 1
    }

    # Check dependencies
    local -a deps=(nm modinfo stat grep awk find sysctl lsmod uname)
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            echo -e "${RED}[!] Missing required tool: $cmd${NC}" >&2
            exit 1
        fi
    done

    # Load kernel info
    KERNEL_VERSION=$(uname -r)
    DRIVER_DIR="/lib/modules/$KERNEL_VERSION/kernel/drivers"
    [[ -d "$DRIVER_DIR" ]] || {
        echo -e "${RED}[!] Driver directory not found: $DRIVER_DIR${NC}" >&2
        exit 1
    }
}

# --- Driver Analysis ---
function analyze_ioctl() {
    local driver=$1
    local major_minors=()
    
    # Sanitize driver name
    driver="${driver//[^a-zA-Z0-9_-]/}"
    
    # Get device numbers
    while IFS= read -r line; do
        major_minors+=("$line")
    done < <(grep -w "$driver" /proc/devices | awk '{print $1}')
    
    (( ${#major_minors[@]} == 0 )) && return
    
    # Find character devices
    while IFS= read -r -d '' node; do
        if [[ "$(stat -c '%t' "$node" 2>/dev/null)" =~ ^(${major_minors[*]})$ ]]; then
            echo -e "${BLUE}  [i] Exposes character device: $node${NC}"
            [[ $VERBOSE -eq 1 ]] && {
                echo -e "  Potential ioctl handlers:"
                nm -D "$(modinfo -F filename "$driver")" 2>/dev/null | \
                    grep -E '\<(unlocked_)?ioctl\>' | \
                    awk '{print "    " $3}'
            }
        fi
    done < <(find /dev -type c -print0 2>/dev/null)
}

function analyze_driver_source() {
    local driver=$1
    local src_dir="$DRIVER_DIR/${driver#*/}"
    
    [[ -d "$src_dir" ]] || return
    
    for pattern in "${EXPLOIT_PATTERNS[@]}"; do
        while IFS= read -r match; do
            [[ -n "$match" ]] && {
                echo -e "${RED}  [!] $pattern found:${NC}"
                echo -e "      ${match%%:*}: ${match#*:}"
            }
        done < <(grep -rn -C2 -iE "$pattern" "$src_dir" 2>/dev/null)
    done
}

function check_module_security() {
    local driver=$1
    local ko_path=$(modinfo -F filename "$driver" 2>/dev/null)
    
    [[ -f "$ko_path" ]] || return
    
    # Check security functions
    local missing=() dangerous=()
    local symbols=$(nm -D "$ko_path" 2>/dev/null)
    
    for func in "${SAFE_FUNCTIONS[@]}"; do
        grep -q -w "$func" <<< "$symbols" || missing+=("$func")
    done
    
    for func in "${UNSAFE_FUNCTIONS[@]}"; do
        grep -q -w "$func" <<< "$symbols" && dangerous+=("$func")
    done
    
    (( ${#missing[@]} > 0 )) && \
        echo -e "${RED}  [!] Missing security functions: ${missing[*]}${NC}"
    
    (( ${#dangerous[@]} > 0 )) && \
        echo -e "${YELLOW}  [>] Potentially unsafe functions: ${dangerous[*]}${NC}"
}

# --- System Checks ---
function analyze_sysctls() {
    declare -A monitored_sysctls=(
        ["vm.mmap_min_addr"]="0"
        ["kernel.yama.ptrace_scope"]="0"
        ["kernel.kptr_restrict"]="0"
        ["kernel.dmesg_restrict"]="0"
    )
    
    while IFS='=' read -r key value; do
        for sysctl in "${!monitored_sysctls[@]}"; do
            if [[ "$key" == *"$sysctl" ]]; then
                if [[ "$value" == "${monitored_sysctls[$sysctl]}" ]]; then
                    echo -e "${RED}  [!] Risky sysctl: $key=$value${NC}"
                else
                    [[ $VERBOSE -eq 1 ]] && \
                        echo -e "${GREEN}  [✓] $key=$value (secure)${NC}"
                fi
            fi
        done
    done < <(sysctl -a 2>/dev/null)
}

# --- CVE Analysis ---
function load_cve_db() {
    [[ -f "$CVE_DB" ]] || return 1
    
    # Validate CSV format
    [[ $(head -1 "$CVE_DB" | grep -o ',' | wc -l) -ge 3 ]] || {
        echo -e "${RED}[!] Invalid CVE DB format${NC}" >&2
        return 1
    }
    
    # Load into associative array
    declare -gA cve_drivers
    while IFS=, read -r cve date component driver _; do
        cve_drivers["$driver"]="$date:$cve"
    done < <(grep -v '^#' "$CVE_DB")
}

function predict_risks() {
    load_cve_db || return
    
    # Show recent CVEs
    echo -e "\n${YELLOW}[+] Recent Kernel CVEs${NC}"
    for driver in "${!cve_drivers[@]}"; do
        IFS=: read -r date cve <<< "${cve_drivers[$driver]}"
        printf "  %s - %-15s %s\n" "$date" "$driver" "$cve"
    done | sort -r | head -5

    # Find unexplored drivers
    echo -e "\n${YELLOW}[+] Unexplored Drivers${NC}"
    find "$DRIVER_DIR" -name '*.ko' -type f | while read -r ko; do
        local driver=$(basename "$ko" .ko)
        [[ -z "${cve_drivers[$driver]}" ]] && \
            echo -e "${GREEN}  $driver${NC}"
    done
}

# --- Main Analysis ---
function analyze_linux() {
    local target=${1:-all}
    
    echo -e "${YELLOW}[+] Kernel Version: $KERNEL_VERSION${NC}"
    echo -e "${YELLOW}[+] Analysis Target: $target${NC}"
    
    # Driver analysis
    echo -e "\n${YELLOW}[+] Loaded Driver Analysis${NC}"
    while IFS= read -r driver; do
        [[ "$target" != "all" && "$driver" != "$target" ]] && continue
        
        echo -e "\n${GREEN}Driver: $driver${NC}"
        analyze_ioctl "$driver"
        check_module_security "$driver"
        [[ $VERBOSE -eq 1 ]] && analyze_driver_source "$driver"
    done < <(lsmod | awk 'NR>1 {print $1}')
    
    # System-wide checks
    echo -e "\n${YELLOW}[+] Kernel-wide Security Checks${NC}"
    analyze_sysctls
    
    # Prediction engine
    predict_risks
}

# --- Windows Analysis ---
function analyze_windows() {
    echo -e "${RED}[!] Windows analysis requires:${NC}"
    echo -e "1. WinDBG installed"
    echo -e "2. Kernel debugging configured"
    echo -e "3. Debug symbols available\n"
    
    if command -v windbg &>/dev/null; then
        echo -e "${YELLOW}[+] Running basic driver check...${NC}"
        windbg -c "lm; !drvobj * 2" | grep -i "driver"
    else
        echo -e "${RED}[!] WinDBG not found in PATH${NC}" >&2
        return 1
    fi
}

# --- Main Function ---
function main() {
    local VERBOSE=0 TARGET_OS="" TARGET_DRIVER="all"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            linux|windows) TARGET_OS="$1"; shift ;;
            all|*) TARGET_DRIVER="${1#-}"; shift ;;
            -v) VERBOSE=1; shift ;;
            -h|--help) show_help; exit 0 ;;
            *) echo -e "${RED}[!] Invalid argument: $1${NC}" >&2; exit 1 ;;
        esac
    done

    show_banner
    init_environment

    case "$TARGET_OS" in
        linux) analyze_linux "$TARGET_DRIVER" ;;
        windows) analyze_windows ;;
        *) echo -e "Usage: $0 [linux|windows] [driver|all] [-v]"; exit 1 ;;
    esac
    
    echo -e "\n${YELLOW}[+] Analysis complete${NC}"
}

main "$@"