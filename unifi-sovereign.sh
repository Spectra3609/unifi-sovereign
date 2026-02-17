#!/bin/bash

#
# UniFi Sovereign - SSH-based device migration & adoption toolkit
# macOS / Linux version (Bash/Zsh)
# 
# Usage: ./unifi-sovereign.sh [--mode SANITY|MIGRATE|ADOPT] [--cidr SUBNET] [--controller IP] ...
#

set -euo pipefail

SCRIPT_VERSION="2.1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ===================================================================
# COLORS & OUTPUT
# ===================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

log_info() {
  echo -e "${CYAN}[INFO]${NC}  $*"
}

log_ok() {
  echo -e "${GREEN}[OK]${NC}    $*"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC}   $*"
}

log_fail() {
  echo -e "${RED}[FAIL]${NC}   $*"
}

log_debug() {
  echo -e "${MAGENTA}[DBG]${NC}    $*"
}

log_header() {
  echo ""
  echo -e "${CYAN}-- $* --${NC}"
  echo ""
}

print_banner() {
  echo ""
  echo "  ============================================================"
  echo "   _   _       _ _____ _   __  __ _            ____  _       "
  echo "  | | | |_ __ (_)  ___(_) |  \/  (_) ___ _ __ |  _ \| |_   _ ___ "
  echo "  | | | | '_ \| | |_  | | | |\/| | |/ __| '__ \| |_) | | | | / __|"
  echo "  | |_| | | | | |  _| | | | |  | | | (__| |  | |  __/| | |_| \__ \\"
  echo "   \___/|_| |_|_|_|   |_| |_|  |_|_|\___|_|  |_|_|   |_|\__,_|___/"
  echo ""
  echo "   SSH Inform Toolkit (Bash/Zsh)                 v${SCRIPT_VERSION}"
  echo "  ============================================================"
  echo ""
}

# ===================================================================
# DEPENDENCIES
# ===================================================================

check_dependencies() {
  log_header "Dependencies"
  
  local missing=()
  
  for cmd in ssh sshpass ssh-keyscan ping awk sed grep; do
    if ! command -v "$cmd" &>/dev/null; then
      missing+=("$cmd")
    else
      log_ok "$cmd"
    fi
  done
  
  # Optional but nice to have
  if command -v fzf &>/dev/null; then
    log_ok "fzf (interactive menus enabled)"
  else
    log_warn "fzf not found (install for better menus)"
  fi
  
  if [ ${#missing[@]} -gt 0 ]; then
    log_fail "Missing required commands: ${missing[*]}"
    echo ""
    echo "On macOS (Homebrew):"
    echo "  brew install openssh ssh-keyscan"
    echo ""
    echo "On Ubuntu/Debian:"
    echo "  sudo apt-get install openssh-client openssh-server"
    echo ""
    exit 1
  fi
}

# ===================================================================
# INTERACTIVE PROMPTS
# ===================================================================

menu_choice() {
  local prompt="$1"
  shift
  local options=("$@")
  
  # Try fzf first for nice menu
  if command -v fzf &>/dev/null; then
    local selected
    selected=$(printf '%s\n' "${options[@]}" | fzf --height=40% --border --prompt="$prompt" --no-preview)
    echo "$selected"
    return 0
  fi
  
  # Fallback to simple numbered menu
  echo ""
  echo -e "${BOLD}${prompt}${NC}"
  echo ""
  for i in "${!options[@]}"; do
    echo "  [$((i+1))] ${options[$i]}"
  done
  echo ""
  
  local choice
  read -p "  Choice [default=1]: " choice
  choice=${choice:-1}
  
  # Validate
  if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#options[@]} ]; then
    echo "${options[$((choice-1))]}"
  else
    log_fail "Invalid choice"
    menu_choice "$prompt" "${options[@]}"
  fi
}

read_input() {
  local prompt="$1"
  local default="${2:-}"
  local input
  
  if [ -n "$default" ]; then
    read -p "  ${prompt} [${default}]: " input
    echo "${input:-$default}"
  else
    while [ -z "$input" ]; do
      read -p "  ${prompt}: " input
      if [ -z "$input" ]; then
        log_warn "Cannot be blank"
      fi
    done
    echo "$input"
  fi
}

read_password() {
  local prompt="$1"
  local password
  
  read -sp "  ${prompt}: " password
  echo ""
  echo "$password"
}

yes_no() {
  local prompt="$1"
  local default="${2:-n}"
  local input
  
  read -p "  ${prompt} [${default}]: " input
  input=${input:-$default}
  
  if [[ "$input" =~ ^[Yy] ]]; then
    echo "Y"
  else
    echo "N"
  fi
}

# ===================================================================
# CIDR UTILITIES
# ===================================================================

cidr_to_ips() {
  local cidr="$1"
  
  # Simple CIDR expansion using ipcalc if available, else basic Python
  if command -v ipcalc &>/dev/null; then
    ipcalc "$cidr" 2>/dev/null | grep "Network:" | awk '{print $2}' || echo ""
    return
  fi
  
  # Fallback: Python (more portable)
  python3 <<EOF 2>/dev/null || echo ""
import ipaddress
import sys

try:
    net = ipaddress.ip_network('$cidr', strict=False)
    for ip in net.hosts():
        print(str(ip))
except:
    pass
EOF
}

# ===================================================================
# SSH & DEVICE INTERACTION
# ===================================================================

ssh_exec() {
  local ip="$1"
  local user="$2"
  local pass="$3"
  local cmd="$4"
  local timeout="${5:-7}"
  
  if [ -n "$pass" ]; then
    timeout "$timeout" sshpass -p "$pass" ssh \
      -o StrictHostKeyChecking=no \
      -o ConnectTimeout=5 \
      -o BatchMode=no \
      "$user@$ip" "$cmd" 2>/dev/null || echo ""
  else
    timeout "$timeout" ssh \
      -o StrictHostKeyChecking=no \
      -o ConnectTimeout=5 \
      "$user@$ip" "$cmd" 2>/dev/null || echo ""
  fi
}

ssh_shell_cmd() {
  local ip="$1"
  local user="$2"
  local pass="$3"
  local cmd="$4"
  local timeout="${5:-14}"
  
  # For interactive shell commands (info, set-inform)
  # Uses expect if available, else tries ssh with pipe
  
  if command -v expect &>/dev/null; then
    expect <<EOF 2>/dev/null
set timeout $timeout
spawn ssh -o StrictHostKeyChecking=no "$user@$ip"
expect "*#" { send "$cmd\\r" }
expect "*#" { send "exit\\r" }
expect eof
EOF
    return 0
  fi
  
  # Fallback: simple echo + ssh (less reliable but works)
  echo "$cmd" | timeout "$timeout" sshpass -p "$pass" ssh \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=5 \
    "$user@$ip" 2>/dev/null || echo ""
}

test_ssh_connection() {
  local ip="$1"
  local user="$2"
  local pass="$3"
  local timeout="${4:-7}"
  
  local result
  result=$(ssh_exec "$ip" "$user" "$pass" "echo ok" "$timeout")
  
  if [ "$result" = "ok" ]; then
    return 0
  else
    return 1
  fi
}

get_device_info() {
  local ip="$1"
  local user="$2"
  local pass="$3"
  local timeout="${4:-14}"
  
  local output
  output=$(ssh_shell_cmd "$ip" "$user" "$pass" "info" "$timeout")
  
  if [ -z "$output" ]; then
    # Fallback to exec channel
    output=$(ssh_exec "$ip" "$user" "$pass" "info" "$timeout")
  fi
  
  # Parse output
  local model firmware hostname mac status inform_url
  
  model=$(echo "$output" | grep -i "^Model:" | head -1 | sed 's/.*Model:\s*//;s/\s*$//' | cut -c1-30)
  firmware=$(echo "$output" | grep -i "^Version:" | head -1 | sed 's/.*Version:\s*//;s/\s*$//')
  hostname=$(echo "$output" | grep -i "^Hostname:" | head -1 | sed 's/.*Hostname:\s*//;s/\s*$//')
  mac=$(echo "$output" | grep -i "MAC" | grep -oE "([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})" | head -1)
  status=$(echo "$output" | grep -i "^Status:" | head -1 | sed 's/.*Status:\s*//;s/\s*$//')
  inform_url=$(echo "$output" | grep -i "Inform.*URL" | sed 's/.*Inform.*URL:\s*//;s/\s*$//')
  
  # If MAC still empty, try Linux system files
  if [ -z "$mac" ]; then
    mac=$(ssh_exec "$ip" "$user" "$pass" "cat /sys/class/net/eth0/address 2>/dev/null" "$timeout" | grep -oE "([0-9A-Fa-f:]{17})")
    if [ -z "$mac" ]; then
      mac=$(ssh_exec "$ip" "$user" "$pass" "cat /sys/class/net/br0/address 2>/dev/null" "$timeout" | grep -oE "([0-9A-Fa-f:]{17})")
    fi
  fi
  
  echo "MODEL=$model"
  echo "FIRMWARE=$firmware"
  echo "HOSTNAME=$hostname"
  echo "MAC=$mac"
  echo "STATUS=$status"
  echo "INFORM_URL=$inform_url"
  echo "RAW=$output"
}

send_set_inform() {
  local ip="$1"
  local user="$2"
  local pass="$3"
  local controller_url="$4"
  local timeout="${5:-14}"
  
  # Try set-inform first
  local output1
  output1=$(ssh_shell_cmd "$ip" "$user" "$pass" "set-inform $controller_url" "$timeout")
  
  if echo "$output1" | grep -iqE "adoption|inform|request|accepted"; then
    echo "METHOD=set-inform"
    echo "OUTPUT=$output1"
    echo "SUCCESS=1"
    return 0
  fi
  
  # Try mca-cli-op (works on adopted devices)
  local output2
  output2=$(ssh_shell_cmd "$ip" "$user" "$pass" "mca-cli-op set-inform $controller_url" "$timeout")
  
  if echo "$output2" | grep -iqE "adoption|inform|request|accepted"; then
    echo "METHOD=mca-cli-op"
    echo "OUTPUT=$output2"
    echo "SUCCESS=1"
    return 0
  fi
  
  # Accept if no error keywords
  if ! echo "$output1$output2" | grep -iqE "not found|unknown|error|denied|invalid"; then
    echo "METHOD=set-inform+mca-cli-op"
    echo "OUTPUT=$output1 | $output2"
    echo "SUCCESS=1"
    return 0
  fi
  
  echo "METHOD=none"
  echo "OUTPUT=$output1 | $output2"
  echo "SUCCESS=0"
  return 1
}

# ===================================================================
# PORT SCANNING
# ===================================================================

port_scan() {
  local -a targets=("$@")
  local open_count=0
  local -a open_ips=()
  
  log_header "Port Scan (TCP/22)"
  log_info "Scanning ${#targets[@]} hosts..."
  
  local total=${#targets[@]}
  local current=0
  
  for ip in "${targets[@]}"; do
    ((current++))
    local pct=$((current * 100 / total))
    
    printf "\r  [%3d%%] %d/%d hosts - Last: %-15s" "$pct" "$current" "$total" "$ip"
    
    if timeout 3 bash -c "cat < /dev/null > /dev/tcp/$ip/22" 2>/dev/null; then
      open_ips+=("$ip")
      ((open_count++))
    fi
  done
  
  echo ""
  echo ""
  
  if [ $open_count -eq 0 ]; then
    log_fail "No hosts with SSH open"
    exit 1
  fi
  
  log_ok "$open_count hosts with SSH open"
  printf '%s\n' "${open_ips[@]}"
}

# ===================================================================
# CSV OUTPUT
# ===================================================================

csv_init() {
  local outfile="$1"
  
  cat > "$outfile" <<'EOF'
Timestamp,IP,MAC,Connected,Username,Model,DevHostname,Firmware,AdoptStatus,CurrentInform,Reset,Inform1,Inform2,InformMethod,Status,Note,DebugInfo
EOF
}

csv_add_row() {
  local outfile="$1"
  shift
  local -n row_data=$1
  
  local timestamp="${row_data[timestamp]}"
  local ip="${row_data[ip]}"
  local mac="${row_data[mac]}"
  local connected="${row_data[connected]}"
  local username="${row_data[username]}"
  local model="${row_data[model]}"
  local hostname="${row_data[hostname]}"
  local firmware="${row_data[firmware]}"
  local adopt_status="${row_data[adopt_status]}"
  local current_inform="${row_data[current_inform]}"
  local reset="${row_data[reset]}"
  local inform1="${row_data[inform1]}"
  local inform2="${row_data[inform2]}"
  local inform_method="${row_data[inform_method]}"
  local status="${row_data[status]}"
  local note="${row_data[note]}"
  local debug_info="${row_data[debug_info]}"
  
  # Escape quotes in fields
  mac="${mac//\"/\"\"}"
  model="${model//\"/\"\"}"
  hostname="${hostname//\"/\"\"}"
  note="${note//\"/\"\"}"
  debug_info="${debug_info//\"/\"\"}"
  
  cat >> "$outfile" <<EOF
"$timestamp","$ip","$mac",$connected,"$username","$model","$hostname","$firmware","$adopt_status","$current_inform","$reset","$inform1","$inform2","$inform_method",$status,"$note","$debug_info"
EOF
}

# ===================================================================
# MAIN LOGIC
# ===================================================================

main() {
  local mode="${MODE:-}"
  local cidr="${CIDR:-}"
  local ips_arg="${IPS:-}"
  local controller="${CONTROLLER:-}"
  local username="${USERNAME:-ubnt}"
  local password="${PASSWORD:-}"
  local reset_first="${RESET_FIRST:-0}"
  local ssh_timeout="${SSH_TIMEOUT:-7}"
  local scan_timeout="${SCAN_TIMEOUT:-3}"
  local out_csv="${OUT_CSV:-}"
  
  print_banner
  check_dependencies
  
  # ===== Mode =====
  if [ -z "$mode" ]; then
    mode=$(menu_choice "Operation mode:" \
      "SANITY   - verify SSH access + collect device info (read-only)" \
      "MIGRATE  - re-point devices to a new controller (no reset, no wipe)" \
      "ADOPT    - full adoption with optional factory reset")
    
    mode=$(echo "$mode" | cut -d' ' -f1)
  fi
  
  mode=$(echo "$mode" | tr '[:lower:]' '[:upper:]')
  log_info "Mode: $mode"
  
  # ===== Targets =====
  log_header "Targets"
  local -a target_ips=()
  
  if [ -n "$cidr" ]; then
    mapfile -t target_ips < <(cidr_to_ips "$cidr")
  elif [ -n "$ips_arg" ]; then
    mapfile -t target_ips < <(echo "$ips_arg" | tr ',' '\n' | grep -E '^\d+\.\d+\.\d+\.\d+$')
  else
    local input_type
    input_type=$(menu_choice "Target input:" \
      "CIDR subnet  (e.g. 192.168.1.0/24)" \
      "IP list      (comma-separated)")
    
    if [[ "$input_type" =~ "list" ]]; then
      local ips_str
      ips_str=$(read_input "IPs (comma-separated)")
      mapfile -t target_ips < <(echo "$ips_str" | tr ',' '\n' | grep -E '^\d+\.\d+\.\d+\.\d+$')
    else
      cidr=$(read_input "CIDR (e.g. 192.168.1.0/24)")
      mapfile -t target_ips < <(cidr_to_ips "$cidr")
    fi
  fi
  
  if [ ${#target_ips[@]} -eq 0 ]; then
    log_fail "No valid targets"
    exit 1
  fi
  
  log_ok "${#target_ips[@]} IPs"
  
  # ===== Controller =====
  local controller_url=""
  
  if [[ "$mode" =~ ^(MIGRATE|ADOPT)$ ]]; then
    log_header "Controller"
    
    if [ -z "$controller" ]; then
      controller=$(read_input "Target controller IP or hostname")
    fi
    
    controller_url="http://${controller}:8080/inform"
    log_info "Inform URL: $controller_url"
    
    if [[ "$mode" == "ADOPT" ]]; then
      if [ "$reset_first" -eq 0 ]; then
        local do_reset
        do_reset=$(yes_no "Factory reset before adoption?" "n")
        if [[ "$do_reset" == "Y" ]]; then
          reset_first=1
        fi
      fi
    fi
  fi
  
  # ===== Credentials =====
  log_header "SSH Credentials"
  
  local -a cred_users=("$username")
  local -a cred_passes=("${password:-ubnt}")
  
  if [ -z "$password" ]; then
    local add_cred
    add_cred=$(yes_no "Provide a known SSH credential?" "n")
    
    if [[ "$add_cred" == "Y" ]]; then
      local user pass
      user=$(read_input "SSH Username")
      pass=$(read_password "SSH Password (hidden)")
      
      cred_users+=("$user")
      cred_passes+=("$pass")
    fi
  fi
  
  # Factory defaults
  cred_users+=("ubnt" "root")
  cred_passes+=("ubnt" "ubnt")
  
  log_ok "Credential chain: $(IFS=, ; echo "${cred_users[*]}")"
  
  # ===== CSV =====
  if [ -z "$out_csv" ]; then
    local default_csv="unifi-$(echo "$mode" | tr '[:upper:]' '[:lower:]')-log.csv"
    out_csv=$(read_input "CSV output path" "$default_csv")
  fi
  
  # ===== Summary =====
  log_header "Plan Summary"
  log_info "Mode        : $mode"
  log_info "Targets     : ${#target_ips[@]} IPs"
  
  if [[ "$mode" =~ ^(MIGRATE|ADOPT)$ ]]; then
    log_info "Controller  : $controller"
    log_info "Inform URL  : $controller_url"
    
    if [[ "$mode" == "ADOPT" ]] && [ $reset_first -eq 1 ]; then
      log_info "Reset First : YES"
    fi
  fi
  
  log_info "SSH Timeout : ${ssh_timeout}s"
  log_info "CSV         : $out_csv"
  
  local confirm
  confirm=$(yes_no "Execute?" "y")
  if [[ "$confirm" != "Y" ]]; then
    echo "Aborted."
    exit 0
  fi
  
  # ===== SCAN =====
  mapfile -t open_hosts < <(port_scan "${target_ips[@]}")
  
  # ===== PROCESSING =====
  log_header "Processing Devices ($mode)"
  
  csv_init "$out_csv"
  
  local total=${#open_hosts[@]}
  local current=0
  
  for ip in "${open_hosts[@]}"; do
    ((current++))
    local pct=$((current * 100 / total))
    
    printf "\r  [%3d%%] %d/%total - Processing: %s" "$pct" "$current" "$ip"
    
    # Try credentials
    local connected=false
    local used_user=""
    
    for i in "${!cred_users[@]}"; do
      if test_ssh_connection "$ip" "${cred_users[$i]}" "${cred_passes[$i]}" "$ssh_timeout"; then
        connected=true
        used_user="${cred_users[$i]}"
        break
      fi
    done
    
    # Initialize row
    declare -A row=(
      [timestamp]="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      [ip]="$ip"
      [mac]=""
      [connected]="$connected"
      [username]="$used_user"
      [model]=""
      [hostname]=""
      [firmware]=""
      [adopt_status]=""
      [current_inform]=""
      [reset]="N/A"
      [inform1]="N/A"
      [inform2]="N/A"
      [inform_method]=""
      [status]="FAIL"
      [note]=""
      [debug_info]=""
    )
    
    if [ "$connected" = "false" ]; then
      row[note]="SSH auth failed"
      csv_add_row "$out_csv" row
      continue
    fi
    
    # Get device info
    eval "$(get_device_info "$ip" "$used_user" "${cred_passes[0]}" "$((ssh_timeout * 2))")"
    
    row[mac]="$MAC"
    row[model]="$MODEL"
    row[hostname]="$HOSTNAME"
    row[firmware]="$FIRMWARE"
    row[adopt_status]="$STATUS"
    row[current_inform]="$INFORM_URL"
    row[debug_info]="$RAW"
    
    # SANITY: done
    if [[ "$mode" == "SANITY" ]]; then
      row[status]="OK"
      csv_add_row "$out_csv" row
      continue
    fi
    
    # MIGRATE/ADOPT: set-inform
    if [[ "$mode" =~ ^(MIGRATE|ADOPT)$ ]]; then
      eval "$(send_set_inform "$ip" "$used_user" "${cred_passes[0]}" "$controller_url" "$((ssh_timeout * 2))")"
      
      row[inform1]="$OUTPUT"
      row[inform_method]="$METHOD"
      
      if [ "$SUCCESS" -eq 1 ]; then
        row[status]="OK"
      else
        row[status]="CHECK"
        row[note]="check CSV DebugInfo"
      fi
    fi
    
    csv_add_row "$out_csv" row
  done
  
  echo ""
  echo ""
  
  log_header "Results"
  log_ok "CSV: $out_csv"
  
  # Summary stats
  local ok_count fail_count check_count
  ok_count=$(grep -c ',OK,' "$out_csv" || echo "0")
  check_count=$(grep -c ',CHECK,' "$out_csv" || echo "0")
  fail_count=$(grep -c ',FAIL,' "$out_csv" || echo "0")
  
  echo ""
  echo -e "  ${GREEN}OK: $ok_count${NC}   ${YELLOW}CHECK: $check_count${NC}   ${RED}FAIL: $fail_count${NC}   ${DIM}Total: $((ok_count + check_count + fail_count))${NC}"
  echo ""
  
  case "$mode" in
    SANITY)
      log_ok "Sanity check complete."
      ;;
    MIGRATE)
      log_ok "Migration complete."
      log_info "Devices should check in with $controller shortly."
      ;;
    ADOPT)
      log_ok "Adoption run complete."
      log_info "Watch for pending devices in the controller."
      ;;
  esac
  
  echo ""
}

# ===================================================================
# ARGUMENT PARSING
# ===================================================================

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --cidr)
      CIDR="$2"
      shift 2
      ;;
    --ips)
      IPS="$2"
      shift 2
      ;;
    --controller)
      CONTROLLER="$2"
      shift 2
      ;;
    --username)
      USERNAME="$2"
      shift 2
      ;;
    --password)
      PASSWORD="$2"
      shift 2
      ;;
    --reset)
      RESET_FIRST=1
      shift
      ;;
    --ssh-timeout)
      SSH_TIMEOUT="$2"
      shift 2
      ;;
    --scan-timeout)
      SCAN_TIMEOUT="$2"
      shift 2
      ;;
    --output)
      OUT_CSV="$2"
      shift 2
      ;;
    --help|-h)
      cat <<EOF
UniFi Sovereign $SCRIPT_VERSION - SSH device migration toolkit

USAGE:
  $0 [OPTIONS]

OPTIONS:
  --mode SANITY|MIGRATE|ADOPT    Operation mode
  --cidr SUBNET                  Target subnet (e.g. 192.168.1.0/24)
  --ips IP1,IP2,...              Comma-separated IP list
  --controller IP                Target controller IP/hostname
  --username USER                SSH username
  --password PASS                SSH password (plaintext)
  --reset                        Factory reset before adoption
  --ssh-timeout SECONDS          SSH timeout (default: 7)
  --scan-timeout SECONDS         Port scan timeout (default: 3)
  --output FILE.csv              CSV output path
  --help                         Show this help

EXAMPLES:
  # Interactive mode
  $0

  # Migrate a subnet
  $0 --mode MIGRATE --cidr 192.168.1.0/24 --controller 10.0.0.5

  # Sanity check
  $0 --mode SANITY --ips 192.168.1.100,192.168.1.101

EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

main
