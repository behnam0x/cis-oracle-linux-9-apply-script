#!/bin/bash
#===============================================================================
# CIS Benchmark REMEDIATION Script — Oracle Linux 9 / RHEL 9 — Level 1 (Server)
#
# Companion to cis_audit.sh. Applies fixes for the automatable CIS controls.
# Section/ID numbers match cis_audit.sh so you can audit -> remediate -> re-audit.
#
# SAFETY MODEL (read this before running on anything you care about):
#   - Must run as root.
#   - Refuses to run on anything that isn't OL9/RHEL9-family by default.
#   - Every file this script touches is backed up first, timestamped, under
#     /var/backups/cis_remediation/<run-timestamp>/ with its original path
#     preserved, so you can restore with a straight `cp` back.
#   - Nothing is applied silently: use --dry-run first to see the exact diff
#     of every change with nothing written to disk.
#   - Interactive by default: prints a plan and asks for confirmation before
#     touching the system. Use --yes to skip the prompt (for automation).
#   - SSH hardening goes into a drop-in file (/etc/ssh/sshd_config.d/50-cis.conf)
#     and is syntax-checked with `sshd -t` before being made active — if it
#     fails validation the drop-in is removed and sshd is left untouched.
#   - High-blast-radius items (SELinux enforcing, disabling kernel modules
#     like usb-storage/bluetooth/uncommon net protocols, disabling services)
#     are OFF by default. Turn them on explicitly with --aggressive or the
#     specific flag noted next to each one. Read the warnings.
#   - Filesystem/partition options (nodev/nosuid/noexec on /tmp, /var, etc.)
#     are NEVER changed by this script — that needs an fstab change and a
#     remount/reboot planned around your actual disk layout. It's flagged
#     as MANUAL in every run.
#   - A reboot is required for SELinux enforcing mode, GRUB/kernel cmdline
#     changes, and some kernel module blacklists to fully take effect. The
#     script tells you at the end if one is needed.
#
# Usage:
#   sudo ./cis_remediate_ol9.sh --dry-run                 # show plan only
#   sudo ./cis_remediate_ol9.sh                            # interactive apply
#   sudo ./cis_remediate_ol9.sh --yes                      # non-interactive
#   sudo ./cis_remediate_ol9.sh --yes --section 5.1        # just SSH
#   sudo ./cis_remediate_ol9.sh --yes --aggressive         # include risky items
#   sudo ./cis_remediate_ol9.sh --list                     # list all item IDs
#===============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
DRY_RUN=false
ASSUME_YES=false
AGGRESSIVE=false
SECTION_FILTER=""
LIST_ONLY=false

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

TS=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backups/cis_remediation/${TS}"
LOG_DIR="/var/log/cis_remediation"
LOG_FILE="${LOG_DIR}/cis_remediate_${TS}.log"

# OL9/RHEL9 standard paths used across sections
PAM_SU="/etc/pam.d/su"
PWQUALITY_CONF="/etc/security/pwquality.conf"
PWHISTORY_CONF="/etc/security/pwhistory.conf"
FAILLOCK_CONF="/etc/security/faillock.conf"
LOGINDEFS="/etc/login.defs"

APPLIED=0; SKIPPED=0; FAILED=0; MANUAL=0
REBOOT_NEEDED=false
declare -a MANUAL_ITEMS=()
declare -a FAILED_ITEMS=()

usage() {
  cat <<'EOF'
Usage: sudo ./cis_remediate_ol9.sh [OPTIONS]
  --dry-run          Show every change that would be made, apply nothing
  --yes              Do not prompt for confirmation (for automation/CI)
  --aggressive       Also apply high-blast-radius items (SELinux enforcing,
                     disabling extra kernel modules/services). Read the
                     header comments before using this on a live server.
  --section NUM      Only run one section, e.g. --section 5.1
  --list             List all remediation item IDs and titles, then exit
  -h, --help         Show this help
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --yes|-y) ASSUME_YES=true; shift ;;
    --aggressive) AGGRESSIVE=true; shift ;;
    --section) SECTION_FILTER="$2"; shift 2 ;;
    --list) LIST_ONLY=true; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

should_run() {
  local sec="$1"
  [ -z "$SECTION_FILTER" ] && return 0
  [[ "$sec" == "$SECTION_FILTER"* ]] && return 0
  return 1
}

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE" 2>/dev/null || true; }

say()      { echo -e "$*"; }
say_ok()   { say "  ${GREEN}✓${NC} $*"; }
say_skip() { say "  ${DIM}·${NC} $*"; }
say_fail() { say "  ${RED}✗${NC} $*"; }
say_man()  { say "  ${YELLOW}![MANUAL]${NC} $*"; }
say_warn() { say "  ${YELLOW}⚠${NC} $*"; }

item_manual() {
  local id="$1" desc="$2"
  ((MANUAL++)); MANUAL_ITEMS+=("$id: $desc")
  $LIST_ONLY || say_man "$id  $desc"
  log "[MANUAL] $id - $desc"
}

# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

# backup_file <path>  — copies file into BACKUP_DIR preserving full path
backup_file() {
  local f="$1"
  [ -e "$f" ] || return 0
  $DRY_RUN && return 0
  local dest="${BACKUP_DIR}${f}"
  mkdir -p "$(dirname "$dest")"
  cp -a "$f" "$dest" 2>>"$LOG_FILE"
}

# ensure_line <id> <desc> <file> <regex-to-detect-present> <exact-line-to-ensure>
# Idempotent "make sure this exact config line exists, replacing any line
# that matches the same key so we don't end up with duplicates".
ensure_line() {
  local id="$1" desc="$2" file="$3" key_regex="$4" line="$5"
  ((APPLIED+SKIPPED+FAILED)) || true
  if [ -f "$file" ] && grep -Eq "^${key_regex}" "$file" 2>/dev/null; then
    if grep -Fxq "$line" "$file" 2>/dev/null; then
      say_skip "$id  $desc ${DIM}(already set)${NC}"; ((SKIPPED++)); log "[SKIP] $id already set in $file"; return 0
    fi
  fi
  if $DRY_RUN; then
    say "  ${CYAN}~${NC} $id  $desc"
    say "      ${DIM}file: $file  ->  $line${NC}"
    return 0
  fi
  mkdir -p "$(dirname "$file")"
  touch "$file"
  backup_file "$file"
  if grep -Eq "^${key_regex}" "$file" 2>/dev/null; then
    sed -i -E "s|^${key_regex}.*$|${line//|/\\|}|" "$file"
  else
    echo "$line" >> "$file"
  fi
  if [ $? -eq 0 ]; then
    say_ok "$id  $desc"; ((APPLIED++)); log "[APPLIED] $id -> $file: $line"
  else
    say_fail "$id  $desc"; ((FAILED++)); FAILED_ITEMS+=("$id"); log "[FAILED] $id -> $file"
  fi
}

# set_sysctl <id> <desc> <key> <value> <dropin-file>
set_sysctl() {
  local id="$1" desc="$2" key="$3" val="$4" file="${5:-/etc/sysctl.d/60-cis.conf}"
  ensure_line "$id" "$desc" "$file" "${key//./\\.}[[:space:]]*=" "${key} = ${val}"
}

apply_sysctl_runtime() {
  $DRY_RUN && return 0
  sysctl --system &>>"$LOG_FILE"
}

# write_file_if_diff <id> <desc> <target-path> <mode> <content-heredoc-var>
write_managed_file() {
  local id="$1" desc="$2" target="$3" mode="$4" content="$5"
  if [ -f "$target" ] && diff -q <(echo "$content") "$target" &>/dev/null; then
    say_skip "$id  $desc ${DIM}(already up to date)${NC}"; ((SKIPPED++)); return 0
  fi
  if $DRY_RUN; then
    say "  ${CYAN}~${NC} $id  $desc"
    say "      ${DIM}would write: $target (mode $mode)${NC}"
    return 0
  fi
  backup_file "$target"
  mkdir -p "$(dirname "$target")"
  printf '%s\n' "$content" > "$target"
  chmod "$mode" "$target"
  chown root:root "$target"
  say_ok "$id  $desc"; ((APPLIED++)); log "[APPLIED] $id -> wrote $target"
}

# set_perm <id> <desc> <path> <mode> [<owner:group>]
set_perm() {
  local id="$1" desc="$2" path="$3" mode="$4" own="${5:-root:root}"
  [ -e "$path" ] || { say_skip "$id  $desc ${DIM}(file not present)${NC}"; ((SKIPPED++)); return 0; }
  local cur_mode cur_own
  cur_mode=$(stat -c '%a' "$path" 2>/dev/null)
  cur_own=$(stat -c '%U:%G' "$path" 2>/dev/null)
  if [ "$cur_mode" = "$mode" ] && [ "$cur_own" = "$own" ]; then
    say_skip "$id  $desc ${DIM}(already $mode $own)${NC}"; ((SKIPPED++)); return 0
  fi
  if $DRY_RUN; then
    say "  ${CYAN}~${NC} $id  $desc"
    say "      ${DIM}$path: $cur_mode $cur_own -> $mode $own${NC}"
    return 0
  fi
  chmod "$mode" "$path" 2>>"$LOG_FILE" && chown "$own" "$path" 2>>"$LOG_FILE"
  if [ $? -eq 0 ]; then
    say_ok "$id  $desc"; ((APPLIED++)); log "[APPLIED] $id -> $path chmod $mode chown $own"
  else
    say_fail "$id  $desc"; ((FAILED++)); FAILED_ITEMS+=("$id")
  fi
}

# pkg_remove <id> <desc> <pkg>
pkg_remove() {
  local id="$1" desc="$2" pkg="$3"
  if ! rpm -q "$pkg" &>/dev/null; then
    say_skip "$id  $desc ${DIM}(not installed)${NC}"; ((SKIPPED++)); return 0
  fi
  if $DRY_RUN; then say "  ${CYAN}~${NC} $id  $desc ${DIM}(dnf remove -y $pkg)${NC}"; return 0; fi
  if dnf remove -y "$pkg" &>>"$LOG_FILE"; then
    say_ok "$id  $desc"; ((APPLIED++)); log "[APPLIED] $id removed $pkg"
  else
    say_fail "$id  $desc"; ((FAILED++)); FAILED_ITEMS+=("$id")
  fi
}

# svc_disable <id> <desc> <service>
svc_disable() {
  local id="$1" desc="$2" svc="$3"
  if ! systemctl list-unit-files "${svc}.service" &>/dev/null | grep -q "${svc}.service"; then
    say_skip "$id  $desc ${DIM}(unit not present)${NC}"; ((SKIPPED++)); return 0
  fi
  if ! systemctl is-enabled "$svc" &>/dev/null && ! systemctl is-active --quiet "$svc"; then
    say_skip "$id  $desc ${DIM}(already disabled)${NC}"; ((SKIPPED++)); return 0
  fi
  if $DRY_RUN; then say "  ${CYAN}~${NC} $id  $desc ${DIM}(systemctl disable --now $svc)${NC}"; return 0; fi
  if systemctl disable --now "$svc" &>>"$LOG_FILE"; then
    say_ok "$id  $desc"; ((APPLIED++)); log "[APPLIED] $id disabled $svc"
  else
    say_fail "$id  $desc"; ((FAILED++)); FAILED_ITEMS+=("$id")
  fi
}

# svc_enable <id> <desc> <service>
svc_enable() {
  local id="$1" desc="$2" svc="$3"
  if ! systemctl list-unit-files "${svc}.service" &>/dev/null | grep -q "${svc}.service"; then
    say_skip "$id  $desc ${DIM}(unit not present — package not installed?)${NC}"; ((SKIPPED++)); return 0
  fi
  if systemctl is-enabled "$svc" &>/dev/null && systemctl is-active --quiet "$svc"; then
    say_skip "$id  $desc ${DIM}(already enabled+active)${NC}"; ((SKIPPED++)); return 0
  fi
  if $DRY_RUN; then say "  ${CYAN}~${NC} $id  $desc ${DIM}(systemctl enable --now $svc)${NC}"; return 0; fi
  if systemctl enable --now "$svc" &>>"$LOG_FILE"; then
    say_ok "$id  $desc"; ((APPLIED++)); log "[APPLIED] $id enabled $svc"
  else
    say_fail "$id  $desc"; ((FAILED++)); FAILED_ITEMS+=("$id")
  fi
}

# ============================================================
# SECTION 1  INITIAL SETUP
# ============================================================

section_1_1() {
  should_run "1.1" || return
  say ""; say "${BOLD}${BLUE}1.1  Filesystem Kernel Modules${NC}"
  local modfile="/etc/modprobe.d/cis-filesystems.conf"
  local content="# CIS: disable rarely-used filesystem kernel modules
install cramfs /bin/false
install freevxfs /bin/false
install hfs /bin/false
install hfsplus /bin/false
install jffs2 /bin/false
install squashfs /bin/false
install udf /bin/false"
  write_managed_file "1.1.1" "Disable unused filesystem modules (cramfs/freevxfs/hfs/hfsplus/jffs2/squashfs/udf)" \
    "$modfile" 644 "$content"

  if $AGGRESSIVE; then
    write_managed_file "1.1.1.8" "Disable usb-storage kernel module (--aggressive: breaks USB mass storage, incl. some virtual media)" \
      "/etc/modprobe.d/cis-usb-storage.conf" 644 "install usb-storage /bin/false"
  else
    say_skip "1.1.1.8  Disable usb-storage module ${DIM}(skipped — needs --aggressive, can break VM console media/USB installs)${NC}"; ((SKIPPED++))
  fi
  item_manual "1.1.2" "Separate partitions and mount options (nodev/nosuid/noexec on /tmp,/var,/var/tmp,/var/log,/var/log/audit,/home,/dev/shm) — requires fstab + planned remount/reboot, not automated by this script"
}

section_1_2() {
  should_run "1.2" || return
  say ""; say "${BOLD}${BLUE}1.2  Package Management${NC}"
  ensure_line "1.2.1.2" "Ensure gpgcheck is globally activated" "/etc/dnf/dnf.conf" "gpgcheck[[:space:]]*=" "gpgcheck=1"
  item_manual "1.2.1.1" "Verify GPG keys configured for all enabled repos (rpm -q gpg-pubkey --qf ...)"
  item_manual "1.2.2.1" "Confirm patch/update cadence and additional security tooling per your policy"
}

section_1_3() {
  should_run "1.3" || return
  say ""; say "${BOLD}${BLUE}1.3  Mandatory Access Control (SELinux)${NC}"
  local mode
  mode=$(getenforce 2>/dev/null || echo "Unknown")
  if $AGGRESSIVE; then
    if grep -Eq 'selinux=0|enforcing=0' /etc/default/grub 2>/dev/null; then
      if $DRY_RUN; then
        say "  ${CYAN}~${NC} 1.3.1.2  Remove selinux=0/enforcing=0 from GRUB_CMDLINE_LINUX"
      else
        backup_file /etc/default/grub
        sed -i -E 's/\s*(selinux|enforcing)=0//g' /etc/default/grub
        grub2-mkconfig -o /boot/grub2/grub.cfg &>>"$LOG_FILE" || true
        say_ok "1.3.1.2  Removed selinux=0/enforcing=0 from GRUB, regenerated grub.cfg"; ((APPLIED++)); REBOOT_NEEDED=true
      fi
    else
      say_skip "1.3.1.2  SELinux not disabled in bootloader ${DIM}(already clean)${NC}"; ((SKIPPED++))
    fi
    ensure_line "1.3.1.3-4" "Ensure SELINUX is not set to disabled" "/etc/selinux/config" "SELINUX[[:space:]]*=" "SELINUX=enforcing"
    if [ "$mode" != "Enforcing" ]; then
      say_warn "1.3.1.5  SELINUX=enforcing written to /etc/selinux/config — mode will only become Enforcing after a REBOOT (relabeling required if switching from disabled/permissive). Do NOT reboot unattended the first time; watch the console."
      REBOOT_NEEDED=true; ((APPLIED++))
    else
      say_skip "1.3.1.5  SELinux already Enforcing"; ((SKIPPED++))
    fi
    pkg_remove "1.3.1.7" "Remove mcstrans (MCS Translation Service)" "mcstrans"
    pkg_remove "1.3.1.8" "Remove setroubleshoot" "setroubleshoot"
  else
    say_skip "1.3.1.x  SELinux enforcing/GRUB changes ${DIM}(skipped — needs --aggressive; current mode: ${mode}. Switching modes needs a reboot and can lock you out if a service isn't labeled — test in staging first)${NC}"
    ((SKIPPED+=6))
  fi
  item_manual "1.3.1.6" "Review for unconfined SELinux domains: semanage permissive -l"
}

section_1_4() {
  should_run "1.4" || return
  say ""; say "${BOLD}${BLUE}1.4  Bootloader${NC}"
  if [ -f /boot/grub2/grub.cfg ]; then
    set_perm "1.4.2" "Restrict access to bootloader config" /boot/grub2/grub.cfg 600 root:root
  fi
  item_manual "1.4.1" "Set a GRUB2 bootloader password (grub2-setpassword) — needs an interactive password choice, not automated"
}

section_1_5() {
  should_run "1.5" || return
  say ""; say "${BOLD}${BLUE}1.5  Additional Process Hardening${NC}"
  set_sysctl "1.5.1" "Enable ASLR" "kernel.randomize_va_space" "2"
  set_sysctl "1.5.2" "Restrict ptrace scope" "kernel.yama.ptrace_scope" "1"
  ensure_line "1.5.3" "Disable core dump backtraces (limits.conf)" "/etc/security/limits.d/99-cis.conf" "\\*[[:space:]]+hard[[:space:]]+core" "* hard core 0"
  write_managed_file "1.5.4" "Disable core dump storage (systemd-coredump)" "/etc/systemd/coredump.conf.d/60-cis.conf" 644 \
"[Coredump]
Storage=none
ProcessSizeMax=0"
  apply_sysctl_runtime
}

section_1_6() {
  should_run "1.6" || return
  say ""; say "${BOLD}${BLUE}1.6  System-Wide Crypto Policy${NC}"
  local pol
  pol=$(update-crypto-policies --show 2>/dev/null || echo "UNKNOWN")
  if [ "$pol" = "LEGACY" ]; then
    if $DRY_RUN; then
      say "  ${CYAN}~${NC} 1.6.1  update-crypto-policies --set DEFAULT ${DIM}(current: LEGACY)${NC}"
    else
      update-crypto-policies --set DEFAULT &>>"$LOG_FILE"
      say_ok "1.6.1  Moved crypto policy off LEGACY to DEFAULT"; ((APPLIED++))
    fi
  else
    say_skip "1.6.1  Crypto policy not LEGACY ${DIM}(current: ${pol})${NC}"; ((SKIPPED++))
  fi
  item_manual "1.6.1b" "Consider FUTURE or FIPS crypto policy if your compliance target requires it (update-crypto-policies --set FUTURE) — test app/SSH client compatibility first"
}

section_1_7() {
  should_run "1.7" || return
  say ""; say "${BOLD}${BLUE}1.7  Warning Banners${NC}"
  local banner="Authorized uses only. All activity may be monitored and reported."
  write_managed_file "1.7.1" "Configure /etc/motd" /etc/motd 644 "$banner"
  write_managed_file "1.7.2" "Configure /etc/issue" /etc/issue 644 "$banner"
  write_managed_file "1.7.3" "Configure /etc/issue.net" /etc/issue.net 644 "$banner"
  set_perm "1.7.4" "Permissions on /etc/motd" /etc/motd 644 root:root
  set_perm "1.7.5" "Permissions on /etc/issue" /etc/issue 644 root:root
  set_perm "1.7.6" "Permissions on /etc/issue.net" /etc/issue.net 644 root:root
}

section_1_8() {
  should_run "1.8" || return
  say ""; say "${BOLD}${BLUE}1.8  GNOME Display Manager${NC}"
  if rpm -q gdm &>/dev/null; then
    write_managed_file "1.8.2" "Disable GDM automatic login / set login banner" /etc/dconf/db/gdm.d/00-cis-login 644 \
"[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized uses only.'
disable-user-list=true"
    if ! $DRY_RUN; then dconf update &>>"$LOG_FILE" || true; fi
  else
    say_skip "1.8.x  GDM not installed on this server ${DIM}(nothing to do)${NC}"; ((SKIPPED++))
  fi
}

# ============================================================
# SECTION 2  SERVICES
# ============================================================

section_2() {
  should_run "2" || return
  say ""; say "${BOLD}${BLUE}2  Services${NC}"

  say "${CYAN}  2.2  Special-purpose services${NC}"
  local -a always_off=(autofs avahi-daemon dhcpd bind vsftpd dovecot smb squid httpd nfs-server ypserv
                        cups rpcbind rsyncd nis telnet.socket tftp.socket xinetd slapd)
  for svc in "${always_off[@]}"; do
    svc_disable "2.2.$svc" "Ensure $svc is not in use" "$svc"
  done
  if $AGGRESSIVE; then
    svc_disable "2.1.x" "Disable X11 forwarding server components (xorg-x11-server-common)" "xorg-x11-server-common" 2>/dev/null || true
  fi

  say "${CYAN}  2.3  Time synchronization${NC}"
  if ! rpm -q chrony &>/dev/null; then
    if $DRY_RUN; then
      say "  ${CYAN}~${NC} 2.3.1.1  Install chrony (dnf install -y chrony)"
    else
      dnf install -y chrony &>>"$LOG_FILE" && { say_ok "2.3.1.1  Installed chrony"; ((APPLIED++)); } || { say_fail "2.3.1.1  Install chrony"; ((FAILED++)); }
    fi
  else
    say_skip "2.3.1.1  chrony already installed"; ((SKIPPED++))
  fi
  svc_enable "2.3.2.1" "Ensure chrony is enabled and running" "chronyd"
  item_manual "2.3.1.2" "Confirm chrony.conf points at your approved NTP sources"

  item_manual "2.4" "Review job schedulers (cron/at) and any custom systemd timers for content you don't recognize"
}

section_2_4() {
  should_run "2.4" || return
  say ""; say "${BOLD}${BLUE}2.4  Cron and at${NC}"
  set_perm "2.4.1.2" "Permissions on /etc/crontab" /etc/crontab 600 root:root
  for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    set_perm "2.4.1.x" "Permissions on $d" "$d" 700 root:root
  done
  if [ ! -f /etc/cron.deny ] && [ ! -f /etc/at.deny ]; then
    say_skip "2.4.1.8  No cron.deny/at.deny present ${DIM}(already correct)${NC}"; ((SKIPPED++))
  else
    if $DRY_RUN; then
      say "  ${CYAN}~${NC} 2.4.1.8  Remove /etc/cron.deny and /etc/at.deny (use allow-lists instead)"
    else
      [ -f /etc/cron.deny ] && { backup_file /etc/cron.deny; rm -f /etc/cron.deny; }
      [ -f /etc/at.deny ] && { backup_file /etc/at.deny; rm -f /etc/at.deny; }
      say_ok "2.4.1.8  Removed cron.deny/at.deny"; ((APPLIED++))
    fi
  fi
  write_managed_file "2.4.1.8b" "Restrict cron to root (cron.allow)" /etc/cron.allow 600 "root"
  write_managed_file "2.4.2.1" "Restrict at to root (at.allow)" /etc/at.allow 600 "root"
}

# ============================================================
# SECTION 3  NETWORK
# ============================================================

section_3() {
  should_run "3" || return
  say ""; say "${BOLD}${BLUE}3.1 / 3.2  Network devices and kernel modules${NC}"
  svc_disable "3.1.3" "Ensure bluetooth service is not active" "bluetooth"

  local content="# CIS: disable rarely-needed network protocol kernel modules
install dccp /bin/false
install tipc /bin/false
install rds /bin/false
install sctp /bin/false"
  if $AGGRESSIVE; then
    write_managed_file "3.2.1" "Disable dccp/tipc/rds/sctp kernel modules (--aggressive: sctp is used by some clustering/telecom stacks — confirm nothing on this host needs it)" \
      "/etc/modprobe.d/cis-net-protocols.conf" 644 "$content"
  else
    say_skip "3.2.1  dccp/tipc/rds/sctp modules ${DIM}(skipped — needs --aggressive)${NC}"; ((SKIPPED++))
  fi
}

section_3_3() {
  should_run "3.3" || return
  say ""; say "${BOLD}${BLUE}3.3  Network Kernel Parameters${NC}"
  set_sysctl "3.3.1"  "Disable IP forwarding"                 "net.ipv4.ip_forward" "0"
  set_sysctl "3.3.2a" "Disable send_redirects (all)"           "net.ipv4.conf.all.send_redirects" "0"
  set_sysctl "3.3.2b" "Disable send_redirects (default)"       "net.ipv4.conf.default.send_redirects" "0"
  set_sysctl "3.3.3"  "Ignore bogus ICMP error responses"      "net.ipv4.icmp_ignore_bogus_error_responses" "1"
  set_sysctl "3.3.4"  "Ignore broadcast ICMP requests"         "net.ipv4.icmp_echo_ignore_broadcasts" "1"
  set_sysctl "3.3.5a" "Ignore ICMP redirects (all)"             "net.ipv4.conf.all.accept_redirects" "0"
  set_sysctl "3.3.5b" "Ignore ICMP redirects (default)"         "net.ipv4.conf.default.accept_redirects" "0"
  set_sysctl "3.3.6a" "Ignore secure ICMP redirects (all)"      "net.ipv4.conf.all.secure_redirects" "0"
  set_sysctl "3.3.6b" "Ignore secure ICMP redirects (default)"  "net.ipv4.conf.default.secure_redirects" "0"
  set_sysctl "3.3.7a" "Enable reverse path filtering (all)"     "net.ipv4.conf.all.rp_filter" "1"
  set_sysctl "3.3.7b" "Enable reverse path filtering (default)" "net.ipv4.conf.default.rp_filter" "1"
  set_sysctl "3.3.8a" "Reject source-routed packets (all)"      "net.ipv4.conf.all.accept_source_route" "0"
  set_sysctl "3.3.8b" "Reject source-routed packets (default)"  "net.ipv4.conf.default.accept_source_route" "0"
  set_sysctl "3.3.9a" "Log martian packets (all)"                "net.ipv4.conf.all.log_martians" "1"
  set_sysctl "3.3.9b" "Log martian packets (default)"            "net.ipv4.conf.default.log_martians" "1"
  set_sysctl "3.3.10" "Enable TCP SYN cookies"                   "net.ipv4.tcp_syncookies" "1"
  set_sysctl "3.3.11a" "Ignore IPv6 router advertisements (all)"     "net.ipv6.conf.all.accept_ra" "0"
  set_sysctl "3.3.11b" "Ignore IPv6 router advertisements (default)" "net.ipv6.conf.default.accept_ra" "0"
  apply_sysctl_runtime
  item_manual "3.1.1" "Decide and document whether IPv6 is required on this host — if not, disable at the NIC/GRUB level deliberately, not blindly"
}

# ============================================================
# SECTION 4  HOST-BASED FIREWALL
# ============================================================

section_4() {
  should_run "4" || return
  say ""; say "${BOLD}${BLUE}4  Host-Based Firewall (firewalld)${NC}"
  if ! rpm -q firewalld &>/dev/null; then
    if $DRY_RUN; then say "  ${CYAN}~${NC} 4.1.1  Install firewalld"; else
      dnf install -y firewalld &>>"$LOG_FILE" && { say_ok "4.1.1  Installed firewalld"; ((APPLIED++)); }
    fi
  else
    say_skip "4.1.1  firewalld already installed"; ((SKIPPED++))
  fi
  svc_enable "4.1.2" "Ensure firewalld is enabled and running" "firewalld"
  say_warn "4.x  NOT auto-changing firewall zones/rules — that risks locking you out of SSH remotely. Review 'firewall-cmd --list-all' yourself and set the default zone / allowed services deliberately."
  item_manual "4.2/4.3" "Review firewalld zones/services and (if not using firewalld) ensure nftables/iptables aren't also active — CIS requires exactly one firewall utility in use"
}

# ============================================================
# SECTION 5  ACCESS CONTROL
# ============================================================

section_5_1() {
  should_run "5.1" || return
  say ""; say "${BOLD}${BLUE}5.1  SSH Server${NC}"
  if [ ! -f /etc/ssh/sshd_config ]; then
    say_skip "5.1.x  sshd not installed"; ((SKIPPED++)); return
  fi

  set_perm "5.1.1" "Permissions on /etc/ssh/sshd_config" /etc/ssh/sshd_config 600 root:root
  if $DRY_RUN; then
    say "  ${CYAN}~${NC} 5.1.2/5.1.3  Fix SSH host key permissions (600 private, 644 public)"
  else
    find /etc/ssh -type f -name '*_key'  -exec chmod 600 {} \; 2>>"$LOG_FILE"
    find /etc/ssh -type f -name '*.pub'  -exec chmod 644 {} \; 2>>"$LOG_FILE"
    say_ok "5.1.2/5.1.3  SSH host key permissions fixed"; ((APPLIED++))
  fi

  local dropin="/etc/ssh/sshd_config.d/50-cis.conf"
  local content="# CIS hardening — managed by cis_remediate_ol9.sh, do not edit by hand
LogLevel INFO
PermitRootLogin no
PermitEmptyPasswords no
IgnoreRhosts yes
HostbasedAuthentication no
GSSAPIAuthentication no
X11Forwarding no
AllowTcpForwarding no
PermitUserEnvironment no
MaxAuthTries 4
MaxSessions 10
MaxStartups 10:30:60
ClientAliveInterval 15
ClientAliveCountMax 3
LoginGraceTime 60
UsePAM yes
Banner /etc/issue.net"

  # NOTE: PermitRootLogin no is included above because CIS requires it, but this
  # will lock out root-over-SSH logins. Refusing to apply it if root-over-SSH
  # looks like the only access path and no other sudo-capable user exists.
  local other_sudo_user
  other_sudo_user=$(getent group wheel 2>/dev/null | cut -d: -f4)
  if [ -z "$other_sudo_user" ]; then
    say_warn "5.1.20  Skipping PermitRootLogin no — no non-root user in the 'wheel' group was found, and disabling root SSH login without one could lock you out. Add an admin user to 'wheel' first, then re-run."
    content=$(echo "$content" | sed '/^PermitRootLogin no$/d')
    ((MANUAL++)); MANUAL_ITEMS+=("5.1.20: Set PermitRootLogin no once a non-root sudo user exists")
  fi

  if $DRY_RUN; then
    say "  ${CYAN}~${NC} 5.1.4-22  Write SSH hardening drop-in"
    say "      ${DIM}file: $dropin${NC}"
    echo "$content" | sed 's/^/      /'
  else
    backup_file "$dropin"
    mkdir -p /etc/ssh/sshd_config.d
    printf '%s\n' "$content" > "$dropin"
    chmod 600 "$dropin"; chown root:root "$dropin"
    if sshd -t &>>"$LOG_FILE"; then
      systemctl reload sshd &>>"$LOG_FILE" || systemctl restart sshd &>>"$LOG_FILE"
      say_ok "5.1.4-22  SSH hardening applied and sshd reloaded (config validated with 'sshd -t' first)"
      ((APPLIED++)); log "[APPLIED] 5.1.x wrote $dropin, sshd -t passed, reloaded"
    else
      rm -f "$dropin"
      say_fail "5.1.4-22  sshd -t FAILED validation — drop-in removed, sshd left untouched. Check $LOG_FILE"
      ((FAILED++)); FAILED_ITEMS+=("5.1.x")
    fi
  fi
  item_manual "5.1.7" "Set AllowUsers/AllowGroups in the drop-in to your actual admin accounts once you know who they are"
  say_warn "5.1.4-6  Ciphers/MACs/KexAlgorithms intentionally left unset so sshd inherits the system-wide crypto policy (see section 1.6) instead of a hardcoded list that can drift out of date."
}

section_5_2() {
  should_run "5.2" || return
  say ""; say "${BOLD}${BLUE}5.2  Privilege Escalation (sudo)${NC}"
  if ! command -v sudo &>/dev/null; then
    if $DRY_RUN; then say "  ${CYAN}~${NC} 5.2.1  Install sudo"; else
      dnf install -y sudo &>>"$LOG_FILE" && { say_ok "5.2.1  Installed sudo"; ((APPLIED++)); }
    fi
  else
    say_skip "5.2.1  sudo already installed"; ((SKIPPED++))
  fi

  local sudoers_dropin="/etc/sudoers.d/99-cis"
  local content="Defaults use_pty
Defaults logfile=\"/var/log/sudo.log\"
Defaults timestamp_timeout=15"
  if [ -f "$sudoers_dropin" ] && diff -q <(echo "$content") "$sudoers_dropin" &>/dev/null; then
    say_skip "5.2.2/3/6  sudo hardening already in place"; ((SKIPPED++))
  elif $DRY_RUN; then
    say "  ${CYAN}~${NC} 5.2.2/3/6  Write $sudoers_dropin"; echo "$content" | sed 's/^/      /'
  else
    backup_file "$sudoers_dropin"
    printf '%s\n' "$content" > "$sudoers_dropin"
    chmod 440 "$sudoers_dropin"; chown root:root "$sudoers_dropin"
    if visudo -cf "$sudoers_dropin" &>>"$LOG_FILE"; then
      say_ok "5.2.2/3/6  sudo hardening applied (use_pty, logfile, 15min timeout)"; ((APPLIED++))
    else
      rm -f "$sudoers_dropin"
      say_fail "5.2.2/3/6  visudo syntax check failed — not applied"; ((FAILED++)); FAILED_ITEMS+=("5.2.x")
    fi
  fi

  if grep -rq 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
    item_manual "5.2.4" "NOPASSWD entries found in sudoers — review and remove manually (not auto-edited, could be intentional for automation accounts): $(grep -rl 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | tr '\n' ' ')"
  else
    say_skip "5.2.4  No NOPASSWD entries found"; ((SKIPPED++))
  fi

  ensure_line "5.2.7" "Restrict su to the wheel group" "$PAM_SU" "auth[[:space:]]+required[[:space:]]+pam_wheel\\.so" "auth             required        pam_wheel.so use_uid group=wheel"
}

section_5_3() {
  should_run "5.3" || return
  say ""; say "${BOLD}${BLUE}5.3  PAM${NC}"
  if command -v authselect &>/dev/null; then
    local current
    current=$(authselect current 2>/dev/null | head -1)
    if echo "$current" | grep -q 'No existing configuration'; then
      if $DRY_RUN; then
        say "  ${CYAN}~${NC} 5.3.1  authselect select sssd with-faillock with-pwquality --force"
      else
        authselect select sssd with-faillock with-pwquality --force &>>"$LOG_FILE" \
          && { say_ok "5.3.1  authselect profile applied (sssd + faillock + pwquality)"; ((APPLIED++)); } \
          || { say_fail "5.3.1  authselect apply failed"; ((FAILED++)); FAILED_ITEMS+=("5.3.1"); }
      fi
    else
      if authselect current 2>/dev/null | grep -q 'with-faillock' && authselect current 2>/dev/null | grep -q 'with-pwquality'; then
        say_skip "5.3.1  authselect already has faillock + pwquality features"; ((SKIPPED++))
      else
        if $DRY_RUN; then
          say "  ${CYAN}~${NC} 5.3.1  authselect enable-feature with-faillock / with-pwquality"
        else
          authselect enable-feature with-faillock &>>"$LOG_FILE"
          authselect enable-feature with-pwquality &>>"$LOG_FILE"
          say_ok "5.3.1  Enabled faillock + pwquality authselect features"; ((APPLIED++))
        fi
      fi
    fi
  else
    item_manual "5.3.1" "authselect not found — configure PAM faillock/pwquality manually"
  fi

  ensure_line "5.3.2.1" "Enforce minimum password length 14"     "$PWQUALITY_CONF" "minlen"     "minlen = 14"
  ensure_line "5.3.2.2" "Require at least 4 character classes"    "$PWQUALITY_CONF" "minclass"   "minclass = 4"
  ensure_line "5.3.2.3" "Limit consecutive repeated characters"   "$PWQUALITY_CONF" "maxrepeat"  "maxrepeat = 3"
  ensure_line "5.3.2.4" "Deny dictionary/username-based passwords" "$PWQUALITY_CONF" "dictcheck"  "dictcheck = 1"

  ensure_line "5.3.3.1.1" "Lockout after 5 failed attempts" "$FAILLOCK_CONF" "deny"        "deny = 5"
  ensure_line "5.3.3.1.2" "Failed-attempt counter window"    "$FAILLOCK_CONF" "fail_interval" "fail_interval = 900"
  ensure_line "5.3.3.1.3" "Account unlock time (15 min)"     "$FAILLOCK_CONF" "unlock_time" "unlock_time = 900"

  ensure_line "5.3.3.2.1" "Remember last 24 passwords" "$PWHISTORY_CONF" "remember"    "remember = 24"
  ensure_line "5.3.3.2.2" "Enforce password history on retry too" "$PWHISTORY_CONF" "enforce_for_root" "enforce_for_root"

  ensure_line "5.3.3.3.2" "SHA-512 password hashing" "/etc/login.defs" "ENCRYPT_METHOD" "ENCRYPT_METHOD SHA512"
}

section_5_4() {
  should_run "5.4" || return
  say ""; say "${BOLD}${BLUE}5.4  User Accounts and Environment${NC}"
  ensure_line "5.4.1.1" "PASS_MAX_DAYS <= 365"  "$LOGINDEFS" "PASS_MAX_DAYS" "PASS_MAX_DAYS   365"
  ensure_line "5.4.1.2" "PASS_MIN_DAYS >= 1"    "$LOGINDEFS" "PASS_MIN_DAYS" "PASS_MIN_DAYS   1"
  ensure_line "5.4.1.4" "PASS_WARN_AGE >= 7"    "$LOGINDEFS" "PASS_WARN_AGE" "PASS_WARN_AGE   7"

  write_managed_file "5.4.2.6" "Default umask 027 for interactive shells" /etc/profile.d/99-cis-umask.sh 644 \
"umask 027"

  if $DRY_RUN; then
    say "  ${CYAN}~${NC} 5.4.2.2  Lock any system accounts (UID<1000, not root/nobody) that still have a login shell"
  else
    local changed=0
    while IFS=: read -r user _ uid _ _ _ shell; do
      if [ "$uid" -lt 1000 ] && [ "$user" != "root" ] && [ "$shell" != "/sbin/nologin" ] && [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
        usermod -s /sbin/nologin "$user" 2>>"$LOG_FILE" && changed=$((changed+1))
      fi
    done < /etc/passwd
    if [ "$changed" -gt 0 ]; then say_ok "5.4.2.2  Set nologin shell on $changed system account(s)"; ((APPLIED++)); log "[APPLIED] 5.4.2.2 changed $changed accounts";
    else say_skip "5.4.2.2  All system accounts already have nologin/false shell"; ((SKIPPED++)); fi
  fi

  item_manual "5.4.2.4" "Confirm root is the only UID 0 account: awk -F: '(\$3==0)' /etc/passwd"
  item_manual "5.4.2.8" "Review dot-file permissions in interactive users' home directories"
}

# ============================================================
# SECTION 6  LOGGING AND AUDITING
# ============================================================

section_6_1() {
  should_run "6.1" || return
  say ""; say "${BOLD}${BLUE}6.1/6.2  System Logging (rsyslog / journald)${NC}"
  if ! rpm -q rsyslog &>/dev/null; then
    if $DRY_RUN; then say "  ${CYAN}~${NC} 6.2.1.1  Install rsyslog"; else
      dnf install -y rsyslog &>>"$LOG_FILE" && { say_ok "6.2.1.1  Installed rsyslog"; ((APPLIED++)); }
    fi
  else
    say_skip "6.2.1.1  rsyslog already installed"; ((SKIPPED++))
  fi
  svc_enable "6.2.1.2" "Ensure rsyslog is enabled and running" "rsyslog"
  ensure_line "6.2.1.3" "rsyslog default file permissions" "/etc/rsyslog.conf" "\\\$FileCreateMode" "\$FileCreateMode 0640"
  set_perm "6.2.4.1" "Permissions on /var/log" /var/log 755 root:root

  write_managed_file "6.2.2.1" "journald forwards to syslog + persistent storage" /etc/systemd/journald.conf.d/60-cis.conf 644 \
"[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=yes"
  if ! $DRY_RUN; then systemctl restart systemd-journald &>>"$LOG_FILE" || true; fi
  item_manual "6.2.3.6" "Configure rsyslog remote log forwarding to your central log host if required by policy"
}

section_6_3() {
  should_run "6.3" || return
  say ""; say "${BOLD}${BLUE}6.3  System Auditing (auditd)${NC}"
  if ! command -v auditctl &>/dev/null; then
    if $DRY_RUN; then
      say "  ${CYAN}~${NC} 6.3.1.1  Install audit audit-libs"
    else
      dnf install -y audit audit-libs &>>"$LOG_FILE" && { say_ok "6.3.1.1  Installed auditd"; ((APPLIED++)); }
    fi
  else
    say_skip "6.3.1.1  auditd already installed"; ((SKIPPED++))
  fi

  ensure_line "6.3.2.1" "Audit log max size (MB)"          /etc/audit/auditd.conf "max_log_file[[:space:]]*=" "max_log_file = 50"
  ensure_line "6.3.2.2" "Never auto-delete audit logs"      /etc/audit/auditd.conf "max_log_file_action[[:space:]]*=" "max_log_file_action = keep_logs"
  ensure_line "6.3.2.3" "Email admin when space is low"     /etc/audit/auditd.conf "space_left_action[[:space:]]*=" "space_left_action = email"
  ensure_line "6.3.2.4" "Halt system when audit space is critically low" /etc/audit/auditd.conf "admin_space_left_action[[:space:]]*=" "admin_space_left_action = halt"

  local rules="/etc/audit/rules.d/50-cis.rules"
  local content="## CIS audit rules — managed by cis_remediate_ol9.sh
-D
-b 8192
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-w /etc/localtime -p wa -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/hostname -p wa -k system-locale
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network/ -p wa -k system-locale
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/sbin/setenforce -p x -k MAC-policy
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b64 -S init_module,delete_module,finit_module -k modules
-w /usr/bin/chcon -p x -k privileged
-w /usr/bin/setfacl -p x -k privileged
-w /usr/bin/chacl -p x -k privileged
-w /usr/sbin/usermod -p x -k privileged
-e 2"
  write_managed_file "6.3.3" "Write standard CIS audit rules (identity, time-change, MAC-policy, logins, session, perm_mod, access, delete, modules, sudoers, made immutable with -e 2)" \
    "$rules" 600 "$content"
  if ! $DRY_RUN && [ -f "$rules" ]; then
    augenrules --load &>>"$LOG_FILE" || true
    say_warn "6.3.3.20  Audit ruleset ends in '-e 2' (immutable) — further rule changes need a REBOOT to take effect, by CIS design."
  fi
  svc_enable "6.3.1.4" "Ensure auditd is enabled and running" "auditd"

  set_perm "6.3.4.1" "Mode on /var/log/audit" /var/log/audit 700 root:root
  if [ -d /var/log/audit ] && ! $DRY_RUN; then
    find /var/log/audit -type f -exec chmod 600 {} \; 2>>"$LOG_FILE"
  fi
  set_perm "6.3.4.5" "Mode on auditd.conf" /etc/audit/auditd.conf 640 root:root
  item_manual "6.3.1.2/3" "audit=1 and audit_backlog_limit on the kernel command line (GRUB) require a reboot — add via 'grubby --update-kernel=ALL --args=\"audit=1 audit_backlog_limit=8192\"' when you're ready to reboot"
}

# ============================================================
# SECTION 7  SYSTEM MAINTENANCE
# ============================================================

section_7_1() {
  should_run "7.1" || return
  say ""; say "${BOLD}${BLUE}7.1  System File Permissions${NC}"
  set_perm "7.1.1" "Permissions on /etc/passwd"  /etc/passwd  644 root:root
  set_perm "7.1.2" "Permissions on /etc/passwd-" /etc/passwd- 644 root:root
  set_perm "7.1.3" "Permissions on /etc/group"   /etc/group   644 root:root
  set_perm "7.1.4" "Permissions on /etc/group-"  /etc/group-  644 root:root
  set_perm "7.1.5" "Permissions on /etc/shadow"  /etc/shadow  000 root:root
  set_perm "7.1.6" "Permissions on /etc/shadow-" /etc/shadow- 000 root:root
  set_perm "7.1.7" "Permissions on /etc/gshadow" /etc/gshadow 000 root:root
  set_perm "7.1.8" "Permissions on /etc/gshadow-" /etc/gshadow- 000 root:root
  set_perm "7.1.9" "Permissions on /etc/shells"  /etc/shells  644 root:root
  set_perm "7.1.10" "Permissions on /etc/security/opasswd" /etc/security/opasswd 600 root:root
  item_manual "7.1.11" "World-writable files: find / -xdev -type f -perm -0002 — review and fix individually, don't blanket chmod"
  item_manual "7.1.12" "Orphaned files (no owner/group): find / -xdev -nouser -o -nogroup — review and reassign individually"
  item_manual "7.1.13" "Review SUID/SGID binaries against a known-good baseline"
}

section_7_2() {
  should_run "7.2" || return
  say ""; say "${BOLD}${BLUE}7.2  Local User and Group Settings${NC}"
  local dupu dupg
  dupu=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
  dupg=$(cut -d: -f3 /etc/group | sort | uniq -d)
  [ -n "$dupu" ] && item_manual "7.2.4" "Duplicate UIDs found — must be resolved by hand, this script will not merge/renumber accounts for you: $dupu"
  [ -n "$dupg" ] && item_manual "7.2.5" "Duplicate GIDs found — resolve manually: $dupg"
  item_manual "7.2.8" "Confirm every interactive user's home directory exists and is owned by them"
  item_manual "7.2.9" "Review dot-file permissions in home directories (.netrc, .forward, .rhosts etc.)"
}

# ============================================================
# MAIN
# ============================================================

run_all_sections() {
  section_1_1; section_1_2; section_1_3; section_1_4; section_1_5; section_1_6; section_1_7; section_1_8
  section_2; section_2_4
  section_3; section_3_3
  section_4
  section_5_1; section_5_2; section_5_3; section_5_4
  section_6_1; section_6_3
  section_7_1; section_7_2
}

show_summary() {
  say ""
  say "${BOLD}${WHITE}================  REMEDIATION SUMMARY  ================${NC}"
  say "  ${GREEN}Applied:${NC}  $APPLIED"
  say "  ${DIM}Skipped (already compliant):${NC} $SKIPPED"
  say "  ${RED}Failed:${NC}   $FAILED"
  say "  ${YELLOW}Manual review needed:${NC} $MANUAL"
  if [ ${#FAILED_ITEMS[@]} -gt 0 ]; then
    say ""; say "  ${RED}Failed items:${NC}"
    for i in "${FAILED_ITEMS[@]}"; do say "    - $i"; done
  fi
  if [ ${#MANUAL_ITEMS[@]} -gt 0 ]; then
    say ""; say "  ${YELLOW}Needs manual attention:${NC}"
    for i in "${MANUAL_ITEMS[@]}"; do say "    - $i"; done
  fi
  say ""
  if ! $DRY_RUN; then
    say "  Backups of every changed file: ${CYAN}${BACKUP_DIR}${NC}"
    say "  Full log:                      ${CYAN}${LOG_FILE}${NC}"
  fi
  if $REBOOT_NEEDED; then
    say ""; say "  ${YELLOW}${BOLD}A REBOOT is required for some changes (SELinux mode, GRUB, audit -e 2 rules) to fully take effect.${NC}"
    say "  ${YELLOW}Reboot only when you're ready to be at the console/have out-of-band access, in case SELinux enforcing surfaces an unexpected denial.${NC}"
  fi
  say "${BOLD}${WHITE}=========================================================${NC}"
  say ""
  say "Next step: re-run your cis_audit.sh to confirm the FAIL count dropped, and review every MANUAL item above."
}

list_items() {
  say "Listing all remediation items (no changes will be made — this implies --dry-run)."
  DRY_RUN=true
  run_all_sections
  exit 0
}

main() {
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}This script must be run as root (it edits system files under /etc, /boot, /var).${NC}"
    exit 1
  fi

  local os_id
  os_id=$(grep '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
  local os_like
  os_like=$(grep '^ID_LIKE=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
  if [[ "$os_id" != "ol" && "$os_id" != "rhel" && "$os_like" != *rhel* ]]; then
    echo -e "${RED}This script targets Oracle Linux 9 / RHEL 9 family systems. Detected ID=${os_id:-unknown}. Refusing to run.${NC}"
    echo "If you're on Ubuntu/Debian, ask for the Ubuntu remediation variant instead — the file paths and tools here (dnf, authselect, firewalld, /etc/selinux) don't apply there."
    exit 1
  fi

  $LIST_ONLY && list_items

  mkdir -p "$LOG_DIR"
  $DRY_RUN || mkdir -p "$BACKUP_DIR"
  log "=== CIS remediation run started (dry_run=$DRY_RUN aggressive=$AGGRESSIVE section=${SECTION_FILTER:-all}) ==="

  say ""
  say "${BOLD}${WHITE}CIS Benchmark Remediation — Oracle Linux 9 / RHEL 9${NC}"
  say "  Mode:      $($DRY_RUN && echo 'DRY RUN (no changes will be written)' || echo 'APPLY')"
  say "  Aggressive: $AGGRESSIVE"
  [ -n "$SECTION_FILTER" ] && say "  Section:   $SECTION_FILTER"
  say ""

  if ! $DRY_RUN && ! $ASSUME_YES; then
    echo -e "${YELLOW}This will modify system configuration files (SSH, PAM, sysctl, auditd, sudoers, permissions, etc).${NC}"
    echo -e "${YELLOW}Every file touched is backed up to ${BACKUP_DIR} first. Recommend running with --dry-run first if you haven't.${NC}"
    read -r -p "Continue? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { echo "Aborted, nothing changed."; exit 0; }
  fi

  run_all_sections
  show_summary
  log "=== CIS remediation run finished: applied=$APPLIED skipped=$SKIPPED failed=$FAILED manual=$MANUAL ==="

  [ "$FAILED" -gt 0 ] && exit 1 || exit 0
}

main
