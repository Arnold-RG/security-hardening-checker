#!/usr/bin/env bash
# =============================================================================
# check-linux.sh - Read-only security hardening audit for Linux
# -----------------------------------------------------------------------------
# Purpose : Check common hardening settings (SSH, firewall, file permissions,
#           SUID binaries, automatic updates, accounts, listening ports) and
#           print PASS / WARN / FAIL / INFO lines with a summary score.
#           The script NEVER changes anything - it only reads.
# Usage   : ./check-linux.sh [-o report.txt] [-c /path/to/sshd_config] [-n] [-q]
#           sudo ./check-linux.sh        # root gives the most complete result
#           ./check-linux.sh -h
# Exit    : 0 = all checks passed, 1 = warnings only, 2 = at least one FAIL,
#           3 = usage error
# Requires: bash 4+, coreutils, findutils, awk. Optional: ss (iproute2),
#           sshd, ufw / firewalld / nft, systemctl, dpkg or rpm.
# Author  : Arnold Rurangwa - MIT License
# =============================================================================
set -uo pipefail

REPORT=""
SSHD_CONFIG="/etc/ssh/sshd_config"
COLOR=1
QUIET=0

usage() {
    cat <<USAGE
Usage: $(basename "$0") [options]

Read-only Linux hardening audit with PASS/WARN/FAIL results and a score.

  -o FILE   also write the report (without colours) to FILE
  -c FILE   sshd_config to audit (default: $SSHD_CONFIG)
  -n        no colours
  -q        only print WARN/FAIL lines and the summary
  -h        show this help

Exit codes: 0 all PASS, 1 warnings, 2 failures, 3 usage error.
Run as root for the full audit (/etc/shadow, firewall rules, sshd -T).
USAGE
}

while getopts ":o:c:nqh" opt; do
    case "$opt" in
        o) REPORT="$OPTARG" ;;
        c) SSHD_CONFIG="$OPTARG" ;;
        n) COLOR=0 ;;
        q) QUIET=1 ;;
        h) usage; exit 0 ;;
        :) echo "Error: -$OPTARG needs a value" >&2; exit 3 ;;
        *) echo "Error: unknown option -$OPTARG (see -h)" >&2; exit 3 ;;
    esac
done
[[ -t 1 ]] || COLOR=0
if [[ -n "$REPORT" ]]; then
    : > "$REPORT" 2>/dev/null || { echo "Error: cannot write $REPORT" >&2; exit 3; }
fi

IS_ROOT=0; [[ $(id -u) -eq 0 ]] && IS_ROOT=1
PASS=0; WARN=0; FAIL=0; INFO=0

# result LEVEL CATEGORY MESSAGE
result() {
    local level=$1 cat=$2 msg=$3 c="" r=""
    case "$level" in
        PASS) PASS=$((PASS + 1)); c=$'\e[32m' ;;
        WARN) WARN=$((WARN + 1)); c=$'\e[33m' ;;
        FAIL) FAIL=$((FAIL + 1)); c=$'\e[31m' ;;
        INFO) INFO=$((INFO + 1)); c=$'\e[36m' ;;
    esac
    (( COLOR )) && r=$'\e[0m' || c=""
    if (( ! QUIET )) || [[ "$level" == WARN || "$level" == FAIL ]]; then
        printf '%s[%-4s]%s %-10s %s\n' "$c" "$level" "$r" "$cat" "$msg"
    fi
    [[ -n "$REPORT" ]] && printf '[%-4s] %-10s %s\n' "$level" "$cat" "$msg" >> "$REPORT"
}
section() { (( QUIET )) || printf '\n== %s ==\n' "$1"; [[ -n "$REPORT" ]] && printf '\n== %s ==\n' "$1" >> "$REPORT"; }
have() { command -v "$1" >/dev/null 2>&1; }

# octal permission of a file, e.g. 640
perm_of() { stat -c '%a' "$1" 2>/dev/null; }

{
    echo "Linux hardening audit - $(hostname 2>/dev/null) - $(date '+%Y-%m-%d %H:%M:%S %z')"
    echo "Kernel: $(uname -r)   Running as: $(id -un)$( (( IS_ROOT )) || echo ' (not root: some checks are limited)')"
} | tee -a "${REPORT:-/dev/null}"

# ---------------------------------------------------------------------------------
section "SSH server"
# Returns the effective value of an sshd option (lower-case), or "" if unset.
# With root and sshd present, `sshd -T` gives the real effective config.
SSHD_T=""
if (( IS_ROOT )) && have sshd && [[ "$SSHD_CONFIG" == /etc/ssh/sshd_config ]]; then
    SSHD_T=$(sshd -T 2>/dev/null)
fi
ssh_opt() {
    local key=${1,,}
    if [[ -n "$SSHD_T" ]]; then
        awk -v k="$key" 'tolower($1) == k {print tolower($2); exit}' <<< "$SSHD_T"
        return
    fi
    # Files parsed in the order sshd reads them: OpenSSH uses the FIRST value
    # found, and Debian/Ubuntu put "Include sshd_config.d/*.conf" at the top.
    local files=()
    if [[ "$SSHD_CONFIG" == /etc/ssh/sshd_config ]] && grep -qi '^[[:space:]]*Include' "$SSHD_CONFIG" 2>/dev/null; then
        for f in /etc/ssh/sshd_config.d/*.conf; do [[ -r "$f" ]] && files+=("$f"); done
    fi
    files+=("$SSHD_CONFIG")
    # Stop at the first "Match" block: its settings only apply conditionally.
    awk -v k="$key" '
        tolower($1) == "match" { exit }
        tolower($1) == k { print tolower($2); exit }' "${files[@]}" 2>/dev/null
}

if [[ ! -r "$SSHD_CONFIG" ]]; then
    if [[ -e "$SSHD_CONFIG" ]]; then
        result INFO SSH "$SSHD_CONFIG exists but is not readable (run as root)"
    else
        result INFO SSH "No SSH server config found ($SSHD_CONFIG) - sshd probably not installed"
    fi
else
    [[ -n "$SSHD_T" ]] && result INFO SSH "Using effective config from 'sshd -T'"

    v=$(ssh_opt PermitRootLogin)
    case "$v" in
        no) result PASS SSH "PermitRootLogin no" ;;
        yes) result FAIL SSH "PermitRootLogin yes - root can log in with a password" ;;
        prohibit-password|without-password) result WARN SSH "PermitRootLogin $v - root can log in with a key; 'no' is safer" ;;
        forced-commands-only) result PASS SSH "PermitRootLogin forced-commands-only" ;;
        "") result WARN SSH "PermitRootLogin not set (OpenSSH default: prohibit-password); set it to 'no'" ;;
        *) result WARN SSH "PermitRootLogin has unexpected value '$v'" ;;
    esac

    v=$(ssh_opt PasswordAuthentication)
    case "$v" in
        no) result PASS SSH "PasswordAuthentication no (keys only)" ;;
        yes) result WARN SSH "PasswordAuthentication yes - exposed to password guessing; prefer keys" ;;
        *) result WARN SSH "PasswordAuthentication not set (default: yes); prefer 'no' with key auth" ;;
    esac

    v=$(ssh_opt PermitEmptyPasswords)
    if [[ "$v" == yes ]]; then result FAIL SSH "PermitEmptyPasswords yes"
    else result PASS SSH "PermitEmptyPasswords ${v:-no (default)}"; fi

    v=$(ssh_opt Protocol)
    if [[ "$v" == *1* ]]; then result FAIL SSH "Protocol $v - SSH protocol 1 is broken"
    else result PASS SSH "Protocol ${v:-2 (only protocol supported by OpenSSH 7.4+)}"; fi

    v=$(ssh_opt Port)
    if [[ -z "$v" || "$v" == 22 ]]; then result INFO SSH "Port 22 (default). A different port only reduces log noise; it is not a security control."
    else result INFO SSH "Port $v"; fi

    v=$(ssh_opt X11Forwarding)
    if [[ "$v" == yes ]]; then result WARN SSH "X11Forwarding yes - disable unless needed"
    else result PASS SSH "X11Forwarding ${v:-no (default)}"; fi

    v=$(ssh_opt MaxAuthTries)
    if [[ -n "$v" && "$v" =~ ^[0-9]+$ ]] && (( v <= 4 )); then result PASS SSH "MaxAuthTries $v"
    else result WARN SSH "MaxAuthTries ${v:-6 (default)} - 3 or 4 is recommended"; fi
fi

# ---------------------------------------------------------------------------------
section "Firewall"
fw_found=0
if have ufw && (( IS_ROOT )); then
    if ufw status 2>/dev/null | grep -q '^Status: active'; then result PASS Firewall "UFW is active"; fw_found=1
    else result INFO Firewall "UFW installed but inactive"; fi
fi
if (( ! fw_found )) && have systemctl; then
    for svc in ufw firewalld nftables; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            result PASS Firewall "$svc service is active"; fw_found=1; break
        fi
    done
fi
if (( ! fw_found )) && (( IS_ROOT )); then
    if have nft && [[ $(nft list ruleset 2>/dev/null | grep -c 'hook input') -gt 0 ]]; then
        result PASS Firewall "nftables input hook present"; fw_found=1
    elif have iptables && iptables -S INPUT 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)|^-A INPUT'; then
        result PASS Firewall "iptables INPUT rules present"; fw_found=1
    fi
fi
if (( ! fw_found )); then
    if (( IS_ROOT )); then result FAIL Firewall "No active host firewall found (ufw, firewalld, nftables, iptables)"
    else result WARN Firewall "No active firewall service detected (run as root to inspect nft/iptables rules)"; fi
fi

# ---------------------------------------------------------------------------------
section "File permissions"
check_perm() {   # check_perm FILE MAX_OCTAL ALLOWED_GROUPS(regex)
    local f=$1 max=$2 groups=$3 p owner grp
    [[ -e "$f" ]] || { result INFO Perms "$f not present"; return; }
    p=$(perm_of "$f"); owner=$(stat -c '%U' "$f"); grp=$(stat -c '%G' "$f")
    if [[ "$owner" != root ]] || ! [[ "$grp" =~ ^($groups)$ ]]; then
        result FAIL Perms "$f owned by $owner:$grp (expected root:${groups//|/ or })"
    elif (( (8#$p & ~8#$max) != 0 )); then
        result FAIL Perms "$f mode $p is more permissive than $max"
    else
        result PASS Perms "$f mode $p owner $owner:$grp"
    fi
}
check_perm /etc/passwd 644 root
check_perm /etc/group 644 root
check_perm /etc/shadow 640 'root|shadow'
check_perm /etc/gshadow 640 'root|shadow'
[[ "$SSHD_CONFIG" == /etc/ssh/sshd_config && -e "$SSHD_CONFIG" ]] && check_perm "$SSHD_CONFIG" 644 root

if [[ -d /tmp ]]; then
    if [[ -k /tmp ]]; then result PASS Perms "/tmp has the sticky bit"
    else result FAIL Perms "/tmp is missing the sticky bit"; fi
fi

DIRS=(/etc /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/lib/systemd)
ww=$(find "${DIRS[@]}" -xdev \( -type f -o -type d \) -perm -0002 ! -perm -1000 2>/dev/null | head -n 20)
if [[ -z "$ww" ]]; then result PASS Perms "No world-writable files/dirs in ${DIRS[*]}"
else
    result FAIL Perms "World-writable entries found (first 20 shown):"
    while read -r f; do result FAIL Perms "  $f"; done <<< "$ww"
fi

# ---------------------------------------------------------------------------------
section "SUID / SGID binaries"
# Common, expected SUID programs on mainstream distributions.
KNOWN_SUID='^(passwd|sudo|su|mount|umount|chsh|chfn|newgrp|gpasswd|pkexec|ping|ping6|ssh-keysign|dbus-daemon-launch-helper|fusermount|fusermount3|unix_chkpwd|polkit-agent-helper-1|Xorg.wrap|ntfs-3g|pppd|at|crontab|expiry|chage|staprun|sg|snap-confine|mount.nfs|mount.cifs|userhelper|pam_timestamp_check|chrome-sandbox|vmware-user-suid-wrapper|ksu|newuidmap|newgidmap|wall|write|ssh-agent|dotlockfile|mlocate|plocate|locate|bsd-write|unix2_chkpwd|utempter|traceroute6.iputils|sudoedit)$'
mapfile -t SUIDS < <(find /bin /sbin /usr/bin /usr/sbin /usr/lib /usr/libexec /usr/local /opt -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort)
result INFO SUID "${#SUIDS[@]} SUID/SGID files found under system paths"
unusual=0
for f in "${SUIDS[@]}"; do
    if ! [[ "$(basename "$f")" =~ $KNOWN_SUID ]]; then
        result WARN SUID "Unusual SUID/SGID binary: $f (mode $(perm_of "$f"))"
        unusual=$((unusual + 1))
    fi
done
(( unusual == 0 )) && result PASS SUID "All SUID/SGID binaries are on the common-programs list"

# ---------------------------------------------------------------------------------
section "Accounts"
uid0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | paste -sd, -)
if [[ "$uid0" == root ]]; then result PASS Accounts "Only 'root' has UID 0"
else result FAIL Accounts "Accounts with UID 0: $uid0"; fi

if [[ -r /etc/shadow ]]; then
    empty=$(awk -F: '$2 == "" {print $1}' /etc/shadow | paste -sd, -)
    if [[ -z "$empty" ]]; then result PASS Accounts "No accounts with an empty password"
    else result FAIL Accounts "Accounts with EMPTY passwords: $empty"; fi
else
    result INFO Accounts "Empty-password check skipped (/etc/shadow needs root)"
fi

if [[ -r /etc/login.defs ]]; then
    max=$(awk '$1 == "PASS_MAX_DAYS" {print $2}' /etc/login.defs)
    if [[ "$max" =~ ^[0-9]+$ ]] && (( max <= 365 )); then result PASS Accounts "PASS_MAX_DAYS $max"
    else result INFO Accounts "PASS_MAX_DAYS ${max:-unset} (password expiry not enforced; fine if you use keys/MFA)"; fi
fi

# ---------------------------------------------------------------------------------
section "Automatic updates"
if have dpkg; then
    if dpkg -s unattended-upgrades >/dev/null 2>&1; then
        if grep -rqsE 'APT::Periodic::Unattended-Upgrade\s+"1"' /etc/apt/apt.conf.d/; then
            result PASS Updates "unattended-upgrades installed and enabled"
        else
            result WARN Updates "unattended-upgrades installed but not enabled (dpkg-reconfigure unattended-upgrades)"
        fi
    else
        result WARN Updates "unattended-upgrades is not installed"
    fi
elif have rpm; then
    if have systemctl && systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null \
        || systemctl is-enabled --quiet dnf-automatic-install.timer 2>/dev/null; then
        result PASS Updates "dnf-automatic timer enabled"
    else
        result WARN Updates "No automatic update timer (dnf-automatic) enabled"
    fi
else
    result INFO Updates "Unknown package manager - check automatic updates manually"
fi

# ---------------------------------------------------------------------------------
section "Listening ports"
if have ss; then
    # FTP, Telnet, TFTP, rpcbind, MSRPC, NetBIOS, SMB, r-services, rsync, NFS,
    # Docker API without TLS (2375), databases, RDP, VNC, Redis, Elasticsearch, memcached, MongoDB
    RISKY='^(21|23|69|111|135|137|139|445|512|513|514|873|2049|2375|3306|3389|5432|5900|6379|9200|11211|27017)$'
    exposed=0
    while read -r proto local; do
        port=${local##*:}; addr=${local%:*}
        if [[ "$addr" == "0.0.0.0" || "$addr" == "*" || "$addr" == "[::]" ]]; then
            if [[ "$port" =~ $RISKY ]]; then
                result WARN Ports "$proto/$port listens on ALL interfaces (commonly attacked service)"
            else
                result INFO Ports "$proto/$port listens on all interfaces"
            fi
            exposed=$((exposed + 1))
        fi
    done < <(ss -tulnH 2>/dev/null | awk '{print $1, $5}' | sort -u | sort -t: -k2,2n)
    (( exposed == 0 )) && result PASS Ports "No services listen on all interfaces"
    local_only=$(ss -tlnH 2>/dev/null | awk '$4 ~ /^(127\.|\[::1\])/' | wc -l)
    result INFO Ports "$local_only TCP listener(s) bound to localhost only"
else
    result INFO Ports "'ss' not found - install iproute2 to list listening ports"
fi

# ---------------------------------------------------------------------------------
TOTAL=$(( PASS + WARN + FAIL ))
SCORE=0; (( TOTAL > 0 )) && SCORE=$(( (PASS * 100 + WARN * 50) / TOTAL ))
summary="Summary: $PASS PASS, $WARN WARN, $FAIL FAIL, $INFO INFO  ->  score ${SCORE}/100"
printf '\n%s\n' "$summary"
[[ -n "$REPORT" ]] && { printf '\n%s\n' "$summary" >> "$REPORT"; echo "Report written to $REPORT"; }
echo "(Score: PASS = 100, WARN = 50, FAIL = 0 points, averaged; INFO lines are not scored.)"

if (( FAIL > 0 )); then exit 2; elif (( WARN > 0 )); then exit 1; else exit 0; fi
