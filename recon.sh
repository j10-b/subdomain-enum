#!/bin/bash

# ============================================================
#  recon.sh - Full Subdomain Recon (Passive + Active)
#  Usage: ./recon.sh <domain>
#  Phase 1: Passive  → subfinder, assetfinder, subdominator, crt.sh
#  Phase 2: Active   → AXFR, alterx, gotator, puredns/shuffledns, vhost
#  Output: passive subs, active-only subs, master list, httpx
# ============================================================

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Banner ───────────────────────────────────────────────────
banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗   ███████╗██╗  ██╗"
  echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║   ██╔════╝██║  ██║"
  echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║   ███████╗███████║"
  echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║   ╚════██║██╔══██║"
  echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╗███████║██║  ██║"
  echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚══════╝╚═╝  ╚═╝"
  echo -e "${RESET}"
  echo -e "${BOLD}        Full Recon Script (Passive + Active) by J10B | Bug Bounty${RESET}"
  echo -e "        ──────────────────────────────────────────────────\n"
}

# ── Usage ─────────────────────────────────────────────────────
usage() {
  echo -e "${YELLOW}Usage:${RESET}   $0 <domain>"
  echo -e "${YELLOW}Example:${RESET} $0 kpt.ch"
  exit 1
}

# ── Validate input ────────────────────────────────────────────
if [ -z "$1" ]; then
  banner
  usage
fi

DOMAIN="$1"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTDIR="./recon_${DOMAIN}_${TIMESTAMP}"
PASSIVE_TMPDIR="${OUTDIR}/passive_tmp"
ACTIVE_TMPDIR="${OUTDIR}/active_tmp"
RESOLVERS="${OUTDIR}/resolvers.txt"

# ── Output files ──────────────────────────────────────────────
PASSIVE_OUTPUT="${OUTDIR}/${DOMAIN}_passive_subdomains.txt"
ACTIVE_ONLY_OUTPUT="${OUTDIR}/${DOMAIN}_active_only_subdomains.txt"
MASTER_OUTPUT="${OUTDIR}/${DOMAIN}_all_subdomains.txt"
MASTER_HTTPX="${OUTDIR}/${DOMAIN}_httpx.txt"

mkdir -p "$PASSIVE_TMPDIR" "$ACTIVE_TMPDIR"

banner
echo -e "${BOLD}[*] Target Domain  :${RESET} ${GREEN}${DOMAIN}${RESET}"
echo -e "${BOLD}[*] Output Dir     :${RESET} ${GREEN}${OUTDIR}${RESET}"
echo -e "${BOLD}[*] Started At     :${RESET} ${GREEN}$(date)${RESET}\n"
echo -e "  ──────────────────────────────────────────────────────\n"

# ── Tool check helper ─────────────────────────────────────────
check_tool() {
  if command -v "$1" &>/dev/null; then
    echo -e "  ${GREEN}[✔]${RESET} $1 found"
    return 0
  else
    echo -e "  ${RED}[✘]${RESET} $1 not found — skipping"
    return 1
  fi
}

# ── Run tool helper ───────────────────────────────────────────
run_tool() {
  local name="$1"
  local outfile="$2"
  local cmd="$3"
  echo -e "${CYAN}[+] Running ${BOLD}${name}${RESET}${CYAN}...${RESET}"
  eval "$cmd" > "$outfile" 2>/dev/null
  local count
  count=$(wc -l < "$outfile" 2>/dev/null || echo 0)
  echo -e "    ${GREEN}[✔]${RESET} ${name} found ${BOLD}${count}${RESET} subdomains\n"
}

# ── Check all tools ───────────────────────────────────────────
echo -e "${BOLD}[*] Checking passive tools...${RESET}"
check_tool subfinder    && HAS_SUBFINDER=true    || HAS_SUBFINDER=false
check_tool assetfinder  && HAS_ASSETFINDER=true  || HAS_ASSETFINDER=false
check_tool subdominator && HAS_SUBDOMINATOR=true || HAS_SUBDOMINATOR=false
check_tool curl         && HAS_CURL=true         || HAS_CURL=false
check_tool jq           && HAS_JQ=true           || HAS_JQ=false
echo ""

echo -e "${BOLD}[*] Checking active tools...${RESET}"
check_tool alterx      && HAS_ALTERX=true      || HAS_ALTERX=false
check_tool gotator     && HAS_GOTATOR=true     || HAS_GOTATOR=false
check_tool puredns     && HAS_PUREDNS=true     || HAS_PUREDNS=false
check_tool shuffledns  && HAS_SHUFFLEDNS=true  || HAS_SHUFFLEDNS=false
check_tool dnsx        && HAS_DNSX=true        || HAS_DNSX=false
check_tool ffuf        && HAS_FFUF=true        || HAS_FFUF=false
check_tool httpx       && HAS_HTTPX=true       || HAS_HTTPX=false
check_tool dig         && HAS_DIG=true         || HAS_DIG=false
echo ""

# ══════════════════════════════════════════════════════════════
#  PHASE 1 — PASSIVE RECON
# ══════════════════════════════════════════════════════════════
echo -e "${BOLD}${CYAN}"
echo -e "  ╔══════════════════════════════════════════════════════╗"
echo -e "  ║           PHASE 1 — PASSIVE RECON                   ║"
echo -e "  ╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}\n"

# ── 1. Subfinder ──────────────────────────────────────────────
if [ "$HAS_SUBFINDER" = true ]; then
  run_tool "subfinder" "${PASSIVE_TMPDIR}/subfinder.txt" \
    "subfinder -d ${DOMAIN} -all -recursive -silent"
fi

# ── 2. Assetfinder ───────────────────────────────────────────
if [ "$HAS_ASSETFINDER" = true ]; then
  run_tool "assetfinder" "${PASSIVE_TMPDIR}/assetfinder.txt" \
    "assetfinder --subs-only ${DOMAIN}"
fi

# ── 3. Subdominator ──────────────────────────────────────────
if [ "$HAS_SUBDOMINATOR" = true ]; then
  run_tool "subdominator" "${PASSIVE_TMPDIR}/subdominator.txt" \
    "subdominator -d ${DOMAIN}"
fi

# ── 4. crt.sh ────────────────────────────────────────────────
if [ "$HAS_CURL" = true ]; then
  echo -e "${CYAN}[+] Running ${BOLD}crt.sh${RESET}${CYAN} (Certificate Transparency Logs)...${RESET}"
  CRTSH_OUT="${PASSIVE_TMPDIR}/crtsh.txt"

  curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
    --retry 3 --retry-delay 2 --max-time 30 \
    -H "User-Agent: Mozilla/5.0 (bug-bounty-recon)" \
    > "${PASSIVE_TMPDIR}/crtsh_raw1.json" 2>/dev/null

  curl -s "https://crt.sh/?q=${DOMAIN}&output=json" \
    --retry 3 --retry-delay 2 --max-time 30 \
    -H "User-Agent: Mozilla/5.0 (bug-bounty-recon)" \
    > "${PASSIVE_TMPDIR}/crtsh_raw2.json" 2>/dev/null

  if [ "$HAS_JQ" = true ]; then
    cat "${PASSIVE_TMPDIR}/crtsh_raw1.json" "${PASSIVE_TMPDIR}/crtsh_raw2.json" 2>/dev/null \
      | jq -r '.[].name_value' 2>/dev/null \
      | tr ',' '\n' \
      | sed 's/\*\.//g' \
      | tr '[:upper:]' '[:lower:]' \
      | grep -E "\.${DOMAIN//./\\.}$" \
      | sort -u > "$CRTSH_OUT"
  else
    cat "${PASSIVE_TMPDIR}/crtsh_raw1.json" "${PASSIVE_TMPDIR}/crtsh_raw2.json" 2>/dev/null \
      | python3 -c "
import json, sys
data = json.load(sys.stdin)
for entry in data:
    for sub in entry['name_value'].split('\n'):
        s = sub.strip().lstrip('*.').lower()
        if s:
            print(s)
" 2>/dev/null \
      | grep -E "\.${DOMAIN//./\\.}$" \
      | sort -u > "$CRTSH_OUT"
  fi

  count=$(wc -l < "$CRTSH_OUT" 2>/dev/null || echo 0)
  echo -e "    ${GREEN}[✔]${RESET} crt.sh found ${BOLD}${count}${RESET} subdomains\n"
else
  echo -e "  ${RED}[✘]${RESET} curl not found — skipping crt.sh\n"
fi

# ── Merge passive results ─────────────────────────────────────
echo -e "${CYAN}[+] Merging passive results...${RESET}"
cat \
  "${PASSIVE_TMPDIR}/subfinder.txt" \
  "${PASSIVE_TMPDIR}/assetfinder.txt" \
  "${PASSIVE_TMPDIR}/subdominator.txt" \
  "${PASSIVE_TMPDIR}/crtsh.txt" \
  2>/dev/null \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/\*\.//g' \
  | grep -E "^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+${DOMAIN//./\\.}$" \
  | sort -u \
  > "$PASSIVE_OUTPUT"

PASSIVE_TOTAL=$(wc -l < "$PASSIVE_OUTPUT")

echo ""
echo -e "${BOLD}  ── Passive Recon Breakdown ─────────────────────────${RESET}"
for f in \
  "${PASSIVE_TMPDIR}/subfinder.txt" \
  "${PASSIVE_TMPDIR}/assetfinder.txt" \
  "${PASSIVE_TMPDIR}/subdominator.txt" \
  "${PASSIVE_TMPDIR}/crtsh.txt"; do
  [ -f "$f" ] || continue
  tool=$(basename "$f" .txt)
  count=$(wc -l < "$f" 2>/dev/null || echo 0)
  printf "  %-20s : %s subdomains\n" "$tool" "$count"
done
echo -e "${BOLD}  ────────────────────────────────────────────────────${RESET}"
echo -e "  ${GREEN}${BOLD}Total Passive Subdomains : ${PASSIVE_TOTAL}${RESET}"
echo -e "${BOLD}  ────────────────────────────────────────────────────${RESET}\n"
echo -e "${GREEN}[✔] Passive subdomains saved to :${RESET} ${BOLD}${PASSIVE_OUTPUT}${RESET}\n"

# ══════════════════════════════════════════════════════════════
#  PHASE 2 — ACTIVE RECON
# ══════════════════════════════════════════════════════════════
echo -e "${BOLD}${MAGENTA}"
echo -e "  ╔══════════════════════════════════════════════════════╗"
echo -e "  ║           PHASE 2 — ACTIVE RECON                    ║"
echo -e "  ╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}\n"

# ── Resolvers ─────────────────────────────────────────────────
cat > "$RESOLVERS" <<EOF
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
64.6.64.6
64.6.65.6
EOF
echo -e "${GREEN}[✔]${RESET} 10 public DNS resolvers ready\n"

# ── Step 1: DNS Zone Transfer ─────────────────────────────────
echo -e "  ──────────────────────────────────────────────────────"
echo -e "${BOLD}  STEP 1 : DNS Zone Transfer (AXFR)${RESET}"
echo -e "  ──────────────────────────────────────────────────────\n"

AXFR_OUT="${ACTIVE_TMPDIR}/axfr.txt"
> "$AXFR_OUT"

if [ "$HAS_DIG" = true ]; then
  NS_RECORDS=$(dig NS "$DOMAIN" +short 2>/dev/null | sed 's/\.$//')
  if [ -z "$NS_RECORDS" ]; then
    echo -e "    ${YELLOW}[!]${RESET} No NS records found\n"
  else
    while IFS= read -r ns; do
      echo -e "    ${CYAN}[>]${RESET} Trying AXFR on ${BOLD}${ns}${RESET}..."
      result=$(dig axfr "$DOMAIN" @"$ns" 2>/dev/null \
        | grep -E "^[a-zA-Z0-9]" \
        | awk '{print $1}' \
        | sed 's/\.$//' \
        | grep -E "\.${DOMAIN//./\\.}$")
      if [ -n "$result" ]; then
        echo "$result" >> "$AXFR_OUT"
        echo -e "    ${GREEN}[✔]${RESET} Zone transfer SUCCESS on ${ns}!"
      else
        echo -e "    ${RED}[✘]${RESET} Zone transfer failed on ${ns} (expected)"
      fi
    done <<< "$NS_RECORDS"
  fi
  AXFR_COUNT=$(sort -u "$AXFR_OUT" | wc -l)
  echo -e "\n    ${GREEN}[✔]${RESET} AXFR found ${BOLD}${AXFR_COUNT}${RESET} subdomains\n"
else
  echo -e "  ${RED}[✘]${RESET} dig not found — skipping\n"
fi

# ── Step 2: Permutation with alterx ──────────────────────────
echo -e "  ──────────────────────────────────────────────────────"
echo -e "${BOLD}  STEP 2 : Permutation & Mutation (alterx)${RESET}"
echo -e "  ──────────────────────────────────────────────────────\n"

ALTERX_PERMS="${ACTIVE_TMPDIR}/alterx_permutations.txt"
ALTERX_RESOLVED="${ACTIVE_TMPDIR}/alterx.txt"
> "$ALTERX_RESOLVED"

if [ "$HAS_ALTERX" = true ]; then
  echo -e "${CYAN}[+] Generating permutations from ${BOLD}${PASSIVE_TOTAL}${RESET}${CYAN} passive subdomains...${RESET}"
  cat "$PASSIVE_OUTPUT" | alterx -enrich -silent 2>/dev/null > "$ALTERX_PERMS"
  PERM_COUNT=$(wc -l < "$ALTERX_PERMS")
  echo -e "    ${GREEN}[✔]${RESET} Generated ${BOLD}${PERM_COUNT}${RESET} permutations\n"

  if [ "$HAS_DNSX" = true ]; then
    echo -e "${CYAN}[+] Resolving with dnsx (500 threads)...${RESET}"
    cat "$ALTERX_PERMS" | dnsx -silent -t 500 -r "$RESOLVERS" 2>/dev/null > "$ALTERX_RESOLVED"
    echo -e "    ${GREEN}[✔]${RESET} alterx resolved ${BOLD}$(wc -l < "$ALTERX_RESOLVED")${RESET} live subdomains\n"
  else
    cp "$ALTERX_PERMS" "$ALTERX_RESOLVED"
    echo -e "    ${YELLOW}[!]${RESET} dnsx not found — saving unresolved\n"
  fi
else
  echo -e "  ${RED}[✘]${RESET} alterx not found — skipping"
  echo -e "      Install: ${YELLOW}go install github.com/projectdiscovery/alterx/cmd/alterx@latest${RESET}\n"
fi

# ── Step 3: Permutation with gotator ─────────────────────────
echo -e "  ──────────────────────────────────────────────────────"
echo -e "${BOLD}  STEP 3 : Permutation & Mutation (gotator)${RESET}"
echo -e "  ──────────────────────────────────────────────────────\n"

GOTATOR_PERMS="${ACTIVE_TMPDIR}/gotator_permutations.txt"
GOTATOR_RESOLVED="${ACTIVE_TMPDIR}/gotator.txt"
> "$GOTATOR_RESOLVED"

PERM_WORDLIST="${ACTIVE_TMPDIR}/permutations_wordlist.txt"
cat > "$PERM_WORDLIST" <<'EOF'
dev
stg
staging
prod
test
uat
qa
beta
api
api2
v1
v2
admin
portal
dashboard
internal
vpn
mail
git
jenkins
jira
cdn
static
backup
db
auth
sso
login
app
mobile
old
new
EOF

if [ "$HAS_GOTATOR" = true ]; then
  echo -e "${CYAN}[+] Running gotator (depth 1)...${RESET}"
  gotator -sub "$PASSIVE_OUTPUT" -perm "$PERM_WORDLIST" -depth 1 -silent 2>/dev/null > "$GOTATOR_PERMS"
  echo -e "    ${GREEN}[✔]${RESET} Generated ${BOLD}$(wc -l < "$GOTATOR_PERMS")${RESET} permutations\n"

  if [ "$HAS_DNSX" = true ]; then
    echo -e "${CYAN}[+] Resolving with dnsx (500 threads)...${RESET}"
    cat "$GOTATOR_PERMS" | dnsx -silent -t 500 -r "$RESOLVERS" 2>/dev/null > "$GOTATOR_RESOLVED"
    echo -e "    ${GREEN}[✔]${RESET} gotator resolved ${BOLD}$(wc -l < "$GOTATOR_RESOLVED")${RESET} live subdomains\n"
  else
    cp "$GOTATOR_PERMS" "$GOTATOR_RESOLVED"
    echo -e "    ${YELLOW}[!]${RESET} dnsx not found — saving unresolved\n"
  fi
else
  echo -e "  ${RED}[✘]${RESET} gotator not found — skipping"
  echo -e "      Install: ${YELLOW}go install github.com/Josue87/gotator@latest${RESET}\n"
fi

# ── Step 4: DNS Bruteforce ────────────────────────────────────
echo -e "  ──────────────────────────────────────────────────────"
echo -e "${BOLD}  STEP 4 : DNS Bruteforce${RESET}"
echo -e "  ──────────────────────────────────────────────────────\n"

BRUTE_OUT="${ACTIVE_TMPDIR}/bruteforce.txt"
> "$BRUTE_OUT"

SECLISTS_DNS="$HOME/tools/SecLists/Discovery/DNS"
WORDLIST=""
for wl in \
  "${SECLISTS_DNS}/subdomains-top1million-110000.txt" \
  "${SECLISTS_DNS}/subdomains-top1million-20000.txt" \
  "${SECLISTS_DNS}/subdomains-top1million-5000.txt" \
  "${SECLISTS_DNS}/dns-Jhaddix.txt" \
  /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt; do
  if [ -f "$wl" ]; then
    WORDLIST="$wl"
    break
  fi
done

if [ -z "$WORDLIST" ]; then
  echo -e "  ${YELLOW}[!]${RESET} No SecLists wordlist found — using built-in wordlist"
  WORDLIST="$PERM_WORDLIST"
fi
echo -e "  ${GREEN}[✔]${RESET} Wordlist: ${BOLD}${WORDLIST}${RESET} ($(wc -l < "$WORDLIST") words)\n"

if [ "$HAS_PUREDNS" = true ]; then
  echo -e "${CYAN}[+] Running puredns bruteforce...${RESET}"
  puredns bruteforce "$WORDLIST" "$DOMAIN" \
    --resolvers "$RESOLVERS" --write "$BRUTE_OUT" --quiet 2>/dev/null
  echo -e "    ${GREEN}[✔]${RESET} puredns found ${BOLD}$(wc -l < "$BRUTE_OUT")${RESET} subdomains\n"

elif [ "$HAS_SHUFFLEDNS" = true ]; then
  echo -e "${CYAN}[+] Running shuffledns bruteforce...${RESET}"
  shuffledns -d "$DOMAIN" -w "$WORDLIST" -r "$RESOLVERS" -o "$BRUTE_OUT" -silent 2>/dev/null
  echo -e "    ${GREEN}[✔]${RESET} shuffledns found ${BOLD}$(wc -l < "$BRUTE_OUT")${RESET} subdomains\n"

elif [ "$HAS_FFUF" = true ]; then
  echo -e "${CYAN}[+] Running ffuf DNS bruteforce...${RESET}"
  ffuf -w "$WORDLIST":FUZZ -u "https://FUZZ.${DOMAIN}" \
    -mc 200,301,302,403,404 -t 200 -silent 2>/dev/null \
    | grep -oP "https://[^\s]+" | sed "s|https://||" | sort -u > "$BRUTE_OUT"
  echo -e "    ${GREEN}[✔]${RESET} ffuf found ${BOLD}$(wc -l < "$BRUTE_OUT")${RESET} subdomains\n"

else
  echo -e "  ${RED}[✘]${RESET} No bruteforce tool found — skipping"
  echo -e "      Install: ${YELLOW}puredns, shuffledns, or ffuf${RESET}\n"
fi

# ── Step 5: VHost Fuzzing ─────────────────────────────────────
echo -e "  ──────────────────────────────────────────────────────"
echo -e "${BOLD}  STEP 5 : Virtual Host (VHost) Fuzzing${RESET}"
echo -e "  ──────────────────────────────────────────────────────\n"

VHOST_OUT="${ACTIVE_TMPDIR}/vhost.txt"
> "$VHOST_OUT"

if [ "$HAS_FFUF" = true ]; then
  TARGET_IP=$(dig +short "$DOMAIN" | grep -E "^[0-9]" | head -1)
  if [ -z "$TARGET_IP" ]; then
    echo -e "    ${YELLOW}[!]${RESET} Could not resolve IP — skipping vhost fuzzing\n"
  else
    echo -e "    ${GREEN}[✔]${RESET} Target IP: ${BOLD}${TARGET_IP}${RESET}"
    BASELINE_SIZE=$(curl -s -o /dev/null -w "%{size_download}" \
      -H "Host: nonexistent12345.${DOMAIN}" "http://${TARGET_IP}" 2>/dev/null || echo 0)
    echo -e "    ${YELLOW}[~]${RESET} Baseline size: ${BASELINE_SIZE} bytes\n"
    ffuf -w "$WORDLIST":FUZZ -u "http://${TARGET_IP}" \
      -H "Host: FUZZ.${DOMAIN}" -mc 200,201,301,302,403 \
      -fs "$BASELINE_SIZE" -t 200 -silent 2>/dev/null \
      | grep -oP "FUZZ: \K[^\s]+" | sed "s/$/.${DOMAIN}/" | sort -u > "$VHOST_OUT"
    echo -e "    ${GREEN}[✔]${RESET} vhost found ${BOLD}$(wc -l < "$VHOST_OUT")${RESET} potential hosts\n"
  fi
else
  echo -e "  ${RED}[✘]${RESET} ffuf not found — skipping vhost fuzzing\n"
fi

# ══════════════════════════════════════════════════════════════
#  FINAL — MERGE & DIFF
# ══════════════════════════════════════════════════════════════
echo -e "${BOLD}${BLUE}"
echo -e "  ╔══════════════════════════════════════════════════════╗"
echo -e "  ║           FINAL — MERGE & RESULTS                   ║"
echo -e "  ╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}\n"

echo -e "${CYAN}[+] Merging active results...${RESET}"

# Merge only resolved active output files
ACTIVE_ALL="${ACTIVE_TMPDIR}/active_merged.txt"
cat \
  "${ACTIVE_TMPDIR}/axfr.txt" \
  "${ACTIVE_TMPDIR}/alterx.txt" \
  "${ACTIVE_TMPDIR}/gotator.txt" \
  "${ACTIVE_TMPDIR}/bruteforce.txt" \
  "${ACTIVE_TMPDIR}/vhost.txt" \
  2>/dev/null \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/\*\.//g' \
  | grep -E "^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+${DOMAIN//./\\.}$" \
  | sort -u \
  > "$ACTIVE_ALL"

# Active-only: subdomains NOT found in passive recon
comm -23 \
  <(sort "$ACTIVE_ALL") \
  <(sort "$PASSIVE_OUTPUT") \
  > "$ACTIVE_ONLY_OUTPUT"

ACTIVE_ONLY_TOTAL=$(wc -l < "$ACTIVE_ONLY_OUTPUT")

# Master list: passive + active combined
cat "$PASSIVE_OUTPUT" "$ACTIVE_ALL" 2>/dev/null | sort -u > "$MASTER_OUTPUT"
MASTER_TOTAL=$(wc -l < "$MASTER_OUTPUT")

# ── Final Stats ───────────────────────────────────────────────
echo ""
echo -e "${BOLD}  ── Active Recon Breakdown ──────────────────────────${RESET}"
for f in \
  "${ACTIVE_TMPDIR}/axfr.txt" \
  "${ACTIVE_TMPDIR}/alterx.txt" \
  "${ACTIVE_TMPDIR}/gotator.txt" \
  "${ACTIVE_TMPDIR}/bruteforce.txt" \
  "${ACTIVE_TMPDIR}/vhost.txt"; do
  [ -f "$f" ] || continue
  tool=$(basename "$f" .txt)
  count=$(wc -l < "$f" 2>/dev/null || echo 0)
  printf "  %-20s : %s subdomains\n" "$tool" "$count"
done

echo -e "${BOLD}  ────────────────────────────────────────────────────${RESET}"
printf "  %-35s : %s\n" "Passive subdomains"              "$PASSIVE_TOTAL"
printf "  %-35s : %s\n" "New (active-only) subdomains"    "$ACTIVE_ONLY_TOTAL"
printf "  %-35s : %s\n" "Master list (passive + active)"  "$MASTER_TOTAL"
echo -e "${BOLD}  ────────────────────────────────────────────────────${RESET}\n"

# ── Print active-only subdomains to terminal ──────────────────
if [ "$ACTIVE_ONLY_TOTAL" -gt 0 ]; then
  echo -e "${BOLD}${GREEN}  ── New Subdomains Found by Active Recon (NOT in passive) ──${RESET}"
  cat "$ACTIVE_ONLY_OUTPUT" | while read -r sub; do
    echo -e "  ${CYAN}[+]${RESET} ${sub}"
  done
  echo -e "${BOLD}  ────────────────────────────────────────────────────${RESET}\n"
else
  echo -e "  ${YELLOW}[!]${RESET} No new subdomains discovered by active recon\n"
fi

echo -e "${GREEN}[✔] Passive subdomains      :${RESET} ${BOLD}${PASSIVE_OUTPUT}${RESET}"
echo -e "${GREEN}[✔] Active-only subdomains  :${RESET} ${BOLD}${ACTIVE_ONLY_OUTPUT}${RESET}"
echo -e "${GREEN}[✔] Master list             :${RESET} ${BOLD}${MASTER_OUTPUT}${RESET}\n"

# ── httpx on master list (passive + active combined) ──────────
MASTER_HTTPX="${OUTDIR}/${DOMAIN}_httpx.txt"

if [ "$HAS_HTTPX" = true ] && [ "$MASTER_TOTAL" -gt 0 ]; then
  echo -e "  ──────────────────────────────────────────────────────"
  echo -e "${BOLD}  PROBING LIVE HOSTS (httpx)${RESET}"
  echo -e "  ──────────────────────────────────────────────────────\n"
  echo -e "${CYAN}[+] Running httpx on ${BOLD}${MASTER_TOTAL}${RESET}${CYAN} total subdomains (passive + active)...${RESET}"
  echo -e "${YELLOW}    Threads: 100 | Follow Redirects | Tech Detection | Title${RESET}\n"

  cat "$MASTER_OUTPUT" | httpx -threads 100 -fr -td -title | tee "$MASTER_HTTPX"

  HTTPX_COUNT=$(wc -l < "$MASTER_HTTPX" 2>/dev/null || echo 0)
  echo ""
  echo -e "${GREEN}[✔]${RESET} ${BOLD}${HTTPX_COUNT}${RESET} live hosts found"
  echo -e "${GREEN}[✔] httpx output saved to   :${RESET} ${BOLD}${MASTER_HTTPX}${RESET}\n"
else
  echo -e "  ${RED}[✘]${RESET} httpx not found — skipping"
  echo -e "      Install: ${YELLOW}go install github.com/projectdiscovery/httpx/cmd/httpx@latest${RESET}\n"
fi

echo -e "${BOLD}[*] Finished At : ${RESET}$(date)"