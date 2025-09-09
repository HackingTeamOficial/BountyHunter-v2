#!/bin/bash

# ===============================================
# BountyHunterV2 - Enhanced Pentest Automation
# Autor: AnonSec777 - Hacking Team Comunidad De Hackers
# 
# ===============================================

# ----------- Configuración de colores -----------
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

# ----------- Rutas por defecto -----------
DEFAULT_WORDLIST="/usr/share/wordlists/rockyou.txt"
DEFAULT_USERLIST="/usr/share/wordlists/metasploit/default_users.txt"
METASPLOIT_SCRIPTS_DIR="$HOME/.msf4/scripts"

# ----------- Funciones -----------

check_dep() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo -e "${RED}[!] $1 no está instalado. Abortando.${RESET}"
        exit 1
    fi
}

header() {
    echo -e "${CYAN}"
    cat << "EOF"
 ██╗  ██╗  █████╗   ██████╗ ██╗  ██╗ ██╗ ███╗   ██╗  ██████╗      ████████╗ ███████╗  █████╗  ███╗   ███╗
 ██║  ██║ ██╔══██╗ ██╔════╝ ██║ ██╔╝ ██║ ████╗  ██║ ██╔════╝      ╚══██╔══╝ ██╔════╝ ██╔══██╗ ████╗ ████║
 ███████║ ███████║ ██║      █████╔╝  ██║ ██╔██╗ ██║ ██║  ███╗        ██║    █████╗   ███████║ ██╔████╔██║
 ██╔══██║ ██╔══██║ ██║      ██╔═██╗  ██║ ██║╚██╗██║ ██║   ██║        ██║    ██╔══╝   ██╔══██║ ██║╚██╔╝██║
 ██║  ██║ ██║  ██║ ╚██████╗ ██║  ██╗ ██║ ██║ ╚████║ ╚██████╔╝        ██║    ███████╗ ██║  ██║ ██║ ╚═╝ ██║
 ╚═╝  ╚═╝ ╚═╝  ╚═╝  ╚═════╝ ╚═╝  ╚═╝ ╚═╝ ╚═╝  ╚═══╝  ╚═════╝         ╚═╝    ╚══════╝ ╚═╝  ╚═╝ ╚═╝     ╚═╝
EOF
    echo "                           by AnonSec777 - Hacking Team Comunidad De Hackers"
    echo -e "${RESET}"
}

error_exit() {
    echo -e "${RED}[!] Error: $1${RESET}" >&2
    exit 1
}

cleanup() {
    echo -e "${YELLOW}[*] Limpiando archivos temporales...${RESET}"
    rm -f "$OUTDIR/temp_*.txt" 2>/dev/null
}

# Función para ejecutar Hydra
run_hydra() {
    local target="$1"
    local port="$2"
    local service="$3"
    local userlist="${4:-$DEFAULT_USERLIST}"
    local passlist="${5:-$DEFAULT_WORDLIST}"
    local outfile="$OUTDIR/hydra_${service}.txt"

    echo -e "${GREEN}[*] Probando fuerza bruta en $service (puerto $port)...${RESET}"
    
    case "$service" in
        "ssh")
            hydra -L "$userlist" -P "$passlist" -t 4 -s "$port" -o "$outfile" "$target" ssh
            ;;
        "ftp")
            hydra -L "$userlist" -P "$passlist" -t 4 -s "$port" -o "$outfile" "$target" ftp
            ;;
        "http")
            hydra -L "$userlist" -P "$passlist" -t 4 -s "$port" -o "$outfile" "$target" http-get /
            ;;
        "smtp")
            hydra -L "$userlist" -P "$passlist" -t 4 -s "$port" -o "$outfile" "$target" smtp
            ;;
        "pop3")
            hydra -L "$userlist" -P "$passlist" -t 4 -s "$port" -o "$outfile" "$target" pop3
            ;;
        "imap")
            hydra -L "$userlist" -P "$passlist" -t 4 -s "$port" -o "$outfile" "$target" imap
            ;;
        "postgres")
            hydra -L "$userlist" -P "$passlist" -t 4 -s "$port" -o "$outfile" "$target" postgres
            ;;
        "mysql")
            hydra -L "$userlist" -P "$passlist" -t 4 -s "$port" -o "$outfile" "$target" mysql
            ;;
        *)
            echo -e "${YELLOW}[!] Servicio $service no soportado para Hydra.${RESET}"
            ;;
    esac
}

# Función para ejecutar Metasploit
run_metasploit() {
    local target="$1"
    local port="$2"
    local service="$3"
    local outfile="$OUTDIR/msf_${service}.txt"

    echo -e "${GREEN}[*] Ejecutando Metasploit para $service (puerto $port)...${RESET}"
    
    case "$service" in
        "http")
            msfconsole -q -x "spool $outfile; use auxiliary/scanner/http/http_version; set RHOSTS $target; set RPORT $port; run; spool off; exit"
            ;;
        "ssh")
            msfconsole -q -x "spool $outfile; use auxiliary/scanner/ssh/ssh_version; set RHOSTS $target; set RPORT $port; run; spool off; exit"
            ;;
        "smtp")
            msfconsole -q -x "spool $outfile; use auxiliary/scanner/smtp/smtp_version; set RHOSTS $target; set RPORT $port; run; spool off; exit"
            ;;
        "pop3")
            msfconsole -q -x "spool $outfile; use auxiliary/scanner/pop3/pop3_version; set RHOSTS $target; set RPORT $port; run; spool off; exit"
            ;;
        "imap")
            msfconsole -q -x "spool $outfile; use auxiliary/scanner/imap/imap_version; set RHOSTS $target; set RPORT $port; run; spool off; exit"
            ;;
        "postgres")
            msfconsole -q -x "spool $outfile; use auxiliary/scanner/postgres/postgres_version; set RHOSTS $target; set RPORT $port; run; spool off; exit"
            ;;
        "mysql")
            msfconsole -q -x "spool $outfile; use auxiliary/scanner/mysql/mysql_version; set RHOSTS $target; set RPORT $port; run; spool off; exit"
            ;;
        *)
            echo -e "${YELLOW}[!] Servicio $service no soportado para Metasploit.${RESET}"
            ;;
    esac
}

# Función para escaneo avanzado con Nmap
run_nmap() {
    local target="$1"
    local port="$2"
    local service="$3"
    local outfile="$OUTDIR/nmap_${service}.txt"

    echo -e "${GREEN}[*] Escaneo avanzado con Nmap para $service (puerto $port)...${RESET}"
    
    case "$service" in
        "http")
            nmap -sV -sC -p "$port" --script=http-vuln* "$target" -oN "$outfile"
            ;;
        "ssh")
            nmap -sV -sC -p "$port" --script=ssh-auth-methods,sshv1 "$target" -oN "$outfile"
            ;;
        "smtp")
            nmap -sV -sC -p "$port" --script=smtp-* "$target" -oN "$outfile"
            ;;
        "pop3")
            nmap -sV -sC -p "$port" --script=pop3-* "$target" -oN "$outfile"
            ;;
        "imap")
            nmap -sV -sC -p "$port" --script=imap-* "$target" -oN "$outfile"
            ;;
        "postgres")
            nmap -sV -sC -p "$port" --script=postgres-* "$target" -oN "$outfile"
            ;;
        "mysql")
            nmap -sV -sC -p "$port" --script=mysql-* "$target" -oN "$outfile"
            ;;
        *)
            echo -e "${YELLOW}[!] Servicio $service no soportado para Nmap.${RESET}"
            ;;
    esac
}

# ----------- Inicio -----------

header

if [ $# -lt 1 ]; then
    echo -e "${RED}Uso: $0 <dominio/IP> [wordlist para ffuf]${RESET}"
    exit 1
fi

TARGET="$1"
WORDLIST="${2:-/usr/share/wordlists/dirb/common.txt}"
OUTDIR="results-$TARGET-$(date +%Y%m%d-%H%M%S)"
LOGFILE="$OUTDIR/bountyhunter.log"

mkdir -p "$OUTDIR" || error_exit "No se pudo crear el directorio $OUTDIR"

DEPENDENCIES=(subfinder assetfinder chaos dnsx httpx gau waybackurls katana ffuf naabu nuclei dalfox hydra msfconsole nmap)
for dep in "${DEPENDENCIES[@]}"; do
    check_dep "$dep"
done

{
    echo "[*] Iniciando reconocimiento sobre: $TARGET"
    echo "[*] Resultados en: $OUTDIR"
    echo "-------------------------------------"
} | tee -a "$LOGFILE"

# 1. Subdominios
echo -e "${GREEN}[1] Enumerando subdominios...${RESET}"
{
    subfinder -d "$TARGET" -silent -all
    assetfinder --subs-only "$TARGET"
    chaos -d "$TARGET" -silent
} | sort -u > "$OUTDIR/subs.txt" || error_exit "Error al enumerar subdominios"

# 2. Resolución y hosts vivos
echo -e "${GREEN}[2] Resolviendo y filtrando hosts vivos...${RESET}"
dnsx -l "$OUTDIR/subs.txt" -silent -resp-only > "$OUTDIR/resolved.txt" || error_exit "Error en dnsx"
httpx -l "$OUTDIR/resolved.txt" -silent -status-code -title -tech-detect -o "$OUTDIR/httpx.txt" || error_exit "Error en httpx"
cut -d " " -f1 "$OUTDIR/httpx.txt" > "$OUTDIR/alive.txt"

# 3. URLs históricas y crawling
echo -e "${GREEN}[3] Recolectando URLs...${RESET}"
{
    gau --threads 30 --o "$OUTDIR/gau_temp.txt" -l "$OUTDIR/alive.txt" || true
    waybackurls < "$OUTDIR/alive.txt" >> "$OUTDIR/gau_temp.txt" || true
    katana -list "$OUTDIR/alive.txt" -silent >> "$OUTDIR/gau_temp.txt" || true
    sort -u "$OUTDIR/gau_temp.txt" > "$OUTDIR/gau.txt"
    rm -f "$OUTDIR/gau_temp.txt"
} | tee -a "$LOGFILE"

# 4. Fuzzing de directorios
echo -e "${GREEN}[4] Fuzzing con ffuf...${RESET}"
ffuf -w "$WORDLIST" -u "https://$TARGET/FUZZ" -mc 200,301,302 -t 50 -of csv -o "$OUTDIR/ffuf.csv" 2>/dev/null || true

# 5. Escaneo de puertos
echo -e "${GREEN}[5] Escaneando puertos...${RESET}"
naabu -host "$TARGET" -silent -p 22,80,443,110,143,465,587,993,995,222,3306,5432 -o "$OUTDIR/ports.txt" || error_exit "Error en naabu"

# 6. Escaneo avanzado con Nmap + Metasploit
echo -e "${GREEN}[6] Escaneo avanzado con Nmap y Metasploit...${RESET}"
while read -r line; do
    host=$(echo "$line" | cut -d ':' -f1)
    port=$(echo "$line" | cut -d ':' -f2)
    case "$port" in
        22|222) service="ssh" ;;
        80|443) service="http" ;;
        465|587) service="smtp" ;;
        110|995) service="pop3" ;;
        143|993) service="imap" ;;
        5432) service="postgres" ;;
        3306) service="mysql" ;;
        *) service="unknown" ;;
    esac
    if [ "$service" != "unknown" ]; then
        run_nmap "$host" "$port" "$service"
        run_metasploit "$host" "$port" "$service"
    fi
done < "$OUTDIR/ports.txt"

# 7. Vulnerabilidades
echo -e "${GREEN}[7] Escaneando vulnerabilidades con nuclei...${RESET}"
nuclei -l "$OUTDIR/alive.txt" -silent -o "$OUTDIR/nuclei.txt" || true

# 8. XSS
echo -e "${GREEN}[8] Testeando XSS con Dalfox...${RESET}"
dalfox file "$OUTDIR/gau.txt" -o "$OUTDIR/dalfox.txt" || true

# 9. Fuerza bruta con Hydra
echo -e "${GREEN}[9] Fuerza bruta con Hydra...${RESET}"
while read -r line; do
    host=$(echo "$line" | cut -d ':' -f1)
    port=$(echo "$line" | cut -d ':' -f2)
    case "$port" in
        22|222) service="ssh" ;;
        21) service="ftp" ;;
        80|443) service="http" ;;
        465|587) service="smtp" ;;
        110|995) service="pop3" ;;
        143|993) service="imap" ;;
        5432) service="postgres" ;;
        3306) service="mysql" ;;
        *) service="unknown" ;;
    esac
    if [ "$service" != "unknown" ]; then
        run_hydra "$host" "$port" "$service"
    fi
done < "$OUTDIR/ports.txt"

# 10. Reporte final
REPORT="$OUTDIR/Reporte_$TARGET.md"
cat > "$REPORT" <<EOF
# Reporte de Recon - $TARGET

**Fecha:** $(date)

## 📊 Executive Summary
| Servicio | Puerto | Credenciales Hydra | Versión detectada |
|----------|--------|--------------------|-------------------|
EOF

# Rellenar resumen
for file in "$OUTDIR"/nmap_*.txt; do
    service=$(basename "$file" | cut -d '_' -f2 | cut -d '.' -f1)
    port=$(grep "open" "$file" | awk '{print $1}' | cut -d '/' -f1 | head -n1)
    version=$(grep "open" "$file" | awk '{$1=$2=$3=""; print $0}' | head -n1 | sed 's/^[ \t]*//')
    creds=$(grep -Eo "\[.*\] host: .* login: .* password: .*" "$OUTDIR/hydra_${service}.txt" 2>/dev/null | head -n1)
    echo "| $service | $port | ${creds:-N/A} | ${version:-N/A} |" >> "$REPORT"
done

cat >> "$REPORT" <<EOF

---

## Subdominios encontrados
$(wc -l < "$OUTDIR/subs.txt") subdominios  
Archivo: subs.txt

## Hosts vivos
$(wc -l < "$OUTDIR/alive.txt") hosts  
Archivo: alive.txt

## URLs recolectadas
$(wc -l < "$OUTDIR/gau.txt") URLs  
Archivo: gau.txt

## Puertos abiertos
Archivo: ports.txt  
$(cat "$OUTDIR/ports.txt")

## Nuclei findings
$(grep -c "" "$OUTDIR/nuclei.txt") vulnerabilidades detectadas  
Archivo: nuclei.txt

## XSS (Dalfox)
Archivo: dalfox.txt

## Resultados de Hydra
$(for file in "$OUTDIR"/hydra_*.txt; do [ -f "$file" ] && echo "### $(basename "$file")" && cat "$file"; done)

## Resultados de Metasploit
$(for file in "$OUTDIR"/msf_*.txt; do [ -f "$file" ] && echo "### $(basename "$file")" && cat "$file"; done)

## Resultados de Nmap
$(for file in "$OUTDIR"/nmap_*.txt; do [ -f "$file" ] && echo "### $(basename "$file")" && cat "$file"; done)

---
_Este reporte es un resumen automático generado por **BountyHunter.sh**_
EOF

cleanup

echo -e "${CYAN}"
echo "==============================================="
echo "   BountyHunter - Reporte Generado en: $REPORT"
echo "==============================================="
echo -e "${RESET}"
