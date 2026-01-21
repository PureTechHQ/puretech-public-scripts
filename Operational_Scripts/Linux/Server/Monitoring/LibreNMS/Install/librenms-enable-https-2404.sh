#!/usr/bin/env bash
################################################################################
# Script Name  : librenms-enable-https-2404.sh
# Description  : Configure HTTPS for LibreNMS on Ubuntu 24.04 LTS using a self-signed TLS certificate.
# Author       : John Harrison
# Created      : 2025-11-12
# Updated      : YYYY-MM-DD
# Version      : 1.0.0
# License      : MIT
#
# Organization  : PureTechHQ
# Website       : https://puretechhq.com
# Project       : PureTechPublic
# Repository    : https://github.com/PureTechHQ/puretech-public-scripts
#
# Changelog:
#   [2025-11-21] v1.0.0 — First stable release (self-signed HTTPS full rewrite).
################################################################################

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="1.1.0"

trap 'echo "[ERROR] ${SCRIPT_NAME}: line ${LINENO}: command \"${BASH_COMMAND}\" failed." >&2' ERR

################################# COLORS #######################################

if [[ -t 1 ]]; then
    BOLD="\e[1m"
    RED="\e[31m"
    GREEN="\e[32m"
    YELLOW="\e[33m"
    BLUE="\e[34m"
    RESET="\e[0m"
else
    BOLD="" RED="" GREEN="" YELLOW="" BLUE="" RESET=""
fi

log_step()    { echo -e "${BLUE}${BOLD}==>${RESET} ${BLUE}$*${RESET}"; }
log_info()    { echo -e "${GREEN}[*]${RESET} $*"; }
log_warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
log_error()   { echo -e "${RED}[x]${RESET} $*" >&2; }
log_success() { echo -e "${GREEN}${BOLD}✔${RESET} $*"; }

################################ FUNCTIONS #####################################

require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 4
    fi
}

prompt_yes_no() {
    local prompt="$1" answer
    while :; do
        read -r -p "$prompt [yes/no]: " answer
        case "$answer" in
            [Yy]|[Yy][Ee][Ss]) return 0 ;;
            [Nn]|[Nn][Oo])     return 1 ;;
            *) echo "Please answer yes or no." ;;
        esac
    done
}

set_env_kv() {
    local file="$1" key="$2" val="$3"
    local esc
    esc=$(printf '%s' "$val" | sed -e 's/[\/&]/\\&/g')
    if grep -qE "^[#[:space:]]*${key}=" "$file" 2>/dev/null; then
        sed -i -E "s|^[#[:space:]]*${key}=.*|${key}=${esc}|" "$file"
    else
        printf '%s=%s\n' "$key" "$val" >> "$file"
    fi
}

valid_domain() {
    [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$ ]]
}

esc_dn() {
    printf '%s' "$1" | sed -e 's,/,\\/,g' -e 's, ,\\ ,g'
}

detect_fastcgi_pass() {
    local listen=""
    if ls /etc/php/*/fpm/pool.d/librenms.conf >/dev/null 2>&1; then
        listen=$(grep -hE '^\s*listen\s*=' /etc/php/*/fpm/pool.d/librenms.conf \
                 | tail -n1 | awk -F= '{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2}')
    fi
    if [[ -z "$listen" && -S /run/php-fpm-librenms.sock ]]; then
        echo "unix:/run/php-fpm-librenms.sock"; return
    fi
    if [[ -z "$listen" ]] && compgen -G "/run/php/php*-fpm.sock" >/dev/null; then
        local s; s=$(ls -1 /run/php/php*-fpm.sock 2>/dev/null | head -n1)
        echo "unix:${s}"; return
    fi
    if [[ -n "$listen" ]]; then
        [[ "$listen" == unix:* ]] && { echo "$listen"; return; }
        [[ "$listen" == /* ]] && { echo "unix:${listen}"; return; }
        echo "$listen"; return
    fi
    echo "unix:/run/php-fpm-librenms.sock"
}

############################### MAIN SCRIPT ####################################

require_root

echo
echo -e "${BOLD}LibreNMS HTTPS Configuration for Ubuntu 24.04 LTS${RESET}"
echo "============================================================"
echo

# Domain input and validation
while :; do
    read -r -p "Enter the LibreNMS domain (e.g., librenms.example.com): " DOMAIN
    if valid_domain "$DOMAIN"; then
        break
    else
        log_warn "Invalid domain format. Use FQDN (e.g., librenms.example.com)"
    fi
done

log_step "Collecting certificate subject information"
echo "Press Enter to accept defaults"
echo

read -r -p "Country (2 letters) [US]: " C
C="${C:-US}"
C="${C^^}"
[[ "$C" =~ ^[A-Z]{2}$ ]] || { log_error "Country must be 2 letters"; exit 1; }

read -r -p "State/Province [Texas]: " ST
ST="${ST:-Texas}"

read -r -p "City/Locality [Austin]: " L
L="${L:-Austin}"

read -r -p "Organization [LibreNMS]: " O
O="${O:-LibreNMS}"

read -r -p "Organizational Unit [Internal Systems]: " OU
OU="${OU:-Internal Systems}"

read -r -p "Email Address [admin@example.com]: " EMAIL
EMAIL="${EMAIL:-admin@example.com}"

# Build subject string
SUBJ=""
[[ -n "$C"     ]] && SUBJ+="/C=$(esc_dn "$C")"
[[ -n "$ST"    ]] && SUBJ+="/ST=$(esc_dn "$ST")"
[[ -n "$L"     ]] && SUBJ+="/L=$(esc_dn "$L")"
[[ -n "$O"     ]] && SUBJ+="/O=$(esc_dn "$O")"
[[ -n "$OU"    ]] && SUBJ+="/OU=$(esc_dn "$OU")"
[[ -n "$EMAIL" ]] && SUBJ+="/emailAddress=$(esc_dn "$EMAIL")"
SUBJ+="/CN=$(esc_dn "$DOMAIN")"

# Build SAN
SAN="DNS:${DOMAIN}"
[[ -n "$EMAIL" ]] && SAN+=",email:${EMAIL}"

# Certificate paths - matching install script structure
CERT_DIR="/etc/ssl/certs"
KEY_DIR="/etc/ssl/private"
KEY="${KEY_DIR}/${DOMAIN}.key"
CRT="${CERT_DIR}/${DOMAIN}.crt"

# Nginx paths
HTTPS_CONF="/etc/nginx/conf.d/librenms.conf"
HTTP_REDIRECT_CONF="/etc/nginx/conf.d/librenms-http-redirect.conf"
GLOBAL_OPTS="/etc/nginx/conf.d/00-options.conf"

# LibreNMS paths
ENV_FILE="/opt/librenms/.env"
CFG_FILE="/opt/librenms/config.php"

# Ensure packages
log_step "Checking dependencies"
command -v openssl >/dev/null 2>&1 || apt install -y openssl
command -v nginx >/dev/null 2>&1 || apt install -y nginx-full

# Detect PHP-FPM
FASTCGI_PASS="$(detect_fastcgi_pass)"
log_info "Detected PHP-FPM: ${FASTCGI_PASS}"

# Create directories
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"

# Check for existing certificate
if [[ -f "$KEY" || -f "$CRT" ]]; then
    echo
    if prompt_yes_no "A certificate for ${DOMAIN} exists. Overwrite?"; then
        rm -f "$KEY" "$CRT"
        log_info "Existing certificate removed"
    else
        log_info "Keeping existing certificate"
    fi
fi

# Generate certificate if needed
if [[ ! -f "$KEY" || ! -f "$CRT" ]]; then
    log_step "Generating self-signed certificate"
    log_info "Algorithm: RSA-4096, Validity: 825 days"
    log_info "Subject Alternative Names: ${SAN}"
    
    openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
        -keyout "$KEY" -out "$CRT" \
        -subj "$SUBJ" \
        -addext "subjectAltName=${SAN}" \
        -addext "basicConstraints=CA:FALSE" \
        -addext "keyUsage=digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth"
    
    chmod 600 "$KEY"
    chmod 644 "$CRT"
    chown root:root "$KEY" "$CRT"
    
    log_success "Certificate generated successfully"
fi

# Configure Nginx global options
log_step "Configuring Nginx"

if [[ ! -f "$GLOBAL_OPTS" ]] || ! grep -q 'server_names_hash_bucket_size' "$GLOBAL_OPTS" 2>/dev/null; then
    cat > "$GLOBAL_OPTS" <<'CONF'
server_names_hash_bucket_size 128;
CONF
    log_info "Global Nginx options configured"
fi

# Create HTTPS server block (replaces existing librenms.conf)
cat > "$HTTPS_CONF" <<NGINX
server {
    listen 443 ssl http2;
    server_name ${DOMAIN};
    root /opt/librenms/html;
    index index.php;

    ssl_certificate     ${CRT};
    ssl_certificate_key ${KEY};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    gzip on;
    gzip_types text/css application/javascript text/javascript application/x-javascript image/svg+xml text/plain text/xsd text/xsl text/xml image/x-icon;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ [^/]\.php(/|$) {
        fastcgi_pass ${FASTCGI_PASS};
        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        include fastcgi.conf;
    }

    location ~ /\.(?!well-known).* {
        deny all;
    }
}
NGINX

# Create HTTP to HTTPS redirect
cat > "$HTTP_REDIRECT_CONF" <<NGINX
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}
NGINX

# Remove default site if present
rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default 2>/dev/null || true

log_success "Nginx configuration updated"

# Test Nginx configuration
log_step "Testing Nginx configuration"
if nginx -t; then
    log_success "Nginx configuration test passed"
else
    log_error "Nginx configuration test failed"
    exit 1
fi

# Update LibreNMS environment
log_step "Updating LibreNMS configuration"

if [[ ! -f "$ENV_FILE" ]]; then
    sudo -u librenms cp /opt/librenms/.env.example "$ENV_FILE" 2>/dev/null || true
fi

set_env_kv "$ENV_FILE" APP_URL "https://${DOMAIN}"
set_env_kv "$ENV_FILE" SESSION_SECURE_COOKIE "true"

# Update config.php
if grep -q "base_url" "$CFG_FILE" 2>/dev/null; then
    sed -i -E "s|^(\$config\['base_url'\].*)|# \1|" "$CFG_FILE"
fi

if ! grep -q "https://${DOMAIN}" "$CFG_FILE" 2>/dev/null; then
    echo "\$config['base_url'] = 'https://${DOMAIN}';" >> "$CFG_FILE"
fi

chown librenms:librenms "$CFG_FILE" 2>/dev/null || true

# Apply configuration via lnms
sudo -u librenms /opt/librenms/lnms config:set base_url "https://${DOMAIN}" >/dev/null 2>&1 || true

# Clear Laravel caches
if command -v php >/dev/null 2>&1; then
    log_step "Clearing application caches"
    sudo -u librenms bash -lc 'cd /opt/librenms && php artisan config:clear && php artisan cache:clear && php artisan config:cache' 2>/dev/null || true
fi

# Restart services
log_step "Restarting services"
systemctl restart php8.3-fpm || systemctl restart php-fpm || log_warn "Could not restart PHP-FPM"
systemctl reload nginx

log_success "Services restarted"

# Installation complete
echo
echo "================================================================================"
log_success "HTTPS configuration completed successfully"
echo
echo "  Web Interface: https://${DOMAIN}"
echo "  Certificate:   ${CRT}"
echo "  Private Key:   ${KEY}"
echo
echo "Next Steps:"
echo "  1. Navigate to https://${DOMAIN}"
echo "  2. Accept the self-signed certificate warning in your browser"
echo "  3. For production use, replace with a trusted certificate (Let's Encrypt)"
echo
echo "Certificate Details:"
echo "  Subject:  ${SUBJ}"
echo "  SAN:      ${SAN}"
echo "  Validity: 825 days"
echo "  Issued:   $(date)"
echo "================================================================================"
echo