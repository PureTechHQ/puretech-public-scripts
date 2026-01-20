#!/usr/bin/env bash
################################################################################
# Script Name  : wikijs-ssl-setup.sh
# Description  : Setup NGINX reverse proxy with SSL for Wiki.js on Ubuntu 24.04
#
# Author        : Your Name
# Created       : 2026-01-19
# Updated       : YYYY-MM-DD
# Version       : 1.0.0
# License       : MIT
#
# Organization  : PureTechHQ
# Website       : https://puretechhq.com
# Project       : PureTechPublic
# Repository    : https://github.com/PureTechHQ/puretech-public-scripts
#
# Changelog     :
#   2026-01-19  1.0.0  - Initial release
################################################################################

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="1.0.0"

trap 'echo "[ERROR] ${SCRIPT_NAME}: line ${LINENO}: command \"${BASH_COMMAND}\" failed." >&2' ERR

################################################################################

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

check_wiki_container() {
    if ! docker ps --format '{{.Names}}' | grep -q '^wiki$'; then
        log_error "Wiki.js container 'wiki' is not running"
        log_error "Please run the Wiki.js installation script first"
        exit 1
    fi
    log_success "Wiki.js container found and running"
}

install_nginx() {
    if ! command -v nginx >/dev/null 2>&1; then
        log_step "Installing NGINX"
        apt -qqy update
        apt -qqy install nginx
        log_success "NGINX installed"
    else
        log_info "NGINX is already installed"
    fi
}

install_openssl() {
    if ! command -v openssl >/dev/null 2>&1; then
        log_step "Installing OpenSSL"
        apt -qqy update
        apt -qqy install openssl
        log_success "OpenSSL installed"
    else
        log_info "OpenSSL is already installed"
    fi
}

read_ssl_config() {
    local server_ip
    server_ip=$(hostname -I | awk '{print $1}')
    
    echo
    log_step "SSL Certificate Configuration"
    echo
    
    read -r -p "Enter Common Name (CN) / Domain [${server_ip}]: " CERT_CN
    CERT_CN="${CERT_CN:-$server_ip}"
    
    echo
    read -r -p "Enter country code (2 letters) [US]: " CERT_COUNTRY
    CERT_COUNTRY="${CERT_COUNTRY:-US}"
    
    read -r -p "Enter state/province [California]: " CERT_STATE
    CERT_STATE="${CERT_STATE:-California}"
    
    read -r -p "Enter city [San Francisco]: " CERT_CITY
    CERT_CITY="${CERT_CITY:-San Francisco}"
    
    read -r -p "Enter organization [My Company]: " CERT_ORG
    CERT_ORG="${CERT_ORG:-My Company}"
    
    read -r -p "Enter organizational unit [IT Department]: " CERT_OU
    CERT_OU="${CERT_OU:-IT Department}"
    
    read -r -p "Enter email address [admin@example.com]: " CERT_EMAIL
    CERT_EMAIL="${CERT_EMAIL:-admin@example.com}"
    
    echo
    read -r -p "Certificate validity in days [365]: " CERT_DAYS
    CERT_DAYS="${CERT_DAYS:-365}"
    
    echo
    log_info "Additional Subject Alternative Names (optional)"
    read -r -p "Enter additional DNS/IP names (space-separated, or press Enter to skip): " CERT_SAN
    
    export CERT_CN CERT_COUNTRY CERT_STATE CERT_CITY CERT_ORG CERT_OU CERT_EMAIL CERT_DAYS CERT_SAN
}

show_config() {
    echo
    log_step "SSL Certificate Configuration"
    echo
    echo "  Country (C):           ${CERT_COUNTRY}"
    echo "  State (ST):            ${CERT_STATE}"
    echo "  City (L):              ${CERT_CITY}"
    echo "  Organization (O):      ${CERT_ORG}"
    echo "  Org Unit (OU):         ${CERT_OU}"
    echo "  Common Name (CN):      ${CERT_CN}"
    echo "  Email:                 ${CERT_EMAIL}"
    echo "  Validity Days:         ${CERT_DAYS}"
    if [[ -n "$CERT_SAN" ]]; then
        echo "  Alt Names (SAN):       ${CERT_SAN}"
    fi
    echo
}

generate_openssl_config() {
    local config_file="$1"
    local san_count=1
    
    cat > "$config_file" <<EOF
# =====================================================
# WIKI.JS TLS CERT CONFIG
# =====================================================

[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_ext

[ dn ]
C  = ${CERT_COUNTRY}
ST = ${CERT_STATE}
L  = ${CERT_CITY}
O  = ${CERT_ORG}
OU = ${CERT_OU}

CN = ${CERT_CN}
emailAddress = ${CERT_EMAIL}

[ v3_ext ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.${san_count} = ${CERT_CN}
EOF

    # Add additional SANs if provided
    if [[ -n "$CERT_SAN" ]]; then
        for san in $CERT_SAN; do
            san_count=$((san_count + 1))
            # Check if it's an IP address or DNS name
            if [[ "$san" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "IP.${san_count} = ${san}" >> "$config_file"
            else
                echo "DNS.${san_count} = ${san}" >> "$config_file"
            fi
        done
    fi
    
    cat >> "$config_file" <<EOF

# =====================================================
# END OF FILE
# =====================================================
EOF
}

generate_certificate() {
    log_step "Generating self-signed SSL certificate"
    
    local cert_dir="/etc/ssl/wikijs"
    mkdir -p "$cert_dir"
    
    local key_file="$cert_dir/wikijs.key"
    local cert_file="$cert_dir/wikijs.crt"
    local config_file="$cert_dir/wikijs-cert.conf"
    
    log_info "Creating OpenSSL configuration file..."
    generate_openssl_config "$config_file"
    
    log_info "Generating self-signed certificate (valid for ${CERT_DAYS} days)..."
    
    openssl req -x509 -nodes -days "$CERT_DAYS" \
        -newkey rsa:2048 \
        -keyout "$key_file" \
        -out "$cert_file" \
        -config "$config_file"
    
    chmod 644 "$cert_file"
    chmod 600 "$key_file"
    chmod 644 "$config_file"
    
    log_success "SSL certificate generated successfully"
    log_info "Certificate:   $cert_file"
    log_info "Private Key:   $key_file"
    log_info "Config File:   $config_file"
    
    export CERT_FILE="$cert_file"
    export KEY_FILE="$key_file"
}

update_wiki_ports() {
    log_step "Updating Wiki.js container port mappings"
    
    log_info "Stopping Wiki.js container..."
    docker stop wiki
    
    log_info "Removing old container..."
    docker rm wiki
    
    log_info "Reading existing database configuration..."
    local db_name db_user
    db_name=$(docker inspect db 2>/dev/null | grep -oP 'POSTGRES_DB=\K[^"]+' || echo "wiki")
    db_user=$(docker inspect db 2>/dev/null | grep -oP 'POSTGRES_USER=\K[^"]+' || echo "wiki")
    
    log_info "Creating new Wiki.js container (internal port only)..."
    docker create --name=wiki \
        -e DB_TYPE=postgres \
        -e DB_HOST=db \
        -e DB_PORT=5432 \
        -e DB_PASS_FILE=/etc/wiki/.db-secret \
        -v /etc/wiki/.db-secret:/etc/wiki/.db-secret:ro \
        -e DB_USER="${db_user}" \
        -e DB_NAME="${db_name}" \
        -e UPGRADE_COMPANION=1 \
        --restart=unless-stopped \
        -h wiki \
        --network=wikinet \
        -p 127.0.0.1:3000:3000 \
        ghcr.io/requarks/wiki:2
    
    log_info "Starting Wiki.js container..."
    docker start wiki
    
    log_success "Wiki.js container updated (now listening on 127.0.0.1:3000)"
}

configure_nginx() {
    log_step "Configuring NGINX reverse proxy"
    
    local nginx_conf="/etc/nginx/sites-available/wikijs"
    
    cat > "$nginx_conf" <<EOF
# Wiki.js NGINX Configuration with SSL

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name ${CERT_CN};
    return 301 https://\$server_name\$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name ${CERT_CN};

    # SSL Configuration
    ssl_certificate /etc/ssl/wikijs/wikijs.crt;
    ssl_certificate_key /etc/ssl/wikijs/wikijs.key;

    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Client upload size
    client_max_body_size 50M;

    # Proxy to Wiki.js
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
        
        # Timeouts
        proxy_read_timeout 90;
        proxy_connect_timeout 90;
    }
}
EOF

    # Enable the site
    ln -sf /etc/nginx/sites-available/wikijs /etc/nginx/sites-enabled/wikijs
    
    # Remove default site if it exists
    rm -f /etc/nginx/sites-enabled/default
    
    # Test configuration
    log_info "Testing NGINX configuration..."
    nginx -t
    
    # Restart NGINX
    log_info "Restarting NGINX..."
    systemctl restart nginx
    systemctl enable nginx
    
    log_success "NGINX configured and restarted"
}

show_completion() {
    echo
    echo "================================================================================"
    log_success "SSL setup completed successfully"
    echo
    echo "  HTTPS Interface: https://${CERT_CN}/"
    echo "  HTTP redirects to HTTPS automatically"
    echo
    echo "  Certificate:     /etc/ssl/wikijs/wikijs.crt"
    echo "  Private Key:     /etc/ssl/wikijs/wikijs.key"
    echo "  Config File:     /etc/ssl/wikijs/wikijs-cert.conf"
    echo "  NGINX Config:    /etc/nginx/sites-available/wikijs"
    echo "  Valid for:       ${CERT_DAYS} days"
    echo
    echo "Important Notes:"
    echo "  - This is a SELF-SIGNED certificate"
    echo "  - Browsers will show a security warning"
    echo "  - You can safely proceed past the warning"
    echo "  - For production, consider using Let's Encrypt (certbot)"
    echo
    echo "Next Steps:"
    echo "  1. Access https://${CERT_CN}/ in your browser"
    echo "  2. Accept the security warning to proceed"
    echo "  3. Update Site URL in Wiki.js admin panel to https://${CERT_CN}"
    echo
    echo "Certificate Details:"
    echo "  View certificate: openssl x509 -in /etc/ssl/wikijs/wikijs.crt -text -noout"
    echo "  Check expiry:     openssl x509 -in /etc/ssl/wikijs/wikijs.crt -noout -dates"
    echo
    echo "Service Management:"
    echo "  NGINX status:     systemctl status nginx"
    echo "  NGINX logs:       tail -f /var/log/nginx/error.log"
    echo "  Wiki.js logs:     docker logs wiki"
    echo "  Test NGINX:       nginx -t"
    echo "================================================================================"
    echo
}

############################### MAIN SCRIPT ####################################

require_root

echo
echo -e "${BOLD}Wiki.js SSL Setup with NGINX Reverse Proxy${RESET}"
echo "============================================================"
echo

check_wiki_container
install_nginx
install_openssl

read_ssl_config
show_config

echo
log_warn "This script will:"
log_warn "  1. Generate a self-signed SSL certificate"
log_warn "  2. Install and configure NGINX as a reverse proxy"
log_warn "  3. Reconfigure Wiki.js container to listen on localhost only"
log_warn "  4. Setup automatic HTTP to HTTPS redirect"
echo

if ! prompt_yes_no "Do you want to proceed with SSL setup?"; then
    log_info "SSL setup cancelled"
    exit 0
fi

echo
generate_certificate
update_wiki_ports
configure_nginx
show_completion