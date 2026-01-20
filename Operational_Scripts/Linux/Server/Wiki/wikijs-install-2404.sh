#!/usr/bin/env bash
################################################################################
# Script Name  : wikijs-install-2404.sh
# Description  : Interactive installer for Wiki.js on Ubuntu 24.04 LTS.
#
# Author        : John Harrison
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

read_database_config() {
    local def_db="wiki" def_user="wiki"
    
    echo
    log_step "Database Configuration"
    echo
    
    read -r -p "Enter database name [${def_db}]: " DBNAME
    DBNAME="${DBNAME:-$def_db}"
    
    read -r -p "Enter database username [${def_user}]: " DBUSER
    DBUSER="${DBUSER:-$def_user}"
    
    log_info "Database password will be auto-generated"
    
    export DBNAME DBUSER
}

read_fqdn_config() {
    local server_ip
    server_ip=$(hostname -I | awk '{print $1}')
    
    echo
    log_step "Server URL Configuration"
    echo
    log_info "Enter a Fully Qualified Domain Name (FQDN) for your Wiki.js instance"
    log_info "Example: wiki.example.com"
    echo
    
    read -r -p "Enter FQDN [${server_ip}]: " FQDN
    FQDN="${FQDN:-$server_ip}"
    
    if [[ "$FQDN" == "$server_ip" ]]; then
        log_info "Using server IP address: ${FQDN}"
    else
        log_success "Using FQDN: ${FQDN}"
    fi
    
    export FQDN
}

check_ubuntu_version() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]]; then
            log_error "This script is designed for Ubuntu only"
            exit 1
        fi
        log_info "Detected Ubuntu $VERSION"
    else
        log_error "Cannot detect OS version"
        exit 1
    fi
}

wait_for_apt_lock() {
    log_step "Checking for package manager availability"
    
    local wait_time=0
    local max_wait=300
    
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        if [[ $wait_time -ge $max_wait ]]; then
            log_error "Package manager is locked by another process. Please try again later."
            exit 1
        fi
        
        if [[ $wait_time -eq 0 ]]; then
            log_warn "Package manager is currently in use by another process"
            log_info "Waiting for it to become available..."
        fi
        
        sleep 5
        wait_time=$((wait_time + 5))
    done
    
    if [[ $wait_time -gt 0 ]]; then
        log_success "Package manager is now available"
    fi
}

update_system() {
    log_step "Updating system packages"
    
    wait_for_apt_lock
    
    apt -qqy update
    DEBIAN_FRONTEND=noninteractive apt-get -qqy -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' dist-upgrade
    log_success "System updated successfully"
}

install_docker() {
    log_step "Installing Docker"
    
    wait_for_apt_lock
    
    log_info "Installing dependencies..."
    apt -qqy -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' install \
        ca-certificates curl gnupg lsb-release
    
    log_info "Registering Docker package registry..."
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    log_info "Installing Docker packages..."
    apt -qqy update
    apt -qqy -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' install \
        docker-ce docker-ce-cli containerd.io docker-compose-plugin
    
    log_success "Docker installed successfully"
}

setup_containers() {
    log_step "Setting up Wiki.js containers"
    
    log_info "Creating installation directory..."
    mkdir -p /etc/wiki
    
    log_info "Generating secure database password..."
    openssl rand -base64 32 > /etc/wiki/.db-secret
    chmod 644 /etc/wiki/.db-secret
    chown root:root /etc/wiki/.db-secret
    
    log_info "Creating Docker network..."
    docker network create wikinet 2>/dev/null || log_warn "Network 'wikinet' already exists"
    
    log_info "Creating PostgreSQL data volume..."
    docker volume create pgdata 2>/dev/null || log_warn "Volume 'pgdata' already exists"
    
    log_info "Creating PostgreSQL container..."
    docker create --name=db \
        -e POSTGRES_DB="${DBNAME}" \
        -e POSTGRES_USER="${DBUSER}" \
        -e POSTGRES_PASSWORD_FILE=/etc/wiki/.db-secret \
        -v /etc/wiki/.db-secret:/etc/wiki/.db-secret:ro \
        -v pgdata:/var/lib/postgresql/data \
        --restart=unless-stopped \
        -h db \
        --network=wikinet \
        postgres:17
    
    log_info "Creating Wiki.js container..."
    docker create --name=wiki \
        -e DB_TYPE=postgres \
        -e DB_HOST=db \
        -e DB_PORT=5432 \
        -e DB_PASS_FILE=/etc/wiki/.db-secret \
        -v /etc/wiki/.db-secret:/etc/wiki/.db-secret:ro \
        -e DB_USER="${DBUSER}" \
        -e DB_NAME="${DBNAME}" \
        -e UPGRADE_COMPANION=1 \
        --restart=unless-stopped \
        -h wiki \
        --network=wikinet \
        -p 80:3000 \
        -p 443:3443 \
        ghcr.io/requarks/wiki:2
    
    log_info "Creating Wiki.js Update Companion container..."
    docker create --name=wiki-update-companion \
        -v /var/run/docker.sock:/var/run/docker.sock:ro \
        --restart=unless-stopped \
        -h wiki-update-companion \
        --network=wikinet \
        ghcr.io/requarks/wiki-update-companion:latest
    
    log_success "Containers created successfully"
}

start_containers() {
    log_step "Starting containers"
    
    log_info "Starting PostgreSQL database..."
    docker start db
    sleep 5
    
    log_info "Starting Wiki.js application..."
    docker start wiki
    
    log_info "Starting Wiki.js Update Companion..."
    docker start wiki-update-companion
    
    log_success "Containers started successfully"
}

show_completion() {
    local db_pass
    db_pass=$(cat /etc/wiki/.db-secret)
    
    echo
    echo "================================================================================"
    log_success "Wiki.js installation completed successfully"
    echo
    echo "  Web Interface: http://${FQDN}/"
    echo "  Database:      ${DBNAME}"
    echo "  User:          ${DBUSER}"
    echo "  Password:      ${db_pass}"
    echo
    echo "  Password file: /etc/wiki/.db-secret"
    echo "  View anytime:  cat /etc/wiki/.db-secret"
    echo
    echo "Next Steps:"
    echo "  1. Wait 2-5 minutes for containers to fully initialize"
    echo "  2. Navigate to the web interface URL above"
    echo "  3. Complete the on-screen setup wizard"
    echo "     - Use the database credentials shown above"
    echo
    echo "Useful Commands:"
    echo "  Check status:   docker ps"
    echo "  View logs:      docker logs wiki"
    echo "  Stop Wiki.js:   docker stop wiki db wiki-update-companion"
    echo "  Start Wiki.js:  docker start db wiki wiki-update-companion"
    echo "================================================================================"
    echo
}

############################### MAIN SCRIPT ####################################

require_root

echo
echo -e "${BOLD}Wiki.js Installation for Ubuntu 24.04 LTS${RESET}"
echo "============================================================"
echo

check_ubuntu_version

if ! prompt_yes_no "Do you want to proceed with the installation?"; then
    log_info "Installation cancelled"
    exit 0
fi

echo
log_step "Starting Wiki.js installation"
echo

update_system
install_docker
read_database_config
read_fqdn_config
setup_containers
start_containers
show_completion
