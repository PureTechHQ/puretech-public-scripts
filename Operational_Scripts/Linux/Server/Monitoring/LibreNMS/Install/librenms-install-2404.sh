#!/usr/bin/env bash
################################################################################
# Script Name  : librenms-install-2404.sh
# Description  : Interactive installer for LibreNMS on Ubuntu 24.04 LTS.
#
# Author        : John Harrison
# Created       : 2026-01-10
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
#   2026-01-10  1.0.0  - Initial release
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

php_set_timezone() {
    local tz="$1"
    log_step "Setting PHP timezone to ${tz}"
    
    for vdir in /etc/php/*; do
        [[ -d "$vdir" ]] || continue
        for sapi in fpm cli; do
            local tzdir="$vdir/$sapi/conf.d"
            local tzfile="$tzdir/99-timezone.ini"
            if [[ -d "$tzdir" ]]; then
                echo "date.timezone = $tz" > "$tzfile"
                log_info "Configured $tzfile"
            fi
        done
    done
    
    systemctl list-units --type=service --all | awk '/php.*fpm\.service/ {print $1}' | xargs -r systemctl restart
}

validate_mysql_identifier() {
    local s="$1"
    [[ "$s" =~ ^[A-Za-z0-9_]{1,63}$ ]]
}

read_mysql_identifiers() {
    local def_db="librenms" def_user="librenms"
    
    echo
    log_step "MariaDB Configuration"
    echo
    
    while :; do
        read -r -p "Enter database name [${def_db}]: " DBNAME
        DBNAME="${DBNAME:-$def_db}"
        if validate_mysql_identifier "$DBNAME"; then
            break
        else
            log_warn "Invalid name. Use 1-63 alphanumeric characters or underscore."
        fi
    done
    
    echo
    while :; do
        read -r -p "Enter database username [${def_user}]: " DBUSER
        DBUSER="${DBUSER:-$def_user}"
        if validate_mysql_identifier "$DBUSER"; then
            break
        else
            log_warn "Invalid username. Use 1-63 alphanumeric characters or underscore."
        fi
    done
    
    echo
    while :; do
        read -r -s -p "Enter database password: " DBPASS
        echo
        [[ -n "$DBPASS" ]] && break || log_warn "Password cannot be empty."
    done
    
    export DBNAME DBUSER DBPASS
}

strip_ipv6_listens() {
    for file in /etc/nginx/sites-available/default /etc/nginx/sites-enabled/*.conf /etc/nginx/conf.d/*.conf; do
        [[ -e "$file" ]] || continue
        sed -i '/listen \[::\]/d' "$file" 2>/dev/null || true
    done
}

cleanup_policy_rc_d() {
    if [[ "$POLICY_RC_D_CREATED" -eq 1 && -f /usr/sbin/policy-rc.d ]]; then
        rm -f /usr/sbin/policy-rc.d
        log_info "Removed temporary policy-rc.d"
    fi
}

############################### MAIN SCRIPT ####################################

require_root

echo
echo -e "${BOLD}LibreNMS Installation for Ubuntu 24.04 LTS${RESET}"
echo "============================================================"
echo

POLICY_RC_D_CREATED=0
trap cleanup_policy_rc_d EXIT

if [[ ! -f /usr/sbin/policy-rc.d ]]; then
    log_step "Creating temporary policy-rc.d to prevent service auto-start"
    cat > /usr/sbin/policy-rc.d <<'EOP'
#!/bin/sh
exit 101
EOP
    chmod +x /usr/sbin/policy-rc.d
    POLICY_RC_D_CREATED=1
fi

# System timezone configuration
if ! prompt_yes_no "Has the system timezone already been configured?"; then
    log_info "Available timezones (press 'q' to exit):"
    sleep 1
    timedatectl list-timezones | less
    echo
    read -r -p "Enter timezone (e.g., America/Chicago): " TZ
    timedatectl set-timezone "$TZ"
fi

TZ=$(timedatectl show -p Timezone --value)
log_success "System timezone: ${TZ}"

# System updates and package installation
log_step "Updating package repositories"
apt update -o Acquire::Check-Valid-Until=false

log_step "Upgrading installed packages"
apt -y upgrade -o Acquire::Check-Valid-Until=false

log_step "Installing required packages"
apt -y install software-properties-common
add-apt-repository -y universe

apt -y install \
    acl curl fping git graphviz imagemagick mariadb-client mariadb-server \
    mtr-tiny nginx-full nmap php-cli php-curl php-fpm php-gd php-gmp php-json \
    php-mbstring php-mysql php-snmp php-xml php-zip rrdtool snmp snmpd unzip \
    python3-command-runner python3-pymysql python3-dotenv python3-redis \
    python3-setuptools python3-psutil python3-systemd python3-pip whois traceroute

# Configure fping capabilities
log_step "Configuring network capabilities for fping"
for cmd in fping fping6; do
    if command -v "$cmd" >/dev/null 2>&1; then
        setcap cap_net_raw+ep "$(command -v $cmd)" || log_warn "Failed to set capabilities for $cmd"
    fi
done
getcap /usr/bin/fping /usr/bin/fping6 2>/dev/null || true

cleanup_policy_rc_d
POLICY_RC_D_CREATED=0

# LibreNMS user and repository setup
log_step "Creating LibreNMS system user"
if ! id -u librenms >/dev/null 2>&1; then
    useradd librenms -d /opt/librenms -M -r -s "$(command -v bash)"
    log_success "User 'librenms' created"
else
    log_info "User 'librenms' already exists"
fi

log_step "Installing LibreNMS from GitHub"
if [[ ! -d /opt/librenms/.git ]]; then
    rm -rf /opt/librenms
    log_info "Cloning repository..."
    git clone https://github.com/librenms/librenms.git /opt/librenms
else
    log_info "LibreNMS repository already exists"
fi

chown -R librenms:librenms /opt/librenms
chmod 771 /opt/librenms
setfacl -d -m g::rwx /opt/librenms/{rrd,logs,bootstrap/cache,storage} 2>/dev/null || true
setfacl -R -m g::rwx /opt/librenms/{rrd,logs,bootstrap/cache,storage} 2>/dev/null || true

log_step "Installing PHP dependencies"
su - librenms -c 'cd /opt/librenms && ./scripts/composer_wrapper.php install --no-dev'

# Ensure proper permissions on all directories
chown -R librenms:librenms /opt/librenms
chmod 771 /opt/librenms
setfacl -d -m g::rwx /opt/librenms/{rrd,logs,bootstrap/cache,storage} 2>/dev/null || true
setfacl -R -m g::rwx /opt/librenms/{rrd,logs,bootstrap/cache,storage} 2>/dev/null || true

php_set_timezone "$TZ"

# MariaDB configuration
log_step "Configuring MariaDB"
systemctl enable --now mariadb

mariadb_cfg="/etc/mysql/mariadb.conf.d/50-server.cnf"

if ! grep -q '^\[mysqld\]' "$mariadb_cfg" 2>/dev/null; then
    echo "[mysqld]" >> "$mariadb_cfg"
fi

grep -q '^innodb_file_per_table' "$mariadb_cfg" 2>/dev/null || echo "innodb_file_per_table=1" >> "$mariadb_cfg"
grep -q '^lower_case_table_names' "$mariadb_cfg" 2>/dev/null || echo "lower_case_table_names=0" >> "$mariadb_cfg"

if grep -q '^default_time_zone' "$mariadb_cfg" 2>/dev/null; then
    sed -i "s|^[#[:space:]]*default_time_zone.*|default_time_zone=SYSTEM|" "$mariadb_cfg"
else
    echo "default_time_zone=SYSTEM" >> "$mariadb_cfg"
fi

systemctl restart mariadb
mysql -uroot -e "SET GLOBAL time_zone = 'SYSTEM';" 2>/dev/null || log_warn "Could not set global timezone"

if command -v mysql_tzinfo_to_sql >/dev/null; then
    mysql_tzinfo_to_sql /usr/share/zoneinfo 2>/dev/null | mysql -uroot mysql 2>/dev/null || log_warn "Timezone data may already be loaded"
fi

read_mysql_identifiers

log_step "Creating database and user"
mysql -uroot <<SQL
CREATE DATABASE IF NOT EXISTS \`${DBNAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DBUSER}'@'localhost' IDENTIFIED BY '${DBPASS}';
ALTER USER '${DBUSER}'@'localhost' IDENTIFIED BY '${DBPASS}';
GRANT ALL PRIVILEGES ON \`${DBNAME}\`.* TO '${DBUSER}'@'localhost';
FLUSH PRIVILEGES;
SQL

# RRDCached configuration
log_step "Configuring RRDCached"
apt -y install rrdcached

mkdir -p /var/run/rrdcached
chown librenms:librenms /var/run/rrdcached

cat > /etc/default/rrdcached <<'EOF'
DAEMON=/usr/bin/rrdcached
OPTS="-s librenms -m 0660 -l unix:/var/run/rrdcached/rrdcached.sock \
      -w 1800 -z 1800 -t 4 -f 3600 -b /opt/librenms/rrd/"
EOF

systemctl enable --now rrdcached
systemctl restart rrdcached

if [[ -S /var/run/rrdcached/rrdcached.sock ]]; then
    chown librenms:librenms /var/run/rrdcached/rrdcached.sock
    chmod 660 /var/run/rrdcached/rrdcached.sock
fi

cat > /etc/tmpfiles.d/rrdcached.conf <<'EOF'
d /var/run/rrdcached 0755 librenms librenms -
EOF

sudo -u librenms lnms config:set rrdcached unix:/var/run/rrdcached/rrdcached.sock >/dev/null 2>&1 \
    && log_success "LibreNMS rrdcached setting applied" \
    || log_warn "Could not apply LibreNMS rrdcached setting (will be set during web install)"

log_success "RRDCached configured"

# PHP-FPM configuration
log_step "Configuring PHP-FPM"
pool_src="/etc/php/8.3/fpm/pool.d/www.conf"
pool_dst="/etc/php/8.3/fpm/pool.d/librenms.conf"

if [[ ! -f "$pool_dst" ]]; then
    cp "$pool_src" "$pool_dst"
fi

sed -i 's/^\[\s*www\s*\]/[librenms]/' "$pool_dst"
sed -i 's/^user\s*=.*/user = librenms/' "$pool_dst"
sed -i 's/^group\s*=.*/group = librenms/' "$pool_dst"
sed -i 's|^listen\s*=.*|listen = /run/php-fpm-librenms.sock|' "$pool_dst"

systemctl restart php8.3-fpm

# NGINX configuration
echo
log_step "Web Server Configuration"
read -r -p "Enter server hostname or IP (use lowercase for FQDN, e.g., librenms.example.com): " HOSTNAME

strip_ipv6_listens
rm -f /etc/nginx/sites-enabled/default

cat > /etc/nginx/conf.d/librenms.conf <<'NGINX'
server {
    listen 80 default_server;
    server_name HOST_PLACEHOLDER;
    root /opt/librenms/html;
    index index.php;
    charset utf-8;

    gzip on;
    gzip_types text/css application/javascript text/javascript application/x-javascript image/svg+xml text/plain text/xsd text/xsl text/xml image/x-icon;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ [^/]\.php(/|$) {
        fastcgi_pass unix:/run/php-fpm-librenms.sock;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        include fastcgi.conf;
    }

    location ~ /\.(?!well-known).* {
        deny all;
    }
}
NGINX

sed -i "s/HOST_PLACEHOLDER/${HOSTNAME}/g" /etc/nginx/conf.d/librenms.conf

nginx -t || { log_error "NGINX configuration test failed"; exit 1; }
systemctl enable nginx
systemctl restart php8.3-fpm nginx

# Environment configuration
log_step "Configuring application environment"
ENV_FILE="/opt/librenms/.env"
sudo -u librenms cp -n /opt/librenms/.env.example "$ENV_FILE"

set_env_kv "$ENV_FILE" DB_HOST "localhost"
set_env_kv "$ENV_FILE" DB_PORT "3306"
set_env_kv "$ENV_FILE" DB_DATABASE "$DBNAME"
set_env_kv "$ENV_FILE" DB_USERNAME "$DBUSER"
set_env_kv "$ENV_FILE" DB_PASSWORD "$DBPASS"
set_env_kv "$ENV_FILE" DB_SOCKET "/run/mysqld/mysqld.sock"
set_env_kv "$ENV_FILE" CACHE_DRIVER "file"
set_env_kv "$ENV_FILE" SESSION_DRIVER "file"
set_env_kv "$ENV_FILE" APP_URL "http://${HOSTNAME}"

sudo -u librenms bash -lc 'cd /opt/librenms && php artisan key:generate --force && php artisan config:clear && php artisan cache:clear'
chown librenms:librenms "$ENV_FILE"
chmod 640 "$ENV_FILE"
systemctl restart php8.3-fpm || true

BASE_URL="http://${HOSTNAME}"
CFG="/opt/librenms/config.php"

if ! grep -q "base_url" "$CFG" 2>/dev/null; then
    {
        echo "<?php"
        echo "\$config['base_url'] = '${BASE_URL}';"
    } >> "$CFG"
    chown librenms:librenms "$CFG"
fi

# Also set server_name in config
if ! grep -q "own_hostname" "$CFG" 2>/dev/null; then
    echo "\$config['own_hostname'] = '${HOSTNAME}';" >> "$CFG"
    chown librenms:librenms "$CFG"
fi

sudo -u librenms /opt/librenms/lnms config:set base_url "$BASE_URL" >/dev/null 2>&1 || true
sudo -u librenms bash -lc 'cd /opt/librenms && php artisan config:clear' || true
log_success "Base URL configured: ${BASE_URL}"

# Disable IPv6 fping6 (IPv4-only)
if ! grep -q "fping6" "$CFG" 2>/dev/null; then
    echo "\$config['fping6'] = '/bin/false';" >> "$CFG"
    chown librenms:librenms "$CFG"
    log_info "IPv6 disabled"
fi

# System integration
log_step "Configuring system integration"
ln -sf /opt/librenms/lnms /usr/bin/lnms
cp -f /opt/librenms/misc/lnms-completion.bash /etc/bash_completion.d/

log_step "Configuring SNMP"
cp -f /opt/librenms/snmpd.conf.example /etc/snmp/snmpd.conf
read -r -p "Enter SNMP community string: " SNMP_COMM
sed -i "s/RANDOMSTRINGGOESHERE/${SNMP_COMM}/g" /etc/snmp/snmpd.conf

curl -fsSL -o /usr/bin/distro https://raw.githubusercontent.com/librenms/librenms-agent/master/snmp/distro
chmod +x /usr/bin/distro
systemctl enable --now snmpd

log_step "Configuring scheduled tasks"
cp -f /opt/librenms/dist/librenms.cron /etc/cron.d/librenms

# Ensure the cron file has proper format
if ! grep -q "python3" /etc/cron.d/librenms; then
    log_warn "Updating cron file format for Python 3"
fi

cp -f /opt/librenms/dist/librenms-scheduler.{service,timer} /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now librenms-scheduler.timer
cp -f /opt/librenms/misc/librenms.logrotate /etc/logrotate.d/librenms

log_success "Scheduled tasks configured"

# Timezone verification
log_step "Verifying timezone configuration"
echo "Host: $(timedatectl | awk -F': ' '/Time zone/ {print $2}')"
if command -v php >/dev/null; then
    echo "PHP CLI: $(php -r 'echo date_default_timezone_get();')"
fi

for bin in php-fpm8.3 php-fpm8.2 php-fpm; do
    if command -v "$bin" >/dev/null 2>&1; then
        tz=$("$bin" -i 2>/dev/null | awk -F'=> ' '/^Default timezone/ {print $2; exit}' || echo "")
        [[ -n "$tz" ]] && echo "PHP-FPM ($bin): $tz"
    fi
done

mysql -N -e "SHOW VARIABLES WHERE Variable_name IN ('time_zone','system_time_zone','default_time_zone');" 2>/dev/null || true

# Installation complete
echo
echo "================================================================================"
log_success "LibreNMS installation completed successfully"
echo
echo "  Web Interface: http://${HOSTNAME}/install"
echo "  Database:      ${DBNAME}"
echo "  User:          ${DBUSER}"
echo
echo "Next Steps:"
echo "  1. Navigate to the web interface URL above"
echo "  2. Complete the web-based installation wizard"
echo "  3. The database credentials are already configured"
echo "================================================================================"
echo