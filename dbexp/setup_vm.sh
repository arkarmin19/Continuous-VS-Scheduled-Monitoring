#!/usr/bin/env bash

#
#   SITE_URL=http://<vm-public-ip> bash setup_vm.sh
#
# Run from the dbexp/ directory as a normal user with sudo. Takes ~5-10 minutes.
set -euo pipefail

SITE_URL="${SITE_URL:?Set SITE_URL, e.g. SITE_URL=http://203.0.113.10}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ME="$(id -un)"
WP_DIR=/var/www/html
DB_NAME=wordpress; DB_USER=wpuser
DB_PASS="$(openssl rand -hex 12)"
ADMIN_PASS="$(openssl rand -hex 10)"
USERS_PASS="$(openssl rand -hex 10)"

echo "==> Swap (free-tier VMs have 1 GB RAM)"
if ! swapon --show | grep -q .; then
  sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
  sudo mkswap /swapfile && sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
fi

echo "==> Packages"
sudo apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  apache2 mariadb-server php php-mysql php-curl php-xml php-mbstring php-zip php-gd \
  libapache2-mod-php python3-venv python3-pip curl unzip openssl

echo "==> Database"
sudo systemctl enable --now mariadb apache2
sudo mysql -e "CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4;
  CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
  GRANT ALL ON ${DB_NAME}.* TO '${DB_USER}'@'localhost'; FLUSH PRIVILEGES;"

echo "==> WP-CLI + WordPress"
sudo curl -sSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp
sudo chmod +x /usr/local/bin/wp
sudo rm -f "${WP_DIR}/index.html"
sudo chown -R www-data:www-data "${WP_DIR}"
WP="sudo -u www-data env WP_CLI_CACHE_DIR=/tmp/wpcli-cache wp --path=${WP_DIR}"
$WP core download
$WP config create --dbname="${DB_NAME}" --dbuser="${DB_USER}" --dbpass="${DB_PASS}" --dbhost=localhost
$WP core install --url="${SITE_URL}" --title="DB Anomaly Lab" --admin_user=admin \
  --admin_password="${ADMIN_PASS}" --admin_email=admin@example.invalid --skip-email
# 'local' environment lets REST application passwords work over plain HTTP (lab only)
$WP config set WP_ENVIRONMENT_TYPE local

echo "==> Typical plugins and accounts"
$WP plugin install contact-form-7 wordpress-seo --activate
$WP user create editor1     editor1@example.invalid     --role=editor     --user_pass="${USERS_PASS}"
$WP user create author1     author1@example.invalid     --role=author     --user_pass="${USERS_PASS}"
$WP user create subscriber1 subscriber1@example.invalid --role=subscriber --user_pass="${USERS_PASS}"

echo "==> URL rewriting (post-name permalinks and /wp-json/ REST addresses)"
sudo a2enmod rewrite
# Ubuntu's default config ignores .htaccess under /var/www; allow it for WordPress
sudo tee /etc/apache2/conf-available/dbexp-wordpress.conf >/dev/null <<'CONF'
<Directory /var/www/html>
    AllowOverride All
</Directory>
CONF
sudo a2enconf dbexp-wordpress
$WP rewrite structure '/%postname%/'
sudo tee "${WP_DIR}/.htaccess" >/dev/null <<'HTACCESS'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
HTACCESS
sudo chown www-data:www-data "${WP_DIR}/.htaccess"
sudo systemctl restart apache2

# fail early if the REST API is still unreachable (this caused the 404s in the pilot round)
code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost/wp-json/)
if [ "$code" != "200" ]; then
  echo "ERROR: http://localhost/wp-json/ returned HTTP $code - URL rewriting is not working." >&2
  exit 1
fi

echo "==> Directories, logger mu-plugin, vulnerable lab plugin"
sudo install -d -o www-data -g www-data -m 0775 /var/log/dbexp
sudo install -d -o "${ME}" -g "${ME}" /var/lib/dbexp /opt/dbexp
sudo install -d -o www-data -g www-data "${WP_DIR}/wp-content/mu-plugins"
sudo cp "${HERE}/wordpress/mu-plugins/dbexp-logger.php" "${WP_DIR}/wp-content/mu-plugins/"
sudo cp -r "${HERE}/wordpress/plugins/dbexp-lab-vulnerable" "${WP_DIR}/wp-content/plugins/"
sudo chown -R www-data:www-data "${WP_DIR}/wp-content"
$WP plugin activate dbexp-lab-vulnerable

echo "==> Python detector"
cp "${HERE}"/detector/*.py "${HERE}/requirements.txt" /opt/dbexp/
python3 -m venv /opt/dbexp/venv
/opt/dbexp/venv/bin/pip install -q -r /opt/dbexp/requirements.txt

echo "==> Application password for the workload generator"
APP_PW="$($WP user application-password create admin dbexp --porcelain)"
cat > /opt/dbexp/lab.env <<EOF
export WP_URL=${SITE_URL}
export WP_ADMIN_USER=admin
export WP_ADMIN_APP_PW="${APP_PW}"
EOF
chmod 600 /opt/dbexp/lab.env

cat <<EOF

Done.
  Site        : ${SITE_URL}          admin / ${ADMIN_PASS}
  Other users : editor1, author1, subscriber1  (password ${USERS_PASS})
  Detector    : /opt/dbexp   (source /opt/dbexp/lab.env; /opt/dbexp/venv/bin/python detector.py ...)

REMINDER: the lab plugin is deliberately injectable. In your cloud firewall / security list,
allow inbound port 80 ONLY from your own IP while experiments run.
EOF
