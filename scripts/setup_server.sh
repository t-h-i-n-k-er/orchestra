#!/bin/bash
set -euo pipefail

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or with sudo"
  exit 1
fi

echo "=== Orchestra Server Setup ==="

# 1. Install System Dependencies
echo "[1/7] Installing dependencies..."
apt-get update
# Non-interactive apt install
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    cargo \
    pkg-config \
    libssl-dev \
    postgresql \
    postgresql-contrib \
    nginx \
    openssl \
    curl

# Setup config storage for idempotency
CONF_DIR="/etc/orchestra"
ENV_FILE="$CONF_DIR/orchestra.env"
KEYS_DIR="$CONF_DIR/certs"
mkdir -p "$KEYS_DIR"

if [ -f "$ENV_FILE" ]; then
    echo "Loading existing configuration from $ENV_FILE"
    source "$ENV_FILE"
else
    echo "Generating new database and admin credentials..."
    DB_USER="orchestra"
    # shellcheck disable=SC2006
    DB_PASS="orchestra_db_pass_$(openssl rand -hex 6)"
    DB_NAME="orchestra"
    ADMIN_USER="admin"
    ADMIN_PASS=${ORCHESTRA_ADMIN_PASSWORD:-$(openssl rand -base64 16)}

    cat > "$ENV_FILE" <<EOF
DB_USER="$DB_USER"
DB_PASS="$DB_PASS"
DB_NAME="$DB_NAME"
ADMIN_USER="$ADMIN_USER"
ADMIN_PASS="$ADMIN_PASS"
EOF
    chmod 600 "$ENV_FILE"
fi

# 2. Setup PostgreSQL
echo "[2/7] Configuring PostgreSQL..."
systemctl enable --now postgresql

# Create user and db if they don't exist
sudo -u postgres psql -tc "SELECT 1 FROM pg_user WHERE usename = '$DB_USER'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"

# Ensure password is correct if user already existed
sudo -u postgres psql -c "ALTER USER $DB_USER WITH PASSWORD '$DB_PASS';"

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

echo "Running migrations..."
# No-op since Orchestra stores data internally or handles db explicitly
echo "No external PostgreSQL migrations required at this time."

# 3. Generate TLS Certificates
echo "[3/7] Generating self-signed TLS certificates..."
if [ ! -f "$KEYS_DIR/server.key" ] || [ ! -f "$KEYS_DIR/server.crt" ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEYS_DIR/server.key" \
        -out "$KEYS_DIR/server.crt" \
        -subj "/C=US/ST=State/L=City/O=Orchestra/CN=localhost"
    chmod 600 "$KEYS_DIR/server.key"
    echo "Certificates generated."
else
    echo "Certificates already exist, skipping."
fi

# 4. Compile the Server Binary
echo "[4/7] Compiling orchestra-server..."
# Navigate to the workspace root relative to this script
cd "$(dirname "$0")/.."
cargo build --release -p orchestra-server
cp target/release/orchestra-server /usr/local/bin/

# Prepare static files
mkdir -p /var/lib/orchestra/static
if [ -d "orchestra-server/static" ]; then
    cp -r orchestra-server/static/* /var/lib/orchestra/static/
fi

# 5. Initialize Administrator Account
echo "[5/7] Initializing default admin..."
echo "====================================================="
echo "ADMINISTRATOR ACCOUNT"
echo "Username: $ADMIN_USER"
echo "Password: $ADMIN_PASS"
echo "If this is the first run, ensure to save this password!"
echo "====================================================="

# 6. Create Systemd Service
echo "[6/7] Creating systemd service..."
cat > /etc/systemd/system/orchestra-server.service <<EOF
[Unit]
Description=Orchestra Management Server
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/orchestra
Environment="DATABASE_URL=postgres://$DB_USER:$DB_PASS@localhost/$DB_NAME"
Environment="TLS_CERT=$KEYS_DIR/server.crt"
Environment="TLS_KEY=$KEYS_DIR/server.key"
Environment="ORCHESTRA_INIT_ADMIN_USER=$ADMIN_USER"
Environment="ORCHESTRA_INIT_ADMIN_PASS=$ADMIN_PASS"
Environment="BIND_ADDR=127.0.0.1:8080"
ExecStart=/usr/local/bin/orchestra-server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable orchestra-server
systemctl restart orchestra-server

# 7. Configure Nginx
echo "[7/7] Configuring Nginx reverse proxy..."

cat > /etc/nginx/sites-available/orchestra <<EOF
server {
    listen 80;
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name _;

    ssl_certificate $KEYS_DIR/server.crt;
    ssl_certificate_key $KEYS_DIR/server.key;

    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

# Enable site and remove default
ln -sf /etc/nginx/sites-available/orchestra /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

systemctl restart nginx

echo "=== Setup Complete! ==="
echo "Orchestra server is running behind Nginx. Access it via https://<server-ip>/"
