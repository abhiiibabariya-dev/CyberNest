#!/bin/bash
# ═══════════════════════════════════════════════════════════
# CyberNest — Full Setup Script
# Installs dependencies, generates certs, starts all services
# ═══════════════════════════════════════════════════════════

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════╗"
echo "║             CyberNest Setup Script                   ║"
echo "║     Enterprise SIEM + SOAR Platform                  ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker not found. Please install Docker first.${NC}"
    exit 1
fi
if ! command -v docker compose &> /dev/null && ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Docker Compose not found. Please install Docker Compose.${NC}"
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

# Create required directories
echo -e "${CYAN}[1/6] Creating directories...${NC}"
mkdir -p deploy/nginx/ssl data/{es,pg,redis,kafka,zk} logs

# Generate self-signed SSL certificates for development
echo -e "${CYAN}[2/6] Generating SSL certificates...${NC}"
if [ ! -f deploy/nginx/ssl/cybernest.crt ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout deploy/nginx/ssl/cybernest.key \
        -out deploy/nginx/ssl/cybernest.crt \
        -subj "/C=US/ST=Security/L=SOC/O=CyberNest/CN=localhost" \
        2>/dev/null
    echo -e "${GREEN}  ✓ SSL certificates generated${NC}"
else
    echo -e "${GREEN}  ✓ SSL certificates already exist${NC}"
fi

# Create .env file if not exists
echo -e "${CYAN}[3/6] Creating environment file...${NC}"
if [ ! -f deploy/.env ]; then
    cat > deploy/.env << 'ENVEOF'
POSTGRES_PASSWORD=CyberNest_DB_2025
JWT_SECRET=cybernest_jwt_secret_change_me_in_production_minimum_64_characters
LOG_LEVEL=INFO
SMTP_HOST=
SLACK_WEBHOOK=
PAGERDUTY_KEY=
VT_API_KEY=
ABUSEIPDB_KEY=
SHODAN_KEY=
OTX_API_KEY=
ENVEOF
    echo -e "${GREEN}  ✓ .env file created${NC}"
fi

# Pull Docker images
echo -e "${CYAN}[4/6] Pulling Docker images...${NC}"
cd deploy
docker compose pull 2>/dev/null || true

# Start infrastructure first
echo -e "${CYAN}[5/6] Starting infrastructure services...${NC}"
docker compose up -d zookeeper postgres redis elasticsearch
echo "Waiting for services to be healthy..."
sleep 15

# Start Kafka (needs Zookeeper)
docker compose up -d kafka
sleep 10

# Create Kafka topics
docker compose up kafka-init
sleep 5

# Start CyberNest services
echo -e "${CYAN}[6/6] Starting CyberNest services...${NC}"
docker compose up -d

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         CyberNest is Starting Up!                    ║${NC}"
echo -e "${GREEN}╠═══════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║ Dashboard:    https://localhost                      ║${NC}"
echo -e "${GREEN}║ API Docs:     http://localhost:5000/docs             ║${NC}"
echo -e "${GREEN}║ Kibana:       http://localhost:9200                  ║${NC}"
echo -e "${GREEN}║                                                     ║${NC}"
echo -e "${GREEN}║ Default Login: admin / CyberNest@2025!              ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Run 'docker compose -f deploy/docker-compose.yml logs -f' to see logs"
