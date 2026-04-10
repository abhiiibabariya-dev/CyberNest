#!/bin/bash
# =============================================================================
# CyberNest SIEM + SOAR Platform — Production Setup Script
# =============================================================================
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

banner() {
cat << 'EOF'
   ______      __              _   __          __
  / ____/_  __/ /_  ___  _____/ | / /__  _____/ /_
 / /   / / / / __ \/ _ \/ ___/  |/ / _ \/ ___/ __/
/ /___/ /_/ / /_/ /  __/ /  / /|  /  __(__  ) /_
\____/\__, /_.___/\___/_/  /_/ |_/\___/____/\__/
     /____/
        SIEM + SOAR Platform
EOF
}

log_info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_dependency() {
    if ! command -v "$1" &>/dev/null; then
        log_error "$1 is required but not installed."
        exit 1
    fi
    log_ok "$1 found"
}

wait_for_service() {
    local name="$1"
    local check_cmd="$2"
    local max_attempts="${3:-60}"
    local attempt=0

    log_info "Waiting for ${name}..."
    while [ $attempt -lt $max_attempts ]; do
        if eval "$check_cmd" &>/dev/null; then
            log_ok "${name} is ready"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    log_error "${name} failed to start after $((max_attempts * 2)) seconds"
    return 1
}

# =============================================================================
banner
echo ""
log_info "Starting CyberNest setup..."
echo ""

# Check dependencies
log_info "Checking dependencies..."
check_dependency "docker"

COMPOSE_CMD="docker compose"
if ! docker compose version &>/dev/null; then
    if command -v docker-compose &>/dev/null; then
        COMPOSE_CMD="docker-compose"
        log_ok "docker-compose (v1) found"
    else
        log_error "Docker Compose is required but not found."
        exit 1
    fi
else
    log_ok "Docker Compose (v2) found"
fi

# Environment file
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        log_ok "Created .env from .env.example"
    else
        log_warn "No .env.example found, continuing with defaults"
    fi
else
    log_ok ".env already exists"
fi

# Generate TLS certificates if script exists
if [ -f scripts/generate-certs.sh ]; then
    if [ ! -d deploy/certs ] || [ ! -f deploy/certs/ca.pem ]; then
        log_info "Generating TLS certificates..."
        bash scripts/generate-certs.sh
        log_ok "TLS certificates generated"
    else
        log_ok "TLS certificates already exist"
    fi
fi

# Pull images
log_info "Pulling Docker images..."
$COMPOSE_CMD pull --ignore-pull-failures 2>/dev/null || true
log_ok "Images pulled"

# Stop existing containers
log_info "Stopping any existing containers..."
$COMPOSE_CMD down --remove-orphans 2>/dev/null || true

# Start infrastructure services first
log_info "Starting infrastructure services..."
$COMPOSE_CMD up -d zookeeper kafka elasticsearch redis postgres
echo ""

# Wait for infrastructure
wait_for_service "PostgreSQL" "docker exec cybernest-postgres pg_isready -U cybernest" 30
wait_for_service "Elasticsearch" "curl -sf http://localhost:9200/_cluster/health" 60
wait_for_service "Redis" "docker exec cybernest-redis redis-cli ping" 15
wait_for_service "Kafka" "docker exec cybernest-kafka kafka-broker-api-versions --bootstrap-server localhost:9092" 60
echo ""

# Create Kafka topics
log_info "Creating Kafka topics..."
$COMPOSE_CMD up kafka-init 2>/dev/null || true
log_ok "Kafka topics created"
echo ""

# Build application images
log_info "Building CyberNest service images..."
$COMPOSE_CMD build --parallel 2>/dev/null || $COMPOSE_CMD build
log_ok "All images built"
echo ""

# Start all services
log_info "Starting all CyberNest services..."
$COMPOSE_CMD up -d
echo ""

# Wait for application services
sleep 5
wait_for_service "CyberNest Manager API" "curl -sf http://localhost:5000/health" 60
echo ""

# Seed data if script exists
if [ -f scripts/seed-rules.py ]; then
    log_info "Seeding rules and default data..."
    python3 scripts/seed-rules.py 2>/dev/null || log_warn "Seed script failed (may need manual run)"
fi

# Show status
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo ""
$COMPOSE_CMD ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || $COMPOSE_CMD ps
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}${BOLD}  ✅ CyberNest is running!${NC}"
echo ""
echo -e "  ${CYAN}Dashboard:${NC}  http://localhost"
echo -e "  ${CYAN}API Docs:${NC}   http://localhost/docs"
echo -e "  ${CYAN}API Health:${NC} http://localhost:5000/health"
echo ""
echo -e "  ${YELLOW}Default Credentials:${NC}"
echo -e "  Username:   ${BOLD}admin${NC}"
echo -e "  Password:   ${BOLD}CyberNest@2025!${NC}"
echo ""
echo -e "  ${YELLOW}Infrastructure:${NC}"
echo -e "  Elasticsearch: http://localhost:9200"
echo -e "  Kafka:         localhost:9092"
echo -e "  PostgreSQL:    localhost:5432"
echo -e "  Redis:         localhost:6379"
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════${NC}"
