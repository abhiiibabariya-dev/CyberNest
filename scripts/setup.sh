#!/bin/bash
# =============================================================================
# CyberNest SIEM + SOAR Platform - Setup Script (Linux / macOS)
# =============================================================================
# Pulls images, starts infrastructure, waits for health, seeds data,
# and brings up all application services.
#
# Usage: bash scripts/setup.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# ---------- Colors ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()    { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()    { echo -e "\n${CYAN}${BOLD}==> $1${NC}"; }
log_success() { echo -e "${GREEN}${BOLD}[OK]${NC}    $1"; }

# ==========================================================================
# 1. Prerequisites
# ==========================================================================

log_step "Checking prerequisites..."

if ! command -v docker &>/dev/null; then
    log_error "Docker is not installed. Install from https://docs.docker.com/get-docker/"
    exit 1
fi
log_success "Docker found: $(docker --version)"

# Detect compose command
COMPOSE_CMD=""
if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_CMD="docker-compose"
else
    log_error "Neither 'docker compose' (v2) nor 'docker-compose' (v1) found."
    log_error "Install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi
log_success "Compose found: $($COMPOSE_CMD version 2>/dev/null || echo "$COMPOSE_CMD")"

# Check Docker daemon is running
if ! docker info &>/dev/null; then
    log_error "Docker daemon is not running. Start Docker Desktop or the Docker service."
    exit 1
fi
log_success "Docker daemon is running"

# ==========================================================================
# 2. Environment file
# ==========================================================================

log_step "Preparing environment..."

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        log_info "Created .env from .env.example"
    else
        log_warn ".env.example not found - continuing without .env"
    fi
else
    log_info ".env already exists, keeping current values"
fi

# ==========================================================================
# 3. Generate TLS certificates
# ==========================================================================

log_step "Generating TLS certificates..."

if [ -f "deploy/certs/server.crt" ] && [ -f "deploy/certs/ca.crt" ]; then
    log_info "Certificates already exist, skipping generation"
else
    if [ -f "scripts/generate-certs.sh" ]; then
        # Run non-interactively: auto-confirm overwrite
        yes y 2>/dev/null | bash scripts/generate-certs.sh || bash scripts/generate-certs.sh
        log_success "TLS certificates generated"
    else
        log_warn "scripts/generate-certs.sh not found, skipping cert generation"
        mkdir -p deploy/certs
    fi
fi

# ==========================================================================
# 4. Pull images
# ==========================================================================

log_step "Pulling Docker images..."
$COMPOSE_CMD pull --ignore-pull-failures 2>/dev/null || $COMPOSE_CMD pull || true
log_success "Image pull complete"

# ==========================================================================
# 5. Start infrastructure services
# ==========================================================================

log_step "Starting infrastructure (Zookeeper, Kafka, Elasticsearch, Redis, PostgreSQL)..."
$COMPOSE_CMD up -d zookeeper kafka elasticsearch redis postgres

# ---------- Health check helpers ----------

wait_for_service() {
    local name="$1"
    local check_cmd="$2"
    local max_attempts="${3:-60}"
    local interval="${4:-5}"
    local attempt=1

    echo -n "  Waiting for ${name}"
    while [ $attempt -le $max_attempts ]; do
        if eval "$check_cmd" &>/dev/null; then
            echo ""
            log_success "${name} is ready (attempt ${attempt}/${max_attempts})"
            return 0
        fi
        echo -n "."
        sleep "$interval"
        attempt=$((attempt + 1))
    done
    echo ""
    log_error "${name} did not become ready after $((max_attempts * interval))s"
    return 1
}

# ---------- Wait for each service ----------

log_step "Waiting for infrastructure health checks..."

wait_for_service "PostgreSQL" \
    "docker exec cybernest-postgres pg_isready -U cybernest -d cybernest" \
    30 3

wait_for_service "Redis" \
    "docker exec cybernest-redis redis-cli ping | grep -q PONG" \
    20 3

wait_for_service "Elasticsearch" \
    "curl -sf http://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=5s" \
    60 5

wait_for_service "Zookeeper" \
    "docker exec cybernest-zookeeper bash -c 'echo ruok | nc localhost 2181 | grep -q imok'" \
    30 3

wait_for_service "Kafka" \
    "docker exec cybernest-kafka kafka-broker-api-versions --bootstrap-server localhost:9092" \
    60 5

# ==========================================================================
# 6. Initialize Kafka topics
# ==========================================================================

log_step "Creating Kafka topics..."
$COMPOSE_CMD up kafka-init
log_success "Kafka topics created"

# ==========================================================================
# 7. Seed database (rules, playbooks, default users)
# ==========================================================================

log_step "Seeding database..."

if [ -f "scripts/seed-rules.py" ]; then
    if command -v python3 &>/dev/null; then
        python3 scripts/seed-rules.py || log_warn "Seed script returned non-zero (DB may already be seeded)"
    elif command -v python &>/dev/null; then
        python scripts/seed-rules.py || log_warn "Seed script returned non-zero (DB may already be seeded)"
    else
        log_warn "Python not found locally - seeding will be handled by init.sql defaults"
    fi
else
    log_info "No seed script found, relying on init.sql defaults"
fi

# ==========================================================================
# 8. Start all application services
# ==========================================================================

log_step "Starting all CyberNest services..."
$COMPOSE_CMD up -d

# Brief wait for services to initialize
sleep 10

# ==========================================================================
# 9. Verify services
# ==========================================================================

log_step "Verifying services..."

SERVICES=(
    "cybernest-manager"
    "cybernest-parser"
    "cybernest-correlator"
    "cybernest-alert-manager"
    "cybernest-soar"
    "cybernest-indexer"
    "cybernest-threat-intel"
    "cybernest-dashboard"
    "cybernest-nginx"
)

ALL_HEALTHY=true
for svc in "${SERVICES[@]}"; do
    STATUS=$(docker inspect --format='{{.State.Status}}' "$svc" 2>/dev/null || echo "not found")
    if [ "$STATUS" = "running" ]; then
        log_success "$svc is running"
    else
        log_warn "$svc status: $STATUS"
        ALL_HEALTHY=false
    fi
done

# ==========================================================================
# 10. Print summary
# ==========================================================================

echo ""
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo -e "${GREEN}${BOLD}  CyberNest SIEM + SOAR Platform - Setup Complete!${NC}"
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo ""
echo -e "  ${CYAN}Dashboard:${NC}        http://localhost"
echo -e "  ${CYAN}API Docs:${NC}         http://localhost/api/docs"
echo -e "  ${CYAN}Manager API:${NC}      http://localhost:5000/api"
echo -e "  ${CYAN}Elasticsearch:${NC}    http://localhost:9200"
echo ""
echo -e "  ${YELLOW}Default Credentials:${NC}"
echo -e "    Username:  ${BOLD}admin${NC}"
echo -e "    Password:  ${BOLD}CyberNest@2025!${NC}"
echo ""
if [ "$ALL_HEALTHY" = true ]; then
    echo -e "  ${GREEN}All services are running.${NC}"
else
    echo -e "  ${YELLOW}Some services may still be starting. Run:${NC}"
    echo -e "    $COMPOSE_CMD ps"
    echo -e "    $COMPOSE_CMD logs -f"
fi
echo ""
echo -e "  ${CYAN}Useful commands:${NC}"
echo -e "    $COMPOSE_CMD ps          # Service status"
echo -e "    $COMPOSE_CMD logs -f     # Follow logs"
echo -e "    $COMPOSE_CMD down        # Stop all services"
echo -e "    $COMPOSE_CMD down -v     # Stop and remove volumes"
echo ""
