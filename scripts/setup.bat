@echo off
REM =============================================================================
REM CyberNest SIEM + SOAR Platform — Setup Script (Windows)
REM =============================================================================
setlocal enabledelayedexpansion

echo.
echo   ======================================
echo     CyberNest Setup (Windows)
echo   ======================================
echo.

REM Check Docker
where docker >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is required but not found.
    echo         Install Docker Desktop: https://docker.com/products/docker-desktop
    exit /b 1
)
echo [OK]   Docker found

REM Check Docker Compose
docker compose version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker Compose is required but not found.
    exit /b 1
)
echo [OK]   Docker Compose found

REM Copy .env if needed
if not exist .env (
    if exist .env.example (
        copy .env.example .env >nul
        echo [OK]   Created .env from .env.example
    )
) else (
    echo [OK]   .env already exists
)

REM Stop existing containers
echo [INFO] Stopping existing containers...
docker compose down --remove-orphans >nul 2>&1

REM Start infrastructure
echo [INFO] Starting infrastructure services...
docker compose up -d zookeeper kafka elasticsearch redis postgres

REM Wait for services
echo [INFO] Waiting for services to start...
:wait_pg
docker exec cybernest-postgres pg_isready -U cybernest >nul 2>&1
if %errorlevel% neq 0 (
    timeout /t 2 /nobreak >nul
    goto wait_pg
)
echo [OK]   PostgreSQL ready

:wait_es
curl -sf http://localhost:9200/_cluster/health >nul 2>&1
if %errorlevel% neq 0 (
    timeout /t 2 /nobreak >nul
    goto wait_es
)
echo [OK]   Elasticsearch ready

:wait_kafka
docker exec cybernest-kafka kafka-broker-api-versions --bootstrap-server localhost:9092 >nul 2>&1
if %errorlevel% neq 0 (
    timeout /t 2 /nobreak >nul
    goto wait_kafka
)
echo [OK]   Kafka ready

REM Create topics
echo [INFO] Creating Kafka topics...
docker compose up kafka-init >nul 2>&1
echo [OK]   Kafka topics created

REM Build and start all
echo [INFO] Building service images...
docker compose build
echo [INFO] Starting all services...
docker compose up -d

REM Wait for manager
echo [INFO] Waiting for CyberNest Manager...
:wait_manager
curl -sf http://localhost:5000/health >nul 2>&1
if %errorlevel% neq 0 (
    timeout /t 3 /nobreak >nul
    goto wait_manager
)
echo [OK]   Manager API ready

echo.
echo   ======================================
echo     CyberNest is running!
echo   ======================================
echo.
echo   Dashboard:  http://localhost
echo   API Docs:   http://localhost/docs
echo.
echo   Login:      admin / CyberNest@2025!
echo.
echo   ======================================
echo.
pause
