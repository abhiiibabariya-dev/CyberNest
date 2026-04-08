@echo off
REM =============================================================================
REM CyberNest SIEM + SOAR Platform - Setup Script (Windows)
REM =============================================================================
REM Uses Docker Compose v2 syntax (docker compose).
REM Requires Docker Desktop for Windows.
REM
REM Usage: scripts\setup.bat
REM =============================================================================

setlocal enabledelayedexpansion

cd /d "%~dp0\.."

echo.
echo ============================================================
echo   CyberNest SIEM + SOAR Platform - Windows Setup
echo ============================================================
echo.

REM ---------- Prerequisites ----------

echo [1/10] Checking prerequisites...

docker --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker is not installed.
    echo         Download from https://docs.docker.com/desktop/install/windows-install/
    exit /b 1
)
for /f "tokens=*" %%i in ('docker --version') do echo [OK]    %%i

docker compose version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker Compose v2 not found.
    echo         Update Docker Desktop or install the compose plugin.
    exit /b 1
)
for /f "tokens=*" %%i in ('docker compose version') do echo [OK]    %%i

docker info >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker daemon is not running. Start Docker Desktop.
    exit /b 1
)
echo [OK]    Docker daemon is running

REM ---------- Environment file ----------

echo.
echo [2/10] Preparing environment...

if not exist ".env" (
    if exist ".env.example" (
        copy .env.example .env >nul
        echo [INFO]  Created .env from .env.example
    ) else (
        echo [WARN]  .env.example not found - continuing without .env
    )
) else (
    echo [INFO]  .env already exists, keeping current values
)

REM ---------- Certificates ----------

echo.
echo [3/10] Checking TLS certificates...

if exist "deploy\certs\server.crt" (
    echo [INFO]  Certificates already exist, skipping generation
) else (
    if exist "scripts\generate-certs.sh" (
        echo [INFO]  Generating certificates via WSL or Git Bash...
        where bash >nul 2>&1
        if !ERRORLEVEL! equ 0 (
            bash scripts/generate-certs.sh
            echo [OK]    Certificates generated
        ) else (
            echo [WARN]  bash not found - create certs manually or install Git Bash
            if not exist "deploy\certs" mkdir "deploy\certs"
        )
    ) else (
        echo [WARN]  generate-certs.sh not found, skipping
        if not exist "deploy\certs" mkdir "deploy\certs"
    )
)

REM ---------- Pull images ----------

echo.
echo [4/10] Pulling Docker images...
docker compose pull 2>nul
echo [OK]    Image pull complete

REM ---------- Start infrastructure ----------

echo.
echo [5/10] Starting infrastructure services...
docker compose up -d zookeeper kafka elasticsearch redis postgres

REM ---------- Health checks ----------

echo.
echo [6/10] Waiting for infrastructure health checks...

echo   Waiting for PostgreSQL...
set /a attempts=0
:pg_check
set /a attempts+=1
if %attempts% gtr 30 (
    echo [ERROR] PostgreSQL did not become ready
    goto pg_done
)
docker exec cybernest-postgres pg_isready -U cybernest -d cybernest >nul 2>&1
if %ERRORLEVEL% neq 0 (
    timeout /t 3 /nobreak >nul
    goto pg_check
)
echo [OK]    PostgreSQL is ready
:pg_done

echo   Waiting for Redis...
set /a attempts=0
:redis_check
set /a attempts+=1
if %attempts% gtr 20 (
    echo [ERROR] Redis did not become ready
    goto redis_done
)
docker exec cybernest-redis redis-cli ping 2>nul | findstr "PONG" >nul
if %ERRORLEVEL% neq 0 (
    timeout /t 3 /nobreak >nul
    goto redis_check
)
echo [OK]    Redis is ready
:redis_done

echo   Waiting for Elasticsearch...
set /a attempts=0
:es_check
set /a attempts+=1
if %attempts% gtr 60 (
    echo [ERROR] Elasticsearch did not become ready
    goto es_done
)
curl -sf "http://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=5s" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    timeout /t 5 /nobreak >nul
    goto es_check
)
echo [OK]    Elasticsearch is ready
:es_done

echo   Waiting for Kafka...
set /a attempts=0
:kafka_check
set /a attempts+=1
if %attempts% gtr 60 (
    echo [ERROR] Kafka did not become ready
    goto kafka_done
)
docker exec cybernest-kafka kafka-broker-api-versions --bootstrap-server localhost:9092 >nul 2>&1
if %ERRORLEVEL% neq 0 (
    timeout /t 5 /nobreak >nul
    goto kafka_check
)
echo [OK]    Kafka is ready
:kafka_done

REM ---------- Kafka topics ----------

echo.
echo [7/10] Creating Kafka topics...
docker compose up kafka-init
echo [OK]    Kafka topics created

REM ---------- Seed database ----------

echo.
echo [8/10] Seeding database...

where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    if exist "scripts\seed-rules.py" (
        python scripts\seed-rules.py
        if %ERRORLEVEL% neq 0 (
            echo [WARN]  Seed script returned non-zero (DB may already be seeded)
        )
    ) else (
        echo [INFO]  No seed script found, relying on init.sql defaults
    )
) else (
    echo [WARN]  Python not found - seeding handled by init.sql defaults
)

REM ---------- Start all services ----------

echo.
echo [9/10] Starting all CyberNest services...
docker compose up -d
timeout /t 10 /nobreak >nul

REM ---------- Verify ----------

echo.
echo [10/10] Verifying services...

for %%s in (
    cybernest-manager
    cybernest-parser
    cybernest-correlator
    cybernest-alert-manager
    cybernest-soar
    cybernest-indexer
    cybernest-threat-intel
    cybernest-dashboard
    cybernest-nginx
) do (
    for /f "tokens=*" %%r in ('docker inspect --format "{{.State.Status}}" %%s 2^>nul') do (
        if "%%r"=="running" (
            echo [OK]    %%s is running
        ) else (
            echo [WARN]  %%s status: %%r
        )
    )
)

REM ---------- Summary ----------

echo.
echo ============================================================
echo   CyberNest SIEM + SOAR Platform - Setup Complete!
echo ============================================================
echo.
echo   Dashboard:        http://localhost
echo   API Docs:         http://localhost/api/docs
echo   Manager API:      http://localhost:5000/api
echo   Elasticsearch:    http://localhost:9200
echo.
echo   Default Credentials:
echo     Username:  admin
echo     Password:  CyberNest@2025!
echo.
echo   Useful commands:
echo     docker compose ps          - Service status
echo     docker compose logs -f     - Follow logs
echo     docker compose down        - Stop all services
echo     docker compose down -v     - Stop and remove volumes
echo.

endlocal
