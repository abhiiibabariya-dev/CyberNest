FROM python:3.13-slim

# System dependencies for asyncpg and bcrypt
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r cybernest && useradd -r -g cybernest -d /app -s /sbin/nologin cybernest

WORKDIR /app

# Install Python dependencies
COPY manager/requirements.txt /app/manager/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/manager/requirements.txt

# Copy shared utilities and manager code
COPY shared/ /app/shared/
COPY manager/ /app/manager/

# Create data directories
RUN mkdir -p /data/attachments && chown -R cybernest:cybernest /data

# Set Python path so shared module is importable
ENV PYTHONPATH="/app"
ENV PYTHONUNBUFFERED=1

# Switch to non-root user
USER cybernest

EXPOSE 5000 5601 514/udp 601

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

CMD ["uvicorn", "manager.main:app", \
     "--host", "0.0.0.0", \
     "--port", "5000", \
     "--workers", "4", \
     "--log-level", "info", \
     "--access-log", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
