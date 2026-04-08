FROM python:3.13-slim

LABEL maintainer="CyberNest Team"
LABEL description="CyberNest SIEM Agent"

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/cybernest-agent

# Install Python dependencies (no pywin32 in Linux container)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy agent code
COPY . .

# State directory
RUN mkdir -p /opt/cybernest-agent/data

# Default config location
ENV CYBERNEST_AGENT_CONFIG=/opt/cybernest-agent/cybernest-agent.yml

# Health check: verify the agent process is running
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import psutil; assert any('cybernest' in (p.name() or '').lower() for p in psutil.process_iter())" || exit 1

ENTRYPOINT ["python", "-m", "agent.cybernest_agent"]
CMD ["--config", "/opt/cybernest-agent/cybernest-agent.yml"]
