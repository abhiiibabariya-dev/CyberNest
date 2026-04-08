FROM python:3.13-slim AS builder
WORKDIR /build
COPY threat_intel/requirements.txt /build/requirements.txt
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim

LABEL maintainer="CyberNest" \
      service="threat_intel"

WORKDIR /app

COPY --from=builder /install /usr/local
COPY threat_intel/ /app/threat_intel/
COPY shared/ /app/shared/

RUN adduser --disabled-password --gecos "" cybernest \
    && chown -R cybernest:cybernest /app

USER cybernest

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

EXPOSE 8084

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8084/health')" || exit 1

CMD ["python", "-m", "threat_intel.main"]
