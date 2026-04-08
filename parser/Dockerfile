FROM python:3.13-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends libxml2 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY . /app/parser/
COPY ../shared /app/shared/

RUN adduser --disabled-password --gecos "" cybernest && \
    chown -R cybernest:cybernest /app

USER cybernest

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost',8080)); s.close()" || exit 1

EXPOSE 8080

CMD ["python", "-m", "parser.consumer"]
