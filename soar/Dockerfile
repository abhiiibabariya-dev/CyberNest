FROM python:3.13-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim
WORKDIR /app

COPY --from=builder /install /usr/local
COPY . /app/soar/
COPY ../shared /app/shared/
COPY ../config/playbooks /app/config/playbooks/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SOAR_PLAYBOOK_DIR=/app/config/playbooks

RUN adduser --disabled-password --gecos "" cybernest && \
    chown -R cybernest:cybernest /app
USER cybernest

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import asyncio, aiohttp; asyncio.run(aiohttp.ClientSession().close())" || exit 1

CMD ["python", "-m", "soar.consumer"]
