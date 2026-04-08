FROM python:3.13-slim AS builder
WORKDIR /build
COPY soar/requirements.txt /build/requirements.txt
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim
WORKDIR /app

COPY --from=builder /install /usr/local
COPY soar/ /app/soar/
COPY shared/ /app/shared/
COPY config/playbooks/ /app/config/playbooks/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SOAR_PLAYBOOK_DIR=/app/config/playbooks \
    PYTHONPATH=/app

RUN adduser --disabled-password --gecos "" cybernest && \
    chown -R cybernest:cybernest /app
USER cybernest

CMD ["python", "-m", "soar.consumer"]
