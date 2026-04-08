FROM python:3.13-slim AS builder
WORKDIR /build
COPY alert_manager/requirements.txt /build/requirements.txt
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim
WORKDIR /app
COPY --from=builder /install /usr/local
COPY alert_manager/ /app/alert_manager/
COPY shared/ /app/shared/
RUN adduser --disabled-password --gecos "" cybernest && chown -R cybernest:cybernest /app
USER cybernest
ENV PYTHONPATH=/app
CMD ["python", "-m", "alert_manager.main"]
