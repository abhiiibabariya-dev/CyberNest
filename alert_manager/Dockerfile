FROM python:3.13-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim
WORKDIR /app
COPY --from=builder /install /usr/local
COPY . /app/alert_manager/
COPY shared/ /app/shared/
RUN adduser --disabled-password --gecos "" cybernest && chown -R cybernest:cybernest /app
USER cybernest
ENV PYTHONPATH=/app
CMD ["python", "-m", "alert_manager.main"]
