FROM python:3.13-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim

WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .

RUN adduser --disabled-password --gecos "" cybernest && \
    chown -R cybernest:cybernest /app
USER cybernest

EXPOSE 8000 514

HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
