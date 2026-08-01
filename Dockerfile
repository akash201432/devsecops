FROM python:3.12-alpine

WORKDIR /app

# Create non-root appuser with explicit UID 10001 (matching k8s spec)
# and create writable directories for SQLite and Gunicorn temporary files
RUN addgroup -g 10001 appuser && \
    adduser -u 10001 -G appuser -D -s /sbin/nologin appuser && \
    mkdir -p /app /tmp/.gunicorn && \
    chown -R appuser:appuser /app /tmp/.gunicorn

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY --chown=appuser:appuser app.py ./

USER 10001

EXPOSE 8000

# Tell Gunicorn to use /tmp for its runtime sockets/files
CMD ["gunicorn", "--worker-tmp-dir", "/tmp", "--bind", "0.0.0.0:8000", "--workers", "2", "app:app"]