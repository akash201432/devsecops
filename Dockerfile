FROM python:3.12-alpine

WORKDIR /app

# 1. Create non-root user & ensure full ownership of working directory
RUN addgroup -S appuser && adduser -S appuser -G appuser && \
    mkdir -p /app && chown -R appuser:appuser /app

# 2. Copy and install updated dependencies (including prometheus-flask-exporter)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# 3. Copy application files with proper ownership
COPY --chown=appuser:appuser app.py ./

# 4. Switch to non-root user context
USER appuser

EXPOSE 8000

# 5. Run using Gunicorn WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "app:app"]