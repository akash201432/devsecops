FROM python:3.12-alpine

WORKDIR /app

# Create non-root user and setup directories
RUN addgroup -S appuser && adduser -S appuser -G appuser && \
    chown appuser:appuser /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY --chown=appuser:appuser app.py ./

USER appuser

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "app:app"]