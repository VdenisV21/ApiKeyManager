FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uvicorn[standard] fastapi httpx pydantic

COPY config.py server.py ./
COPY core/ ./core/
COPY routes/ ./routes/

RUN mkdir -p /app/data && \
    useradd -m appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]