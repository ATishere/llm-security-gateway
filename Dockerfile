FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[pii]" \
    && python -m spacy download en_core_web_lg

EXPOSE 8000
ENV GATEWAY_PII_BACKEND=presidio
USER 10001
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
