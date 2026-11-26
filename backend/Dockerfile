# AIVeritX backend (FastAPI). Runtime dependencies only; test/dev files do not enter the image.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

# pango for WeasyPrint (PDF report); tesseract-ocr for the multimodal carrier pre-processing (OCR; optional); curl only for the healthcheck.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 fonts-dejavu-core curl tesseract-ocr \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home app \
 && mkdir -p /sandbox-jobs/in /sandbox-jobs/out && chmod 777 /sandbox-jobs /sandbox-jobs/in /sandbox-jobs/out

WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY main.py ./
COPY llm_redteam ./llm_redteam
COPY starter_kit ./starter_kit

USER app
EXPOSE 8000

# Host header 127.0.0.1: the API's Host validation (DNS-rebinding protection) allows it.
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=6 \
  CMD curl -fsS http://127.0.0.1:8000/api/auth/status >/dev/null || exit 1

CMD ["python", "-m", "uvicorn", "main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
