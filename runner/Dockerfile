# AIVeritX sandbox runner: standard library only, runs without network and with a read-only filesystem (see docker-compose.yml).
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN mkdir -p /jobs/in /jobs/out && chmod 777 /jobs /jobs/in /jobs/out
COPY runner.py /opt/runner.py
USER 65534:65534
CMD ["python", "/opt/runner.py"]
