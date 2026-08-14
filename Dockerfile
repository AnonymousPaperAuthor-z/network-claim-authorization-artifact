FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /artifact
COPY . /artifact

CMD ["python", "scripts/run_all.py"]
