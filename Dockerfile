FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SPAMFIGHTER_DATA_DIR=/data \
    SPAMFIGHTER_CONFIG_PATH=/data/config.toml \
    SPAMFIGHTER_SPAM_RULES_PATH=/data/spam_rules.toml \
    SPAMFIGHTER_SPAM_RULES_HISTORY_DIR=/data/spam_rules_history \
    SPAMFIGHTER_RULE_REPORTS_PATH=/data/rule_review_reports.json \
    SPAMFIGHTER_AI_USAGE_PATH=/data/ai_review_usage.json \
    SPAMFIGHTER_STATE_DB_PATH=/data/spamfighter_state.sqlite3 \
    SPAMFIGHTER_HEALTHCHECK_HOST=0.0.0.0 \
    SPAMFIGHTER_HEALTHCHECK_PORT=8080 \
    SPAMFIGHTER_INSTANCE_ROLE=auto

RUN groupadd --system spamfighter \
    && useradd --system --gid spamfighter --create-home --home-dir /home/spamfighter spamfighter \
    && mkdir -p /app /data \
    && chown -R spamfighter:spamfighter /app /data

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

COPY SpamFighter.py /app/SpamFighter.py

USER spamfighter

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 CMD python -c "import json,sys,urllib.request; response=urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=3); payload=json.load(response); sys.exit(0 if payload.get('ready') else 1)"

CMD ["python", "SpamFighter.py"]
