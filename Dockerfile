FROM python:3.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TOLLGATE_HOME=/data \
    TOLLGATE_FEEDS=/config/feeds.json

# Unprivileged user: a parser bug should never be a root-in-container bug.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin tollgate \
 && mkdir /data && chown tollgate /data

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY tollgate ./tollgate
RUN pip install --no-cache-dir ".[all]" && rm -rf /app/tollgate /app/build
USER tollgate

ENTRYPOINT ["tollgate"]
