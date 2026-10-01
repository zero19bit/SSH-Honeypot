FROM python:3.14-slim-bookworm

ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/nonexistent \
    HONEYPOT_HOST=0.0.0.0 \
    HONEYPOT_PORT=2222 \
    HONEYPOT_PRODUCTION=true

RUN groupadd --gid "${APP_GID}" honeypot \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --no-create-home \
       --home-dir /nonexistent --shell /usr/sbin/nologin honeypot

WORKDIR /app

COPY requirements.lock ./requirements.lock
RUN python -m pip install --require-hashes -r requirements.lock

COPY pyproject.toml README.md ./
COPY honeypot ./honeypot

RUN python -m compileall -q honeypot \
    && chown -R "${APP_UID}:${APP_GID}" /app

USER ${APP_UID}:${APP_GID}

EXPOSE 2222/tcp
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 CMD ["python", "-m", "honeypot.healthcheck"]

ENTRYPOINT ["python", "-m", "honeypot"]
