# Pin patch version AND digest in real use:
# docker buildx imagetools inspect python:3.13.11-slim-bookworm
FROM python:3.13.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# If you have deps that need compilation, add build tools here (and ONLY here).
# RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Best: requirements.txt is fully pinned + hashes, then use --require-hashes.
# RUN python -m pip install --upgrade pip && python -m pip install --require-hashes -r requirements.txt

RUN python -m venv /opt/venv && \
    /opt/venv/bin/python -m pip install --upgrade pip && \
    /opt/venv/bin/python -m pip install -r requirements.txt

# --- Runtime image ---
FROM python:3.13.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Non-root user (no home needed)
RUN useradd --system --uid 1000 --create-home --home-dir /home/appuser appuser

COPY --from=builder /opt/venv /opt/venv
COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 5000

# In containers, bind to 0.0.0.0 unless you *really* know why you're not.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--log-level", "info", "app:app"]
