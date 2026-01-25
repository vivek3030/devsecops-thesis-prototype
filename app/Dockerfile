FROM python:3.13.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/python -m pip install --upgrade pip \
 && /opt/venv/bin/python -m pip install -r requirements.txt

COPY . .

# Distroless runtime with C libs (no shell). We'll bring our own Python from builder.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:/usr/local/bin:$PATH"

WORKDIR /app

# Copy Python interpreter + stdlib from builder
COPY --from=builder /usr/local /usr/local

# Copy venv + app
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app /app

EXPOSE 5000
CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:5000", "--log-level", "info", "app:app"]
