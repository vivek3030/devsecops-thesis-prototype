FROM python:3.13-slim

# ✅ FIXED: Upgraded Python version to 3.11 (CVE-2023-36632, CVE-2025-12084)
# Minimal dependencies, removed unnecessary packages like vim
RUN apt-get update && \
    apt-get install -y curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
    
# ✅ FIXED: Removed secrets from ENV, use .env file instead
WORKDIR /app

COPY requirements.txt .
# ✅ FIXED: Upgrade pip to latest version
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ✅ FIXED: Create non-root user
RUN useradd -m -u 1000 appuser

COPY . .
RUN chown -R appuser:appuser /app

# ✅ FIXED: Run as non-root user
USER appuser
EXPOSE 5000

# ✅ FIXED: Reduced logging verbosity
CMD ["gunicorn", "--bind", "127.0.0.1:5000", "--log-level", "info", "app:app"]