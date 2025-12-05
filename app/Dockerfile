FROM python:3.9-slim

# 🔴 Install build tools + vulnerable packages (more CVEs!)
RUN apt-get update && \
    apt-get install -y gcc python3-dev curl vim && \
    rm -rf /var/lib/apt/lists/*
    
# 🔴 SECURITY VULNERABILITY: Secrets in ENV
ENV DATABASE_PASSWORD="super_secret_password_123"
ENV JWT_SECRET="insecure_jwt_secret_change_in_production"
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 🔴 Run as root (bad practice)
USER root
EXPOSE 5000

# 🔴 Verbose logging (information disclosure)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--log-level", "debug", "app:app"]