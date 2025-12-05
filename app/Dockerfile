FROM python:3.11-slim 

# 🔴 Remove security updates
# RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# 🔴 Install unnecessary packages (increase attack surface)
RUN apt-get update && apt-get install -y curl vim netcat && rm -rf /var/lib/apt/lists/*

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