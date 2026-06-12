FROM python:3.11-slim

LABEL maintainer="openvpn-admin"
LABEL description="OpenVPN Admin — Web Management Dashboard"

# Install system deps for ssh client
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd --create-home --shell /bin/bash app

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY --chown=app:app . .

# Create data directory for SQLite
RUN mkdir -p /app/data && chown app:app /app/data

# Create keys directory for SSH key
RUN mkdir -p /app/keys && chown app:app /app/keys

USER app

# Default environment
ENV HOST=0.0.0.0
ENV PORT=5000
ENV DEBUG=false
ENV FLASK_APP=app.py

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]
