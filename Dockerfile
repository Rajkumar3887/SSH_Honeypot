FROM python:3.11-slim

LABEL maintainer="honeypot"
LABEL description="Enterprise SSH Honeypot with Wazuh SIEM integration"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/honeypot

# Install Python deps first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create log directory
RUN mkdir -p logs

# Expose the honeypot SSH port
EXPOSE 2222

# Default: open honeypot on port 2222
ENTRYPOINT ["python", "main.py"]
CMD ["--host", "0.0.0.0", "--port", "2222", "--open"]
