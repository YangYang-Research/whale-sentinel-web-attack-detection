# First Stage: Build Python Environment
FROM python:3.9-slim AS builder

RUN apt-get update && apt-get install -y nginx openssl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy application files
COPY . /app/whale-sentinel-web-attack-detection

# Set working directory for the service
WORKDIR /app/whale-sentinel-web-attack-detection

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Download Sentence Transformers Model
RUN python -c "import os; from sentence_transformers import SentenceTransformer; SentenceTransformer(os.environ.get('model_name_or_path', 'sentence-transformers/all-MiniLM-L6-v2'));"

# Download Web Attack Detection Model
RUN python -c "from huggingface_hub import hf_hub_download; hf_hub_download(repo_id='noobpk/web-attack-detection', filename='model.h5')"

# Create directory for SSL certificates
RUN mkdir -p /etc/nginx/certs

# Generate self-signed certificate for Nginx
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/certs/server.key -out /etc/nginx/certs/server.crt \
    -subj "/CN=localhost"

# Copy Nginx configuration
COPY  --from=builder whale-sentinel-web-attack-detection/nginx.conf /etc/nginx/nginx.conf

# Expose port 443 for HTTPS
EXPOSE 443

# Run the Flask API using Waitress and Nginx
CMD ["sh", "-c", "nginx & uvicorn app:app --host 0.0.0.0 --port 5001"]