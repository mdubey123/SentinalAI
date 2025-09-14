# SentinelAI v2 - Multi-stage Dockerfile
# Optimized for production deployment with security scanning capabilities

# Stage 1: Base Python environment
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Essential build tools
    build-essential \
    gcc \
    g++ \
    make \
    # Security scanning dependencies
    clamav \
    clamav-daemon \
    clamav-freshclam \
    # File type detection
    libmagic1 \
    libmagic-dev \
    # Network tools
    nmap \
    # System utilities
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Stage 2: Python dependencies
FROM base as python-deps

# Create app directory
WORKDIR /app

# Copy requirements files
COPY requirements.txt requirements_windows.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Stage 3: Application build
FROM python-deps as app

# Create non-root user for security
RUN groupadd -r sentinelai && useradd -r -g sentinelai sentinelai

# Create necessary directories
RUN mkdir -p /app/logs /app/reports /app/cache /app/config /app/rules/yara

# Copy application code
COPY . /app/

# Set ownership
RUN chown -R sentinelai:sentinelai /app

# Switch to non-root user
USER sentinelai

# Initialize ClamAV database
RUN freshclam || true

# Create default configuration if not exists
RUN if [ ! -f /app/config.json ]; then \
    echo '{"version": "2.1.0", "scan_settings": {"hash_algorithms": ["sha256", "fuzzy"]}}' > /app/config.json; \
    fi

# Expose port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Default command
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true", "--server.enableCORS=false", "--server.enableXsrfProtection=false"]

# Stage 4: Production image (optional - for smaller final image)
FROM app as production

# Remove development dependencies
RUN pip uninstall -y pytest pytest-asyncio black flake8 mypy

# Clean up
RUN apt-get autoremove -y && apt-get clean

# Final optimizations
RUN find /app -name "*.pyc" -delete && \
    find /app -name "__pycache__" -type d -exec rm -rf {} + || true

