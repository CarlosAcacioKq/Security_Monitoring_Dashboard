# =============================================================================
# ENTERPRISE SECURITY MONITORING DASHBOARD - PRODUCTION DOCKER IMAGE
# =============================================================================

FROM python:3.11-slim

LABEL maintainer="Carlos Acacio <carlos.acacio@example.com>"
LABEL description="Enterprise Security Monitoring Dashboard with 7 Threat Intelligence APIs"
LABEL version="2.0.0"
LABEL org.opencontainers.image.source="https://github.com/CarlosAcacioKq/Security_Monitoring_Dashboard"

# Set working directory
WORKDIR /app

# Install system dependencies for production
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies with optimizations
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directories for data persistence
RUN mkdir -p /app/data /app/logs

# Set production environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DATABASE_URL=sqlite:///data/security_monitor.db
ENV LOG_LEVEL=INFO
ENV FLASK_ENV=production

# Create non-root user for security
RUN groupadd -r siem && useradd -r -g siem -d /app -s /sbin/nologin -c "SIEM User" siem \
    && chown -R siem:siem /app
USER siem

# Expose dashboard port
EXPOSE 8050

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8050/ || exit 1

# Volume for data persistence
VOLUME ["/app/data", "/app/logs"]

# Default command - can be overridden for different services
CMD ["python", "web_dashboard.py"]