# Software Supply-Chain Threat Detection Gatekeeper - Production Sandbox Container
FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies for static analysis & compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Upgrade pip and install core wheel/setuptools
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install PyTorch & PyTorch Geometric (CPU optimized for container portability)
RUN pip install --no-cache-dir \
    torch torchvision --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir \
    torch-geometric

# Copy requirements and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir \
    pandas \
    openpyxl \
    scikit-learn \
    scipy \
    matplotlib \
    networkx \
    bandit \
    semgrep \
    cyclonedx-bom

# Copy project files
COPY . .

# Ensure outputs and graphs directories exist
RUN mkdir -p outputs graphs outputs/scan_temp

# Expose port for interactive Gatekeeper Dashboard
EXPOSE 5000

# Health check for dashboard endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Default command: launch the Gatekeeper Dashboard server
CMD ["python", "main.py"]
