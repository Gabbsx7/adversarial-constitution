FROM python:3.11-slim

LABEL maintainer="gabriel@antz.studio"
LABEL description="Adversarial Constitution Framework — Automated Red Teaming"

# System deps for weasyprint (PDF export) + build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer cache)
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e ".[dev]" \
    || true

# Copy source
COPY . .

# Final install with source
RUN pip install --no-cache-dir -e ".[dev]"

# Create output dirs
RUN mkdir -p /app/reports /app/constitution/examples

# Health check — verify CLI is importable
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from adversarial.attack_engine import cli_entry; print('OK')" || exit 1

# Default: show help
ENTRYPOINT ["python", "-m", "adversarial.attack_engine"]
CMD ["--help"]