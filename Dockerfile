# Single image for both the OSINT scan (main.py) and opt-out automation (bin/removal.py).
# Uses the official Playwright base which bundles Chromium + all system deps.
FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

# Extra system dependencies needed by the OSINT tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.cargo/bin:/root/.local/bin:$PATH"

WORKDIR /app

# Install Python deps via uv first (layer cache)
COPY pyproject.toml ./
RUN uv sync --no-dev

# Install Playwright browser (Chromium already bundled in base image, this registers it)
RUN uv run playwright install chromium

# Clone Blackbird (not on PyPI — baked into image)
RUN git clone --depth 1 https://github.com/p1ngul1n0/blackbird /opt/blackbird

# Copy project source
COPY . .

# GHunt credentials mount point
RUN mkdir -p /root/.malfrats/ghunt

# Patch ghunt source for Google API response changes (container key + data[24] bounds)
RUN python3 bin/patch-ghunt.py

# Default entrypoint: OSINT scan
# Override with --entrypoint or `command:` in docker-compose for bin/removal.py
ENTRYPOINT ["uv", "run", "python", "main.py"]
