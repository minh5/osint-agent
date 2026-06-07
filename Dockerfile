FROM python:3.12-slim

# System dependencies
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

# Clone Blackbird (not on PyPI — baked into image)
RUN git clone --depth 1 https://github.com/p1ngul1n0/blackbird /opt/blackbird \
    && uv pip install aiohttp chardet reportlab pillow

# Copy project source
COPY . .

# GHunt credentials mount point
RUN mkdir -p /root/.malfrats/ghunt

ENTRYPOINT ["uv", "run", "python", "main.py"]
