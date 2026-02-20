# syntax=docker/dockerfile:1.7

# ===========================
# Builder Stage
# ===========================
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN python -m pip install --upgrade pip \
    && python -m pip wheel --wheel-dir /wheels .

# ===========================
# Runtime Stage
# ===========================
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
RUN python -m pip install /wheels/*.whl \
    && rm -rf /wheels

RUN groupadd --system --gid 10001 gcc \
    && useradd --system --uid 10001 --gid gcc --create-home --home-dir /home/gcc gcc \
    && mkdir -p /workspace /var/log/gcc \
    && chown -R gcc:gcc /workspace /var/log/gcc /home/gcc

USER gcc:gcc

EXPOSE 8000

ENTRYPOINT ["gcc-mcp"]
CMD ["--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8000", "--allow-public-http"]

# ===========================
# Test Stage
# ===========================
FROM python:3.11-slim AS test

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY tests/ ./tests/

RUN python -m pip install --upgrade pip \
    && python -m pip install -e ".[dev]"

CMD ["sh", "-c", "python -m pytest -q && gcc-cli --help >/dev/null && gcc-mcp --help >/dev/null"]
