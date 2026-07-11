FROM python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY requirements-build.lock ./
RUN python -m pip install --require-hashes --no-compile -r requirements-build.lock

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip wheel --no-deps --no-build-isolation --wheel-dir /dist .

FROM python:3.12-slim@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf

LABEL org.opencontainers.image.source="https://github.com/kai-linux/eigendark-agent-mcp" \
      org.opencontainers.image.version="0.4.0" \
      org.opencontainers.image.licenses="MIT" \
      io.modelcontextprotocol.server.name="io.github.kai-linux/eigendark-agent-mcp"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN addgroup --system app && adduser --system --ingroup app app

COPY requirements-runtime.lock ./
RUN python -m pip install --require-hashes --no-compile -r requirements-runtime.lock

COPY --from=builder /dist/*.whl /tmp/dist/
RUN python -m pip install --no-deps --no-compile /tmp/dist/*.whl \
    && python -m pip check \
    && python -m pip uninstall --yes pip \
    && rm -rf /tmp/dist /root/.cache /app/requirements-runtime.lock

USER app
ENTRYPOINT ["eigendark-agent-mcp"]
