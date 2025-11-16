# Reversecore_MCP Dockerfile with Multi-stage Build
# 
# This Dockerfile uses a multi-stage build to reduce final image size and improve security.
# Build stage includes compilation tools, while runtime stage only contains necessary dependencies.
#
# Note: radare2 is not available in Debian Bookworm main repo, so we skip version pinning for it
# or install it from testing/backports if needed.

# ============================================================================
# Build Stage: Install dependencies that require compilation
# ============================================================================
FROM python:3.11-slim-bookworm AS builder
ARG YARA_VERSION=4.3.1
ARG RADARE2_VERSION=6.0.4

# Set working directory
WORKDIR /app

# Install build dependencies for Python packages that may need compilation
# These will NOT be included in the final image
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    automake \
    autoconf \
    libtool \
    pkg-config \
    flex \
    bison \
    libssl-dev \
    git \
    patch \
    xz-utils \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build and install native YARA matching the pinned Python binding (4.3.1)
RUN curl -sSL "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz" -o /tmp/yara.tar.gz \
    && tar -xzf /tmp/yara.tar.gz -C /tmp \
    && cd /tmp/yara-${YARA_VERSION} \
    && ./bootstrap.sh \
    && ./configure --disable-cuckoo --disable-magic --disable-dotnet \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && rm -rf /tmp/yara*

# Build radare2 from source to ensure availability on Debian bookworm
RUN curl -sSL "https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2-${RADARE2_VERSION}.tar.xz" -o /tmp/radare2.tar.xz \
    && tar -xJf /tmp/radare2.tar.xz -C /tmp \
    && cd /tmp/radare2-${RADARE2_VERSION} \
    && ./configure --prefix=/opt/radare2 \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/radare2*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies into a virtual environment
# Using a venv makes it easy to copy only the installed packages to the runtime stage
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir -r requirements.txt

# ============================================================================
# Runtime Stage: Create minimal production image
# ============================================================================
FROM python:3.11-slim-bookworm

# Set working directory
WORKDIR /app

# Create workspace and rules directories
RUN mkdir -p /app/workspace /app/rules

# Install only runtime dependencies (no build tools)
# Versions are pinned to ensure consistent behavior across builds
# To check available versions: apt-cache madison <package-name>
#
# Note: radare2 is built in the builder stage to guarantee availability on bookworm.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        # coreutils "file" command required by run_file tool
        # Version: 1:5.44-3 (Debian 12 Bookworm)
        file=1:5.44-3 \
        # Binutils for strings command
        # Version: 2.40-2 (Debian 12 Bookworm)
        binutils=2.40-2 \
        # Binwalk for firmware analysis and file carving
        # Version: 2.3.4+dfsg1-1 (Debian 12 Bookworm)
        binwalk=2.3.4+dfsg1-1 \
    && rm -rf /var/lib/apt/lists/*

# Copy native tooling built in the builder stage so CLI tools match Python bindings
RUN mkdir -p /usr/local/include /usr/local/lib/pkgconfig
COPY --from=builder /usr/local/bin/yara /usr/local/bin/yara
COPY --from=builder /usr/local/bin/yarac /usr/local/bin/yarac
COPY --from=builder /usr/local/lib/libyara* /usr/local/lib/
COPY --from=builder /usr/local/include/yara /usr/local/include/yara
COPY --from=builder /usr/local/lib/pkgconfig/yara.pc /usr/local/lib/pkgconfig/yara.pc
COPY --from=builder /opt/radare2 /opt/radare2
RUN echo "/opt/radare2/lib" > /etc/ld.so.conf.d/radare2.conf && ldconfig

# Copy Python virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY reversecore_mcp/ ./reversecore_mcp/
COPY server.py ./

# Set Python path to use the venv and configure application
ENV PATH="/opt/radare2/bin:/opt/venv/bin:$PATH" \
    PYTHONPATH=/app \
    REVERSECORE_WORKSPACE=/app/workspace \
    MCP_TRANSPORT=http \
    LOG_LEVEL=INFO \
    LOG_FILE=/var/log/reversecore/app.log \
    RATE_LIMIT=60

# Create log directory
RUN mkdir -p /var/log/reversecore

# Expose port for HTTP transport
EXPOSE 8000

# Run the MCP server
CMD ["python", "server.py"]

