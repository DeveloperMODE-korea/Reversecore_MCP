# Reversecore_MCP Dockerfile
# 
# This Dockerfile sets up a containerized environment for the Reversecore_MCP
# server with all required system dependencies and pinned versions for
# reproducibility.

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies with pinned versions where possible
# Note: Some packages may not have exact version pinning available in Debian repos
# We use the latest stable versions and document them for reproducibility
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Radare2 reverse engineering framework
    # Version: Latest stable from Debian repos (typically 5.9.x)
    radare2 \
    # YARA pattern matching tool and development libraries
    # Version: Latest stable from Debian repos (typically 4.3.x)
    yara \
    libyara-dev \
    # Binutils for strings command
    binutils \
    # Build dependencies for Python packages that may need compilation
    gcc \
    g++ \
    make \
    # Cleanup
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY reversecore_mcp/ ./reversecore_mcp/

# Set Python path
ENV PYTHONPATH=/app

# Expose port (if using HTTP transport)
# EXPOSE 8000

# Run the MCP server
CMD ["python", "-m", "reversecore_mcp.server"]

