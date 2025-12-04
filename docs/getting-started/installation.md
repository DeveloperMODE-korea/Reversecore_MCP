# Installation

## Requirements

- Python 3.10+
- Radare2
- Java 11+ (for Ghidra decompilation)
- YARA (optional, for signature scanning)
- Graphviz (optional, for CFG visualization)

## Docker Installation (Recommended)

The easiest way to get started is using Docker:

```bash
# Pull the latest image
docker pull ghcr.io/yourusername/reversecore_mcp:latest

# Run with workspace volume
docker run -v /path/to/binaries:/app/workspace \
  -e REVERSECORE_WORKSPACE=/app/workspace \
  ghcr.io/yourusername/reversecore_mcp:latest
```

### ARM64 (Apple Silicon)

```bash
docker pull ghcr.io/yourusername/reversecore_mcp:latest-arm64
```

## Manual Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/Reversecore_MCP.git
cd Reversecore_MCP
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install System Dependencies

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y radare2 yara graphviz openjdk-11-jre
```

#### macOS

```bash
brew install radare2 yara graphviz openjdk@11
```

#### Windows

Download and install:
- [Radare2](https://github.com/radareorg/radare2/releases)
- [YARA](https://github.com/VirusTotal/yara/releases)
- [Graphviz](https://graphviz.org/download/)
- [Java 11](https://adoptium.net/)

### 5. Verify Installation

```bash
# Check dependencies
radare2 -v
java -version
yara --version
dot -V

# Run tests
pytest tests/ -v
```

## Configuration

See [Configuration Guide](configuration.md) for environment variable setup.
