# FastMCP Cloud Support Report

**Date**: 2025-11-13  
**Version**: 1.1  
**Status**: Analysis Complete, Implementation Pending

## Table of Contents

1. [Summary](#summary)
2. [FastMCP Cloud Overview](#fastmcp-cloud-overview)
3. [Current Architecture Analysis](#current-architecture-analysis)
4. [Compatibility Issues Analysis](#compatibility-issues-analysis)
5. [FastMCP Cloud Support Requirements](#fastmcp-cloud-support-requirements)
6. [Implementation Plan](#implementation-plan)
7. [Technical Considerations](#technical-considerations)
8. [Security Considerations](#security-considerations)
9. [Alternatives and Recommendations](#alternatives-and-recommendations)
10. [Conclusion](#conclusion)

---

## Summary

### Key Findings

**Reversecore_MCP is currently designed with a local file system-based architecture and is not directly compatible with FastMCP Cloud.**

Key Constraints:
- ✅ **Local Server**: Direct access to local files
- ❌ **FastMCP Cloud**: Cannot access local files from cloud servers

### Recommendations

1. **Short-term**: Continue using local server (current approach)
2. **Medium-term**: Review adding file upload functionality
3. **Long-term**: Support hybrid mode (local + cloud)

---

## FastMCP Cloud Overview

### Definition

FastMCP Cloud is a **managed MCP server deployment platform** developed by the FastMCP team that automatically deploys MCP servers to cloud environments by connecting GitHub repositories.

### Key Features

#### 1. Zero-Configuration Deployment
- Deploy MCP servers by simply connecting GitHub repositories
- No complex configuration files required
- Template-based quick start

#### 2. Serverless Scalability
- Automatic scaling based on request volume
- Pay-as-you-go pricing
- Cold start time < 1 second

#### 3. Built-in OAuth and Security
- OAuth authentication provided by default
- No need to implement separate authentication flows
- Support for integration with existing identity providers

#### 4. Git-based CI/CD
- Automatic builds on commit push
- Branch deployment on PR creation
- Version management and rollback support

#### 5. MCP Native Analytics
- Request/response pair tracking
- Tool usage monitoring
- User behavior analysis

#### 6. Enterprise Features
- SSO (Single Sign-On)
- SCIM and directory synchronization
- Role-Based Access Control (RBAC)
- Audit trails

### Pricing Plans

| Plan | Price | Features |
|------|-------|----------|
| **Hobby** | Free | Personal use, 1M requests/month |
| **Pro** | $20/month | Advanced analytics, more usage, Slack support |
| **Enterprise** | Contact | RBAC, MCP governance, dedicated compute resources |

### Use Cases

FastMCP Cloud is suitable for the following scenarios:
- ✅ Team-shared MCP servers
- ✅ Production environment deployment
- ✅ High availability requirements
- ✅ Automatic scaling needs
- ✅ Centralized management

---

## Current Architecture Analysis

### File Access Model

Reversecore_MCP is designed with a **local file system-based** architecture:

```python
# reversecore_mcp/core/security.py
def validate_file_path(path: str, read_only: bool = False) -> str:
    """
    File path validation:
    1. Convert to absolute path
    2. Only allow files within workspace directory
    3. Support only local file system paths
    """
    abs_path = file_path.resolve(strict=True)  # Local file system path
    workspace_path = _get_allowed_workspace()  # REVERSECORE_WORKSPACE env var
    
    # Check if file is within workspace
    if not is_path_in_directory(abs_path_str, workspace_path_str):
        raise ValidationError("File path is outside allowed directories")
```

### Workspace Constraints

```python
# reversecore_mcp/core/config.py
reversecore_workspace: Path = Field(
    default=Path("/app/workspace"),
    description="Allowed workspace directory for file operations",
    alias="REVERSECORE_WORKSPACE",
)
```

**Characteristics**:
- Only local file system paths allowed
- Docker volume mount approach (`-v ./samples:/app/workspace`)
- No network-based file transfer support
- No cloud storage integration

### Security Model

```python
# Security validation logic
1. Path normalization (symlink removal)
2. Workspace boundary checks
3. File existence verification
4. Read-only directory support (YARA rules)
```

**Constraints**:
- Optimized for local path validation
- Does not support cloud environment file access patterns

---

## Compatibility Issues Analysis

### Structural Constraints

```
┌─────────────────────────────────────────────────────────┐
│                    FastMCP Cloud                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Cloud Server (AWS/GCP/Azure)                   │  │
│  │  - Independent file system                       │  │
│  │  - Cannot access local file system ❌            │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                          ↕
                    MCP Protocol
                          ↕
┌─────────────────────────────────────────────────────────┐
│          User Local Environment (Windows)               │
│  E:\Reversecore_Workspace\EverPlanet_KR_v1842_U_DEVM.exe│
│  - Local file system                                    │
│  - Cannot be accessed from cloud server ❌              │
└─────────────────────────────────────────────────────────┘
```

### Detailed Problem Analysis

#### 1. File Path Access Impossible

**Current Approach**:
```python
# Running on local server
file_path = "E:\Reversecore_Workspace\sample.exe"
validate_file_path(file_path)  # ✅ Success: Local file access possible
```

**Running on FastMCP Cloud**:
```python
# Running on cloud server
file_path = "E:\Reversecore_Workspace\sample.exe"
validate_file_path(file_path)  # ❌ Failure: Path does not exist on cloud server
```

#### 2. Workspace Constraints

**Local Server**:
```bash
# Docker volume mount
docker run -v ./samples:/app/workspace reversecore-mcp
# Local files → Accessible inside container
```

**FastMCP Cloud**:
```bash
# Cloud server has independent file system
# Cannot mount local files
# Files must be transferred to cloud
```

#### 3. Security Validation Logic

**Current Validation**:
- Local path-based validation
- Uses `os.path.commonpath()`
- Absolute path resolution

**Cloud Environment Requirements**:
- Cloud storage path support
- File identifier-based access for uploaded files
- Temporary file management

### Compatibility Matrix

| Feature | Local Server | FastMCP Cloud | Compatibility |
|---------|--------------|---------------|---------------|
| Local file access | ✅ | ❌ | **Not Possible** |
| Docker volume mount | ✅ | ❌ | **Not Possible** |
| Network file transfer | ❌ | ✅ | **Required** |
| Cloud storage | ❌ | ✅ | **Required** |
| Path validation | Local paths | Cloud paths | **Modification Required** |
| File upload | ❌ | ✅ | **Required** |

---

## FastMCP Cloud Support Requirements

### Functional Requirements

#### 1. File Upload Functionality

**Required Features**:
- Base64-encoded file upload
- Multipart file upload
- Temporary storage management
- File size limits (existing LIEF limit: 1GB)

**Proposed API**:
```python
@mcp.tool()
def upload_file(
    file_name: str,
    file_content: str,  # Base64 encoded
    file_size: int,
) -> str:
    """
    Upload a file to the cloud server for analysis.
    
    Returns:
        File identifier (UUID) for use in other tools
    """
    pass
```

**AI Agent File Upload Mechanism**:

Since AI agents cannot directly access the file system, the following workflow is required:

**Option A: MCP Client Reads File (Recommended)**
```
User → "Analyze this file" (provides file path)
  ↓
AI Agent → Requests file read from MCP client
  ↓
MCP Client (Cursor/Claude Desktop) → Reads file and Base64 encodes
  ↓
AI Agent → Calls upload_file(file_name, file_content, file_size)
  ↓
FastMCP Cloud → Stores file and returns file_id
  ↓
AI Agent → Uses file_id to call analysis tools
```

**Option B: User Provides File Content Directly**
```
User → Provides file encoded as Base64
  ↓
AI Agent → Calls upload_file(file_name, file_content, file_size)
  ↓
FastMCP Cloud → Stores file and returns file_id
```

**Option C: File URL Provision (Future Support)**
```
User → Provides file URL (e.g., https://example.com/sample.exe)
  ↓
AI Agent → Calls download_and_upload(url) tool
  ↓
FastMCP Cloud → Downloads file, stores it, returns file_id
```

**Realistic Constraints**:
- ❌ AI agents cannot directly access local file system (security reasons)
- ✅ MCP client must read and provide the file
- ✅ Or user must provide file content directly
- ⚠️ Base64 encoding overhead must be considered for large files

**MCP Client Support Required**:
The MCP protocol currently does not have a standardized file reading feature. Therefore:
1. **Cursor/Claude Desktop Extension**: File reading functionality needs to be added
2. **Temporary Workaround**: User provides file encoded as Base64
3. **Future Improvement**: Add file reading standard to MCP protocol

#### 2. File Identifier-Based Access

**Changes Required**:
- Use file ID instead of file path
- Query files from temporary storage
- File lifecycle management (TTL)

**Proposed Structure**:
```python
# Before
def run_file(file_path: str) -> str:
    validated_path = validate_file_path(file_path)
    # ...

# After
def run_file(file_path: str = None, file_id: str = None) -> str:
    if file_id:
        file_path = get_file_from_storage(file_id)
    else:
        file_path = validate_file_path(file_path)
    # ...
```

#### 3. Cloud Storage Integration

**Option 1: Temporary File System**
- Store uploaded files in temporary directory
- TTL-based automatic deletion
- Consider memory-based storage (Redis)

**Option 2: Cloud Storage Service**
- AWS S3, GCS, Azure Blob Storage
- URL-based file access
- Increased external dependencies

**Option 3: Hybrid**
- Small files: Temporary file system
- Large files: Cloud storage

#### 4. Path Validation Logic Modification

**Current**:
```python
def validate_file_path(path: str) -> str:
    abs_path = Path(path).resolve(strict=True)
    # Local path validation
```

**After Changes**:
```python
def validate_file_path(path: str, cloud_mode: bool = False) -> str:
    if cloud_mode:
        # Cloud mode: Validate file ID or cloud path
        return validate_cloud_path(path)
    else:
        # Local mode: Existing logic
        return validate_local_path(path)
```

### Non-Functional Requirements

#### 1. Performance
- Minimize file upload time
- Support streaming for large files
- Minimize temporary file cleanup overhead

#### 2. Security
- Uploaded file validation (virus scanning)
- File size limits
- TTL-based automatic deletion
- Access control

#### 3. Scalability
- Handle concurrent uploads
- Storage capacity management
- File lifecycle management

---

## Implementation Plan

### Phase 1: Add File Upload Functionality (Required)

**Goal**: Implement basic file upload and temporary storage

**Tasks**:
1. Add file upload tool (`upload_file`)
2. Implement temporary storage module (`reversecore_mcp/core/storage.py`)
3. File ID generation and management (UUID)
4. TTL-based automatic deletion

**Estimated Effort**: 2-3 days

**File Structure**:
```
reversecore_mcp/
├── core/
│   ├── storage.py          # New: Temporary storage management
│   └── security.py         # Modified: Add cloud path validation
├── tools/
│   └── file_tools.py       # New: File upload tool
```

### Phase 2: Modify Tool Functions (Required)

**Goal**: All tool functions support file IDs

**Tasks**:
1. `run_file`: Add file ID support
2. `run_strings`: Add file ID support
3. `run_radare2`: Add file ID support
4. `run_binwalk`: Add file ID support
5. `run_yara`: Add file ID support
6. `disassemble_with_capstone`: Add file ID support
7. `parse_binary_with_lief`: Add file ID support

**Estimated Effort**: 3-4 days

**Change Pattern**:
```python
# Before
@log_execution(tool_name="run_file")
def run_file(file_path: str, timeout: int = 30) -> str:
    validated_path = validate_file_path(file_path)
    # ...

# After
@log_execution(tool_name="run_file")
def run_file(
    file_path: str = None,
    file_id: str = None,
    timeout: int = 30
) -> str:
    if file_id:
        file_path = get_file_from_storage(file_id)
    elif file_path:
        file_path = validate_file_path(file_path, cloud_mode=False)
    else:
        raise ValueError("Either file_path or file_id must be provided")
    # ...
```

### Phase 3: Configuration and Environment Detection (Optional)

**Goal**: Automatic local/cloud mode detection

**Tasks**:
1. Add environment variables (`CLOUD_MODE`, `STORAGE_TYPE`)
2. Separate path validation logic by mode
3. Update configuration management

**Estimated Effort**: 1 day

### Phase 4: Testing and Documentation (Required)

**Goal**: Write FastMCP Cloud deployment guide

**Tasks**:
1. Test file upload functionality
2. Cloud mode integration testing
3. Write FastMCP Cloud deployment guide
4. Update README

**Estimated Effort**: 2 days

### Total Estimated Effort

| Phase | Effort | Priority |
|-------|--------|----------|
| Phase 1 | 2-3 days | High |
| Phase 2 | 3-4 days | High |
| Phase 3 | 1 day | Medium |
| Phase 4 | 2 days | High |
| **Total** | **8-10 days** | - |

---

## Technical Considerations

### 1. Temporary Storage Implementation

#### Option A: File System-Based

**Advantages**:
- Simple implementation
- No external dependencies
- Easy debugging

**Disadvantages**:
- Disk I/O overhead
- Limited scalability
- Data loss on server restart

**Implementation Example**:
```python
# reversecore_mcp/core/storage.py
import tempfile
import uuid
from pathlib import Path
from datetime import datetime, timedelta

class FileStorage:
    def __init__(self, base_dir: Path = None, ttl_hours: int = 24):
        self.base_dir = base_dir or Path(tempfile.gettempdir()) / "reversecore_uploads"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_hours = ttl_hours
        self.files = {}  # file_id -> (path, uploaded_at)
    
    def store_file(self, file_content: bytes, file_name: str) -> str:
        file_id = str(uuid.uuid4())
        file_path = self.base_dir / file_id
        file_path.write_bytes(file_content)
        self.files[file_id] = (file_path, datetime.now())
        return file_id
    
    def get_file_path(self, file_id: str) -> Path:
        if file_id not in self.files:
            raise ValueError(f"File not found: {file_id}")
        file_path, uploaded_at = self.files[file_id]
        if datetime.now() - uploaded_at > timedelta(hours=self.ttl_hours):
            self.delete_file(file_id)
            raise ValueError(f"File expired: {file_id}")
        return file_path
    
    def delete_file(self, file_id: str):
        if file_id in self.files:
            file_path, _ = self.files[file_id]
            file_path.unlink(missing_ok=True)
            del self.files[file_id]
    
    def cleanup_expired(self):
        now = datetime.now()
        expired = [
            file_id for file_id, (_, uploaded_at) in self.files.items()
            if now - uploaded_at > timedelta(hours=self.ttl_hours)
        ]
        for file_id in expired:
            self.delete_file(file_id)
```

#### Option B: Memory-Based (Redis)

**Advantages**:
- Fast access speed
- Automatic TTL support
- Excellent scalability

**Disadvantages**:
- External dependency (Redis)
- Memory limitations
- Not suitable for large files

**Implementation Example**:
```python
import redis
import uuid

class RedisFileStorage:
    def __init__(self, redis_url: str = "redis://localhost:6379", ttl_seconds: int = 86400):
        self.redis = redis.from_url(redis_url)
        self.ttl_seconds = ttl_seconds
    
    def store_file(self, file_content: bytes, file_name: str) -> str:
        file_id = str(uuid.uuid4())
        self.redis.setex(
            f"file:{file_id}",
            self.ttl_seconds,
            file_content
        )
        self.redis.setex(
            f"meta:{file_id}",
            self.ttl_seconds,
            file_name
        )
        return file_id
    
    def get_file_content(self, file_id: str) -> bytes:
        content = self.redis.get(f"file:{file_id}")
        if not content:
            raise ValueError(f"File not found: {file_id}")
        return content
```

#### Recommendations

**Initial Implementation**: File system-based (Option A)
- Simple implementation
- No external dependencies
- Works in FastMCP Cloud environment

**Future Improvement**: Hybrid approach
- Small files (< 10MB): Memory-based
- Large files (≥ 10MB): File system-based

### 2. File Upload Method

#### Base64 Encoding

**Advantages**:
- Compatible with MCP protocol
- Can be transmitted as JSON
- Simple implementation

**Disadvantages**:
- 33% overhead (encoding)
- Not suitable for large files

**Use Case**: Small files (< 10MB)

#### Multipart Upload

**Advantages**:
- Supports large files
- Streaming possible
- Efficient

**Disadvantages**:
- Requires MCP protocol extension
- Complex implementation

**Use Case**: Large files (≥ 10MB)

#### Recommendations

**Initial Implementation**: Base64 encoding
- MCP protocol compatible
- Quick implementation

**Future Improvement**: Multipart upload
- Large file support
- Performance optimization

### 3. File Size Limits

**Current Limits**:
- LIEF: 1GB
- General tools: Output size limit (10MB)

**Cloud Environment Considerations**:
- Upload time
- Storage capacity
- Memory usage

**Proposed Limits**:
- Default upload: 100MB
- Configurable: `MAX_UPLOAD_SIZE` environment variable
- LIEF analysis: Maintain existing 1GB limit

### 4. File Lifecycle Management

**TTL (Time To Live)**:
- Default: 24 hours
- Configurable: `FILE_TTL_HOURS` environment variable
- Automatic cleanup: Background job

**Cleanup Strategy**:
- Periodic cleanup (cron job)
- TTL check on access
- Cleanup on server shutdown

---

## Security Considerations

### 1. File Upload Validation

**Required Validation**:
- File size limits
- File type validation (header-based)
- Malicious file scanning (optional)

**Implementation Example**:
```python
def validate_uploaded_file(file_content: bytes, file_name: str):
    # Size validation
    max_size = get_settings().max_upload_size
    if len(file_content) > max_size:
        raise ValidationError(f"File too large: {len(file_content)} > {max_size}")
    
    # File type validation (magic numbers)
    if not is_valid_binary_file(file_content):
        raise ValidationError("Invalid file type")
    
    # Filename validation
    if contains_path_traversal(file_name):
        raise ValidationError("Invalid file name")
```

### 2. Access Control

**File ID-Based Access**:
- Use UUID (unpredictable)
- Session-based access control (optional)
- User-specific file isolation (optional)

### 3. Data Protection

**Temporary File Protection**:
- Appropriate file permissions (600)
- Encrypted storage (optional)
- Secure deletion

### 4. Logging and Auditing

**Recorded Items**:
- File upload events
- File access events
- File deletion events
- Error events

**Sensitive Information Excluded**:
- Do not log file contents
- Hash file paths

---

## Alternatives and Recommendations

### Option 1: Maintain Local Server (Current Approach) ⭐ Recommended

**Advantages**:
- ✅ Direct access to local files
- ✅ Easy security control
- ✅ Works offline
- ✅ No additional development needed

**Disadvantages**:
- ❌ Difficult team sharing
- ❌ No automatic scaling
- ❌ No centralized management

**Use Cases**:
- Personal development environment
- Local file analysis
- Offline environment

### Option 2: Add FastMCP Cloud Support

**Advantages**:
- ✅ Team sharing possible
- ✅ Automatic scaling
- ✅ Centralized management
- ✅ High availability

**Disadvantages**:
- ❌ File upload required
- ❌ Additional development needed (8-10 days)
- ❌ Storage management required
- ❌ Increased security considerations

**Use Cases**:
- Team collaboration
- Production environment
- High availability requirements

### Option 3: Hybrid Mode

**Implementation**:
- Local mode: Maintain existing approach
- Cloud mode: Support file upload
- Automatic detection: Environment variable-based

**Advantages**:
- ✅ Supports both modes
- ✅ User choice available
- ✅ Gradual migration

**Disadvantages**:
- ❌ Increased code complexity
- ❌ Expanded test scope

### Recommendations

**Short-term (Current)**:
- Continue using local server
- FastMCP Cloud support is optional

**Medium-term (3-6 months)**:
- Review adding file upload functionality
- Survey user requirements

**Long-term (6+ months)**:
- Implement hybrid mode
- Official FastMCP Cloud support

---

## Conclusion

### Key Summary

1. **Structural Constraint**: Reversecore_MCP is designed with a local file system-based architecture and is not directly compatible with FastMCP Cloud

2. **AI Agent Constraint**: AI agents cannot directly access the file system, so for file uploads:
   - MCP client (Cursor/Claude Desktop) file reading functionality is required
   - Or user must provide file encoded as Base64
   - MCP protocol currently does not have a file reading standard

3. **Support Feasibility**: FastMCP Cloud support is possible with file upload functionality added (estimated effort: 8-10 days)
   - However, MCP client file reading functionality support must come first

4. **Recommendation**: Currently maintain local server usage, review FastMCP Cloud support based on future user requirements

### Real-World Usage Scenario Comparison

#### Scenario 1: Local Server (Current Approach) ✅

```
User: "Analyze the file E:\Reversecore_Workspace\sample.exe"
  ↓
AI Agent: Calls run_file(file_path="E:\Reversecore_Workspace\sample.exe")
  ↓
Local Server: Direct file access → Returns analysis results
```

**Advantages**: Simple and intuitive, immediately usable

#### Scenario 2: FastMCP Cloud (Proposed Approach) ⚠️

**Current State (Not Supported)**:
```
User: "Analyze the file E:\Reversecore_Workspace\sample.exe"
  ↓
AI Agent: Only receives file path → Cannot access from cloud server ❌
```

**When Supported (Assumed)**:
```
User: "Analyze this file" (file path or drag-and-drop)
  ↓
MCP Client: Reads file and Base64 encodes
  ↓
AI Agent: Calls upload_file(file_name, file_content, file_size)
  ↓
FastMCP Cloud: Stores file → Returns file_id
  ↓
AI Agent: Calls run_file(file_id=file_id)
  ↓
FastMCP Cloud: Analyzes file → Returns results
```

**Required Conditions**:
- MCP client file reading functionality support
- Or user provides file as Base64 directly

### Next Steps

1. **Immediate**: Strengthen local server usage guide
2. **Short-term**: 
   - Consult with MCP client development teams about file reading functionality
   - Collect user feedback (FastMCP Cloud support necessity)
3. **Medium-term**: 
   - Develop file upload functionality prototype
   - Confirm MCP client file reading functionality support
4. **Long-term**: 
   - Implement hybrid mode
   - Official FastMCP Cloud support

### References

- [FastMCP Cloud Official Documentation](https://fastmcp.cloud)
- [FastMCP GitHub Repository](https://github.com/jlowin/fastmcp)
- [MCP Protocol Specification](https://modelcontextprotocol.io)

---

**Document Version**: 1.1  
**Last Updated**: 2025-11-13  
**Author**: Reversecore_MCP Development Team

### Changelog

- **v1.1 (2025-11-13)**: Added AI agent file upload mechanism section, added real-world usage scenario comparison
- **v1.0 (2025-11-13)**: Initial report creation
