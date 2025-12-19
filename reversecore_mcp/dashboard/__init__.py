"""
Web Dashboard for Reversecore MCP.

Provides a visual interface for binary analysis using FastAPI + Jinja2.
"""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Setup paths
DASHBOARD_DIR = Path(__file__).parent
TEMPLATES_DIR = DASHBOARD_DIR / "templates"
STATIC_DIR = DASHBOARD_DIR / "static"

# Create router
router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# Setup templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def get_router() -> APIRouter:
    """Get the dashboard router."""
    return router


def get_static_files() -> StaticFiles:
    """Get static files mount."""
    return StaticFiles(directory=str(STATIC_DIR))


@router.get("/", response_class=HTMLResponse)
async def dashboard_index(request: Request):
    """Dashboard overview page."""
    from reversecore_mcp.core.config import get_config

    settings = get_config()
    workspace = settings.workspace

    # Get list of files in workspace
    files = []
    if workspace.exists():
        for f in workspace.iterdir():
            if f.is_file() and not f.name.startswith("."):
                stat = f.stat()
                files.append(
                    {
                        "name": f.name,
                        "size": stat.st_size,
                        "modified": stat.st_mtime,
                    }
                )

    # Sort by modified time (newest first)
    files.sort(key=lambda x: x["modified"], reverse=True)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "files": files,
            "workspace": str(workspace),
            "file_count": len(files),
        },
    )


@router.get("/analysis/{filename}", response_class=HTMLResponse)
async def dashboard_analysis(request: Request, filename: str):
    """Analysis page for a specific file."""
    from reversecore_mcp.core.config import get_config
    from reversecore_mcp.core.security import validate_file_path

    settings = get_config()
    file_path = settings.workspace / filename

    try:
        validated_path = validate_file_path(str(file_path))
    except Exception as e:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)},
        )

    # Get basic file info
    file_info = {
        "name": validated_path.name,
        "path": str(validated_path),
        "size": validated_path.stat().st_size,
    }

    # Try to get functions list
    functions = []
    disasm = ""

    try:
        from reversecore_mcp.tools.radare2.r2_session import R2Session

        session = R2Session(str(validated_path))
        session.analyze(level=1)

        # Get functions
        funcs_json = session.cmdj("aflj") or []
        for func in funcs_json[:50]:  # Limit to 50
            functions.append(
                {
                    "name": func.get("name", "unknown"),
                    "offset": hex(func.get("offset", 0)),
                    "size": func.get("size", 0),
                }
            )

        # Get entry point disassembly
        disasm = session.cmd("pdf @ entry0") or "No disassembly available"

    except Exception as e:
        disasm = f"Error: {e}"

    return templates.TemplateResponse(
        "analysis.html",
        {
            "request": request,
            "file": file_info,
            "functions": functions,
            "disasm": disasm,
        },
    )


@router.get("/iocs/{filename}", response_class=HTMLResponse)
async def dashboard_iocs(request: Request, filename: str):
    """IOC extraction page."""
    from reversecore_mcp.core.config import get_config
    from reversecore_mcp.core.security import validate_file_path

    settings = get_config()
    file_path = settings.workspace / filename

    try:
        validated_path = validate_file_path(str(file_path))
    except Exception as e:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": str(e)},
        )

    # Extract IOCs
    iocs = {"urls": [], "ips": [], "emails": [], "strings": []}

    try:
        from reversecore_mcp.tools.malware.ioc_tools import extract_iocs

        result = await extract_iocs(str(validated_path))
        if result.status == "success" and isinstance(result.data, dict):
            iocs = result.data

    except Exception as e:
        iocs["error"] = str(e)

    return templates.TemplateResponse(
        "iocs.html",
        {
            "request": request,
            "filename": filename,
            "iocs": iocs,
        },
    )
