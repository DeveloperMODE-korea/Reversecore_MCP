"""
Game Client Analysis Tools for Cheat Detection and Security Research.

This module provides specialized tools for analyzing game clients:
- Cheat Point Finder: Identifies potential memory/speed/teleport hack locations
- Game Protocol Analyzer: Extracts packet structures and handlers
- Anti-Cheat Profiler: Detects protection mechanisms
"""

from typing import Any

from fastmcp import Context

from reversecore_mcp.core import json_utils as json
from reversecore_mcp.core.decorators import log_execution
from reversecore_mcp.core.error_handling import handle_tool_errors
from reversecore_mcp.core.execution import execute_subprocess_async
from reversecore_mcp.core.logging_config import get_logger
from reversecore_mcp.core.metrics import track_metrics
from reversecore_mcp.core.r2_helpers import (
    build_r2_cmd as _build_r2_cmd,
)
from reversecore_mcp.core.r2_helpers import (
    calculate_dynamic_timeout,
)
from reversecore_mcp.core.r2_helpers import (
    parse_json_output as _parse_json_output,
)
from reversecore_mcp.core.result import ToolResult, success
from reversecore_mcp.core.security import validate_file_path

logger = get_logger(__name__)

# =============================================================================
# Cheat Categories and Target Functions
# =============================================================================

# Speed Hack: Time-related functions that can be hooked/modified
_SPEED_HACK_TARGETS = frozenset(
    {
        # Windows time functions
        "GetTickCount",
        "GetTickCount64",
        "timeGetTime",
        "QueryPerformanceCounter",
        "QueryPerformanceFrequency",
        # Sleep/delay manipulation
        "Sleep",
        "SleepEx",
        "NtDelayExecution",
        # High-precision timers
        "timeBeginPeriod",
        "timeEndPeriod",
        # Game-specific common names
        "GetTime",
        "GetGameTime",
        "GetDeltaTime",
        "UpdateTime",
    }
)

# Teleport/Position Hack: Movement and position functions
_TELEPORT_TARGETS = frozenset(
    {
        # Common game function patterns
        "SetPosition",
        "SetPos",
        "MoveTo",
        "Teleport",
        "Warp",
        "UpdatePosition",
        "SyncPosition",
        "SetCoord",
        "SetLocation",
        # Physics/collision
        "SetVelocity",
        "ApplyForce",
        "SetSpeed",
        # Network position sync
        "SendPosition",
        "RecvPosition",
        "PosSync",
        "MoveSync",
    }
)

# God Mode: Damage and health functions
_GOD_MODE_TARGETS = frozenset(
    {
        # Damage functions
        "TakeDamage",
        "ApplyDamage",
        "OnDamage",
        "ReceiveDamage",
        "DealDamage",
        "ProcessDamage",
        "CalcDamage",
        # Health functions
        "SetHealth",
        "SetHP",
        "ModifyHealth",
        "AddHealth",
        "SubHealth",
        "Die",
        "OnDeath",
        "Kill",
        "Respawn",
        # Invincibility
        "SetInvincible",
        "SetGodMode",
        "SetImmortal",
    }
)

# Item Duplication: Inventory and item functions
_ITEM_DUPE_TARGETS = frozenset(
    {
        # Item creation
        "AddItem",
        "CreateItem",
        "SpawnItem",
        "GiveItem",
        "AddToInventory",
        "InsertItem",
        # Item quantity
        "SetItemCount",
        "SetQuantity",
        "ModifyStack",
        "AddGold",
        "SetGold",
        "AddMoney",
        "SetMoney",
        # Item transfer
        "DropItem",
        "TradeItem",
        "SendItem",
        "UseItem",
    }
)

# Wall Hack / No Clip: Collision and visibility
_WALLHACK_TARGETS = frozenset(
    {
        # Collision
        "CheckCollision",
        "TestCollision",
        "RayTrace",
        "Raycast",
        "SetCollision",
        "EnableCollision",
        "DisableCollision",
        # Visibility
        "IsVisible",
        "CheckVisibility",
        "LineOfSight",
        "CanSee",
        # Clipping
        "SetClip",
        "NoClip",
        "SetSolid",
    }
)

# Anti-cheat detection functions
_ANTICHEAT_SIGNATURES = frozenset(
    {
        # Common anti-cheat APIs
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugString",
        # Memory protection
        "VirtualProtect",
        "VirtualQuery",
        "ReadProcessMemory",
        "WriteProcessMemory",
        "NtReadVirtualMemory",
        # Integrity checks
        "GetModuleHandle",
        "GetProcAddress",
        "CRC32",
        "MD5",
        "SHA1",
        "CheckSum",
        # Known anti-cheat vendors
        "GameGuard",
        "nProtect",
        "HackShield",
        "EasyAntiCheat",
        "BattlEye",
        "PunkBuster",
        "VAC",
        "Themida",
        "VMProtect",
    }
)

# All cheat categories combined
_ALL_CHEAT_TARGETS = {
    "speed_hack": _SPEED_HACK_TARGETS,
    "teleport": _TELEPORT_TARGETS,
    "god_mode": _GOD_MODE_TARGETS,
    "item_dupe": _ITEM_DUPE_TARGETS,
    "wallhack": _WALLHACK_TARGETS,
}


# =============================================================================
# Cheat Point Finder Tool
# =============================================================================


@log_execution(tool_name="find_cheat_points")
@track_metrics("find_cheat_points")
@handle_tool_errors
async def find_cheat_points(
    file_path: str,
    categories: list[str] | None = None,
    include_strings: bool = True,
    include_imports: bool = True,
    max_results_per_category: int = 20,
    timeout: int | None = None,
    ctx: Context = None,
) -> ToolResult:
    """
    Find potential cheat points in a game client binary.

    This tool combines multiple analysis techniques to identify locations
    where game mechanics could be manipulated (speed hacks, god mode, etc.).

    **Analysis Methods:**
    1. Import table scanning for known vulnerable APIs
    2. String pattern matching for game-specific functions
    3. Cross-reference analysis to find callers

    **Cheat Categories:**
    - `speed_hack`: Time manipulation (GetTickCount, Sleep hooks)
    - `teleport`: Position/movement manipulation
    - `god_mode`: Health/damage manipulation
    - `item_dupe`: Inventory/currency manipulation
    - `wallhack`: Collision/visibility manipulation

    Args:
        file_path: Path to the game executable
        categories: List of cheat categories to search (default: all)
        include_strings: Search for patterns in strings (default: True)
        include_imports: Search in import table (default: True)
        max_results_per_category: Maximum results per category (default: 20)
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with categorized cheat points and exploitation hints.

    Example:
        find_cheat_points("/app/workspace/game.exe", categories=["speed_hack", "god_mode"])
    """
    validated_path = validate_file_path(file_path)
    effective_timeout = (
        timeout if timeout else calculate_dynamic_timeout(str(validated_path), base_timeout=60)
    )

    # Determine which categories to search
    if categories:
        search_categories = {
            cat: targets for cat, targets in _ALL_CHEAT_TARGETS.items() if cat in categories
        }
    else:
        search_categories = _ALL_CHEAT_TARGETS

    if ctx:
        await ctx.info(f"🎮 Scanning for cheat points in {len(search_categories)} categories...")

    results: dict[str, list[dict[str, Any]]] = {cat: [] for cat in search_categories}
    anticheat_detected: list[dict[str, Any]] = []

    # Step 1: Analyze imports
    if include_imports:
        if ctx:
            await ctx.info("📦 Analyzing import table...")

        cmd = _build_r2_cmd(str(validated_path), ["iij"], "-n")  # Fast: no analysis needed
        out, _ = await execute_subprocess_async(cmd, timeout=effective_timeout)

        try:
            imports = _parse_json_output(out)
            if isinstance(imports, list):
                for imp in imports:
                    if not isinstance(imp, dict):
                        continue

                    func_name = imp.get("name", "")
                    func_addr = imp.get("plt", imp.get("vaddr", 0))

                    # Check against cheat targets
                    for category, targets in search_categories.items():
                        if len(results[category]) >= max_results_per_category:
                            continue

                        for target in targets:
                            if target.lower() in func_name.lower():
                                results[category].append(
                                    {
                                        "name": func_name,
                                        "address": hex(func_addr)
                                        if isinstance(func_addr, int)
                                        else func_addr,
                                        "source": "import",
                                        "target_pattern": target,
                                        "exploitation_hint": _get_exploitation_hint(
                                            category, target
                                        ),
                                    }
                                )
                                break

                    # Check for anti-cheat signatures
                    for sig in _ANTICHEAT_SIGNATURES:
                        if sig.lower() in func_name.lower():
                            anticheat_detected.append(
                                {
                                    "name": func_name,
                                    "address": hex(func_addr)
                                    if isinstance(func_addr, int)
                                    else func_addr,
                                    "type": "import",
                                    "signature": sig,
                                }
                            )
                            break

        except (json.JSONDecodeError, TypeError):
            logger.warning("Failed to parse import table")

    # Step 2: Analyze strings
    if include_strings:
        if ctx:
            await ctx.info("🔤 Analyzing strings for game function patterns...")

        cmd = _build_r2_cmd(str(validated_path), ["izj"], "-n")
        out, _ = await execute_subprocess_async(cmd, timeout=effective_timeout)

        try:
            strings = _parse_json_output(out)
            if isinstance(strings, list):
                for s in strings:
                    if not isinstance(s, dict):
                        continue

                    string_value = s.get("string", "")
                    string_addr = s.get("vaddr", 0)

                    # Skip very short strings
                    if len(string_value) < 4:
                        continue

                    # Check against cheat targets
                    for category, targets in search_categories.items():
                        if len(results[category]) >= max_results_per_category:
                            continue

                        for target in targets:
                            if target.lower() in string_value.lower():
                                results[category].append(
                                    {
                                        "name": string_value[:50],  # Truncate long strings
                                        "address": hex(string_addr)
                                        if isinstance(string_addr, int)
                                        else string_addr,
                                        "source": "string",
                                        "target_pattern": target,
                                        "exploitation_hint": _get_exploitation_hint(
                                            category, target
                                        ),
                                    }
                                )
                                break

                    # Check for anti-cheat strings
                    for sig in _ANTICHEAT_SIGNATURES:
                        if sig.lower() in string_value.lower():
                            anticheat_detected.append(
                                {
                                    "name": string_value[:50],
                                    "address": hex(string_addr)
                                    if isinstance(string_addr, int)
                                    else string_addr,
                                    "type": "string",
                                    "signature": sig,
                                }
                            )
                            break

        except (json.JSONDecodeError, TypeError):
            logger.warning("Failed to parse strings")

    # Step 3: Find xrefs for high-value targets (speed hack is most common)
    if "speed_hack" in results and results["speed_hack"]:
        if ctx:
            await ctx.info("🔍 Tracing cross-references for speed hack targets...")

        for point in results["speed_hack"][:5]:  # Limit to first 5
            addr = point.get("address", "")
            if not addr:
                continue

            cmd = _build_r2_cmd(str(validated_path), [f"axtj @ {addr}"], "aa")
            out, _ = await execute_subprocess_async(cmd, timeout=30)

            try:
                xrefs = _parse_json_output(out)
                if isinstance(xrefs, list) and xrefs:
                    point["callers"] = [
                        {
                            "address": hex(x.get("from", 0)),
                            "function": x.get("fcn_name", "unknown"),
                        }
                        for x in xrefs[:5]
                        if isinstance(x, dict)
                    ]
            except (json.JSONDecodeError, TypeError):
                pass

    # Calculate summary statistics
    total_points = sum(len(v) for v in results.values())
    categories_with_findings = [cat for cat, points in results.items() if points]

    # Determine overall cheat difficulty
    cheat_difficulty = _calculate_cheat_difficulty(results, anticheat_detected)

    return success(
        {
            "cheat_points": results,
            "anticheat_detected": anticheat_detected,
            "summary": {
                "total_points_found": total_points,
                "categories_with_findings": categories_with_findings,
                "anticheat_signatures": len(anticheat_detected),
                "cheat_difficulty": cheat_difficulty,
            },
        },
        total_points=total_points,
        categories_searched=list(search_categories.keys()),
        anticheat_count=len(anticheat_detected),
        description=f"Found {total_points} potential cheat points across {len(categories_with_findings)} categories",
    )


def _get_exploitation_hint(category: str, target: str) -> str:
    """Generate exploitation hints based on category and target function."""
    hints = {
        "speed_hack": {
            "GetTickCount": "Hook and return modified tick count (multiply/divide for speed)",
            "Sleep": "NOP or reduce sleep duration for speed boost",
            "QueryPerformanceCounter": "Manipulate high-precision timer values",
            "default": "Intercept time function and modify return value",
        },
        "teleport": {
            "SetPosition": "Call directly with desired coordinates",
            "Teleport": "Find coordinate parameters and modify before call",
            "default": "Locate position struct and modify X/Y/Z values",
        },
        "god_mode": {
            "TakeDamage": "Hook and return 0 or NOP the damage application",
            "SetHealth": "Call with max value or hook to prevent decrease",
            "default": "Find health variable and freeze or set to max",
        },
        "item_dupe": {
            "AddItem": "Call multiple times or modify quantity parameter",
            "SetGold": "Call with desired amount",
            "default": "Locate item/gold memory and modify directly",
        },
        "wallhack": {
            "CheckCollision": "Hook and always return false (no collision)",
            "IsVisible": "Hook and always return true",
            "default": "Disable collision checks or force visibility",
        },
    }

    category_hints = hints.get(category, {})
    return category_hints.get(
        target, category_hints.get("default", "Analyze function for modification")
    )


def _calculate_cheat_difficulty(
    results: dict[str, list[dict]],
    anticheat: list[dict],
) -> str:
    """Calculate overall cheat development difficulty."""
    total_points = sum(len(v) for v in results.values())

    # More anti-cheat = harder
    anticheat_score = len(anticheat) * 2

    # More cheat points = easier (more attack surface)
    point_score = min(total_points // 5, 10)

    # Known vendor anti-cheat = much harder
    vendor_keywords = ["gameguard", "battleye", "easyanticheat", "vac", "punkbuster"]
    for ac in anticheat:
        if any(v in ac.get("name", "").lower() for v in vendor_keywords):
            anticheat_score += 5

    difficulty_score = anticheat_score - point_score

    if difficulty_score >= 10:
        return "Very Hard (Professional anti-cheat detected)"
    elif difficulty_score >= 5:
        return "Hard (Multiple protection mechanisms)"
    elif difficulty_score >= 0:
        return "Medium (Some protections present)"
    else:
        return "Easy (Minimal protection, many attack vectors)"


# =============================================================================
# Game Protocol Analyzer Tool
# =============================================================================


@log_execution(tool_name="analyze_game_protocol")
@track_metrics("analyze_game_protocol")
@handle_tool_errors
async def analyze_game_protocol(
    file_path: str,
    packet_prefixes: list[str] | None = None,
    timeout: int | None = None,
    ctx: Context = None,
) -> ToolResult:
    """
    Analyze game network protocol by extracting packet structures and handlers.

    This tool identifies packet naming patterns, handler functions, and
    potential encryption/serialization routines.

    **Detection Methods:**
    1. String pattern matching for packet names (Pd*, Pu*, Pq*, etc.)
    2. Network API (send/recv) cross-reference analysis
    3. Handler table detection via function pointer arrays

    Args:
        file_path: Path to the game executable
        packet_prefixes: Custom packet prefixes to search (default: common patterns)
        timeout: Execution timeout in seconds

    Returns:
        ToolResult with packet handlers, network functions, and protocol hints.

    Example:
        analyze_game_protocol("/app/workspace/game.exe", packet_prefixes=["Pd", "Pu", "Pq"])
    """
    validated_path = validate_file_path(file_path)
    effective_timeout = (
        timeout if timeout else calculate_dynamic_timeout(str(validated_path), base_timeout=60)
    )

    # Default packet prefixes (common in Korean/Asian MMOs)
    if not packet_prefixes:
        packet_prefixes = [
            "Pd",
            "Pu",
            "Pq",
            "Ps",  # Common Korean MMO patterns
            "CS_",
            "SC_",  # Client-Server, Server-Client
            "MSG_",
            "PKT_",
            "PACKET_",  # Generic patterns
            "REQ_",
            "RES_",
            "ACK_",
            "NOTIFY_",  # Request/Response patterns
        ]

    if ctx:
        await ctx.info(f"📡 Analyzing game protocol with {len(packet_prefixes)} prefix patterns...")

    packets_found: list[dict[str, Any]] = []
    network_functions: list[dict[str, Any]] = []

    # Step 1: Extract strings matching packet patterns
    cmd = _build_r2_cmd(str(validated_path), ["izj"], "-n")
    out, _ = await execute_subprocess_async(cmd, timeout=effective_timeout)

    try:
        strings = _parse_json_output(out)
        if isinstance(strings, list):
            for s in strings:
                if not isinstance(s, dict):
                    continue

                string_value = s.get("string", "")
                string_addr = s.get("vaddr", 0)

                # Check if string matches any packet prefix
                for prefix in packet_prefixes:
                    if string_value.startswith(prefix) and len(string_value) < 50:
                        # Categorize packet type
                        packet_type = _categorize_packet(string_value)
                        packets_found.append(
                            {
                                "name": string_value,
                                "address": hex(string_addr)
                                if isinstance(string_addr, int)
                                else string_addr,
                                "prefix": prefix,
                                "type": packet_type,
                            }
                        )
                        break

    except (json.JSONDecodeError, TypeError):
        logger.warning("Failed to parse strings for protocol analysis")

    # Step 2: Find network-related imports
    cmd = _build_r2_cmd(str(validated_path), ["iij"], "-n")
    out, _ = await execute_subprocess_async(cmd, timeout=effective_timeout)

    network_apis = [
        "send",
        "recv",
        "WSASend",
        "WSARecv",
        "sendto",
        "recvfrom",
        "connect",
        "accept",
        "socket",
        "WSAStartup",
    ]

    try:
        imports = _parse_json_output(out)
        if isinstance(imports, list):
            for imp in imports:
                if not isinstance(imp, dict):
                    continue

                func_name = imp.get("name", "")
                func_addr = imp.get("plt", imp.get("vaddr", 0))

                for api in network_apis:
                    if api.lower() in func_name.lower():
                        network_functions.append(
                            {
                                "name": func_name,
                                "address": hex(func_addr)
                                if isinstance(func_addr, int)
                                else func_addr,
                                "api_type": api,
                                "hint": _get_network_hint(api),
                            }
                        )
                        break

    except (json.JSONDecodeError, TypeError):
        logger.warning("Failed to parse imports for network analysis")

    # Categorize packets
    packet_categories: dict[str, list[str]] = {}
    for pkt in packets_found:
        ptype = pkt.get("type", "unknown")
        if ptype not in packet_categories:
            packet_categories[ptype] = []
        packet_categories[ptype].append(pkt.get("name", ""))

    return success(
        {
            "packets": packets_found[:100],  # Limit output
            "packet_categories": packet_categories,
            "network_functions": network_functions,
            "summary": {
                "total_packets": len(packets_found),
                "total_network_functions": len(network_functions),
                "packet_types": list(packet_categories.keys()),
            },
            "analysis_hints": [
                "Look for send() callers to find packet building functions",
                "Look for recv() callers to find packet parsing functions",
                "Packet handlers often stored in dispatch tables (function pointer arrays)",
            ],
        },
        total_packets=len(packets_found),
        total_network_functions=len(network_functions),
        description=f"Found {len(packets_found)} packet patterns and {len(network_functions)} network functions",
    )


def _categorize_packet(packet_name: str) -> str:
    """Categorize a packet based on its name."""
    name_lower = packet_name.lower()

    if any(k in name_lower for k in ["move", "pos", "position", "coord", "location"]):
        return "movement"
    elif any(k in name_lower for k in ["chat", "msg", "whisper", "say", "shout"]):
        return "chat"
    elif any(k in name_lower for k in ["skill", "cast", "spell", "ability"]):
        return "combat"
    elif any(k in name_lower for k in ["item", "inventory", "equip", "loot"]):
        return "inventory"
    elif any(k in name_lower for k in ["login", "auth", "logout", "connect"]):
        return "authentication"
    elif any(k in name_lower for k in ["npc", "quest", "shop", "trade"]):
        return "interaction"
    elif any(k in name_lower for k in ["party", "guild", "friend", "group"]):
        return "social"
    elif any(k in name_lower for k in ["zone", "map", "warp", "teleport"]):
        return "world"
    else:
        return "unknown"


def _get_network_hint(api: str) -> str:
    """Get analysis hint for a network API."""
    hints = {
        "send": "Find callers to locate packet serialization",
        "recv": "Find callers to locate packet deserialization",
        "WSASend": "Async send - look for completion callbacks",
        "WSARecv": "Async recv - look for completion callbacks",
        "connect": "Find server IP/port configuration",
        "socket": "Identify protocol (TCP/UDP)",
    }
    return hints.get(api, "Analyze cross-references")


# =============================================================================
# Plugin Registration
# =============================================================================

# Plugin import at bottom to avoid circular imports
from reversecore_mcp.core.plugin import Plugin  # noqa: E402


class GameAnalysisPlugin(Plugin):
    """Plugin for game client analysis tools."""

    @property
    def name(self) -> str:
        return "game_analysis"

    @property
    def description(self) -> str:
        return "Specialized tools for game client security analysis and cheat detection."

    def register(self, mcp_server: Any) -> None:
        """Register game analysis tools."""
        mcp_server.tool(find_cheat_points)
        mcp_server.tool(analyze_game_protocol)
