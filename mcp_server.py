#!/usr/bin/env python3
"""
auth-watcher MCP Server

Monitor SSH login attempts on your server.
"""

import json
import sys

from auth_watcher import find_auth_log, analyze_log, get_geo_info

try:
    from fastmcp import FastMCP
    mcp = FastMCP("auth-watcher")
    HAS_MCP = True
except ImportError:
    HAS_MCP = False
    class DummyMCP:
        def tool(self):
            def decorator(f):
                return f
            return decorator
    mcp = DummyMCP()


@mcp.tool()
def auth_watcher_summary(top: int = 10) -> str:
    """
    Get a summary of SSH login attempts on this server.
    
    Returns failed/successful login counts, top attacking IPs,
    and most targeted usernames.
    
    Args:
        top: Number of top attackers/usernames to return (default: 10)
    
    Requires sudo/root to read /var/log/auth.log
    """
    log_path = find_auth_log()
    if not log_path:
        return json.dumps({
            "error": "No auth log found",
            "hint": "Checked: /var/log/auth.log, /var/log/secure, /var/log/messages",
        })
    
    try:
        stats = analyze_log(log_path)
        
        # Get top IPs with geo
        top_ips = []
        for ip, count in stats["failed_by_ip"].most_common(top):
            geo = get_geo_info(ip)
            top_ips.append({
                "ip": ip,
                "attempts": count,
                "location": geo,
            })
        
        # Get top usernames
        top_users = [
            {"username": user, "attempts": count}
            for user, count in stats["failed_by_user"].most_common(top)
        ]
        
        return json.dumps({
            "log_file": log_path,
            "total_failed": stats["total_failed"],
            "total_success": stats["total_success"],
            "unique_attackers": len(stats["failed_by_ip"]),
            "top_attackers": top_ips,
            "top_usernames": top_users,
        }, indent=2)
        
    except PermissionError:
        return json.dumps({
            "error": "Permission denied",
            "hint": "Run with sudo/root to read auth log",
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def auth_watcher_ip(ip: str) -> str:
    """
    Check login attempts from a specific IP address.
    
    Args:
        ip: IP address to check
    """
    log_path = find_auth_log()
    if not log_path:
        return json.dumps({"error": "No auth log found"})
    
    try:
        stats = analyze_log(log_path)
        
        failed_count = stats["failed_by_ip"].get(ip, 0)
        success_count = stats["success_by_ip"].get(ip, 0)
        
        if failed_count == 0 and success_count == 0:
            return json.dumps({
                "ip": ip,
                "found": False,
                "message": "No login attempts from this IP",
            })
        
        geo = get_geo_info(ip) if failed_count > 0 else "N/A"
        
        return json.dumps({
            "ip": ip,
            "found": True,
            "failed_attempts": failed_count,
            "successful_logins": success_count,
            "location": geo,
            "threat_level": "high" if failed_count > 100 else ("medium" if failed_count > 10 else "low"),
        }, indent=2)
        
    except PermissionError:
        return json.dumps({"error": "Permission denied - run as root"})
    except Exception as e:
        return json.dumps({"error": str(e)})


def main():
    if not HAS_MCP:
        print("Error: fastmcp not installed.", file=sys.stderr)
        print("Install with: pip install fastmcp", file=sys.stderr)
        sys.exit(1)
    mcp.run()


if __name__ == "__main__":
    main()
