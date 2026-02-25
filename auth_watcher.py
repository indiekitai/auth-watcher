#!/usr/bin/env python3
"""
auth-watcher: 实时监控服务器登录尝试

灵感来自 HN 热门项目 Knock-Knock.net (214分)
很多开发者想知道自己的服务器被谁在扫描/攻击

用法:
    python auth_watcher.py              # 实时监控
    python auth_watcher.py --summary    # 显示统计摘要
    python auth_watcher.py --top 10     # 显示 top 10 攻击者 IP
"""

import re
import sys
import json
import argparse
import subprocess
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# 常见的 auth log 位置
AUTH_LOG_PATHS = [
    "/var/log/auth.log",      # Ubuntu/Debian
    "/var/log/secure",        # RHEL/CentOS
    "/var/log/messages",      # 其他系统
]

# 解析失败登录的正则
FAILED_PATTERNS = [
    r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)",
    r"Invalid user (\S+) from (\S+) port (\d+)",
    r"Connection closed by authenticating user (\S+) (\S+) port (\d+)",
    r"Disconnected from authenticating user (\S+) (\S+) port (\d+)",
]

# 解析成功登录的正则
SUCCESS_PATTERNS = [
    r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)",
]


def find_auth_log():
    """查找系统的 auth log 文件"""
    for path in AUTH_LOG_PATHS:
        if Path(path).exists():
            return path
    return None


def parse_log_line(line):
    """解析单行日志，返回 (event_type, user, ip, port) 或 None"""
    for pattern in FAILED_PATTERNS:
        match = re.search(pattern, line)
        if match:
            groups = match.groups()
            if len(groups) >= 3:
                return ("failed", groups[0], groups[1], groups[2])
    
    for pattern in SUCCESS_PATTERNS:
        match = re.search(pattern, line)
        if match:
            groups = match.groups()
            if len(groups) >= 3:
                return ("success", groups[0], groups[1], groups[2])
    
    return None


def get_geo_info(ip):
    """获取 IP 地理位置（使用免费的 ip-api.com）"""
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=country,city,isp"
        with urllib.request.urlopen(url, timeout=2) as resp:
            data = json.loads(resp.read())
            if data.get("country"):
                return f"{data.get('city', '?')}, {data['country']}"
    except:
        pass
    return "Unknown"


def analyze_log(log_path, limit=None):
    """分析整个日志文件，返回统计信息"""
    failed_by_ip = Counter()
    failed_by_user = Counter()
    success_by_ip = Counter()
    timeline = defaultdict(int)
    
    try:
        with open(log_path, "r", errors="ignore") as f:
            for line in f:
                result = parse_log_line(line)
                if result:
                    event_type, user, ip, port = result
                    if event_type == "failed":
                        failed_by_ip[ip] += 1
                        failed_by_user[user] += 1
                        # 提取日期
                        date_match = re.match(r"(\w{3}\s+\d+)", line)
                        if date_match:
                            timeline[date_match.group(1)] += 1
                    else:
                        success_by_ip[ip] += 1
    except PermissionError:
        print(f"❌ 需要 root 权限读取 {log_path}")
        print("   请使用: sudo python auth_watcher.py")
        sys.exit(1)
    
    return {
        "failed_by_ip": failed_by_ip,
        "failed_by_user": failed_by_user,
        "success_by_ip": success_by_ip,
        "timeline": dict(timeline),
        "total_failed": sum(failed_by_ip.values()),
        "total_success": sum(success_by_ip.values()),
    }


def print_summary(stats, top_n=10):
    """打印统计摘要"""
    print("\n" + "=" * 60)
    print("🔐 AUTH-WATCHER 安全报告")
    print("=" * 60)
    
    print(f"\n📊 总计:")
    print(f"   ❌ 失败登录: {stats['total_failed']:,}")
    print(f"   ✅ 成功登录: {stats['total_success']:,}")
    
    if stats['failed_by_ip']:
        print(f"\n🎯 Top {top_n} 攻击者 IP:")
        for ip, count in stats['failed_by_ip'].most_common(top_n):
            geo = get_geo_info(ip)
            bar = "█" * min(count // 10, 30)
            print(f"   {ip:18} {count:>6} 次  {bar}  ({geo})")
    
    if stats['failed_by_user']:
        print(f"\n👤 Top {top_n} 被尝试的用户名:")
        for user, count in stats['failed_by_user'].most_common(top_n):
            bar = "█" * min(count // 10, 30)
            print(f"   {user:18} {count:>6} 次  {bar}")
    
    print("\n" + "=" * 60)


def watch_realtime(log_path):
    """实时监控日志（类似 tail -f）"""
    print(f"👀 正在监控 {log_path} ...")
    print("   按 Ctrl+C 退出\n")
    
    try:
        process = subprocess.Popen(
            ["tail", "-f", log_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        for line in process.stdout:
            result = parse_log_line(line)
            if result:
                event_type, user, ip, port = result
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                if event_type == "failed":
                    print(f"❌ [{timestamp}] 失败: {user}@{ip}:{port}")
                else:
                    print(f"✅ [{timestamp}] 成功: {user}@{ip}:{port}")
    
    except KeyboardInterrupt:
        print("\n\n👋 退出监控")
        process.terminate()


def main():
    parser = argparse.ArgumentParser(
        description="监控服务器 SSH 登录尝试",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    auth_watcher.py              # 实时监控
    auth_watcher.py --summary    # 显示摘要
    auth_watcher.py --top 20     # 显示 top 20
    auth_watcher.py --json       # JSON 输出
        """
    )
    parser.add_argument("--summary", "-s", action="store_true", help="显示统计摘要")
    parser.add_argument("--top", "-t", type=int, default=10, help="显示 top N (默认 10)")
    parser.add_argument("--json", "-j", action="store_true", help="JSON 格式输出")
    parser.add_argument("--log", "-l", type=str, help="指定日志文件路径")
    
    args = parser.parse_args()
    
    # 查找日志文件
    log_path = args.log or find_auth_log()
    if not log_path:
        print("❌ 找不到 auth log 文件")
        print("   请使用 --log 指定路径")
        sys.exit(1)
    
    if args.summary or args.json:
        stats = analyze_log(log_path)
        if args.json:
            output = {
                "total_failed": stats["total_failed"],
                "total_success": stats["total_success"],
                "top_attackers": dict(stats["failed_by_ip"].most_common(args.top)),
                "top_usernames": dict(stats["failed_by_user"].most_common(args.top)),
            }
            print(json.dumps(output, indent=2))
        else:
            print_summary(stats, args.top)
    else:
        watch_realtime(log_path)


if __name__ == "__main__":
    main()
