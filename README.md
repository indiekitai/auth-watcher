# auth-watcher 🔐

Monitor SSH login attempts on your server. See who's trying to break in.

Inspired by [Knock-Knock.net](https://knock-knock.net) - a visualization of server attacks that went viral on Hacker News.

## Installation

```bash
pip install auth-watcher
```

## Usage

```bash
# Show summary of all login attempts
auth-watcher --summary

# Real-time monitoring (like tail -f)
auth-watcher

# Show top 20 attackers
auth-watcher --top 20

# JSON output for scripts
auth-watcher --json
```

## Example Output

```
============================================================
🔐 AUTH-WATCHER 安全报告
============================================================

📊 总计:
   ❌ 失败登录: 8,523
   ✅ 成功登录: 42

🎯 Top 10 攻击者 IP:
   154.193.217.4        2048 次  ████████████████  (Los Angeles, US)
   103.145.88.12        1256 次  ██████████  (Shanghai, CN)
   45.33.32.156          892 次  ████████  (Singapore, SG)

👤 Top 10 被尝试的用户名:
   root                 3258 次  ████████████████████████████████
   admin                 688 次  ██████
   ubuntu                456 次  ████
   test                  234 次  ██
```

## Features

- 📊 **Summary stats** - Total failed/successful logins
- 🎯 **Top attackers** - IPs with most failed attempts + geolocation
- 👤 **Username analysis** - Most targeted usernames
- 👀 **Real-time watch** - Live monitoring with colored output
- 📋 **JSON export** - For scripts and automation

## Requirements

- Linux server with SSH
- Python 3.8+
- Root access (to read `/var/log/auth.log`)

## Supported Systems

- Ubuntu / Debian (`/var/log/auth.log`)
- RHEL / CentOS (`/var/log/secure`)
- Other Linux distros (use `--log` to specify path)

## Security Tips

If you're seeing thousands of failed logins (you probably are):

1. ✅ **Disable password auth** - Use SSH keys only
2. ✅ **Use fail2ban** - Auto-ban repeat offenders  
3. ✅ **Change SSH port** - Move away from 22
4. ✅ **Use a firewall** - Restrict access by IP

## License

MIT - Built by [IndieKit](https://indiekit.ai)
