[English](README.md) | [中文](README.zh-CN.md)

# auth-watcher 🔐

监控服务器上的 SSH 登录尝试，看看谁在试图入侵你的机器。

灵感来自 [Knock-Knock.net](https://knock-knock.net)——一个在 Hacker News 上火过的服务器攻击可视化项目。

## 安装

```bash
pip install auth-watcher
```

## 使用

```bash
# 显示所有登录尝试的摘要
auth-watcher --summary

# 实时监控（类似 tail -f）
auth-watcher

# 显示 Top 20 攻击者
auth-watcher --top 20

# JSON 输出，方便脚本处理
auth-watcher --json
```

## 输出示例

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

## 功能

- 📊 **统计摘要** - 失败/成功登录总数
- 🎯 **攻击者排行** - 失败次数最多的 IP + 地理位置
- 👤 **用户名分析** - 最常被尝试的用户名
- 👀 **实时监控** - 彩色输出的实时日志
- 📋 **JSON 导出** - 方便脚本和自动化使用

## 系统要求

- Linux 服务器（需要 SSH）
- Python 3.8+
- Root 权限（需要读取 `/var/log/auth.log`）

## 支持的系统

- Ubuntu / Debian（`/var/log/auth.log`）
- RHEL / CentOS（`/var/log/secure`）
- 其他 Linux 发行版（用 `--log` 指定日志路径）

## 安全建议

如果你看到成千上万的失败登录（大概率是这样）：

1. ✅ **禁用密码认证** - 仅使用 SSH 密钥
2. ✅ **使用 fail2ban** - 自动封禁重复攻击者
3. ✅ **修改 SSH 端口** - 不要用默认的 22
4. ✅ **配置防火墙** - 按 IP 限制访问

## License

MIT - Built by [IndieKit](https://indiekit.ai)
