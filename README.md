# 🔐 OpenVPN Admin

> 基于 Flask 的 OpenVPN Web 管理面板 — 用户管理、密钥签发、服务控制、在线配置编辑，一站式搞定。

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-green.svg)](https://flask.palletsprojects.com/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## ✨ 功能概览

| 模块 | 能力 | 角色权限 |
|------|------|----------|
| 📊 **仪表盘** | 用户数 / 活跃密钥 / OpenVPN 运行状态 / 实时已连接客户端 | 所有用户 |
| 👥 **用户管理** | 创建、删除、启用/禁用、密码重置、角色分配 | `admin` |
| 🔑 **密钥管理** | 签发客户端证书、生成 `.ovpn` 配置文件、吊销证书、一键下载 | `admin` / `operator` |
| ⚙️ **服务管理** | 启动 / 停止 / 重启 OpenVPN 服务 + 主机资源监控 | `admin` / `operator` |
| 📝 **配置编辑** | 在线编辑 `server.conf`、自动备份、历史版本追溯 | `admin` |
| 📋 **审计日志** | 所有操作全量记录（登录/创建密钥/修改配置等），分页筛选 | 所有用户 |
| 📜 **服务日志** | 实时查看 OpenVPN 运行日志（tail 模式） | 所有用户 |
| 👤 **个人设置** | 修改密码、查看账户信息 | 所有用户 |

**三级角色体系：**
- `admin` — 全权限
- `operator` — 密钥管理 + 服务控制
- `viewer` — 只读

---

## 🏗️ 架构

```
┌─────────────────────────────────────────────────────┐
│                    浏览器 (HTTPS)                    │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│              Gunicorn + Flask (容器化)               │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │  auth.py │  │  app.py  │  │  database.py      │  │
│  │  认证/鉴权 │  │  路由/业务 │  │  SQLite (WAL模式)  │  │
│  └──────────┘  └────┬─────┘  └───────────────────┘  │
│                     │                               │
│            ┌────────▼────────┐                      │
│            │  openvpn/       │                      │
│            │  SSH (paramiko) │                      │
│            └────────┬────────┘                      │
└─────────────────────┼───────────────────────────────┘
                      │ SSH
┌─────────────────────▼───────────────────────────────┐
│                OpenVPN 服务器                        │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │ systemd  │  │ EasyRSA  │  │ server.conf       │  │
│  │ 服务控制  │  │ 证书管理  │  │ 配置读写           │  │
│  └──────────┘  └──────────┘  └───────────────────┘  │
└─────────────────────────────────────────────────────┘
```

**技术栈：**
- **Backend:** Flask 3.x + Gunicorn
- **认证:** bcrypt + Session (Flask session)
- **数据库:** SQLite (WAL 模式, 外键约束)
- **远程管理:** Paramiko SSH
- **前端:** 原生 HTML/CSS/JS（零框架依赖），暗色主题

---

## 🚀 快速开始

### 前置条件

- Python 3.11+
- 一台运行 OpenVPN + EasyRSA 的服务器（可通过 SSH 访问）
- SSH 密钥或密码

### 本地开发

```bash
# 1. 克隆 & 进入目录
cd /data/openvpn-admin

# 2. 创建虚拟环境 & 安装依赖
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3. 配置环境变量
export SECRET_KEY="$(openssl rand -hex 32)"
export OPENVPN_HOST="192.168.3.147"      # OpenVPN 服务器 IP
export OPENVPN_SSH_USER="root"
export OPENVPN_SSH_KEY="/path/to/id_rsa"  # 或设置 OPENVPN_SSH_PASSWORD="..."

# 4. 启动
python app.py
# 访问 http://localhost:5000
# 默认账户: admin / admin123
```

### Docker 部署

```bash
# 创建 SSH 密钥目录
mkdir -p ./keys
# 将 SSH 私钥放入 ./keys/id_rsa

# 构建镜像
docker build -t openvpn-admin .

# 运行
docker run -d \
  --name openvpn-admin \
  -p 7000:5000 \
  -v $(pwd)/keys:/app/keys:ro \
  -v $(pwd)/data:/app/data \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e OPENVPN_HOST="192.168.3.147" \
  -e OPENVPN_SSH_USER="root" \
  -e OPENVPN_SSH_KEY="/app/keys/id_rsa" \
  -e ADMIN_PASSWORD="your-secure-password" \
  openvpn-admin
```

### Docker Compose

```yaml
# docker-compose.yml
services:
  openvpn-admin:
    build: .
    ports:
      - "7000:5000"
    volumes:
      - ./keys:/app/keys:ro
      - ./data:/app/data
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - OPENVPN_HOST=192.168.3.147
      - OPENVPN_SSH_USER=root
      - OPENVPN_SSH_KEY=/app/keys/id_rsa
      - ADMIN_PASSWORD=admin123
    restart: unless-stopped
```

---

## ⚙️ 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `SECRET_KEY` | Flask 会话密钥（**必填，生产环境**） | 随机值 |
| `ADMIN_PASSWORD` | 初始 admin 密码 | `admin123` |
| `OPENVPN_HOST` | OpenVPN 服务器 IP/域名 | `192.168.3.147` |
| `OPENVPN_SSH_PORT` | SSH 端口 | `22` |
| `OPENVPN_SSH_USER` | SSH 用户名 | `root` |
| `OPENVPN_SSH_KEY` | SSH 私钥路径 | `/app/keys/id_rsa` |
| `OPENVPN_SSH_PASSWORD` | SSH 密码（备选） | 空 |
| `OPENVPN_SERVICE` | OpenVPN systemd 单元名 | `openvpn@server` |
| `OPENVPN_CONFIG` | server.conf 路径 | `/etc/openvpn/server/server.conf` |
| `OPENVPN_EASYRSA_DIR` | EasyRSA 安装目录 | `/etc/openvpn/easy-rsa` |
| `OPENVPN_CLIENT_DIR` | 客户端配置输出目录 | `/etc/openvpn/client-configs` |
| `SESSION_TIMEOUT` | 会话超时（秒） | `3600` |
| `HOST` | 监听地址 | `0.0.0.0` |
| `PORT` | 监听端口 | `5000` |
| `DEBUG` | 调试模式 | `false` |

---

## 📸 界面预览

### 仪表盘

```
╔══════════════════════════════════════════════════════════════╗
║  🔐 OpenVPN Admin    📊仪表盘  👥用户  🔑密钥  ...    admin 🚪 ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  ╔══════════╗  ╔══════════╗  ╔══════════╗  ╔══════════╗     ║
║  ║   5      ║  ║   23     ║  ║   3      ║  ║   2      ║     ║
║  ║  用户    ║  ║  活跃密钥 ║  ║  已吊销  ║  ║  在线客户 ║     ║
║  ╚══════════╝  ╚══════════╝  ╚══════════╝  ╚══════════╝     ║
║                                                              ║
║  ⚙️ OpenVPN 服务状态                                         ║
║  🟢 运行中  |  服务: openvpn@server  |  主机: 192.168.3.147  ║
║                                                              ║
║  📋 最近审计日志                                              ║
║  ┌─────────────────────────────────────────────────────────┐ ║
║  │ 2024-01-15 09:30  admin     create_key   cn=zhangsan    │ ║
║  │ 2024-01-15 09:25  operator  restart_svc  success=True   │ ║
║  │ 2024-01-15 09:20  admin     login         role=admin    │ ║
║  └─────────────────────────────────────────────────────────┘ ║
╚══════════════════════════════════════════════════════════════╝
```

### 密钥管理

```
╔══════════════════════════════════════════════════════════════╗
║  🔑 密钥管理                     [+ 签发新密钥]              ║
╠══════════════════════════════════════════════════════════════╣
║  客户端名称: [___________]  描述: [___________]  [签发]     ║
╠══════════════════════════════════════════════════════════════╣
║  Common Name   状态    签发者   签发时间          操作       ║
║  ──────────────────────────────────────────────────────────  ║
║  zhangsan      🟢 活跃  admin   2024-01-15 09:30  ⬇下载 🗑吊销║
║  lisi          🟢 活跃  admin   2024-01-14 14:20  ⬇下载 🗑吊销║
║  wangwu        🔴 吊销  operator 2024-01-10 08:00  —        ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 🔧 OpenVPN 服务器准备

管理面板通过 SSH 连接 OpenVPN 服务器，需要目标服务器上安装好：

```bash
# 1. 安装 OpenVPN + EasyRSA
apt-get install openvpn easy-rsa

# 2. 确保 systemd 服务可用
systemctl status openvpn@server

# 3. 确保 EasyRSA 目录结构正确
ls /etc/openvpn/easy-rsa/pki/index.txt

# 4. 创建客户端配置模板目录
mkdir -p /etc/openvpn/client-configs

# 5. 配置 SSH 密钥认证（推荐）
ssh-copy-id root@192.168.3.147
```

---

## 📁 项目结构

```
openvpn-admin/
├── app.py                      # Flask 主应用（15 个路由）
├── auth.py                     # 认证 & 鉴权模块
├── database.py                 # SQLite 数据模型
├── openvpn/
│   └── __init__.py             # OpenVPN SSH 管理器
├── requirements.txt            # Python 依赖
├── Dockerfile                  # Docker 镜像
├── static/
│   ├── style.css               # 暗色主题样式
│   └── app.js                  # 前端交互
└── templates/
    ├── base.html               # 基础布局
    ├── login.html              # 登录
    ├── dashboard.html          # 仪表盘
    ├── users.html              # 用户管理
    ├── keys.html               # 密钥管理
    ├── service.html            # 服务管理
    ├── config.html             # 配置编辑
    ├── config_view.html        # 配置历史
    ├── logs.html               # 审计日志
    ├── logs_openvpn.html       # 服务日志
    ├── profile.html            # 个人设置
    └── error.html              # 错误页
```

---

## 🔒 安全建议

- **生产环境务必修改 `SECRET_KEY`**（用 `openssl rand -hex 32` 生成）
- **生产环境务必修改 `ADMIN_PASSWORD`**
- 建议使用 SSH 密钥认证而非密码
- 启用 HTTPS（Nginx/Caddy 反向代理 + Let's Encrypt）
- 定期审计 `/logs` 页面检查异常操作
- SSH 私钥设为只读（`chmod 400`）

---

## 📜 许可证

MIT License — 自由使用、修改和分发。
