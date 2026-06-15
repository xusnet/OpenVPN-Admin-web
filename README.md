# OpenVPN Admin

Web 管理面板，用于远程管理 OpenVPN 服务器。纯 Python/Flask 实现，通过 SSH 控制远端 VPN 服务。

## 功能

| 模块 | 说明 |
|------|------|
| **仪表盘** | 用户/密钥统计、最近审计日志、VPN 运行状态、实时在线客户端 |
| **用户管理** | CRUD + 角色管理（admin / operator / viewer），激活/禁用，密码重置 |
| **密钥管理** | 签发/吊销客户端证书、下载 .ovpn 配置文件、与 EasyRSA PKI 同步 |
| **服务管理** | 启动/停止/重启 OpenVPN 服务、查看系统资源（磁盘/内存/端口） |
| **配置编辑** | 在线编辑 server.conf、自动备份、修改历史记录 |
| **审计日志** | 所有管理员操作全记录（分页 + 按用户/操作类型筛选） |
| **服务日志** | 实时查看 OpenVPN 服务器日志 |

### 角色权限

| 角色 | 仪表盘 | 用户管理 | 密钥管理 | 服务管理 | 配置编辑 | 日志查看 |
|------|:---:|:---:|:---:|:---:|:---:|:---:|
| **admin** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **operator** | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ |
| **viewer** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |

## 架构

```
┌──────────────────────────────────────────────┐
│                  Browser                      │
│            http://admin:5000                  │
└──────────────────┬───────────────────────────┘
                   │
┌──────────────────▼───────────────────────────┐
│              Flask (app.py)                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │  auth.py  │ │  routes  │ │  templates/  │  │
│  │  (RBAC)   │ │ (15 条)  │ │  (12 页面)   │  │
│  └──────────┘ └──────────┘ └──────────────┘  │
│  ┌──────────┐ ┌──────────────────────────┐   │
│  │database.py│ │   openvpn/__init__.py    │   │
│  │ (SQLite)  │ │   (Paramiko SSH)         │   │
│  └──────────┘ └──────────┬───────────────┘   │
└──────────────────────────┼───────────────────┘
                           │ SSH (密钥或密码)
┌──────────────────────────▼───────────────────┐
│           OpenVPN Server                      │
│  systemctl openvpn@server                     │
│  /etc/openvpn/server/server.conf              │
│  /etc/openvpn/easy-rsa/pki/                   │
└──────────────────────────────────────────────┘
```

- **Flask**：Web 框架，Jinja2 模板渲染
- **SQLite**：本地数据库（users, key_records, audit_log, config_history）
- **Paramiko**：SSH 客户端，远程执行 `systemctl`、`easyrsa`、cat 等命令
- **bcrypt**：密码哈希，防御彩虹表攻击
- **纯前端**：无 JS 框架依赖，暗色主题 CSS

## 快速开始

### 环境要求

- Python ≥ 3.9
- 目标 OpenVPN 服务器需启用 SSH（密钥或密码登录）
- 目标服务器需安装 `easy-rsa`（用于证书管理）

### 本地开发

```bash
git clone <repo> /data/openvpn-admin
cd /data/openvpn-admin

# 创建虚拟环境
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 配置环境变量（可选，均有默认值）
export SECRET_KEY="your-random-secret"
export OPENVPN_HOST="192.168.3.147"
export OPENVPN_SSH_USER="root"
export OPENVPN_SSH_KEY="/app/keys/id_rsa"
# 或使用密码认证：
export OPENVPN_SSH_PASSWORD="your-password"
export ADMIN_PASSWORD="change-me"

# 启动
python app.py
# → http://localhost:5000
```

### Docker 部署（推荐）

```bash
# 准备 SSH 密钥
mkdir -p keys
cp ~/.ssh/id_rsa keys/

# 构建镜像
docker build -t openvpn-admin .

# 运行
docker run -d \
  --name openvpn-admin \
  -p 5000:5000 \
  -v $(pwd)/keys:/app/keys:ro \
  -v $(pwd)/data:/app/data \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e OPENVPN_HOST="192.168.3.147" \
  -e OPENVPN_SSH_USER="root" \
  -e OPENVPN_SSH_KEY="/app/keys/id_rsa" \
  -e ADMIN_PASSWORD="your-admin-password" \
  openvpn-admin
```

## 配置

全部配置通过环境变量注入：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SECRET_KEY` | 随机 24 hex | Flask 会话密钥（**生产环境必须设置**） |
| `HOST` | `0.0.0.0` | 监听地址 |
| `PORT` | `5000` | 监听端口 |
| `DEBUG` | `false` | 开启 Flask debug 模式 |
| `SESSION_TIMEOUT` | `3600` | 会话超时（秒） |
| `ADMIN_PASSWORD` | `admin123` | 初始管理员密码（仅首次启动创建） |
| `OPENVPN_HOST` | `192.168.3.147` | VPN 服务器 IP/域名 |
| `OPENVPN_SSH_PORT` | `22` | SSH 端口 |
| `OPENVPN_SSH_USER` | `root` | SSH 用户名 |
| `OPENVPN_SSH_KEY` | `/app/keys/id_rsa` | SSH 私钥路径（优先级高于密码） |
| `OPENVPN_SSH_PASSWORD` | `""` | SSH 密码（找不到密钥时使用） |
| `OPENVPN_SERVICE` | `openvpn@server` | systemd 服务名 |
| `OPENVPN_CONFIG` | `/etc/openvpn/server/server.conf` | 配置文件路径 |
| `OPENVPN_EASYRSA_DIR` | `/etc/openvpn/easy-rsa` | EasyRSA 目录 |
| `OPENVPN_CLIENT_DIR` | `/etc/openvpn/client-configs` | 客户端 .ovpn 输出目录 |
| `OPENVPN_LOG_DIR` | `/var/log/openvpn` | 日志目录 |
| `OPENVPN_ADMIN_DB` | `/app/data/admin.db` | SQLite 数据库路径 |

## API

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| `GET` | `/` | 全部 | 仪表盘 |
| `GET/POST` | `/login` | 公开 | 登录页 |
| `GET` | `/logout` | 全部 | 退出登录 |
| `GET/POST` | `/profile` | 全部 | 修改个人密码 |
| `GET` | `/users` | admin | 用户列表 |
| `POST` | `/users/create` | admin | 创建用户 |
| `POST` | `/users/<id>/delete` | admin | 删除用户 |
| `POST` | `/users/<id>/toggle` | admin | 启用/禁用用户 |
| `POST` | `/users/<id>/reset-password` | admin | 重置密码 |
| `GET` | `/keys` | 全部 | 密钥列表 |
| `POST` | `/keys/create` | admin, operator | 创建客户端密钥 |
| `GET` | `/keys/<cn>/download` | 全部 | 下载 .ovpn |
| `POST` | `/keys/<cn>/revoke` | admin, operator | 吊销密钥 |
| `GET` | `/service` | 全部 | 服务状态 |
| `POST` | `/service/<action>` | admin, operator | 启动/停止/重启 |
| `GET` | `/config` | admin | 配置编辑器 |
| `POST` | `/config/update` | admin | 保存配置 |
| `GET` | `/config/history/<id>` | admin | 查看历史配置 |
| `GET` | `/logs` | 全部 | 审计日志 |
| `GET` | `/logs/openvpn` | 全部 | VPN 服务日志 |
| `GET` | `/api/status` | 全部 | 服务状态 JSON（AJAX 轮询） |

## 安全注意事项

- **生产环境必须设置 `SECRET_KEY`**，否则每次重启会话失效
- **SSH 密钥优先**：将私钥挂载到 `/app/keys/id_rsa`，避免密码泄露
- **默认密码必须更改**：首次启动后立即修改 admin 密码
- **HTTPS 反向代理**：建议前置 Nginx/Caddy 并启用 TLS
- **防火墙**：仅允许管理网段访问 5000 端口
- **定期备份**：`/app/data/admin.db` 包含所有审计日志和配置历史

## 文件结构

```
/data/openvpn-admin/
├── app.py                    # Flask 主应用（548行，15 条路由）
├── auth.py                   # 认证与 RBAC 模块
├── database.py               # SQLite 数据模型与初始化
├── openvpn/
│   └── __init__.py           # OpenVPN SSH 管理器
├── requirements.txt          # Python 依赖
├── Dockerfile                # 容器构建文件
├── static/
│   ├── style.css             # 暗色主题样式
│   └── app.js                # 前端交互逻辑
└── templates/                # Jinja2 模板（12 个）
    ├── base.html             # 基础布局 + 导航栏
    ├── login.html            # 登录页
    ├── dashboard.html        # 仪表盘
    ├── users.html            # 用户管理
    ├── keys.html             # 密钥管理
    ├── service.html          # 服务管理
    ├── config.html           # 配置编辑器
    ├── config_view.html      # 配置历史详情
    ├── logs.html             # 审计日志
    ├── logs_openvpn.html     # OpenVPN 服务日志
    ├── profile.html          # 个人设置
    └── error.html            # 错误页
```

## 许可

MIT License
