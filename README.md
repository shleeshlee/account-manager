# 🍯 AccBox (通用账号管家) v4.0

> ⚠️ **此版本已停止维护**
> 
> v4.0 存在已知的安全问题（SHA256密码哈希、Token永不过期等），且不再更新修复。
> 
> **强烈建议升级到 [v5.1 主分支](https://github.com/shleeshlee/account-manager)**，安全性更高，功能更完整。

---

一个简洁、安全的多用户账号管理系统，支持 2FA 验证码生成、二维码扫描导入、自定义分类标签等功能。

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-4.0-orange.svg)
![Status](https://img.shields.io/badge/status-已停止维护-red.svg)

## ❓ 为什么停止维护

| 问题 | v4.0 | v5.1 |
|------|------|------|
| 密码哈希 | SHA256（易破解） | bcrypt ✅ |
| Token | 永不过期 | JWT 7天过期 ✅ |
| 备份功能 | 无 | 一键备份/定时备份 ✅ |
| CORS | 允许所有来源 | 白名单模式 ✅ |

v4.0 的定位是「极简版」，如果修复这些安全问题，代码量会大幅增加，失去「极简」的意义。

**如果你正在使用 v4.0，建议：**
1. 导出数据（JSON 格式）
2. 部署 v5.1
3. 导入数据

---

## ✨ 功能特性

### 核心功能
- 🔐 **密码加密存储** - 使用 Fernet 对称加密，支持环境变量配置主密钥
- 🛡️ **完整 2FA 支持** - 标准 TOTP + Steam Guard，支持多种算法
- 📷 **二维码扫描** - 直接上传或拖拽 2FA 二维码图片自动识别导入
- 👥 **多用户隔离** - 每个用户独立数据空间，互不干扰
- 🔒 **安全中间件** - 自动阻止访问敏感文件（源码、数据库、密钥）

### 2FA 验证功能
- 🔢 **标准 TOTP** - 支持 6/8 位数字验证码
- 🎮 **Steam Guard** - 支持 Steam 专用 5 位字母验证码
- 🔐 **多算法** - SHA1 / SHA256 / SHA512
- 📝 **otpauth URI** - 支持从链接或二维码导入
- ⏱️ **实时倒计时** - 验证码过期时间可视化

### 账号管理
- 📁 自定义账号类型（Google、Microsoft、Discord 等）
- 🎨 账号类型自定义图标和背景色
- 🏷️ 自定义属性组和组合标签
- ⭐ 收藏功能（多种样式可选）
- 🕐 最近使用记录追踪
- 🔍 搜索和多条件筛选

### 数据管理
- 📥 JSON/CSV 导入导出
- ✅ 批量选择和删除
- 🔄 导入重复检测（跳过/覆盖/全部导入）

### 界面体验
- 🌙 日间/夜间主题切换
- 🃏 卡片/列表两种视图模式
- 👤 用户头像自定义
- 📱 响应式设计，支持移动端

## 🚀 快速部署

### 方式一：Docker 一键部署（推荐）

```bash
# 1. 克隆项目
git clone -b v4.0简要版 https://github.com/shleeshlee/account-manager.git
cd account-manager

# 2. 修改密钥（重要！）
# 生成安全密钥:
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# 将生成的密钥填入 docker-compose.yml 的 APP_MASTER_KEY

# 3. 启动服务
docker-compose up -d

# 4. 访问
# 浏览器打开 http://localhost:9111
```

### 方式二：手动部署

```bash
# 安装依赖
pip install fastapi uvicorn cryptography pydantic

# 设置密钥（可选，不设置则自动生成文件密钥）
export APP_MASTER_KEY="your-secure-key-here"

# 启动
python main.py
```

## 🔐 安全配置

### 密钥管理

AccBox 支持三种密钥模式：

| 模式 | 安全级别 | 说明 |
|------|---------|------|
| 环境变量密钥 | ⭐⭐⭐ 推荐 | 通过 `APP_MASTER_KEY` 环境变量配置 |
| 文件密钥 | ⭐⭐ | 自动生成 `data/.encryption_key` 文件 |
| 默认公开密钥 | ❌ 危险 | 使用默认值，数据极易被破解 |

**⚠️ 重要提醒：**
- 使用默认密钥时，系统会显示红色安全警告
- 一旦存入数据，更换密钥将导致旧数据无法解密
- 请在首次使用前配置好正式密钥

## 📁 项目结构

```
account-manager/
├── index.html          # 前端页面
├── style.css           # 样式文件
├── app.js              # 前端逻辑
├── flags.js            # 国家旗帜图标
├── main.py             # 后端 API (FastAPI)
├── Dockerfile          # Docker 镜像构建
├── docker-compose.yml  # Docker Compose 配置
└── data/               # 数据目录（自动创建）
    ├── accounts.db     # SQLite 数据库
    └── .encryption_key # 加密密钥（文件模式）
```

## 📝 API 文档

启动后访问 `http://localhost:9111/docs` 查看 Swagger API 文档。

## 📄 License

MIT License
