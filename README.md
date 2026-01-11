# 🍯 AccBox (通用账号管家)

一个简洁、安全的多用户账号管理系统，支持 2FA 验证码生成、二维码扫描导入、自定义分类标签等功能。

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-4.0-green.svg)

## ✨ 功能特性

### 核心功能
- 🔐 **密码加密存储** - 使用 Fernet 对称加密，支持环境变量配置主密钥
- 🛡️ **2FA 双重验证** - 内置 TOTP 验证码生成器，支持标准 6/8 位验证码
- 📷 **二维码扫描** - 直接上传或拖拽 2FA 二维码图片自动识别导入
- 👥 **多用户隔离** - 每个用户独立数据空间，互不干扰
- 🔒 **安全中间件** - 自动阻止访问敏感文件（源码、数据库、密钥）

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
git clone https://github.com/shleeshlee/account-manager.git
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

### 生成安全密钥

```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
# 输出类似: d8Kf9sJ2mN4pQ7rT0vW3xY6zA1bC5eH8iL=
```

## 📷 2FA 二维码扫描

v4.0 新增二维码扫描功能，支持：

1. **上传图片** - 点击上传区域选择二维码截图
2. **拖拽导入** - 直接将图片拖到上传区域
3. **自动识别** - 解析 `otpauth://` URI 并填充配置

支持的 2FA 应用：
- Google Authenticator
- Microsoft Authenticator  
- Authy
- 1Password
- 其他标准 TOTP 应用

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

## 🛠️ 常用操作

### 修改端口

```yaml
# docker-compose.yml
ports:
  - "你的端口:9111"
```

### 查看日志

```bash
docker-compose logs -f
```

### 数据备份

```bash
# 备份数据目录
cp -r data/ data_backup_$(date +%Y%m%d)/

# 或导出 JSON（在 Web 界面操作）
# 点击 📤 导出 按钮
```

### 停止服务

```bash
docker-compose down
```

## 📝 API 文档

启动后访问 `http://localhost:9111/docs` 查看 Swagger API 文档。

### 主要接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/register` | POST | 用户注册 |
| `/api/login` | POST | 用户登录 |
| `/api/accounts` | GET/POST | 账号列表/创建 |
| `/api/accounts/{id}/totp` | GET/POST/DELETE | 2FA 配置 |
| `/api/export` | GET | 导出数据 |
| `/api/import` | POST | 导入数据 |
| `/api/health` | GET | 健康检查（含密钥状态） |

## 🔄 更新日志

### v4.0 (当前版本)
- ✨ 新增：二维码扫描导入 2FA 配置
- ✨ 新增：2FA 配置模态框（替代 prompt 弹窗）
- 🔧 优化：后端代码结构重构
- 🔧 优化：2FA API 支持更多配置项（issuer、算法、位数）
- 🔒 安全：密钥状态检测与前端警告

### v3.0
- 安全中间件（阻止访问敏感文件）
- 环境变量密钥支持
- 2FA 基础功能

### v2.0
- 组合标签系统
- 批量操作功能
- 导入重复检测

### v1.0
- 基础账号管理
- 多用户支持
- 主题切换

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 License

MIT License
