# LAN文件服务器

一个基于Python的局域网文件共享服务器，支持多媒体文件浏览、搜索和移动端访问。

## 功能特性

### 🔐 安全认证
- 密码保护访问
- PBKDF2-HMAC-SHA256密码哈希存储
- 防暴力破解机制（IP封禁）
- 会话管理

### 📁 文件管理
- 局域网内文件共享
- 支持图片、音频、视频文件预览
- 目录结构展示
- 文件搜索功能

### 📱 移动端优化
- 响应式设计，适配手机和平板
- 触控友好的界面
- 移动端文件预览

### ⚙️ 配置灵活
- 完整的INI配置文件支持
- 日志配置
- 缓存管理
- 主题设置

## 项目文档

- [用户需求规格说明书](user-requirements): 从用户角度描述的需求文档
- [技术需求规格说明书](technical-requirements): 从技术实现角度描述的需求文档

## 快速开始

### 环境要求
- Python 3.7+
- Windows/Linux/macOS

### 安装运行

1. **直接运行**
```bash
python server.py
```

2. **使用启动脚本（Windows）**
```bash
启动LAN文件服务器.bat
```

3. **PowerShell脚本**
```powershell
.\启动LAN文件服务器.ps1
```

## 配置说明

### 服务器配置 (server_config.ini)
```ini
[SERVER]
port = 8000
share_dir = /path/to/your/files

[LOGGING]
log_level = INFO
log_file = lan_file_server.log

[THEME]
default_theme = light

[CACHING]
index_cache_size = 1000
search_cache_size = 500
```

### 认证配置 (auth_config.ini)
```ini
[AUTH]
username = your_username
password_hash = your_password_hash
salt = your_salt
failed_auth_limit = 5
failed_auth_block_time = 300
```

## 使用说明

1. **访问服务器**
   - 打开浏览器访问 `https://localhost:8000`
   - 输入配置的用户名和密码

2. **浏览文件**
   - 主页面显示所有文件
   - 支持按类型筛选（图片/音频/视频/其他）
   - 支持搜索功能

3. **移动端使用**
   - 在手机浏览器中访问相同地址
   - 界面会自动适配移动设备

## 开发信息

### 技术栈
- **后端**: Python + HTTP服务器
- **前端**: HTML + CSS + JavaScript
- **配置**: INI格式配置文件
- **安全**: PBKDF2密码哈希

### 核心功能模块
- **认证管理**: 用户登录、会话管理
- **文件服务**: 文件列表、下载、预览
- **搜索功能**: 文件名搜索、类型筛选
- **配置管理**: 配置文件加载和验证

## 安全说明

- 密码使用PBKDF2-HMAC-SHA256哈希存储
- 配置文件不包含明文密码
- 支持IP封禁防止暴力破解
- 路径安全检查防止目录遍历

## 版本信息

- **当前版本**: v1.0.0
- **发布日期**: 2025-12-29
- **兼容性**: Python 3.7+

## 作者

- **开发者**: blycr
- **项目类型**: 个人文件共享工具
- **许可证**: MIT

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。

## 免责声明

本软件仅供学习和个人使用，请确保在合法合规的前提下使用。