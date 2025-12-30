# LAN文件服务器

一个基于Python的局域网文件共享服务器，支持多媒体文件浏览、搜索和移动端访问。

## 功能特性

### 🔐 安全认证
- 固定用户名：blycr
- 时间格式密码（yyyymmddHHMM）
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

### 🎨 增强日志系统
- 彩色日志输出，提高可读性
- 不同日志级别使用不同颜色标识（信息、警告、错误等）
- 时间戳记录，便于问题追踪
- 控制台和文件双重输出
- 丰富的格式化信息，包括模块名和级别

### 🖥️ 视觉增强界面
- ASCII艺术标题和彩色边框
- Emoji图标增强视觉效果
- 彩色菜单和状态提示
- 用户友好的进度反馈
- 增强的PowerShell启动器界面

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
```powershell
.\lan-file-server-launcher.ps1
```

3. **初始化配置**
```powershell
.\lan-file-server-launcher.ps1 -Initialize
```

### 首次配置

1. 运行PowerShell启动脚本：`.lan-file-server-launcher.ps1`
2. 选择"2. 初始化服务器配置"
3. 配置用户名和共享目录
4. 使用当前时间作为密码（例如：202512301310）
5. 配置信息会保存在 `auth_config.ini` 和 `server_config.ini` 中

## 项目结构

```
lan-file-server/
├── server.py                              # 主服务器文件
├── color_logger.py                        # 彩色日志系统
├── config.py                              # 配置管理
├── static/
│   └── style.css                         # 样式文件
├── auth_config.ini                       # 认证配置（已排除）
├── server_config.ini                     # 服务器配置（已排除）
├── lan-file-server-launcher.ps1          # PowerShell启动脚本
├── lan-file-server-requirements-specification.md  # 需求规格文档
├── README.md                             # 项目说明
├── PROJECT_TIMELINE.md                   # 项目时间线
└── .gitignore                            # Git忽略文件
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
username = blycr
password_hash =  # 已改为时间格式密码，此字段不再使用
salt = # 已改为时间格式密码，此字段不再使用
failed_auth_limit = 5
failed_auth_block_time = 300
```

> **注意**: 当前系统使用固定用户名"blycr"和时间格式密码（yyyymmddHHMM）。例如，如果当前时间是2025年12月30日13:10，则密码是202512301310。

## 使用说明

1. **访问服务器**
   - 打开浏览器访问 `http://localhost:8000`
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

- **当前版本**: v1.1.0
- **发布日期**: 2025-12-30
- **兼容性**: Python 3.7+

## 作者

- **开发者**: blycr
- **项目类型**: 个人文件共享工具
- **许可证**: MIT

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。

## 免责声明

本软件仅供学习和个人使用，请确保在合法合规的前提下使用。