# LAN文件服务器

一个基于Python的高性能局域网文件共享服务器，支持多媒体文件浏览、搜索和移动端访问。

## 核心功能

- 🔐 **安全认证**：用户名密码验证、防暴力破解机制、智能会话管理
- 📁 **文件管理**：局域网内文件共享、多媒体文件预览、快速搜索
- 📱 **移动端优化**：响应式设计，完美适配手机和平板设备
- ⚙️ **配置灵活**：JSON配置文件，支持热重载，易于定制
- 🔍 **高级搜索**：支持正则表达式和模糊匹配，快速定位文件
- 📊 **增强日志**：彩色日志输出，便于问题追踪和性能分析
- 🚀 **性能优化**：多级缓存、异步索引、sendfile优化，提升传输速度
- 📱 **多媒体支持**：视频流媒体播放，支持Range请求
- 📦 **智能缓存**：基于搜索词和排序参数的缓存机制
- 🔄 **增量更新**：SQLite数据库增量更新，减少资源占用

## 快速开始

### 环境要求
- Python 3.7+（推荐Python 3.9+）
- Windows/Linux/macOS
- 足够的磁盘空间用于存储日志和缓存

### 安装与运行

#### 直接运行
```bash
# 克隆仓库
# git clone https://github.com/blycr/lan-file-server.git
# cd lan-file-server

# 直接运行服务器
python server.py
```

#### 使用PowerShell启动脚本（Windows）
```powershell
# 以管理员身份运行PowerShell
.an-file-server-launcher.ps1
```

### 访问服务器

启动成功后，服务器会显示访问地址：
- **本地访问**: http://localhost:8001
- **局域网访问**: http://[本机IP]:8001

## 配置说明

### 主要配置文件

| 文件名 | 功能 |
|--------|------|
| `config.json` | 服务器主要配置，包括端口、共享目录、认证信息等 |
| `sessions.json` | 会话管理，存储用户登录状态 |
| `.gitignore` | Git忽略规则，避免不必要的文件被纳入版本控制 |

### 核心配置选项

在`config.json`中可以配置以下关键选项：

```json
{
  "server": {
    "PORT": 8000,
    "MAX_CONCURRENT_THREADS": 10,
    "SHARE_DIR": ".",
    "SSL_ENABLED": false,
    "SSL_CERT_FILE": "ssl_cert.pem",
    "SSL_KEY_FILE": "ssl_key.pem"
  },
  "auth": {
    "username": "admin",
    "password": "password",
    "FAILED_AUTH_LIMIT": 5,
    "FAILED_AUTH_BLOCK_TIME": 300
  },
  "logging": {
    "LOG_LEVEL": "INFO",
    "LOG_FILE": "lan_file_server.log"
  }
}
```

## API文档

### 文件API

#### 获取文件列表
```
GET /api/files?path=/&sort_by=name&sort_order=asc&page=1&limit=20
```

#### 搜索文件
```
GET /api/files/search?q=keyword&sort_by=name&sort_order=asc
```

## 版本信息

- **当前版本**: v1.2.0
- **发布日期**: 2025-12-31
- **兼容性**: Python 3.7+

## 技术栈

- **后端**: Python 3.7+
- **Web框架**: 内置http.server
- **数据库**: SQLite3
- **前端**: HTML5, CSS3, JavaScript
- **日志**: 自定义彩色日志系统
- **认证**: 会话管理，防暴力破解

## 作者与许可证

- **开发者**: blycr
- **项目类型**: 开源个人文件共享工具
- **许可证**: MIT License

## 贡献指南

欢迎提交Issue和Pull Request来改进这个项目。

### 开发流程
1. Fork本仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开Pull Request

## 常见问题解答

### 1. 如何修改共享目录？
在`config.json`中修改`SHARE_DIR`配置项即可。

### 2. 如何修改用户名和密码？
在`config.json`中修改`auth.username`和`auth.password`配置项。

### 3. 如何启用HTTPS？
1. 生成SSL证书和密钥文件
2. 在`config.json`中设置`SSL_ENABLED: true`
3. 配置`SSL_CERT_FILE`和`SSL_KEY_FILE`路径

### 4. 服务器无法启动怎么办？
- 检查端口是否被占用
- 检查配置文件格式是否正确
- 查看日志文件获取详细错误信息

## 详细文档

请查看项目的[GitHub Wiki](https://github.com/blycr/lan-file-server.wiki.git)获取完整的：
- 技术文档
- 开发指南
- 详细配置说明
- 高级功能使用
- 常见问题解答

## 免责声明

本软件仅供学习和个人使用，请确保在合法合规的前提下使用。