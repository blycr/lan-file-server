# LAN文件服务器

一个基于Python的局域网文件共享服务器，支持多媒体文件浏览、搜索和移动端访问。

## 功能特性

### 🔐 安全认证
- 固定用户名：blycr
- 时间格式密码（yyyymmddHHMM）
- 支持时间范围密码验证（前后5分钟）
- 防暴力破解机制（IP封禁）
- 会话管理，支持多设备登录
- 会话持久化，重启服务器后会话不丢失
- 智能会话超时（普通24小时，媒体活跃时48小时）

### 📁 文件管理
- 局域网内文件共享
- 支持图片、音频、视频文件预览
- 目录结构展示
- 快速文件搜索功能
- 增量索引机制，只索引变化的文件
- 异步索引生成，提高用户体验

### 📱 移动端优化
- 响应式设计，适配手机和平板
- 触控友好的界面
- 移动端文件预览

### ⚙️ 配置灵活
- 完整的JSON配置文件支持
- 日志配置
- 缓存管理，支持多级缓存
- 主题设置
- 自动配置迁移（从旧INI格式迁移到JSON）
- 配置热重载，无需重启服务器
- 文件检测机制，检测关键文件完整性

### 📡 RESTful API支持
- 完整的RESTful API接口
- 支持HTTP Basic Authentication和Session Cookie认证
- CORS跨域支持
- 支持分页和排序
- 提供API文档页面
- 支持文件和目录管理、搜索、下载

### 🔍 高级搜索功能
- 支持正则表达式搜索
- 支持模糊匹配搜索
- 搜索结果高亮显示
- 高效搜索，响应时间<300ms（10,000条记录）
- 支持文件名和路径搜索

### 📊 增强日志系统
- 彩色日志输出，提高可读性
- 不同日志级别使用不同颜色标识（信息、警告、错误等）
- 时间戳记录，便于问题追踪
- 控制台和文件双重输出
- 丰富的格式化信息，包括模块名和级别

### 🚀 性能优化
- 使用sendfile系统调用优化文件传输
- 多级缓存机制，提高索引和搜索速度
- 异步索引生成，避免阻塞主线程
- 增量索引，只索引变化的文件

### 🔒 安全增强
- HTTPS支持（可选）
- 路径安全检查，防止目录遍历
- 密码安全存储，使用PBKDF2-HMAC-SHA256算法

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
├── config.py                              # 配置管理，支持热重载
├── static/
│   └── style.css                         # 样式文件
├── lan-file-server-launcher.ps1          # PowerShell启动脚本
├── README.md                             # 项目说明
├── .gitignore                            # Git忽略文件
├── LICENSE                               # MIT许可证
└── tests/                                # 测试文件目录
    ├── test_auth.py                      # 认证功能测试
    ├── test_integration.py               # 集成测试
```

## 配置说明

### 集中式配置 (config.json) [推荐]

系统现在使用集中式的JSON配置文件，支持热重载功能，修改配置后无需重启服务器。

```json
{
  "version": "1.0.0",
  "server": {
    "port": 8000,
    "max_concurrent_threads": 10,
    "share_dir": "/path/to/your/files",
    "ssl_cert_file": "",
    "ssl_key_file": "",
    "failed_auth_limit": 5,
    "failed_auth_block_time": 300,
    "session_timeout": 86400
  },
  "logging": {
    "log_level": "INFO",
    "log_file": "lan_file_server.log"
  },
  "theme": {
    "default_theme": "light"
  },
  "caching": {
    "index_cache_size": 1000,
    "search_cache_size": 500,
    "update_interval": 300,
    "enable_multi_level_cache": true,
    "memory_cache_size": 100,
    "disk_cache_enabled": false
  }
}
```

### 旧格式配置文件 (兼容)

系统仍支持旧的INI格式配置文件，但推荐使用新的JSON格式。

> **注意**: 当前系统使用固定用户名"blycr"和时间格式密码（yyyymmddHHMM）。例如，如果当前时间是2025年12月30日13:10，则密码是202512301310。系统支持前后5分钟内的密码验证，便于多设备登录。

## 使用说明

1. **访问服务器**
   - 打开浏览器访问 `http://localhost:8000`
   - 输入配置的用户名和密码

2. **浏览文件**
   - 主页面显示所有文件
   - 支持按类型筛选（图片/音频/视频/其他）
   - 支持搜索功能，包括正则表达式和模糊匹配

3. **移动端使用**
   - 在手机浏览器中访问相同地址
   - 界面会自动适配移动设备

4. **使用API**
   - 访问 `http://localhost:8000/api` 查看API文档
   - 使用HTTP Basic Authentication或Session Cookie进行认证
   - 支持CORS跨域请求

## RESTful API文档

### 认证方式
- **HTTP Basic Authentication**：在请求头中包含 `Authorization: Basic base64(username:password)`
- **Session Cookie**：登录后使用服务器返回的 `session_id` Cookie

### API端点

| 端点 | 方法 | 描述 | 认证 |
|------|------|------|------|
| `/api` | GET | API文档页面 | 否 |
| `/api/files` | GET | 获取文件列表 | 是 |
| `/api/files/{path}` | GET | 获取单个文件信息 | 是 |
| `/api/directories` | GET | 获取目录列表 | 是 |
| `/api/directories/{path}` | GET | 获取目录内容 | 是 |
| `/api/search` | GET | 搜索文件和目录 | 是 |
| `/api/download/{path}` | GET | 下载文件 | 是 |

### 请求参数

#### 文件列表 (`/api/files`)
- `page`：页码（默认：1）
- `per_page`：每页数量（默认：20）
- `sort_by`：排序字段（name, size, modified_time，默认：name）
- `sort_order`：排序顺序（asc, desc，默认：asc）

#### 搜索 (`/api/search`)
- `q`：搜索关键词
- `type`：搜索类型（file, directory, all，默认：all）
- `regex`：是否启用正则表达式（true/false，默认：false）
- `page`：页码（默认：1）
- `per_page`：每页数量（默认：20）

### 响应格式

```json
{
  "success": true,
  "data": {...}, // 响应数据
  "error": null,
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 100,
    "pages": 5
  }
}
```

### 示例请求

```bash
# 使用HTTP Basic Authentication获取文件列表
curl -u username:password http://localhost:8000/api/files?page=1&per_page=20&sort_by=modified_time&sort_order=desc

# 搜索文件
curl -u username:password http://localhost:8000/api/search?q=test&type=file

# 使用正则表达式搜索
curl -u username:password http://localhost:8000/api/search?q=.*test.*&type=file&regex=true
```

## 开发信息

### 技术栈
- **后端**: Python + HTTP服务器，支持多线程
- **前端**: HTML + CSS + JavaScript，支持响应式设计
- **配置**: JSON格式配置文件，支持热重载
- **安全**: PBKDF2密码哈希，IP封禁机制
- **文件传输**: 支持sendfile系统调用优化
- **会话管理**: 基于文件的会话持久化

### 核心功能模块
- **认证管理**: 用户登录、会话管理、多设备支持
- **文件服务**: 文件列表、下载、预览、流式传输
- **搜索功能**: 文件名搜索、增量索引、异步索引生成
- **配置管理**: 配置文件加载、验证和热重载
- **文件检测**: 关键文件完整性检测
- **缓存管理**: 多级缓存机制，提高性能

## 安全说明

- 密码使用PBKDF2-HMAC-SHA256哈希存储
- 配置文件不包含明文密码
- 支持IP封禁防止暴力破解
- 路径安全检查防止目录遍历

## 版本信息

- **当前版本**: v1.2.0
- **发布日期**: 2025-12-31
- **兼容性**: Python 3.7+

## 作者

- **开发者**: blycr
- **项目类型**: 个人文件共享工具
- **许可证**: MIT

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。

## 免责声明

本软件仅供学习和个人使用，请确保在合法合规的前提下使用。