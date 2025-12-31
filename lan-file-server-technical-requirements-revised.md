# LAN文件服务器技术需求规格说明书

## 文档信息

|项|内容|
|---|---|
|文档版本|V3.0|
|编制日期|2025-12-30|
|适用范围|LAN文件服务器（本地多媒体文件共享）|
|核心目标|轻量、美观、安全的本地多媒体文件共享服务器，支持全局护眼模式与精准索引|
|状态|✅ 已完成开发并部署运行（根据实际代码实现修正）|

## 一、文档概述

### 1.1 文档目的

明确LAN文件服务器的技术架构、功能实现、性能要求等核心技术规范，作为开发、测试、验收的技术依据。

### 1.2 项目范围

- 核心：共享指定目录下的多媒体文件，提供索引/目录浏览功能
- 边界：仅支持白名单内的多媒体文件，不处理其他类型文件；仅局域网内访问，不对外暴露

## 二、技术架构

### 2.1 整体架构

本系统采用轻量级Python HTTP服务器架构，主要组件如下：

- **ConfigManager**: 配置管理器，负责加载和保存配置文件，支持配置热重载，管理服务器设置、认证信息、白名单文件类型等
- **AuthenticationManager**: 身份认证管理器，处理用户登录、会话管理、密码哈希验证和IP封禁逻辑，支持会话持久化和智能会话超时
- **FileIndexer**: 文件索引器，递归遍历指定目录，生成文件和文件夹索引，支持搜索功能，实现增量索引和异步索引
- **HTMLTemplate**: HTML模板生成器，生成所有页面的HTML内容，包括护眼模式支持
- **FileServerHandler**: 文件服务器处理器，继承自BaseHTTPRequestHandler，处理HTTP请求，支持sendfile系统调用优化
- **FileServer**: 文件服务器主类，负责启动和管理服务器实例

### 2.2 核心模块

#### 2.2.1 ConfigManager (配置管理器)

```python
class ConfigManager:
    # 白名单文件扩展名
    WHITELIST_EXTENSIONS = {
        'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'],
        'audio': ['.wav', '.mp3', '.ogg', '.wma', '.m4a', '.flac'],
        'video': ['.mp4', '.mov', '.avi', '.flv', '.mkv', '.wmv', '.mpeg', '.mpg']
    }
    
    class ConfigFileHandler(FileSystemEventHandler):
        """配置文件变更处理器"""
        def on_modified(self, event):
            # 处理配置文件变更
    
    def _start_config_watch(self):
        """启动配置文件监控"""
    
    def _load_sessions(self):
        """从文件加载会话数据"""
    
    def _save_sessions(self):
        """将会话数据保存到文件"""
```

关键功能：
- 配置文件管理（JSON格式，支持热重载）
- 配置热重载机制
- 关键文件完整性检测
- 白名单文件类型管理
- 端口检查和自动选择
- 文件大小格式化
- 路径安全检查
- 会话持久化管理
- 智能会话超时（媒体活跃时延长超时时间）
- IP封禁逻辑

#### 2.2.2 AuthenticationManager (身份认证管理器)

```python
class AuthenticationManager:
    def verify_credentials(self, username, password):
        # 验证用户名密码
    
    def _hash_password(self, password, salt):
        # 使用PBKDF2-HMAC-SHA256哈希密码
    
    def create_session(self, username):
        # 创建新会话
    
    def validate_session(self, session_id):
        # 验证会话有效性
```

关键功能：
- 用户名密码验证
- PBKDF2-HMAC-SHA256密码哈希（100,000次迭代）
- 会话创建和管理
- 密码哈希生成

#### 2.2.3 FileIndexer (文件索引器)

```python
class FileIndexer:
    def generate_index(self, search_term=""):
        # 生成文件索引，支持增量更新
    
    def _index_directory_flat(self, dir_path, relative_path, index_data, search_term):
        # 递归索引目录
    
    def get_directory_listing(self, dir_path=""):
        # 获取目录列表
    
    def _check_file_changes(self):
        # 检查文件变化，用于增量索引
    
    def _update_index_incrementally(self):
        # 增量更新索引
    
    def start_async_indexing(self):
        # 启动异步索引生成
```

关键功能：
- 递归目录遍历
- 白名单文件过滤
- 搜索功能实现
- 目录导航
- 增量索引生成，只索引变化的文件
- 异步索引生成，提高用户体验
- 索引缓存机制，减少重复计算

#### 2.2.4 HTMLTemplate (HTML模板生成器)

```python
class HTMLTemplate:
    def get_base_template(self, title, content, theme="light", additional_head=""):
        # 生成基础HTML模板
    
    def get_login_page(self, error_message="", remaining_attempts=5):
        # 生成登录页面
    
    def get_index_page(self, index_data, search_term=""):
        # 生成索引页面
    
    def get_browse_page(self, listing_data):
        # 生成目录浏览页面
```

关键功能：
- 主题切换支持（白天/夜间模式）
- 响应式布局生成
- 搜索框和导航元素生成
- 会话状态保持

#### 2.2.5 FileServerHandler (文件服务器处理器)

```python
class FileServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # 处理GET请求
    
    def do_POST(self):
        # 处理POST请求
    
    def _handle_index(self, query_params):
        # 处理索引页面请求
    
    def _handle_browse(self, path):
        # 处理目录浏览请求
    
    def _handle_download(self, path):
        # 处理文件下载请求
```

关键功能：
- HTTP请求路由
- 会话验证
- 文件下载处理
- 范围请求支持（视频播放）
- 静态资源处理

#### 2.2.6 FileServer (文件服务器)

```python
class FileServer:
    def __init__(self, config_manager=None):
        # 初始化服务器
    
    def start(self):
        # 启动服务器
    
    def stop(self):
        # 停止服务器
```

关键功能：
- 服务器生命周期管理
- 端口自动选择
- 线程池管理
- 信号处理

## 三、功能实现

### 3.1 身份认证系统

|功能|实现细节|状态|
|---|---|---|
|用户名密码验证|基于配置的auth_config.ini文件|✅ 已实现|
|密码哈希存储|PBKDF2-HMAC-SHA256算法，100,000次迭代|✅ 已实现|
|会话管理|基于UUID的会话ID，24小时有效期|✅ 已实现|
|IP封禁机制|连续5次失败后封禁5分钟（可配置）|✅ 已实现|
|会话Cookie|使用HTTP Cookie维持登录状态|✅ 已实现|

### 3.2 文件索引和搜索

|功能|实现细节|状态|
|---|---|---|
|目录递归遍历|使用os.walk()递归遍历目录结构|✅ 已实现|
|白名单过滤|仅处理配置中的20种文件类型|✅ 已实现|
|搜索功能|基于文件名的模糊搜索|✅ 已实现|
|文件大小格式化|自动转换为B/KB/MB/GB/TB格式|✅ 已实现|
|目录导航|面包屑导航和返回上级功能|✅ 已实现|

### 3.3 护眼模式

|功能|实现细节|状态|
|---|---|---|
|主题切换|基于CSS变量实现白天/夜间模式切换|✅ 已实现|
|状态保持|使用localStorage保存用户主题偏好|✅ 已实现|
|平滑过渡|CSS过渡动画实现0.3秒平滑切换|✅ 已实现|
|全页面支持|所有页面（索引、浏览、登录、404）均支持|✅ 已实现|

### 3.4 文件服务

|功能|实现细节|状态|
|---|---|---|
|文件下载|使用HTTP范围请求实现部分内容传输|✅ 已实现|
|文件预览|图片文件直接在浏览器中显示|✅ 已实现|
|音频播放|音频文件使用HTML5 audio标签播放|✅ 已实现|
|视频播放|视频文件使用HTML5 video标签播放，支持范围请求|✅ 已实现|
|目录浏览|支持层级目录结构和文件列表显示|✅ 已实现|

### 3.5 配置管理

|功能|实现细节|状态|
|---|---|---|
|服务器配置|server_config.ini文件，支持[SERVER]、[LOGGING]、[THEME]、[CACHING]等节|✅ 已实现|
|认证配置|auth_config.ini文件，存储用户名、密码哈希和盐值|✅ 已实现|
|端口自动选择|启动时自动检测可用端口并在8000-9000范围内选择|✅ 已实现|
|默认配置|首次运行自动生成默认配置文件|✅ 已实现|

## 四、技术规范

### 4.1 开发语言与框架

- **后端**: Python 3.7+
- **服务器**: Python原生http.server模块
- **前端**: 原生HTML/CSS/JavaScript
- **配置**: INI格式配置文件（使用configparser）

### 4.2 安全规范

- **密码存储**: PBKDF2-HMAC-SHA256哈希，100,000次迭代
- **会话管理**: 基于UUID的会话ID，24小时过期时间
- **路径安全**: 使用Path.is_relative_to()防止目录遍历
- **IP封禁**: 基于IP的认证失败计数和临时封禁

### 4.3 性能规范

- **并发处理**: 使用ThreadingHTTPServer支持多线程并发
- **索引缓存**: 支持索引和搜索结果缓存（可配置大小）
- **缓存更新**: 可配置的缓存更新间隔
- **文件传输**: 支持HTTP范围请求优化大文件传输

### 4.4 兼容性规范

- **操作系统**: Windows 10/11（主要），兼容Linux/macOS
- **浏览器**: Chrome、Edge、Firefox、Safari
- **Python版本**: Python 3.7+

## 五、文件结构

```
lan-file-server/
├── server.py                              # 主服务器文件
├── color_logger.py                        # 彩色日志系统
├── config.py                              # 配置管理，支持热重载
├── static/
│   └── style.css                         # 样式文件
├── config.json                            # 集中式配置文件（推荐）
├── sessions.json                          # 会话持久化文件
├── lan-file-server-launcher.ps1          # PowerShell启动脚本
├── README.md                             # 项目说明
├── OPTIMIZATION_IMPROVEMENT_DIRECTIONS.md # 系统优化方向
├── user-requirements-specification-revised.md # 用户需求规格
├── lan-file-server-technical-requirements-revised.md # 技术需求规格
└── .gitignore                            # Git忽略文件
```

## 六、配置文件

### 6.1 集中式配置 (config.json) [推荐]

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

### 6.2 旧格式配置文件 (兼容)

系统仍支持旧的INI格式配置文件，但推荐使用新的JSON格式。

#### 6.2.1 服务器配置 (server_config.ini)

```ini
[SERVER]
PORT = 8000
MAX_CONCURRENT_THREADS = 10
SHARE_DIR = D:\SteamLibrary\steamapps\workshop\content\431960
SSL_CERT_FILE =
SSL_KEY_FILE =
FAILED_AUTH_LIMIT = 5
FAILED_AUTH_BLOCK_TIME = 300

[LOGGING]
LOG_LEVEL = INFO
LOG_FILE = lan_file_server.log

[THEME]
DEFAULT_THEME = light

[CACHING]
INDEX_CACHE_SIZE = 1000
SEARCH_CACHE_SIZE = 500
UPDATE_INTERVAL = 300
```

#### 6.2.2 认证配置 (auth_config.ini)

```ini
[AUTH]
username = blycr
password_hash = 87ccab888d83c951d537627f9b16e73809bea76a882d201d6af1b68959bdfab5
salt = a0d3aad3ec4799a63d210b3568258dea
failed_auth_limit = 5
failed_auth_block_time = 300
```

### 6.3 配置热重载

系统支持配置热重载功能，修改配置文件后无需重启服务器：

```python
class ConfigFileHandler(FileSystemEventHandler):
    """配置文件变更处理器"""
    def on_modified(self, event):
        # 处理配置文件变更
```

## 七、部署与运维

### 7.1 部署方式

1. **直接运行**
   ```bash
   python server.py
   ```

2. **使用启动脚本**
   ```powershell
   .\lan-file-server-launcher.ps1
   ```

3. **初始化并运行**
   ```powershell
   .\initialize-server.ps1
   ```

### 7.2 运维要点

- **端口冲突**: 服务器启动时自动检测并选择可用端口
- **配置变更**: 修改JSON配置文件后自动热重载，无需重启服务器
- **日志管理**: 日志记录在配置的日志文件中
  - 支持彩色日志输出，提高控制台可读性
  - 不同日志级别使用不同颜色区分（信息、警告、错误等）
  - 彩色日志同时支持控制台和文件输出
  - 提供丰富的格式化信息，包括时间戳、级别、模块名等
- **性能监控**: 可通过缓存配置优化索引性能
  - 增量索引减少资源消耗
  - 异步索引生成不阻塞用户请求
- **会话管理**: 会话数据持久化保存，服务器重启后会话不丢失
  - 智能会话超时，平衡安全性和用户体验

## 八、测试规范

### 8.1 功能测试

|测试项|测试内容|测试状态|
|---|---|---|
|启动测试|服务器正常启动，控制台显示访问地址|✅ 已测试|
|认证测试|用户名密码验证正确，错误密码被拒绝|✅ 已测试|
|会话测试|登录后访问保持，注销后需要重新登录|✅ 已测试|
|会话持久化测试|服务器重启后会话不丢失，用户无需重新登录|✅ 已测试|
|文件索引测试|共享目录中的文件正确显示，搜索功能正常|✅ 已测试|
|增量索引测试|新增文件后索引自动更新，无需重新生成|✅ 已测试|
|异步索引测试|索引生成不阻塞用户请求，页面响应迅速|✅ 已测试|
|配置热重载测试|修改配置文件后无需重启，配置自动生效|✅ 已测试|
|主题切换测试|白天/夜间模式切换成功，状态保持|✅ 已测试|
|移动端测试|在手机浏览器中正常访问和使用|✅ 已测试|
|IP封禁测试|连续错误登录后IP被封禁，过期后自动解封|✅ 已测试|

### 8.2 性能测试

|测试项|测试内容|测试结果|
|---|---|---|
|并发测试|10个客户端同时访问无明显延迟|✅ 通过|
|大文件测试|传输大文件（>100MB）正常，使用sendfile优化|✅ 通过|
|长时间运行|服务器连续运行24小时无崩溃|✅ 通过|
|搜索性能|1000个文件索引搜索响应时间<1秒|✅ 通过|
|索引性能|1000个文件增量索引更新时间<2秒|✅ 通过|
|异步索引性能|索引生成过程中页面响应时间<500ms|✅ 通过|
|配置热重载性能|配置变更后生效时间<1秒|✅ 通过|

### 8.3 安全测试

|测试项|测试内容|测试结果|
|---|---|---|
|目录遍历|尝试访问共享目录外文件被拒绝|✅ 通过|
|暴力破解|IP封禁机制有效阻止暴力破解|✅ 通过|
|密码存储|配置文件中无明文密码|✅ 通过|
|XSS防护|输入特殊字符不会导致XSS攻击|✅ 通过|

## 九、已知限制

1. **文件格式限制**: 仅支持预定义的20种多媒体文件格式
2. **并发连接限制**: 最大并发连接数受限于线程池配置
3. **网络限制**: 仅支持局域网访问，不支持外网访问
4. **身份验证**: 仅支持单一用户身份验证，不支持多用户

## 十、未来扩展

1. **多用户支持**: 扩展认证系统支持多个用户
2. **文件上传**: 添加文件上传功能
3. **权限管理**: 实现基于用户/组的访问权限控制
4. **视频转码**: 添加视频格式转换功能
5. **文件共享链接**: 生成临时共享链接，方便分享文件
6. **插件系统**: 支持插件扩展，便于添加新功能
7. **RESTful API**: 提供API接口，支持第三方应用集成

---

**文档版本历史**

|版本|日期|修改内容|
|---|---|---|
|V1.0|2025-12-29|初始版本|
|V2.0|2025-12-29|根据最终实现成果更新需求规格说明书|
|V2.1|2025-12-29|更新配置部分，新增LOGGING、THEME、CACHING配置节及相关参数|
|V3.0|2025-12-30|根据实际代码实现修正：更正技术架构为Python原生http.server，修正文件类型支持数量，更新启动方式说明，完善项目结构，详细描述核心模块实现|
|V3.1|2025-12-31|更新系统优化内容：添加配置热重载、会话持久化、智能会话超时、增量索引、异步索引、sendfile优化等新功能，更新项目结构和配置文件格式|

> （注：此文档反映了项目的最终实现状态，所有功能均已验证通过）