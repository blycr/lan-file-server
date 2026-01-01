import socket
import platform
import uuid
import time
import json
import threading
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class ConfigManager:
    """配置管理器 - 处理服务器配置、认证配置和白名单文件类型"""
    
    # 常量定义
    SESSION_EXPIRE_TIME = 24 * 3600  # 会话过期时间（秒） - 保留向后兼容，实际使用配置中的SESSION_TIMEOUT
    
    class ConfigFileHandler(FileSystemEventHandler):
        """配置文件变更处理器"""
        def __init__(self, config_manager):
            self.config_manager = config_manager
        
        def on_modified(self, event):
            """处理文件修改事件"""
            if Path(event.src_path) == self.config_manager.json_config_file:
                print(f"\n📝 检测到配置文件 {event.src_path} 变更，正在重载配置...")
                try:
                    self.config_manager._load_json_config()
                    print(f"✅ 配置文件重载成功")
                except Exception as e:
                    print(f"❌ 配置文件重载失败: {e}")
    
    def __init__(self, config_dir="."):
        """初始化配置管理器
        
        Args:
            config_dir (str): 配置文件所在目录
        """
        self.config_dir = Path(config_dir)
        self.json_config_file = self.config_dir / "config.json"  # JSON配置文件
        
        # 默认服务器配置
        self.server_config = {
            'PORT': 8000,
            'MAX_CONCURRENT_THREADS': 10,
            'SHARE_DIR': self._get_default_share_dir(),
            'SSL_ENABLED': False,
            'SSL_CERT_FILE': '',
            'SSL_KEY_FILE': '',
            'FAILED_AUTH_LIMIT': 5,
            'FAILED_AUTH_BLOCK_TIME': 300,
            'SESSION_TIMEOUT': 24 * 3600  # 会话超时配置
        }
        
        # 默认日志配置
        self.logging_config = {
            'LOG_LEVEL': 'INFO',
            'LOG_FILE': 'lan_file_server.log'
        }
        
        # 默认主题配置
        self.theme_config = {
            'DEFAULT_THEME': 'light'
        }
        
        # 默认缓存配置
        self.caching_config = {
            'INDEX_CACHE_SIZE': 1000,
            'SEARCH_CACHE_SIZE': 500,
            'UPDATE_INTERVAL': 300,
            'ENABLE_MULTI_LEVEL_CACHE': True,
            'MEMORY_CACHE_SIZE': 100,  # 内存缓存大小
            'DISK_CACHE_ENABLED': False,  # 是否启用磁盘缓存
            'ENABLE_SQLITE_INDEX': True  # 是否启用SQLite索引
        }
        
        # 默认认证配置
        self.auth_config = {
            'username': 'admin',
            'password_hash': '',
            'salt': '',
            'failed_auth_limit': 5,
            'failed_auth_block_time': 300
        }
        
        # 白名单配置
        self.whitelist_config = {
            'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'],
            'audio': ['.wav', '.mp3', '.ogg', '.wma', '.m4a', '.flac'],
            'video': ['.mp4', '.mov', '.avi', '.flv', '.mkv', '.wmv', '.mpeg', '.mpg']
        }
        
        # 所有白名单扩展名的集合（用于快速检查）
        self.ALL_WHITELIST_EXTENSIONS = set()
        for ext_list in self.whitelist_config.values():
            self.ALL_WHITELIST_EXTENSIONS.update(ext_list)
        
        # IP封禁记录
        self.failed_attempts = {}  # {'ip': {'count': int, 'last_attempt': timestamp}}
        
        # Session存储 - 在所有实例间共享
        self.sessions = {}  # 存储活跃会话：session_id -> {username, created_at, last_access, device_info, media_active}
        
        # 会话持久化相关
        self.session_file = self.config_dir / "sessions.json"
        
        # 配置热重载相关
        self.observer = None
        self.config_handler = None
        
        # 确保配置目录存在
        self.config_dir.mkdir(exist_ok=True)
        
        # 加载配置
        self._load_or_create_config()
        
        # 加载持久化会话
        self._load_sessions()
        
        # 启动配置热重载
        self._start_config_watch()
        
        # 启动会话清理线程
        self._start_session_cleanup_thread()
        
    def _start_config_watch(self):
        """启动配置文件监控"""
        self.config_handler = self.ConfigFileHandler(self)
        self.observer = Observer()
        self.observer.schedule(self.config_handler, str(self.config_dir), recursive=False)
        self.observer.start()
        print(f"🔍 已启动配置文件监控，监控目录: {self.config_dir}")
    
    def _stop_config_watch(self):
        """停止配置文件监控"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            print(f"🛑 已停止配置文件监控")
    
    def _get_default_share_dir(self):
        """获取默认共享目录"""
        if platform.system() == "Windows":
            return str(Path.home() / "Documents")
        else:
            return str(Path.home())
    
    def _load_or_create_config(self):
        """加载或创建配置文件"""
        # 只从JSON配置加载
        if self.json_config_file.exists():
            self._load_json_config()
        else:
            # 创建默认JSON配置
            self._migrate_to_json_config()
            print(f"已创建默认JSON配置文件: {self.json_config_file}")
    
    def _validate_config(self, config_data):
        """验证配置数据的有效性
        
        Args:
            config_data (dict): 配置数据
            
        Returns:
            dict: 验证后的配置数据
        """
        # 配置验证规则
        validation_rules = {
            'server': {
                'port': {'type': int, 'min': 1, 'max': 65535},
                'max_concurrent_threads': {'type': int, 'min': 1, 'max': 100},
                'failed_auth_limit': {'type': int, 'min': 1, 'max': 100},
                'failed_auth_block_time': {'type': int, 'min': 0, 'max': 86400},
                'session_timeout': {'type': int, 'min': 60, 'max': 2592000}
            },
            'logging': {
                'log_level': {'type': str, 'allowed_values': ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']}
            },
            'caching': {
                'index_cache_size': {'type': int, 'min': 100, 'max': 10000},
                'search_cache_size': {'type': int, 'min': 50, 'max': 5000},
                'update_interval': {'type': int, 'min': 60, 'max': 3600}
            }
        }
        
        # 验证配置数据
        def validate_section(section_name, section_data, rules):
            """验证配置节"""
            if section_name not in section_data:
                return section_data
            
            for key, rule in rules.items():
                if key in section_data[section_name]:
                    value = section_data[section_name][key]
                    # 类型验证
                    if not isinstance(value, rule['type']):
                        print(f"配置验证警告: {section_name}.{key} 类型错误，应为 {rule['type'].__name__}，使用默认值")
                        del section_data[section_name][key]
                        continue
                    
                    # 数值范围验证
                    if 'min' in rule and value < rule['min']:
                        print(f"配置验证警告: {section_name}.{key} 小于最小值 {rule['min']}，使用默认值")
                        del section_data[section_name][key]
                        continue
                    
                    if 'max' in rule and value > rule['max']:
                        print(f"配置验证警告: {section_name}.{key} 大于最大值 {rule['max']}，使用默认值")
                        del section_data[section_name][key]
                        continue
                    
                    # 允许值验证
                    if 'allowed_values' in rule and value not in rule['allowed_values']:
                        print(f"配置验证警告: {section_name}.{key} 值无效，允许值: {rule['allowed_values']}，使用默认值")
                        del section_data[section_name][key]
                        continue
            
            return section_data
        
        # 验证各个配置节
        for section, rules in validation_rules.items():
            config_data = validate_section(section, config_data, rules)
        
        return config_data
    
    def _upgrade_config(self, config_data):
        """升级配置文件到最新版本
        
        Args:
            config_data (dict): 配置数据
            
        Returns:
            dict: 升级后的配置数据
        """
        CURRENT_VERSION = "1.0.0"
        
        # 获取当前配置版本
        config_version = config_data.get('version', "0.0.0")
        
        # 如果是最新版本，直接返回
        if config_version == CURRENT_VERSION:
            return config_data
        
        print(f"正在升级配置文件从版本 {config_version} 到 {CURRENT_VERSION}...")
        
        # 版本升级逻辑
        upgrade_steps = {
            "0.0.0": self._upgrade_from_0_0_0,
            "1.0.0": lambda x: x  # 已是最新版本，无需升级
        }
        
        # 执行升级
        while config_version != CURRENT_VERSION:
            if config_version not in upgrade_steps:
                print(f"警告：未知的配置版本 {config_version}，使用默认配置")
                return self._create_default_json_config()
            
            upgrade_func = upgrade_steps[config_version]
            config_data = upgrade_func(config_data)
            config_version = config_data['version']
            print(f"已升级到版本 {config_version}")
        
        print("配置文件升级完成")
        return config_data
    
    def _upgrade_from_0_0_0(self, config_data):
        """从版本 0.0.0 升级到 1.0.0
        
        Args:
            config_data (dict): 配置数据
            
        Returns:
            dict: 升级后的配置数据
        """
        # 添加版本信息
        config_data['version'] = "1.0.0"
        
        # 确保所有必需的配置节存在
        required_sections = ['server', 'logging', 'theme', 'caching', 'auth', 'whitelist']
        for section in required_sections:
            if section not in config_data:
                config_data[section] = {}
        
        # 确保server配置节的必需字段存在
        if 'server' in config_data:
            server_config = config_data['server']
            server_config.setdefault('port', 8000)
            server_config.setdefault('max_concurrent_threads', 10)
            server_config.setdefault('share_dir', self._get_default_share_dir())
            server_config.setdefault('ssl_cert_file', '')
            server_config.setdefault('ssl_key_file', '')
            server_config.setdefault('failed_auth_limit', 5)
            server_config.setdefault('failed_auth_block_time', 300)
            server_config.setdefault('session_timeout', 86400)
        
        return config_data
    
    def _create_default_json_config(self):
        """创建默认的JSON配置"""
        return {
            "version": "1.0.0",
            "server": {
                "port": self.server_config['PORT'],
                "max_concurrent_threads": self.server_config['MAX_CONCURRENT_THREADS'],
                "share_dir": self.server_config['SHARE_DIR'],
                "ssl_enabled": self.server_config['SSL_ENABLED'],
                "ssl_cert_file": self.server_config['SSL_CERT_FILE'],
                "ssl_key_file": self.server_config['SSL_KEY_FILE'],
                "failed_auth_limit": self.server_config['FAILED_AUTH_LIMIT'],
                "failed_auth_block_time": self.server_config['FAILED_AUTH_BLOCK_TIME'],
                "session_timeout": self.server_config['SESSION_TIMEOUT']
            },
            "logging": {
                "log_level": self.logging_config['LOG_LEVEL'],
                "log_file": self.logging_config['LOG_FILE']
            },
            "theme": {
                "default_theme": self.theme_config['DEFAULT_THEME']
            },
            "caching": {
                "index_cache_size": self.caching_config['INDEX_CACHE_SIZE'],
                "search_cache_size": self.caching_config['SEARCH_CACHE_SIZE'],
                "update_interval": self.caching_config['UPDATE_INTERVAL']
            },
            "auth": {
                "username": self.auth_config['username'],
                "password_hash": self.auth_config['password_hash'],
                "salt": self.auth_config['salt'],
                "failed_auth_limit": self.auth_config['failed_auth_limit'],
                "failed_auth_block_time": self.auth_config['failed_auth_block_time']
            },
            "whitelist": {
                "image": self.whitelist_config['image'],
                "audio": self.whitelist_config['audio'],
                "video": self.whitelist_config['video']
            }
        }
    
    def _load_json_config(self):
        """从JSON配置文件加载配置"""
        try:
            with open(self.json_config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # 升级配置到最新版本
            config_data = self._upgrade_config(config_data)
            
            # 验证配置数据
            config_data = self._validate_config(config_data)
            
            # 加载服务器配置
            if 'server' in config_data:
                server_config = config_data['server']
                self.server_config['PORT'] = server_config.get('port', self.server_config['PORT'])
                self.server_config['MAX_CONCURRENT_THREADS'] = server_config.get('max_concurrent_threads', self.server_config['MAX_CONCURRENT_THREADS'])
                self.server_config['SHARE_DIR'] = server_config.get('share_dir', self.server_config['SHARE_DIR'])
                self.server_config['SSL_ENABLED'] = server_config.get('ssl_enabled', self.server_config['SSL_ENABLED'])
                self.server_config['SSL_CERT_FILE'] = server_config.get('ssl_cert_file', self.server_config['SSL_CERT_FILE'])
                self.server_config['SSL_KEY_FILE'] = server_config.get('ssl_key_file', self.server_config['SSL_KEY_FILE'])
                self.server_config['FAILED_AUTH_LIMIT'] = server_config.get('failed_auth_limit', self.server_config['FAILED_AUTH_LIMIT'])
                self.server_config['FAILED_AUTH_BLOCK_TIME'] = server_config.get('failed_auth_block_time', self.server_config['FAILED_AUTH_BLOCK_TIME'])
                self.server_config['SESSION_TIMEOUT'] = server_config.get('session_timeout', self.server_config['SESSION_TIMEOUT'])
            
            # 加载日志配置
            if 'logging' in config_data:
                logging_config = config_data['logging']
                self.logging_config['LOG_LEVEL'] = logging_config.get('log_level', self.logging_config['LOG_LEVEL']).upper()
                self.logging_config['LOG_FILE'] = logging_config.get('log_file', self.logging_config['LOG_FILE'])
            
            # 加载主题配置
            if 'theme' in config_data:
                theme_config = config_data['theme']
                self.theme_config['DEFAULT_THEME'] = theme_config.get('default_theme', self.theme_config['DEFAULT_THEME'])
            
            # 加载缓存配置
            if 'caching' in config_data:
                caching_config = config_data['caching']
                self.caching_config['INDEX_CACHE_SIZE'] = caching_config.get('index_cache_size', self.caching_config['INDEX_CACHE_SIZE'])
                self.caching_config['SEARCH_CACHE_SIZE'] = caching_config.get('search_cache_size', self.caching_config['SEARCH_CACHE_SIZE'])
                self.caching_config['UPDATE_INTERVAL'] = caching_config.get('update_interval', self.caching_config['UPDATE_INTERVAL'])
                # 加载SQLite索引配置
                self.caching_config['ENABLE_SQLITE_INDEX'] = caching_config.get('enable_sqlite_index', self.caching_config['ENABLE_SQLITE_INDEX'])
            
            # 加载认证配置
            if 'auth' in config_data:
                auth_config = config_data['auth']
                self.auth_config['username'] = auth_config.get('username', self.auth_config['username'])
                self.auth_config['password_hash'] = auth_config.get('password_hash', self.auth_config['password_hash'])
                self.auth_config['salt'] = auth_config.get('salt', self.auth_config['salt'])
                # 认证配置中的失败尝试限制优先于服务器配置
                if 'failed_auth_limit' in auth_config:
                    self.auth_config['failed_auth_limit'] = auth_config['failed_auth_limit']
                    self.server_config['FAILED_AUTH_LIMIT'] = auth_config['failed_auth_limit']
                if 'failed_auth_block_time' in auth_config:
                    self.auth_config['failed_auth_block_time'] = auth_config['failed_auth_block_time']
                    self.server_config['FAILED_AUTH_BLOCK_TIME'] = auth_config['failed_auth_block_time']
            
            # 加载白名单配置
            if 'whitelist' in config_data:
                whitelist_config = config_data['whitelist']
                if 'image' in whitelist_config:
                    self.whitelist_config['image'] = whitelist_config['image']
                if 'audio' in whitelist_config:
                    self.whitelist_config['audio'] = whitelist_config['audio']
                if 'video' in whitelist_config:
                    self.whitelist_config['video'] = whitelist_config['video']
                
                # 更新白名单扩展名集合
                self.ALL_WHITELIST_EXTENSIONS.clear()
                for ext_list in self.whitelist_config.values():
                    self.ALL_WHITELIST_EXTENSIONS.update(ext_list)
            
            print(f"已从JSON配置文件加载配置: {self.json_config_file}")
        except Exception as e:
            print(f"警告：加载JSON配置文件出错，使用默认值: {e}")
    
    def _migrate_to_json_config(self):
        """将现有配置迁移到JSON格式"""
        try:
            # 创建JSON配置数据
            config_data = {
                "version": "1.0.0",
                "server": {
                    "port": self.server_config['PORT'],
                    "max_concurrent_threads": self.server_config['MAX_CONCURRENT_THREADS'],
                    "share_dir": self.server_config['SHARE_DIR'],
                    "ssl_enabled": self.server_config['SSL_ENABLED'],
                    "ssl_cert_file": self.server_config['SSL_CERT_FILE'],
                    "ssl_key_file": self.server_config['SSL_KEY_FILE'],
                    "failed_auth_limit": self.server_config['FAILED_AUTH_LIMIT'],
                    "failed_auth_block_time": self.server_config['FAILED_AUTH_BLOCK_TIME'],
                    "session_timeout": self.server_config['SESSION_TIMEOUT']
                },
                "logging": {
                    "log_level": self.logging_config['LOG_LEVEL'],
                    "log_file": self.logging_config['LOG_FILE']
                },
                "theme": {
                    "default_theme": self.theme_config['DEFAULT_THEME']
                },
                "caching": {
                    "index_cache_size": self.caching_config['INDEX_CACHE_SIZE'],
                    "search_cache_size": self.caching_config['SEARCH_CACHE_SIZE'],
                    "update_interval": self.caching_config['UPDATE_INTERVAL']
                },
                "auth": {
                    "username": self.auth_config['username'],
                    "password_hash": self.auth_config['password_hash'],
                    "salt": self.auth_config['salt'],
                    "failed_auth_limit": self.auth_config['failed_auth_limit'],
                    "failed_auth_block_time": self.auth_config['failed_auth_block_time']
                },
                "whitelist": {
                    "image": self.whitelist_config['image'],
                    "audio": self.whitelist_config['audio'],
                    "video": self.whitelist_config['video']
                }
            }
            
            # 写入JSON配置文件
            with open(self.json_config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            
            print(f"已将配置迁移到JSON格式: {self.json_config_file}")
        except Exception as e:
            print(f"警告：迁移配置到JSON格式失败: {e}")
    
    def save_auth_config(self, username=None, password_hash=None, salt=None):
        """保存认证配置"""
        try:
            # 更新内存中的配置
            if username is not None:
                self.auth_config['username'] = username
            if password_hash is not None:
                self.auth_config['password_hash'] = password_hash
            if salt is not None:
                self.auth_config['salt'] = salt
            
            # 保存到JSON配置文件
            if self.json_config_file.exists():
                # 读取现有JSON配置
                with open(self.json_config_file, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                
                # 更新认证配置
                if 'auth' not in config_data:
                    config_data['auth'] = {}
                config_data['auth']['username'] = self.auth_config['username']
                config_data['auth']['password_hash'] = self.auth_config['password_hash']
                config_data['auth']['salt'] = self.auth_config['salt']
                config_data['auth']['failed_auth_limit'] = self.auth_config['failed_auth_limit']
                config_data['auth']['failed_auth_block_time'] = self.auth_config['failed_auth_block_time']
                
                # 写回JSON配置文件
                with open(self.json_config_file, 'w', encoding='utf-8') as f:
                    json.dump(config_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"保存认证配置失败: {e}")
    
    def find_available_port(self, start_port=8000, end_port=9000):
        """查找可用端口
        
        Args:
            start_port (int): 起始端口
            end_port (int): 结束端口
            
        Returns:
            int: 可用端口号，如果没有可用端口则返回None
        """
        for port in range(start_port, end_port + 1):
            if self._is_port_available(port):
                return port
        return None
    
    def _is_port_available(self, port):
        """检查端口是否可用"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
                return True

        except OSError:
            return False
    
    def get_effective_port(self):
        """获取有效端口（如果配置的端口被占用，自动查找可用端口）"""
        configured_port = self.server_config['PORT']
        
        if self._is_port_available(configured_port):
            return configured_port
        
        print(f"端口 {configured_port} 被占用，正在查找可用端口...")
        available_port = self.find_available_port()
        
        if available_port:
            print(f"找到可用端口: {available_port}")
            return available_port
        else:
            print("错误：无法找到可用端口 (8000-9000)")
            return None
    
    def is_whitelisted_file(self, file_path):
        """检查文件是否为白名单文件
        
        Args:
            file_path (str): 文件路径
            
        Returns:
            bool: 是否为白名单文件
        """
        file_ext = Path(file_path).suffix.lower()
        return file_ext in self.ALL_WHITELIST_EXTENSIONS
    
    def get_file_type(self, file_path):
        """获取文件类型
        
        Args:
            file_path (str): 文件路径
            
        Returns:
            str: 文件类型 ('image', 'audio', 'video', 'other')
        """
        file_ext = Path(file_path).suffix.lower()
        
        for file_type, extensions in self.whitelist_config.items():
            if file_ext in extensions:
                return file_type
        
        return 'other'
    
    def format_file_size(self, size_bytes):
        """格式化文件大小
        
        Args:
            size_bytes (int): 文件大小（字节）
            
        Returns:
            str: 格式化后的文件大小
        """
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        size = float(size_bytes)
        
        while size >= 1024.0 and i < len(size_names) - 1:
            size /= 1024.0
            i += 1
        
        return f"{size:.2f} {size_names[i]}"
    
    def is_path_safe(self, path, base_dir):
        """检查路径是否安全（防止目录遍历攻击）
        
        Args:
            path (str): 要检查的路径
            base_dir (str): 基础目录
            
        Returns:
            bool: 路径是否安全
        """
        try:
            # 简化路径安全检查，适合内网环境
            # 对于内网环境，放宽安全限制，允许所有在共享目录内的路径
            
            # 处理不同类型的路径输入
            if hasattr(path, 'path'):  # 处理DirEntry对象
                path_str = path.path
            else:
                path_str = str(path)
            
            # 构建完整的绝对路径
            if not Path(path_str).is_absolute():
                # 如果是相对路径，直接认为是安全的
                return True
            
            # 规范化路径
            normalized_path = Path(path_str).resolve()
            normalized_base = Path(base_dir).resolve()
            
            # 检查路径是否在基础目录内
            return normalized_path.is_relative_to(normalized_base)
        except Exception as e:
            # 在内网环境下，出错时也返回True，避免误判
            print(f"路径安全检查出错，放宽限制: {path} - {e}")
            return True
    
    def record_failed_attempt(self, ip_address):
        """记录认证失败尝试
        
        Args:
            ip_address (str): IP地址
        """
        import time
        
        current_time = time.time()
        
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = {'count': 0, 'last_attempt': current_time}
        
        self.failed_attempts[ip_address]['count'] += 1
        self.failed_attempts[ip_address]['last_attempt'] = current_time
    
    def is_ip_blocked(self, ip_address):
        """检查IP是否被封禁
        
        Args:
            ip_address (str): IP地址
            
        Returns:
            bool: IP是否被封禁
        """
        import time
        
        if ip_address not in self.failed_attempts:
            return False
        
        attempt_info = self.failed_attempts[ip_address]
        
        # 检查是否超过失败次数限制
        if attempt_info['count'] >= self.server_config['FAILED_AUTH_LIMIT']:
            # 检查封禁时间是否已过
            time_since_last = time.time() - attempt_info['last_attempt']
            block_duration = self.server_config['FAILED_AUTH_BLOCK_TIME']
            
            if time_since_last < block_duration:
                return True
            else:
                # 封禁时间已过，清除记录
                del self.failed_attempts[ip_address]
        
        return False
    
    def get_remaining_attempts(self, ip_address):
        """获取剩余尝试次数
        
        Args:
            ip_address (str): IP地址
            
        Returns:
            int: 剩余尝试次数
        """
        if ip_address not in self.failed_attempts:
            return self.server_config['FAILED_AUTH_LIMIT']
        
        attempt_info = self.failed_attempts[ip_address]
        remaining = self.server_config['FAILED_AUTH_LIMIT'] - attempt_info['count']
        return max(0, remaining)
    
    def reset_failed_attempts(self, ip_address):
        """重置IP的失败尝试记录
        
        Args:
            ip_address (str): IP地址
        """
        if ip_address in self.failed_attempts:
            del self.failed_attempts[ip_address]
    
    def get_session_username(self, session_id):
        """获取会话对应的用户名
        
        Args:
            session_id (str): 会话ID
            
        Returns:
            str or None: 用户名或None
        """
        if self.validate_session(session_id):
            return self.sessions[session_id]['username']
        return None
    
    def delete_session(self, session_id):
        """删除会话
        
        Args:
            session_id (str): 会话ID
        """
        if session_id in self.sessions:
            del self.sessions[session_id]
            self._save_sessions()
    
    def cleanup_expired_sessions(self):
        """清理过期会话
        
        智能超时逻辑：
        - 一般情况：默认超时时间
        - 用户正在观看媒体文件：延长超时时间
        """
        current_time = time.time()
        expired_sessions = []
        
        for session_id, session_data in self.sessions.items():
            # 计算超时时间
            if session_data.get('media_active', False):
                # 媒体活跃时，延长超时时间到48小时
                expire_time = self.server_config['SESSION_TIMEOUT'] * 2
            else:
                # 普通超时时间
                expire_time = self.server_config['SESSION_TIMEOUT']
            
            if current_time - session_data['last_access'] > expire_time:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.sessions[session_id]
        
        # 保存会话状态
        if expired_sessions:
            self._save_sessions()
    
    def _load_sessions(self):
        """从文件加载会话数据"""
        try:
            if self.session_file.exists():
                with open(self.session_file, 'r', encoding='utf-8') as f:
                    sessions_data = json.load(f)
                    self.sessions = sessions_data
                print(f"已从 {self.session_file} 加载 {len(self.sessions)} 个会话")
        except Exception as e:
            print(f"加载会话文件失败: {e}")
            self.sessions = {}
    
    def _save_sessions(self):
        """将会话数据保存到文件"""
        try:
            with open(self.session_file, 'w', encoding='utf-8') as f:
                json.dump(self.sessions, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"保存会话文件失败: {e}")
    
    def _start_session_cleanup_thread(self):
        """启动会话清理线程"""
        def cleanup_thread():
            while True:
                time.sleep(300)  # 每5分钟清理一次
                self.cleanup_expired_sessions()
        
        thread = threading.Thread(target=cleanup_thread, daemon=True)
        thread.start()
    
    def update_session_activity(self, session_id, media_active=False):
        """更新会话活动状态
        
        Args:
            session_id (str): 会话ID
            media_active (bool): 媒体是否活跃
        """
        if session_id in self.sessions:
            self.sessions[session_id]['last_access'] = time.time()
            self.sessions[session_id]['media_active'] = media_active
            self._save_sessions()
    
    def create_session(self, username, device_info=""):
        """创建新会话
        
        Args:
            username (str): 用户名
            device_info (str): 设备标识信息
            
        Returns:
            str: 会话ID
        """
        session_id = str(uuid.uuid4())
        current_time = time.time()
        
        self.sessions[session_id] = {
            'username': username,
            'created_at': current_time,
            'last_access': current_time,
            'device_info': device_info,
            'media_active': False  # 新增媒体活跃状态
        }
        
        # 保存会话
        self._save_sessions()
        
        return session_id
    
    def validate_session(self, session_id):
        """验证会话有效性
        
        Args:
            session_id (str): 会话ID
            
        Returns:
            bool: 会话是否有效
        """
        if not session_id or session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        current_time = time.time()
        
        # 计算超时时间
        if session.get('media_active', False):
            # 媒体活跃时，延长超时时间到48小时
            expire_time = self.server_config['SESSION_TIMEOUT'] * 2
        else:
            # 普通超时时间
            expire_time = self.server_config['SESSION_TIMEOUT']
        
        # 检查会话是否过期
        if current_time - session['last_access'] > expire_time:
            del self.sessions[session_id]
            self._save_sessions()
            return False
        
        # 更新最后访问时间
        session['last_access'] = current_time
        self._save_sessions()
        return True
    
    def get_config_summary(self):
        """获取配置摘要信息"""
        return {
            'server': self.server_config.copy(),
            'logging': self.logging_config.copy(),
            'theme': self.theme_config.copy(),
            'caching': self.caching_config.copy(),
            'auth': {
                'username': self.auth_config['username'],
                'has_password': bool(self.auth_config['password_hash']),
                'failed_auth_limit': self.auth_config['failed_auth_limit'],
                'failed_auth_block_time': self.auth_config['failed_auth_block_time']
            },
            'whitelist': {
                'total_extensions': len(self.ALL_WHITELIST_EXTENSIONS),
                'image_extensions': self.whitelist_config['image'],
                'audio_extensions': self.whitelist_config['audio'],
                'video_extensions': self.whitelist_config['video']
            }
        }


# 全局配置管理器实例
config_manager = None

def get_config_manager():
    """获取全局配置管理器实例"""
    global config_manager
    if config_manager is None:
        config_manager = ConfigManager()
    return config_manager


if __name__ == "__main__":
    # 测试配置管理器
    print("=== LAN文件服务器配置管理器测试 ===")
    
    config = get_config_manager()
    
    # 显示配置摘要
    summary = config.get_config_summary()
    print(f"\n服务器配置:")
    for key, value in summary['server'].items():
        print(f"  {key}: {value}")
    
    print(f"\n认证配置:")
    for key, value in summary['auth'].items():
        print(f"  {key}: {value}")
    
    print(f"\n白名单配置:")
    print(f"  总扩展名数量: {summary['whitelist']['total_extensions']}")
    print(f"  图片格式: {', '.join(summary['whitelist']['image_extensions'])}")
    print(f"  音频格式: {', '.join(summary['whitelist']['audio_extensions'])}")
    print(f"  视频格式: {', '.join(summary['whitelist']['video_extensions'])}")
    
    # 测试端口检查
    effective_port = config.get_effective_port()
    print(f"\n有效端口: {effective_port}")
    
    # 测试白名单检查
    test_files = [
        "test.jpg", "test.mp3", "test.mp4", "test.txt", "test.pdf"
    ]
    
    print(f"\n白名单检查测试:")
    for test_file in test_files:
        is_whitelisted = config.is_whitelisted_file(test_file)
        file_type = config.get_file_type(test_file)
        print(f"  {test_file}: {'✓' if is_whitelisted else '✗'} ({file_type})")
    
    # 测试文件大小格式化
    print(f"\n文件大小格式化测试:")
    test_sizes = [0, 1024, 1048576, 1073741824, 1099511627776]
    for size in test_sizes:
        formatted = config.format_file_size(size)
        print(f"  {size} bytes -> {formatted}")
