import os
import sys
import configparser
import socket
import platform
import uuid
import time
from pathlib import Path


class ConfigManager:
    """配置管理器 - 处理服务器配置、认证配置和白名单文件类型"""
    
    # 常量定义
    SESSION_EXPIRE_TIME = 24 * 3600  # 会话过期时间（秒）
    
    # 白名单文件扩展名
    WHITELIST_EXTENSIONS = {
        'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'],
        'audio': ['.wav', '.mp3', '.ogg', '.wma', '.m4a', '.flac'],
        'video': ['.mp4', '.mov', '.avi', '.flv', '.mkv', '.wmv', '.mpeg', '.mpg']
    }
    
    # 所有白名单扩展名的集合（用于快速检查）
    ALL_WHITELIST_EXTENSIONS = set()
    for ext_list in WHITELIST_EXTENSIONS.values():
        ALL_WHITELIST_EXTENSIONS.update(ext_list)
    
    def __init__(self, config_dir="."):
        """初始化配置管理器
        
        Args:
            config_dir (str): 配置文件所在目录
        """
        self.config_dir = Path(config_dir)
        self.server_config_file = self.config_dir / "server_config.ini"
        self.auth_config_file = self.config_dir / "auth_config.ini"
        
        # 默认服务器配置
        self.server_config = {
            'PORT': 8000,
            'MAX_CONCURRENT_THREADS': 10,
            'SHARE_DIR': self._get_default_share_dir(),
            'SSL_CERT_FILE': '',
            'SSL_KEY_FILE': '',
            'FAILED_AUTH_LIMIT': 5,
            'FAILED_AUTH_BLOCK_TIME': 300
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
            'UPDATE_INTERVAL': 300
        }
        
        # 默认认证配置
        self.auth_config = {
            'username': 'admin',
            'password_hash': '',
            'salt': '',
            'failed_auth_limit': 5,
            'failed_auth_block_time': 300
        }
        
        # IP封禁记录
        self.failed_attempts = {}  # {'ip': {'count': int, 'last_attempt': timestamp}}
        
        # Session存储 - 在所有实例间共享
        self.sessions = {}  # 存储活跃会话：session_id -> {username, created_at, last_access}
        
        # 确保配置目录存在
        self.config_dir.mkdir(exist_ok=True)
        
        # 加载配置
        self._load_or_create_config()
    
    def _get_default_share_dir(self):
        """获取默认共享目录"""
        if platform.system() == "Windows":
            return str(Path.home() / "Documents")
        else:
            return str(Path.home())
    
    def _load_or_create_config(self):
        """加载或创建配置文件"""
        # 检查并创建服务器配置
        if not self.server_config_file.exists():
            self._create_default_server_config()
            print(f"已创建默认服务器配置文件: {self.server_config_file}")
        
        # 检查并创建认证配置
        if not self.auth_config_file.exists():
            self._create_default_auth_config()
            print(f"已创建默认认证配置文件: {self.auth_config_file}")
        
        # 加载现有配置
        self._load_server_config()
        self._load_auth_config()
    
    def _create_default_server_config(self):
        """创建默认服务器配置文件"""
        config = configparser.ConfigParser()
        config['SERVER'] = {
            'PORT': str(self.server_config['PORT']),
            'MAX_CONCURRENT_THREADS': str(self.server_config['MAX_CONCURRENT_THREADS']),
            'SHARE_DIR': self.server_config['SHARE_DIR'],
            'SSL_CERT_FILE': self.server_config['SSL_CERT_FILE'],
            'SSL_KEY_FILE': self.server_config['SSL_KEY_FILE'],
            'FAILED_AUTH_LIMIT': str(self.server_config['FAILED_AUTH_LIMIT']),
            'FAILED_AUTH_BLOCK_TIME': str(self.server_config['FAILED_AUTH_BLOCK_TIME'])
        }
        
        config['LOGGING'] = {
            'LOG_LEVEL': self.logging_config['LOG_LEVEL'],
            'LOG_FILE': self.logging_config['LOG_FILE']
        }
        
        config['THEME'] = {
            'DEFAULT_THEME': self.theme_config['DEFAULT_THEME']
        }
        
        config['CACHING'] = {
            'INDEX_CACHE_SIZE': str(self.caching_config['INDEX_CACHE_SIZE']),
            'SEARCH_CACHE_SIZE': str(self.caching_config['SEARCH_CACHE_SIZE']),
            'UPDATE_INTERVAL': str(self.caching_config['UPDATE_INTERVAL'])
        }
        
        with open(self.server_config_file, 'w', encoding='utf-8') as f:
            config.write(f)
    
    def _create_default_auth_config(self):
        """创建默认认证配置文件"""
        config = configparser.ConfigParser()
        config['AUTH'] = {
            'username': self.auth_config['username'],
            'password_hash': self.auth_config['password_hash'],
            'salt': self.auth_config['salt'],
            'failed_auth_limit': str(self.auth_config['failed_auth_limit']),
            'failed_auth_block_time': str(self.auth_config['failed_auth_block_time'])
        }
        
        with open(self.auth_config_file, 'w', encoding='utf-8') as f:
            config.write(f)
    
    def _load_server_config(self):
        """加载服务器配置"""
        try:
            config = configparser.ConfigParser()
            config.read(self.server_config_file, encoding='utf-8')
            
            if 'SERVER' in config:
                server_section = config['SERVER']
                self.server_config['PORT'] = server_section.getint('PORT', self.server_config['PORT'])
                self.server_config['MAX_CONCURRENT_THREADS'] = server_section.getint('MAX_CONCURRENT_THREADS', self.server_config['MAX_CONCURRENT_THREADS'])
                self.server_config['SHARE_DIR'] = server_section.get('SHARE_DIR', self.server_config['SHARE_DIR'])
                self.server_config['SSL_CERT_FILE'] = server_section.get('SSL_CERT_FILE', self.server_config['SSL_CERT_FILE'])
                self.server_config['SSL_KEY_FILE'] = server_section.get('SSL_KEY_FILE', self.server_config['SSL_KEY_FILE'])
                self.server_config['FAILED_AUTH_LIMIT'] = server_section.getint('FAILED_AUTH_LIMIT', self.server_config['FAILED_AUTH_LIMIT'])
                self.server_config['FAILED_AUTH_BLOCK_TIME'] = server_section.getint('FAILED_AUTH_BLOCK_TIME', self.server_config['FAILED_AUTH_BLOCK_TIME'])
            
            # 加载日志配置
            if 'LOGGING' in config:
                logging_section = config['LOGGING']
                self.logging_config['LOG_LEVEL'] = logging_section.get('LOG_LEVEL', self.logging_config['LOG_LEVEL'])
                self.logging_config['LOG_FILE'] = logging_section.get('LOG_FILE', self.logging_config['LOG_FILE'])
            
            # 加载主题配置
            if 'THEME' in config:
                theme_section = config['THEME']
                self.theme_config['DEFAULT_THEME'] = theme_section.get('DEFAULT_THEME', self.theme_config['DEFAULT_THEME'])
            
            # 加载缓存配置
            if 'CACHING' in config:
                caching_section = config['CACHING']
                self.caching_config['INDEX_CACHE_SIZE'] = caching_section.getint('INDEX_CACHE_SIZE', self.caching_config['INDEX_CACHE_SIZE'])
                self.caching_config['SEARCH_CACHE_SIZE'] = caching_section.getint('SEARCH_CACHE_SIZE', self.caching_config['SEARCH_CACHE_SIZE'])
                self.caching_config['UPDATE_INTERVAL'] = caching_section.getint('UPDATE_INTERVAL', self.caching_config['UPDATE_INTERVAL'])
                
        except Exception as e:
            print(f"警告：加载服务器配置时出错，使用默认值: {e}")
    
    def _load_auth_config(self):
        """加载认证配置"""
        try:
            config = configparser.ConfigParser()
            config.read(self.auth_config_file, encoding='utf-8')
            
            if 'AUTH' in config:
                auth_section = config['AUTH']
                self.auth_config['username'] = auth_section.get('username', self.auth_config['username'])
                self.auth_config['password_hash'] = auth_section.get('password_hash', self.auth_config['password_hash'])
                self.auth_config['salt'] = auth_section.get('salt', self.auth_config['salt'])
                self.auth_config['failed_auth_limit'] = auth_section.getint('failed_auth_limit', self.auth_config['failed_auth_limit'])
                self.auth_config['failed_auth_block_time'] = auth_section.getint('failed_auth_block_time', self.auth_config['failed_auth_block_time'])
        except Exception as e:
            print(f"警告：加载认证配置时出错，使用默认值: {e}")
    
    def save_auth_config(self, username=None, password_hash=None, salt=None):
        """保存认证配置"""
        try:
            config = configparser.ConfigParser()
            config['AUTH'] = {
                'username': username or self.auth_config['username'],
                'password_hash': password_hash or self.auth_config['password_hash'],
                'salt': salt or self.auth_config['salt'],
                'failed_auth_limit': str(self.auth_config['failed_auth_limit']),
                'failed_auth_block_time': str(self.auth_config['failed_auth_block_time'])
            }
            
            with open(self.auth_config_file, 'w', encoding='utf-8') as f:
                config.write(f)
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
        
        for file_type, extensions in self.WHITELIST_EXTENSIONS.items():
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
            # 规范化路径
            normalized_path = Path(path).resolve()
            normalized_base = Path(base_dir).resolve()
            
            # 检查路径是否在基础目录内
            return normalized_path.is_relative_to(normalized_base)
        except Exception:
            return False
    
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
    
    def create_session(self, username):
        """创建新会话
        
        Args:
            username (str): 用户名
            
        Returns:
            str: 会话ID
        """
        session_id = str(uuid.uuid4())
        current_time = time.time()
        
        self.sessions[session_id] = {
            'username': username,
            'created_at': current_time,
            'last_access': current_time
        }
        
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
        
        # 检查会话是否过期
        expire_time = ConfigManager.SESSION_EXPIRE_TIME
        if current_time - session['created_at'] > expire_time:
            del self.sessions[session_id]
            return False
        
        # 更新最后访问时间
        session['last_access'] = current_time
        return True
    
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
    
    def cleanup_expired_sessions(self):
        """清理过期会话"""
        current_time = time.time()
        expired_sessions = []
        
        for session_id, session_data in self.sessions.items():
            if current_time - session_data['created_at'] > 24 * 3600:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.sessions[session_id]
    
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
                'image_extensions': self.WHITELIST_EXTENSIONS['image'],
                'audio_extensions': self.WHITELIST_EXTENSIONS['audio'],
                'video_extensions': self.WHITELIST_EXTENSIONS['video']
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