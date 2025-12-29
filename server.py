import os
import sys
import hashlib
import base64
import json
import mimetypes
import uuid
import secrets
import signal
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote, quote
from urllib.parse import quote as urlquote
from pathlib import Path
import threading
import time
import socket
import hmac

from config import get_config_manager


# 获取配置管理器实例
config_manager = get_config_manager()

# 配置日志记录
log_level = getattr(logging, config_manager.logging_config['LOG_LEVEL'].upper(), logging.INFO)
log_file = config_manager.logging_config['LOG_FILE']

logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file, encoding='utf-8')
    ]
)

logger = logging.getLogger('LANFileServer')


class AuthenticationManager:
    """认证管理器 - 处理用户认证和密码验证"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        # Session管理现在通过config_manager进行
    
    def verify_credentials(self, username, password):
        """验证用户名和密码
        
        Args:
            username (str): 用户名
            password (str): 密码
            
        Returns:
            bool: 认证是否成功
        """
        config = self.config_manager
        
        # 检查是否有密码哈希
        if not config.auth_config['password_hash']:
            return username == config.auth_config['username'] and password == ""
        
        # 验证密码
        stored_hash = config.auth_config['password_hash']
        salt = config.auth_config['salt']
        
        if not salt:
            return False
        
        # 计算输入密码的哈希值
        password_hash = self._hash_password(password, salt)
        
        return (username == config.auth_config['username'] and 
                hmac.compare_digest(password_hash, stored_hash))
    
    def _hash_password(self, password, salt):
        """使用PBKDF2-HMAC-SHA256哈希密码
        
        Args:
            password (str): 密码
            salt (str): 盐值
            
        Returns:
            str: 哈希值（十六进制字符串）
        """
        # 使用 PBKDF2-HMAC-SHA256（Python标准库实现）
        # 格式：salt$iterations$hash
        iterations = 100000
        salt_bytes = bytes.fromhex(salt) if len(salt) == 32 else salt.encode('utf-8')
        password_bytes = password.encode('utf-8')
        
        # 使用hashlib.pbkdf2_hmac（Python 3.4+）
        derived_key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, iterations, dklen=32)
        return derived_key.hex()
    
    def create_password_hash(self, password, salt=None):
        """创建密码哈希
        
        Args:
            password (str): 密码
            salt (str): 可选的盐值，如果为None则自动生成
            
        Returns:
            tuple: (哈希值, 盐值)
        """
        if salt is None:
            # 生成16字节的随机盐值
            salt_bytes = secrets.token_bytes(16)
            salt = salt_bytes.hex()
        
        password_hash = self._hash_password(password, salt)
        return password_hash, salt
    
    def extract_credentials(self, auth_header):
        """从HTTP Authorization头提取认证信息
        
        Args:
            auth_header (str): Authorization头值
            
        Returns:
            tuple: (用户名, 密码) 或 (None, None)
        """
        if not auth_header:
            return None, None
        
        try:
            # 解析 "Basic base64(username:password)" 格式
            auth_type, credentials = auth_header.split(' ', 1)
            
            if auth_type.lower() != 'basic':
                return None, None
            
            # 解码base64
            decoded_credentials = base64.b64decode(credentials).decode('utf-8')
            username, password = decoded_credentials.split(':', 1)
            
            return username, password
        except Exception:
            return None, None
    
    def create_session(self, username):
        """创建新会话
        
        Args:
            username (str): 用户名
            
        Returns:
            str: 会话ID
        """
        return self.config_manager.create_session(username)
    
    def validate_session(self, session_id):
        """验证会话有效性
        
        Args:
            session_id (str): 会话ID
            
        Returns:
            bool: 会话是否有效
        """
        return self.config_manager.validate_session(session_id)
    
    def get_session_username(self, session_id):
        """获取会话对应的用户名
        
        Args:
            session_id (str): 会话ID
            
        Returns:
            str or None: 用户名或None
        """
        return self.config_manager.get_session_username(session_id)
    
    def delete_session(self, session_id):
        """删除会话
        
        Args:
            session_id (str): 会话ID
        """
        self.config_manager.delete_session(session_id)
    
    def cleanup_expired_sessions(self):
        """清理过期会话"""
        self.config_manager.cleanup_expired_sessions()


class FileIndexer:
    """文件索引器 - 生成和管理文件索引"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.share_dir = Path(config_manager.server_config['SHARE_DIR'])
        self.cache = {}
        self.cache_time = 0
        self.cache_duration = 300  # 5分钟缓存
    
    def generate_index(self, search_term=""):
        """生成文件索引
        
        Args:
            search_term (str): 搜索关键词（可选）
            
        Returns:
            dict: 索引数据
        """
        current_time = time.time()
        
        # 检查缓存
        if (self.cache and 
            current_time - self.cache_time < self.cache_duration and
            search_term == self.cache.get('search_term', '')):
            return self.cache
        
        index_data = {
            'search_term': search_term,
            'timestamp': current_time,
            'directories': [],
            'files': []
        }
        
        if not self.share_dir.exists():
            return index_data
        
        try:
            # 只显示根目录内容，模仿手机文件管理器体验
            self._index_directory_flat(self.share_dir, "", index_data, search_term)
            
            # 排序
            index_data['directories'].sort(key=lambda x: x['name'].lower())
            index_data['files'].sort(key=lambda x: x['name'].lower())
            
            # 更新缓存
            self.cache = index_data
            self.cache_time = current_time
            
        except Exception as e:
            logger.error(f"生成索引时出错: {e}", exc_info=True)
        
        return index_data
    
    def _index_directory_flat(self, dir_path, relative_path, index_data, search_term):
        """扁平化索引目录 - 正常浏览只显示当前目录，搜索时递归搜索所有子目录
        
        Args:
            dir_path (Path): 目录路径
            relative_path (str): 相对路径
            index_data (dict): 索引数据
            search_term (str): 搜索关键词
        """
        try:
            # 严格检查目录是否在共享目录内
            if not self.config_manager.is_path_safe(str(dir_path), str(self.share_dir)):
                logger.warning(f"跳过目录遍历攻击尝试: {dir_path}")
                return
            
            for item in dir_path.iterdir():
                # 确保item_name使用UTF-8编码，处理所有Unicode字符
                try:
                    item_name = str(item.name)
                except UnicodeDecodeError:
                    logger.warning(f"文件名编码错误，跳过: {item}")
                    continue
                
                # 正确构造相对路径：确保与share_dir的关联性
                if relative_path and relative_path.strip():
                    item_relative_path = str(Path(relative_path) / item_name)
                else:
                    item_relative_path = item_name
                
                # 再次检查路径安全性
                if not self.config_manager.is_path_safe(str(item), str(self.share_dir)):
                    logger.warning(f"跳过不安全的路径: {item}")
                    continue
                
                if item.is_dir():
                    # 检查目录名是否匹配搜索条件
                    directory_matches = True
                    if search_term:
                        try:
                            search_lower = search_term.lower()
                            name_lower = item_name.lower()
                            directory_matches = search_lower in name_lower
                        except Exception as e:
                            logger.error(f"搜索匹配错误: {e}")
                            directory_matches = False
                    
                    # 如果目录名匹配搜索条件，或者没有搜索条件（正常浏览），添加目录
                    if directory_matches or not search_term:
                        dir_info = {
                            'name': item_name,
                            'path': item_relative_path,
                            'full_path': str(item),
                            'type': 'directory'
                        }
                        index_data['directories'].append(dir_info)
                    
                    # 只有在搜索时才递归搜索子目录
                    if search_term:
                        self._index_directory_flat(item, item_relative_path, index_data, search_term)
                    
                elif item.is_file():
                    # 首先检查是否为白名单文件
                    if not self.config_manager.is_whitelisted_file(str(item)):
                        continue
                    
                    # 如果没有搜索条件（正常浏览），或者文件名匹配搜索条件（搜索模式），添加文件
                    file_matches = True
                    if search_term:
                        try:
                            search_lower = search_term.lower()
                            name_lower = item_name.lower()
                            file_matches = search_lower in name_lower
                        except Exception as e:
                            print(f"搜索匹配错误: {e}")
                            file_matches = False
                    
                    if file_matches:
                        # 添加白名单内的文件
                        try:
                            file_info = {
                                'name': item_name,
                                'path': item_relative_path,
                                'full_path': str(item),
                                'type': self.config_manager.get_file_type(str(item)),
                                'size': item.stat().st_size,
                                'size_formatted': self.config_manager.format_file_size(item.stat().st_size),
                                'extension': item.suffix.lower()
                            }
                            index_data['files'].append(file_info)
                        except Exception as e:
                            print(f"获取文件信息失败: {item} - {e}")
                            continue
        
        except PermissionError:
            # 忽略权限错误
            print(f"权限不足，跳过目录: {dir_path}")
            pass
        except Exception as e:
            print(f"索引目录 {dir_path} 时出错: {e}")
    
    def _index_directory(self, dir_path, relative_path, index_data, search_term):
        """递归索引目录
        
        Args:
            dir_path (Path): 目录路径
            relative_path (str): 相对路径
            index_data (dict): 索引数据
            search_term (str): 搜索关键词
        """
        try:
            # 严格检查目录是否在共享目录内
            if not self.config_manager.is_path_safe(str(dir_path), str(self.share_dir)):
                print(f"跳过目录遍历攻击尝试: {dir_path}")
                return
            
            for item in dir_path.iterdir():
                # 确保item_name使用UTF-8编码，处理所有Unicode字符
                try:
                    item_name = str(item.name)
                except UnicodeDecodeError:
                    print(f"文件名编码错误，跳过: {item}")
                    continue
                
                # 正确构造相对路径：确保与share_dir的关联性
                if relative_path and relative_path.strip():
                    item_relative_path = str(Path(relative_path) / item_name)
                else:
                    item_relative_path = item_name
                
                # 检查搜索条件（支持Unicode字符搜索）
                if search_term:
                    try:
                        search_lower = search_term.lower()
                        name_lower = item_name.lower()
                        # 使用UTF-8编码确保Unicode字符正确比较
                        if isinstance(search_lower, str) and isinstance(name_lower, str):
                            if search_lower not in name_lower:
                                continue
                    except Exception as e:
                        print(f"搜索匹配错误: {e}")
                        continue
                
                # 再次检查路径安全性
                if not self.config_manager.is_path_safe(str(item), str(self.share_dir)):
                    print(f"跳过不安全的路径: {item}")
                    continue
                
                if item.is_dir():
                    # 添加目录
                    dir_info = {
                        'name': item_name,
                        'path': item_relative_path,
                        'full_path': str(item),
                        'type': 'directory'
                    }
                    index_data['directories'].append(dir_info)
                    
                    # 递归索引子目录
                    self._index_directory(item, item_relative_path, index_data, search_term)
                
                elif item.is_file():
                    # 首先检查是否为白名单文件
                    if not self.config_manager.is_whitelisted_file(str(item)):
                        continue
                    
                    try:
                        file_info = {
                            'name': item_name,
                            'path': item_relative_path,
                            'full_path': str(item),
                            'type': self.config_manager.get_file_type(str(item)),
                            'size': item.stat().st_size,
                            'size_formatted': self.config_manager.format_file_size(item.stat().st_size),
                            'extension': item.suffix.lower()
                        }
                        index_data['files'].append(file_info)
                    except Exception as e:
                        print(f"获取文件信息失败: {item} - {e}")
                        continue
        
        except PermissionError:
            # 忽略权限错误
            print(f"权限不足，跳过目录: {dir_path}")
            pass
        except Exception as e:
            print(f"索引目录 {dir_path} 时出错: {e}")
    
    def get_directory_listing(self, dir_path=""):
        """获取目录列表
        
        Args:
            dir_path (str): 相对目录路径
            
        Returns:
            dict: 目录列表数据
        """
        target_dir = self.share_dir / dir_path if dir_path else self.share_dir
        
        if not self.config_manager.is_path_safe(str(target_dir), str(self.share_dir)):
            return None
        
        if not target_dir.exists() or not target_dir.is_dir():
            return None
        
        listing_data = {
            'current_path': dir_path,
            'parent_path': str(Path(dir_path).parent) if dir_path else "",
            'directories': [],
            'files': []
        }
        
        try:
            for item in target_dir.iterdir():
                # 确保item_name使用UTF-8编码，处理所有Unicode字符
                try:
                    item_name = str(item.name)
                except UnicodeDecodeError:
                    print(f"文件名编码错误，跳过: {item}")
                    continue
                
                # 正确构造路径，确保与当前目录的关联性
                if dir_path and dir_path.strip():
                    item_path = str(Path(dir_path) / item_name)
                else:
                    item_path = item_name
                
                if item.is_dir():
                    dir_info = {
                        'name': item_name,
                        'path': item_path,
                        'type': 'directory'
                    }
                    listing_data['directories'].append(dir_info)
                
                elif item.is_file():
                    # 首先检查是否为白名单文件
                    if not self.config_manager.is_whitelisted_file(str(item)):
                        continue
                    
                    file_info = {
                        'name': item_name,
                        'path': item_path,
                        'type': self.config_manager.get_file_type(str(item)),
                        'size': item.stat().st_size,
                        'size_formatted': self.config_manager.format_file_size(item.stat().st_size),
                        'extension': item.suffix.lower()
                    }
                    listing_data['files'].append(file_info)
            
            # 排序
            listing_data['directories'].sort(key=lambda x: x['name'].lower())
            listing_data['files'].sort(key=lambda x: x['name'].lower())
        
        except Exception as e:
            print(f"获取目录列表时出错: {e}")
        
        return listing_data
    
    def get_file_info(self, file_path):
        """获取文件信息
        
        Args:
            file_path (str): 相对文件路径
            
        Returns:
            dict: 文件信息或None
        """
        try:
            # 确保文件路径是安全的
            target_file = self.share_dir / file_path
            
            if not self.config_manager.is_path_safe(str(target_file), str(self.share_dir)):
                print(f"文件路径不安全: {file_path}")
                return None
            
            if not target_file.exists() or not target_file.is_file():
                print(f"文件不存在或不是文件: {target_file}")
                return None
            
            # 获取文件统计信息
            stat = target_file.stat()
            
            # 使用Path.name确保正确处理中文文件名
            file_name = target_file.name
            
            file_info = {
                'name': file_name,
                'path': file_path,
                'full_path': str(target_file),
                'type': self.config_manager.get_file_type(str(target_file)),
                'size': stat.st_size,
                'size_formatted': self.config_manager.format_file_size(stat.st_size),
                'extension': target_file.suffix.lower(),
                'modified_time': stat.st_mtime
            }
            
            print(f"成功获取文件信息: {file_name}")
            return file_info
            
        except Exception as e:
            print(f"获取文件信息时出错: {file_path} - {e}")
            return None


class HTMLTemplate:
    """HTML模板生成器 - 生成所有页面的HTML内容"""
    
    @staticmethod
    def _get_theme_management_js():
        """获取主题管理的JavaScript代码
        
        Returns:
            str: 主题管理JavaScript代码
        """
        return """
    <script>
        // 主题管理工具类
        const ThemeManager = {
            getCurrentTheme() {
                return localStorage.getItem('lan-server-theme') || 'light';
            },
            
            setTheme(theme) {
                document.documentElement.className = theme + '-theme';
                localStorage.setItem('lan-server-theme', theme);
                this.updateThemeButton(theme);
            },
            
            toggleTheme() {
                const currentTheme = this.getCurrentTheme();
                const newTheme = currentTheme === 'light' ? 'dark' : 'light';
                this.setTheme(newTheme);
            },
            
            updateThemeButton(theme) {
                const button = document.getElementById('theme-toggle');
                if (button) {
                    button.textContent = theme === 'light' ? '🌙' : '☀️';
                    button.title = theme === 'light' ? '切换到夜间模式' : '切换到白天模式';
                }
            },
            
            init() {
                const theme = this.getCurrentTheme();
                this.setTheme(theme);
            },
            
            // 强制重新应用主题（用于页面导航后）
            forceApplyTheme() {
                const theme = this.getCurrentTheme();
                // 先移除所有主题类
                document.documentElement.classList.remove('light-theme', 'dark-theme');
                // 再应用当前主题
                document.documentElement.classList.add(theme + '-theme');
                this.updateThemeButton(theme);
                localStorage.setItem('lan-server-theme', theme);
            }
        };
        
        // 全局主题函数
        function toggleTheme() {
            ThemeManager.toggleTheme();
        }
        
        // 立即应用主题（在DOM加载前）
        ThemeManager.forceApplyTheme();
        
        // DOM加载完成后再次确认
        document.addEventListener('DOMContentLoaded', function() {
            ThemeManager.forceApplyTheme();
        });
        
        // 页面加载完成后的最终保障
        window.addEventListener('load', function() {
            ThemeManager.forceApplyTheme();
        });
    </script>"""
    
    @staticmethod
    def _get_search_management_js():
        """获取搜索管理的JavaScript代码
        
        Returns:
            str: 搜索管理JavaScript代码
        """
        return """
    <script>
        // 搜索管理工具类
        const SearchManager = {
            performSearch() {
                const searchInput = document.getElementById('search-input');
                if (!searchInput) return;
                
                const searchTerm = searchInput.value.trim();
                const url = searchTerm ? `/search?q=${encodeURIComponent(searchTerm)}` : '/index';
                window.location.href = url;
            },
            
            initSearch() {
                const searchInput = document.getElementById('search-input');
                if (searchInput) {
                    // 回车搜索
                    searchInput.addEventListener('keypress', function(e) {
                        if (e.key === 'Enter') {
                            SearchManager.performSearch();
                        }
                    });
                }
            }
        };
        
        // 全局搜索函数
        function performSearch() {
            SearchManager.performSearch();
        }
    </script>"""
    
    @staticmethod
    def get_base_template(title, content, theme="light", additional_head=""):
        """获取基础HTML模板
        
        Args:
            title (str): 页面标题
            content (str): 页面内容
            theme (str): 主题（light/dark）
            additional_head (str): 额外的head内容
            
        Returns:
            str: 完整的HTML
        """
        theme_class = "dark-theme" if theme == "dark" else "light-theme"
        theme_js = HTMLTemplate._get_theme_management_js()
        
        return f"""<!DOCTYPE html>
<html lang="zh-CN" class="{theme_class}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link rel="stylesheet" href="/static/style.css?v=2025-12-29-4">
    {theme_js}
    {additional_head}
</head>
<body>
    <header class="header">
        <h1 class="title">LAN文件服务器</h1>
        <button id="theme-toggle" class="theme-toggle" onclick="toggleTheme()" title="切换主题">🌙</button>
    </header>
    
    <main class="main-content">
        {content}
    </main>
    
    <footer class="footer">
        <p>&copy; 2025 LAN文件服务器 - 轻量、美观、安全</p>
    </footer>
</body>
</html>"""
    
    @staticmethod
    def get_login_page(error_message="", remaining_attempts=5):
        """获取登录页面HTML
        
        Args:
            error_message (str): 错误信息
            remaining_attempts (int): 剩余尝试次数
            
        Returns:
            str: 登录页面HTML
        """
        error_html = f'<div class="error-message">{error_message}</div>' if error_message else ""
        attempts_html = f'<div class="attempts-info">剩余尝试次数: {remaining_attempts}</div>' if remaining_attempts <= 3 else ""
        
        content = f"""
        <div class="login-container">
            <div class="login-card">
                <h2>身份认证</h2>
                {error_html}
                {attempts_html}
                <form method="post" action="/login">
                    <div class="form-group">
                        <label for="username">用户名:</label>
                        <input type="text" id="username" name="username" required autocomplete="username">
                    </div>
                    <div class="form-group">
                        <label for="password">密码:</label>
                        <input type="password" id="password" name="password" required autocomplete="current-password">
                    </div>
                    <button type="submit" class="login-button">登录</button>
                </form>
                <div class="login-hint">
                    <p>请输入用户名和密码以访问文件服务器</p>
                </div>
            </div>
        </div>
        """
        
        return HTMLTemplate.get_base_template("登录 - LAN文件服务器", content)
    
    @staticmethod
    def get_index_page(index_data, search_term=""):
        """获取索引页面HTML
        
        Args:
            index_data (dict): 索引数据
            search_term (str): 搜索关键词
            
        Returns:
            str: 索引页面HTML
        """
        # 搜索框
        search_html = f"""
        <div class="search-container">
            <input type="text" 
                   id="search-input" 
                   class="search-input" 
                   placeholder="搜索文件或文件夹..." 
                   value="{search_term}">
            <button class="search-button" onclick="performSearch()">搜索</button>
        </div>
        """
        
        # 统计信息
        total_dirs = len(index_data['directories'])
        total_files = len(index_data['files'])
        stats_html = f'<div class="stats">找到 {total_dirs} 个文件夹，{total_files} 个文件</div>'
        
        # 目录列表
        directories_html = ""
        if index_data['directories']:
            directories_html = """
            <div class="section">
                <h3>📁 文件夹 ({total_dirs})</h3>
                <ul class="file-list">
            """.format(total_dirs=total_dirs)
            
            for directory in index_data['directories']:
                directories_html += f"""
                    <li class="file-item directory">
                        <span class="file-icon">📁</span>
                        <a href="/browse/{directory['path']}" class="file-link">{directory['name']}</a>
                    </li>
                """
            
            directories_html += """
                </ul>
            </div>
            """
        
        # 文件列表
        files_html = ""
        if index_data['files']:
            files_html = """
            <div class="section">
                <h3>📄 文件 ({total_files})</h3>
                <ul class="file-list">
            """.format(total_files=total_files)
            
            for file_info in index_data['files']:
                type_icon = {
                    'image': '🖼️',
                    'audio': '🎵',
                    'video': '🎬'
                }.get(file_info['type'], '📄')
                
                files_html += f"""
                    <li class="file-item file">
                        <span class="file-icon">{type_icon}</span>
                        <div class="file-info">
                            <a href="/download/{urlquote(file_info['path'], encoding='utf-8', safe='')}" class="file-link" title="{file_info['name']}">{file_info['name']}</a>
                            <span class="file-size">{file_info['size_formatted']}</span>
                        </div>
                    </li>
                """
            
            files_html += """
                </ul>
            </div>
            """
        
        # 无结果提示
        no_results_html = ""
        if total_dirs == 0 and total_files == 0:
            no_results_html = '<div class="no-results">未找到匹配的内容</div>'
        
        content = f"""
        <div class="index-container">
            <div class="header-section">
                <div class="page-header">
                    <h2>文件浏览器</h2>
                    <p class="page-description">当前目录内容</p>
                </div>
                
                <div class="search-section">
                    {search_html}
                </div>
            </div>
            
            <div class="files-content">
                {stats_html}
                {directories_html}
                {files_html}
                {no_results_html}
            </div>
        </div>
        
        {HTMLTemplate._get_search_management_js()}
        <script>
            // 初始化搜索功能
            document.addEventListener('DOMContentLoaded', function() {{
                SearchManager.initSearch();
            }});
        </script>
        """
        
        return HTMLTemplate.get_base_template("文件索引 - LAN文件服务器", content)
    
    @staticmethod
    def get_browse_page(listing_data):
        """获取浏览页面HTML
        
        Args:
            listing_data (dict): 目录列表数据
            
        Returns:
            str: 浏览页面HTML
        """
        current_path = listing_data['current_path']
        parent_path = listing_data['parent_path']
        
        # 路径导航
        path_breadcrumbs = ""
        if current_path:
            path_parts = current_path.split('/')
            path_breadcrumbs = '<a href="/index">首页</a>'
            accumulated_path = ""
            
            for i, part in enumerate(path_parts):
                accumulated_path += part + '/' if i < len(path_parts) - 1 else part
                path_breadcrumbs += f' / <a href="/browse/{urlquote(accumulated_path, encoding='utf-8', safe='')}">{part}</a>'
        else:
            path_breadcrumbs = '<span>首页</span>'
        
        # 返回按钮
        back_button = ""
        if current_path:
            back_url = "/browse/" + urlquote(parent_path, encoding='utf-8', safe='') if parent_path else "/index"
            back_button = f'<a href="{back_url}" class="back-button">⬅️ 返回上一层</a>'
        
        # 统计信息
        total_dirs = len(listing_data['directories'])
        total_files = len(listing_data['files'])
        stats_html = f'<div class="stats">当前目录: {total_dirs} 个文件夹，{total_files} 个文件</div>'
        
        # 目录列表
        directories_html = ""
        if listing_data['directories']:
            directories_html = """
            <div class="section">
                <h3>📁 文件夹 ({total_dirs})</h3>
                <ul class="file-list">
            """.format(total_dirs=total_dirs)
            
            for directory in listing_data['directories']:
                directories_html += f"""
                    <li class="file-item directory">
                        <span class="file-icon">📁</span>
                        <a href="/browse/{urlquote(directory['path'], encoding='utf-8', safe='')}" class="file-link">{directory['name']}</a>
                    </li>
                """
            
            directories_html += """
                </ul>
            </div>
            """
        
        # 文件列表
        files_html = ""
        if listing_data['files']:
            files_html = """
            <div class="section">
                <h3>📄 文件 ({total_files})</h3>
                <ul class="file-list">
            """.format(total_files=total_files)
            
            for file_info in listing_data['files']:
                type_icon = {
                    'image': '🖼️',
                    'audio': '🎵',
                    'video': '🎬'
                }.get(file_info['type'], '📄')
                
                files_html += f"""
                    <li class="file-item file">
                        <span class="file-icon">{type_icon}</span>
                        <div class="file-info">
                            <a href="/download/{urlquote(file_info['path'], encoding='utf-8', safe='')}" class="file-link" title="{file_info['name']}">{file_info['name']}</a>
                            <span class="file-size">{file_info['size_formatted']}</span>
                        </div>
                    </li>
                """
            
            files_html += """
                </ul>
            </div>
            """
        
        # 搜索框
        search_html = """
        <div class="search-container">
            <input type="text" 
                   id="search-input" 
                   class="search-input" 
                   placeholder="搜索文件或文件夹...">
            <button class="search-button" onclick="performSearch()">搜索</button>
        </div>
        """
        
        content = f"""
        <div class="browse-container">
            <div class="header-section">
                <div class="page-header">
                    <h2>浏览目录</h2>
                    <div class="path-navigation">
                        {path_breadcrumbs}
                    </div>
                    {back_button}
                </div>
                
                {search_html}
            </div>
            
            <div class="files-content">
                {stats_html}
                {directories_html}
                {files_html}
            </div>
        </div>
        """
        
        title = f"浏览: {current_path if current_path else '根目录'} - LAN文件服务器"
        
        # 添加搜索管理的JavaScript
        content += f"""
        {HTMLTemplate._get_search_management_js()}
        <script>
            // 初始化搜索功能
            document.addEventListener('DOMContentLoaded', function() {{
                SearchManager.initSearch();
            }});
        </script>
        """
        
        return HTMLTemplate.get_base_template(title, content)
    
    @staticmethod
    def get_404_page():
        """获取404错误页面HTML
        
        Returns:
            str: 404页面HTML
        """
        content = """
        <div class="error-container">
            <div class="error-card">
                <h2>404 - 页面未找到</h2>
                <p>抱歉，您访问的页面不存在。</p>
                <div class="error-actions">
                    <a href="/index" class="action-button">返回首页</a>
                    <a href="/browse" class="action-button">浏览目录</a>
                </div>
            </div>
        </div>
        """
        
        return HTMLTemplate.get_base_template("404 - 页面未找到", content)
    
    @staticmethod
    def get_blocked_page(remaining_time):
        """获取IP封禁页面HTML
        
        Args:
            remaining_time (int): 剩余封禁时间（秒）
            
        Returns:
            str: 封禁页面HTML
        """
        minutes = remaining_time // 60
        seconds = remaining_time % 60
        time_str = f"{minutes}分{seconds}秒" if minutes > 0 else f"{seconds}秒"
        
        content = f"""
        <div class="error-container">
            <div class="error-card">
                <h2>访问被限制</h2>
                <p>由于多次认证失败，您的IP地址已被临时封禁。</p>
                <div class="blocked-info">
                    <p>剩余封禁时间: <strong>{time_str}</strong></p>
                    <p>请稍后再试，或联系管理员。</p>
                </div>
            </div>
        </div>
        """
        
        return HTMLTemplate.get_base_template("访问被限制 - LAN文件服务器", content)


class FileServerHandler(BaseHTTPRequestHandler):
    """文件服务器请求处理器"""
    
    def __init__(self, *args, config_manager=None, **kwargs):
        self.config_manager = config_manager
        self.auth_manager = AuthenticationManager(config_manager)
        self.file_indexer = FileIndexer(config_manager)
        
        # 设置静态文件目录
        if config_manager:
            self.share_dir = Path(config_manager.server_config['SHARE_DIR'])
            # 静态文件目录指向项目根目录下的static文件夹
            self.static_dir = Path(__file__).parent / 'static'
        else:
            self.share_dir = Path('.')
            self.static_dir = Path('.') / 'static'
        
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """处理GET请求"""
        try:
            # 解析URL
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            query_params = parse_qs(parsed_url.query)
            
            # 检查IP封禁
            client_ip = self.client_address[0]
            if self.config_manager.is_ip_blocked(client_ip):
                remaining_time = self.config_manager.server_config['FAILED_AUTH_BLOCK_TIME']
                html = HTMLTemplate.get_blocked_page(remaining_time)
                self._send_html_response(html, 429)
                return
            
            # 检查认证
            if not self._is_authenticated():
                if path.startswith('/static/') or path == '/favicon.ico':
                    # 允许访问静态资源（但通常是认证后访问）
                    pass
                else:
                    # 重定向到登录页面
                    if path != '/login':
                        self.send_response(302)
                        self.send_header('Location', '/login')
                        self.end_headers()
                        return
                    else:
                        # 显示登录页面
                        html = HTMLTemplate.get_login_page()
                        self._send_html_response(html)
                        return
            
            # 路由处理
            if path == '/' or path == '/index':
                self._handle_index(query_params)
            elif path == '/search':
                self._handle_search(query_params)
            elif path.startswith('/browse'):
                self._handle_browse(path)
            elif path.startswith('/download'):
                self._handle_download(path)
            elif path.startswith('/static/'):
                self._handle_static(path)
            elif path == '/favicon.ico':
                self._handle_favicon()
            else:
                # 404页面
                html = HTMLTemplate.get_404_page()
                self._send_html_response(html, 404)
        
        except Exception as e:
            print(f"处理GET请求时出错: {e}")
            self._send_error_response(500, "服务器内部错误")
    
    def do_POST(self):
        """处理POST请求"""
        try:
            if self.path == '/login':
                self._handle_login()
            else:
                self._send_error_response(404, "页面未找到")
        except Exception as e:
            print(f"处理POST请求时出错: {e}")
            self._send_error_response(500, "服务器内部错误")
    
    def _is_authenticated(self):
        """检查是否已认证"""
        # 首先检查Session Cookie
        cookie_header = self.headers.get('Cookie', '')
        session_id = self._extract_session_id(cookie_header)
        
        print(f"DEBUG: Cookie header: {cookie_header}")
        print(f"DEBUG: Session ID: {session_id}")
        
        if session_id:
            is_valid = self.auth_manager.validate_session(session_id)
            print(f"DEBUG: Session valid: {is_valid}")
            if is_valid:
                return True
        
        # 回退到HTTP Basic Auth（向后兼容）
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            return False
        
        username, password = self.auth_manager.extract_credentials(auth_header)
        if not username or not password:
            return False
        
        return self.auth_manager.verify_credentials(username, password)
    
    def _extract_session_id(self, cookie_header):
        """从Cookie头中提取session ID
        
        Args:
            cookie_header (str): Cookie头值
            
        Returns:
            str or None: session ID或None
        """
        if not cookie_header:
            return None
        
        try:
            for cookie in cookie_header.split(';'):
                cookie = cookie.strip()
                if cookie.startswith('lan_session='):
                    return cookie.split('=', 1)[1]
            return None
        except Exception:
            return None
    
    def _handle_index(self, query_params):
        """处理索引页面请求"""
        search_term = query_params.get('search', [''])[0]
        search_term = unquote(search_term, encoding='utf-8', errors='replace')
        
        index_data = self.file_indexer.generate_index(search_term)
        html = HTMLTemplate.get_index_page(index_data, search_term)
        self._send_html_response(html)
    
    def _handle_search(self, query_params):
        """处理搜索页面请求"""
        search_term = query_params.get('q', [''])[0]
        search_term = unquote(search_term, encoding='utf-8', errors='replace')
        
        index_data = self.file_indexer.generate_index(search_term)
        html = HTMLTemplate.get_index_page(index_data, search_term)
        self._send_html_response(html)
    
    def _handle_browse(self, path):
        """处理目录浏览请求"""
        # 提取相对路径
        relative_path = path[8:]  # 移除 "/browse/" 前缀
        if relative_path.startswith('/'):
            relative_path = relative_path[1:]
        
        # URL解码处理中文文件夹名和特殊字符
        try:
            relative_path = unquote(relative_path)
        except Exception as e:
            print(f"URL解码失败: {e}")
            html = HTMLTemplate.get_404_page()
            self._send_html_response(html, 404)
            return
        
        listing_data = self.file_indexer.get_directory_listing(relative_path)
        
        if listing_data is None:
            html = HTMLTemplate.get_404_page()
            self._send_html_response(html, 404)
            return
        
        html = HTMLTemplate.get_browse_page(listing_data)
        self._send_html_response(html)
    
    def _handle_download(self, path):
        """处理文件下载请求"""
        # 提取文件路径
        file_path = path[10:]  # 移除 "/download/" 前缀
        if file_path.startswith('/'):
            file_path = file_path[1:]
        
        # 检查Range请求（用于视频流播放）
        range_header = self.headers.get('Range')
        range_info = None
        if range_header:
            range_info = self._parse_range_header(range_header)
        
        # URL解码处理中文文件名和特殊字符
        try:
            file_path = unquote(file_path, encoding='utf-8', errors='replace')
            print(f"处理下载请求: {file_path}")
            if range_info:
                print(f"Range请求: {range_info}")
        except Exception as e:
            print(f"URL解码失败: {e}")
            html = HTMLTemplate.get_404_page()
            self._send_html_response(html, 404)
            return
        
        file_info = self.file_indexer.get_file_info(file_path)
        
        if file_info is None:
            html = HTMLTemplate.get_404_page()
            self._send_html_response(html, 404)
            return
        
        # 发送文件
        try:
            # 再次检查文件路径安全性
            if not self.config_manager.is_path_safe(file_info['full_path'], str(self.file_indexer.share_dir)):
                print(f"下载请求路径不安全: {file_info['full_path']}")
                html = HTMLTemplate.get_404_page()
                self._send_html_response(html, 404)
                return
            
            # 大文件处理：支持流式传输
            file_size = os.path.getsize(file_info['full_path'])
            content_type = mimetypes.guess_type(file_info['full_path'])[0] or 'application/octet-stream'
            
            # 检测文件类型决定是否inline显示
            inline_types = {'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp', 
                           'video/mp4', 'video/webm', 'video/ogg', 'video/avi', 'video/mov'}
            is_inline = content_type in inline_types
            
            # 处理Range请求
            if range_info:
                # Range请求返回206状态码
                self.send_response(206)
                
                # 处理end为None的情况（从start到文件末尾）
                range_end = range_info['end']
                if range_end is None:
                    range_end = file_size - 1
                
                # 设置Content-Range头
                content_range = f"bytes {range_info['start']}-{range_end}/{file_size}"
                self.send_header('Content-Range', content_range)
                # 设置Content-Length为实际发送的数据长度
                content_length = range_end - range_info['start'] + 1
                self.send_header('Content-Length', str(content_length))
            else:
                # 正常请求返回200状态码
                self.send_response(200)
                # 大文件不设置Content-Length，让浏览器自动检测
                if file_size < 100 * 1024 * 1024:  # 小于100MB的文件才设置Content-Length
                    self.send_header('Content-Length', str(file_size))
            
            # 设置Content-Type
            self.send_header('Content-Type', content_type)
            
            # 使用RFC 2231标准处理Unicode字符（中文、日文、韩文、生僻字、特殊符号）
            filename_encoded = urlquote(file_info["name"], encoding='utf-8', safe='')
            if is_inline:
                # 浏览器原生预览
                self.send_header('Content-Disposition', f'inline; filename*=UTF-8\'\'{filename_encoded}')
            else:
                # 强制下载
                self.send_header('Content-Disposition', f'attachment; filename*=UTF-8\'\'{filename_encoded}')
            
            # 支持Range请求，允许视频流播放
            if content_type.startswith('video/') or content_type.startswith('audio/'):
                self.send_header('Accept-Ranges', 'bytes')
                self.send_header('Cache-Control', 'no-cache')
            elif is_inline:
                # 设置缓存控制头
                self.send_header('Cache-Control', 'public, max-age=3600')
            
            self.end_headers()
            
            # 发送文件内容
            self._send_file_content(file_info['full_path'], range_info)
        
        except FileNotFoundError:
            print(f"文件未找到: {file_info['full_path']}")
            html = HTMLTemplate.get_404_page()
            self._send_html_response(html, 404)
        except Exception as e:
            print(f"发送文件时出错: {e}")
            self._send_error_response(500, "文件读取错误")
    
    def _send_file_stream(self, file_path):
        """流式发送大文件"""
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)  # 8KB块
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except Exception as e:
            print(f"流式发送文件时出错: {e}")
    
    def _parse_range_header(self, range_header):
        """解析Range请求头
        
        Args:
            range_header (str): Range请求头，如 "bytes=0-1023"
            
        Returns:
            dict: 包含start和end的字典，如果解析失败返回None
        """
        try:
            if not range_header.startswith('bytes='):
                return None
            
            range_spec = range_header[6:]  # 移除 "bytes=" 前缀
            
            if '-' not in range_spec:
                return None
            
            parts = range_spec.split('-', 1)
            start_str = parts[0]
            end_str = parts[1]
            
            # 处理开始位置
            if start_str:
                start = int(start_str)
            else:
                start = 0
            
            # 处理结束位置
            if end_str:
                end = int(end_str)
            else:
                end = None
            
            return {'start': start, 'end': end}
        except (ValueError, IndexError):
            return None
    
    def _send_file_content(self, file_path, range_info=None):
        """发送文件内容（支持Range请求）
        
        Args:
            file_path (str): 文件路径
            range_info (dict): Range信息，包含start和end
        """
        try:
            with open(file_path, 'rb') as f:
                if range_info:
                    # Range请求：跳转到指定位置
                    start = range_info['start']
                    end = range_info['end']
                    
                    if end is None:
                        # 范围请求的结尾未指定，读取到文件末尾
                        f.seek(start)
                        while True:
                            chunk = f.read(8192)  # 8KB块
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                    else:
                        # 指定的范围
                        file_size = os.path.getsize(file_path)
                        end = min(end, file_size - 1)  # 确保不超过文件大小
                        
                        f.seek(start)
                        remaining = end - start + 1
                        while remaining > 0:
                            chunk_size = min(8192, remaining)
                            chunk = f.read(chunk_size)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            remaining -= len(chunk)
                else:
                    # 正常请求：根据文件大小决定传输方式
                    file_size = os.path.getsize(file_path)
                    if file_size >= 100 * 1024 * 1024:  # 大文件流式传输
                        while True:
                            chunk = f.read(8192)  # 8KB块
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            self.wfile.flush()
                    else:
                        # 小文件直接读取发送
                        content = f.read()
                        self.wfile.write(content)
        except Exception as e:
            print(f"发送文件内容时出错: {e}")
    
    def _handle_static(self, path):
        """处理静态资源请求"""
        try:
            # 移除 /static/ 前缀
            static_file = path.replace('/static/', '')
            static_path = self.static_dir / static_file
            
            # 安全检查：确保文件在static目录内
            if not str(static_path).startswith(str(self.static_dir)):
                self._send_error_response(403, "访问被禁止")
                return
            
            # 检查文件是否存在
            if not static_path.exists() or not static_path.is_file():
                self._send_error_response(404, "文件未找到")
                return
            
            # 获取文件类型
            content_type = self._get_content_type(static_path.suffix)
            
            # 读取并发送文件
            with open(static_path, 'rb') as f:
                content = f.read()
            
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'public, max-age=3600')  # 缓存1小时
            self.end_headers()
            self.wfile.write(content)
            
        except Exception as e:
            print(f"处理静态文件时出错: {e}")
            self._send_error_response(500, "服务器内部错误")
    
    def _handle_favicon(self):
        """处理网站图标请求"""
        self.send_response(204)
        self.end_headers()
    
    def _handle_login(self):
        """处理登录请求"""
        client_ip = self.client_address[0]
        
        # 检查IP封禁
        if self.config_manager.is_ip_blocked(client_ip):
            remaining_time = self.config_manager.server_config['FAILED_AUTH_BLOCK_TIME']
            html = HTMLTemplate.get_blocked_page(remaining_time)
            self._send_html_response(html, 429)
            return
        
        # 读取POST数据
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            # 解析表单数据
            form_data = {}
            for param in post_data.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    form_data[unquote(key)] = unquote(value)
            
            username = form_data.get('username', '')
            password = form_data.get('password', '')
            
            # 验证凭据
            if self.auth_manager.verify_credentials(username, password):
                # 认证成功，清除失败记录，创建session
                self.config_manager.reset_failed_attempts(client_ip)
                session_id = self.auth_manager.create_session(username)
                
                # 设置session cookie
                cookie_value = f"lan_session={session_id}; Path=/; HttpOnly; Max-Age=86400"  # 24小时
                
                self.send_response(302)
                self.send_header('Location', '/index')
                self.send_header('Set-Cookie', cookie_value)
                self.end_headers()
                return
            else:
                # 认证失败，记录失败尝试
                self.config_manager.record_failed_attempt(client_ip)
                remaining_attempts = self.config_manager.get_remaining_attempts(client_ip)
                
                error_message = "用户名或密码错误"
                if remaining_attempts <= 0:
                    error_message = "认证失败次数过多，IP已被封禁"
                
                html = HTMLTemplate.get_login_page(error_message, remaining_attempts)
                self._send_html_response(html, 401)
                return
        
        # 如果没有POST数据，显示登录页面
        html = HTMLTemplate.get_login_page()
        self._send_html_response(html)
    
    def _send_html_response(self, html_content, status_code=200):
        """发送HTML响应
        
        Args:
            html_content (str): HTML内容
            status_code (int): HTTP状态码
        """
        try:
            self.send_response(status_code)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(html_content.encode('utf-8'))))
            self.end_headers()
            self.wfile.write(html_content.encode('utf-8'))
        except Exception as e:
            print(f"发送HTML响应时出错: {e}")
    
    def _get_content_type(self, file_extension):
        """获取文件MIME类型
        
        Args:
            file_extension (str): 文件扩展名
            
        Returns:
            str: MIME类型
        """
        content_types = {
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.svg': 'image/svg+xml',
            '.ico': 'image/x-icon',
            '.woff': 'font/woff',
            '.woff2': 'font/woff2',
            '.ttf': 'font/ttf',
            '.otf': 'font/otf'
        }
        return content_types.get(file_extension.lower(), 'application/octet-stream')
    
    def _send_error_response(self, status_code, message):
        """发送错误响应
        
        Args:
            status_code (int): HTTP状态码
            message (str): 错误信息
        """
        error_html = f"""
        <html>
        <head><title>Error {status_code}</title></head>
        <body>
            <h1>Error {status_code}</h1>
            <p>{message}</p>
        </body>
        </html>
        """
        self._send_html_response(error_html, status_code)
    
    def log_message(self, format, *args):
        """重写日志方法，减少输出"""
        if args[1] != '200':  # 只记录非200状态码的请求
            super().log_message(format, *args)


class FileServer:
    """文件服务器主类"""
    
    def __init__(self, config_manager=None):
        self.config_manager = config_manager or get_config_manager()
        self.server = None
        self.server_thread = None
        self.running = False
    
    def start(self):
        """启动服务器"""
        try:
            # 获取有效端口
            port = self.config_manager.get_effective_port()
            if not port:
                print("无法启动服务器：没有可用端口")
                return False
            
            # 创建服务器
            def create_handler(*args, **kwargs):
                return FileServerHandler(*args, config_manager=self.config_manager, **kwargs)
            
            self.server = HTTPServer(('0.0.0.0', port), create_handler)
            self.running = True
            
            logger.info("=== LAN文件服务器启动成功 ===")
            logger.info(f"本地访问: http://localhost:{port}")
            logger.info(f"局域网访问: http://[本机IP]:{port}")
            logger.info(f"共享目录: {self.config_manager.server_config['SHARE_DIR']}")
            logger.info(f"白名单文件类型: {len(self.config_manager.ALL_WHITELIST_EXTENSIONS)} 种")
            logger.info("按 Ctrl+C 停止服务器")
            logger.info("=" * 40)
            
            print(f"\n=== LAN文件服务器启动成功 ===")
            print(f"本地访问: http://localhost:{port}")
            print(f"局域网访问: http://[本机IP]:{port}")
            print(f"共享目录: {self.config_manager.server_config['SHARE_DIR']}")
            print(f"白名单文件类型: {len(self.config_manager.ALL_WHITELIST_EXTENSIONS)} 种")
            print(f"按 Ctrl+C 停止服务器")
            print("=" * 40)
            
            # 在新线程中启动服务器
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            
            return True
        
        except Exception as e:
            logger.error(f"启动服务器时出错: {e}", exc_info=True)
            print(f"启动服务器时出错: {e}")
            return False
    
    def stop(self):
        """停止服务器"""
        if self.server and self.running:
            logger.info("正在停止服务器...")
            print("\n正在停止服务器...")
            self.running = False
            self.server.shutdown()
            self.server.server_close()
            logger.info("服务器已停止")
            print("服务器已停止")


# 全局变量用于信号处理
server_instance = None

def signal_handler(signum, frame):
    """信号处理器"""
    global server_instance
    print(f"\n收到信号 {signum}，正在退出...")
    if server_instance:
        server_instance.stop()
    sys.exit(0)

def main():
    """主函数"""
    global server_instance
    
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # 初始化配置管理器
        config = get_config_manager()
        
        # 创建服务器
        server_instance = FileServer(config)
        
        if server_instance.start():
            try:
                # 保持主线程运行
                while server_instance.running:
                    time.sleep(0.1)  # 短暂休眠，减少CPU使用
            except KeyboardInterrupt:
                print("\n收到中断信号，正在停止服务器...")
                server_instance.stop()
    except Exception as e:
        print(f"服务器运行出错: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()