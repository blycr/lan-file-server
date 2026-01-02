import os
import sys
import base64
import json
import mimetypes
import signal
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote
from urllib.parse import quote as urlquote
from pathlib import Path
import threading
import time
from datetime import datetime, timedelta

# 添加正确的MIME类型映射
mimetypes.add_type("video/x-msvideo", ".avi")  # 标准.avi文件MIME类型
mimetypes.add_type("video/mp4", ".mp4")  # 确保mp4映射正确
mimetypes.add_type("video/webm", ".webm")  # 确保webm映射正确
mimetypes.add_type("video/ogg", ".ogg")  # 确保ogg映射正确
mimetypes.add_type("video/x-matroska", ".mkv")  # 确保mkv映射正确
mimetypes.add_type("video/x-ms-wmv", ".wmv")  # 确保wmv映射正确
mimetypes.add_type("video/x-flv", ".flv")  # 确保flv映射正确

from config import get_config_manager
from color_logger import get_rich_logger


# 获取配置管理器实例
config_manager = get_config_manager()

# 配置日志记录 - 使用彩色日志系统
log_level = getattr(
    logging, config_manager.logging_config["LOG_LEVEL"].upper(), logging.INFO
)

# 初始化富文本日志器
logger = get_rich_logger("LANFileServer", log_level)


# 文件大小格式化缓存
_size_format_cache = {}
_MAX_SIZE_CACHE = 100  # 限制缓存条数，内存占用可忽略


def format_file_size(size):
    """缓存文件大小格式化结果，减少重复计算

    Args:
        size (int): 文件大小（字节）

    Returns:
        str: 格式化后的文件大小
    """
    # 缓存键：文件大小数值（字符串类型，避免类型冲突）
    cache_key = str(size)
    if cache_key in _size_format_cache:
        return _size_format_cache[cache_key]

    # 原有大小格式化逻辑
    if size == 0:
        formatted = "0 B"
    else:
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024.0:
                formatted = f"{size:.2f} {unit}"
                break
            size /= 1024.0
        else:
            formatted = f"{size:.2f} TB"

    # 写入缓存，超出数量时删除最旧条目
    _size_format_cache[cache_key] = formatted
    if len(_size_format_cache) > _MAX_SIZE_CACHE:
        _size_format_cache.pop(next(iter(_size_format_cache)))

    return formatted


class HTTPError(Exception):
    """HTTP错误异常类

    Args:
        status_code (int): HTTP状态码
        message (str): 错误信息
        details (dict, optional): 详细错误信息
    """

    def __init__(self, status_code, message, details=None):
        self.status_code = status_code
        self.message = message
        self.details = details or {}
        super().__init__(f"HTTP {status_code}: {message}")


def error_handler(func):
    """统一错误处理装饰器

    捕获函数执行过程中的所有异常，记录详细日志，并返回适当的错误响应
    """

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except HTTPError as e:
            # 处理HTTP错误
            logger.error(f"HTTP错误: {e}")
            if hasattr(args[0], "send_response"):
                handler = args[0]
                try:
                    # 使用HTML模板生成友好的错误页面
                    if e.status_code == 404:
                        html = HTMLTemplate.get_404_page()
                    elif e.status_code == 429:
                        remaining_time = handler.config_manager.server_config[
                            "FAILED_AUTH_BLOCK_TIME"
                        ]
                        html = HTMLTemplate.get_blocked_page(remaining_time)
                    else:
                        # 生成通用错误页面
                        content = f"""
                        <div class="error-container glass-effect">
                            <div class="error-card glass-card">
                                <h2>{e.status_code} - {e.message}</h2>
                                <p>抱歉，服务器遇到了一个错误。</p>
                                <div class="error-details">
                                    <p>{e.details.get('description', '')}</p>
                                </div>
                                <div class="error-actions">
                                    <a href="/index" class="action-button">返回首页</a>
                                    <a href="/browse" class="action-button">浏览目录</a>
                                </div>
                            </div>
                        </div>
                        """
                        html = HTMLTemplate.get_base_template(
                            f"{e.status_code} - {e.message}", content
                        )

                    handler._send_html_response(html, e.status_code)
                except Exception as e2:
                    logger.error(f"发送HTTP错误响应时出错: {e2}", exc_info=True)
        except Exception as e:
            # 记录详细错误日志
            logger.error(f"执行 {func.__name__} 时出错: {e}", exc_info=True)
            # 对于HTTP请求处理函数，返回500错误
            if hasattr(args[0], "send_response"):
                handler = args[0]
                try:
                    # 生成500错误页面
                    content = f"""
                    <div class="error-container glass-effect">
                        <div class="error-card glass-card">
                            <h2>500 - 服务器内部错误</h2>
                            <p>抱歉，服务器遇到了一个意外的错误。</p>
                            <div class="error-details">
                                <p>错误信息: {str(e)}</p>
                                <p>请联系管理员或稍后重试。</p>
                            </div>
                            <div class="error-actions">
                                <a href="/index" class="action-button">返回首页</a>
                                <a href="/browse" class="action-button">浏览目录</a>
                            </div>
                        </div>
                    </div>
                    """
                    html = HTMLTemplate.get_base_template(
                        "500 - 服务器内部错误", content
                    )
                    handler._send_html_response(html, 500)
                except Exception as e2:
                    logger.error(f"发送错误响应时出错: {e2}", exc_info=True)
        return

    return wrapper


class AuthenticationManager:
    """认证管理器 - 处理用户认证和密码验证"""

    def __init__(self, config_manager):
        self.config_manager = config_manager
        # 存储已使用的密码时间戳，用于防重放攻击
        self.used_timestamps = set()
        # 已使用时间戳的清理周期（秒）
        self.timestamp_cleanup_interval = 3600  # 1小时
        # 启动清理线程
        self._start_timestamp_cleanup_thread()

    def _start_timestamp_cleanup_thread(self):
        """启动定期清理已使用时间戳的线程"""

        def cleanup_thread_func():
            while True:
                time.sleep(self.timestamp_cleanup_interval)
                self._cleanup_used_timestamps()

        thread = threading.Thread(
            target=cleanup_thread_func, daemon=True, name="TimestampCleanup"
        )
        thread.start()

    def _cleanup_used_timestamps(self):
        """清理已过期的时间戳（超过5分钟）"""
        current_time = time.time()
        expired_timestamps = [
            ts for ts in self.used_timestamps if current_time - ts > 360
        ]  # 6分钟
        for ts in expired_timestamps:
            self.used_timestamps.discard(ts)
        logger.debug(
            f"清理已过期时间戳，清理了 {len(expired_timestamps)} 个，剩余 {len(self.used_timestamps)} 个"
        )

    def verify_credentials(self, username, password):
        """验证用户名和密码

        基于用户当前登录时间前后5分钟的动态密码验证机制

        Args:
            username (str): 用户名
            password (str): 密码

        Returns:
            bool: 认证是否成功
        """
        # 从配置文件获取用户名
        config_username = self.config_manager.auth_config.get("username", "admin")
        if username != config_username:
            logger.info(f"用户认证失败 - 用户名不正确: {username}")
            return False

        current_time = datetime.now()
        expected_passwords = []
        used_timestamps = []

        # 生成前后5分钟内的所有可能密码和对应的时间戳
        for minutes_offset in range(-5, 6):
            # 计算偏移后的时间
            offset_time = current_time + timedelta(minutes=minutes_offset)
            # 生成密码格式 yyyymmddHHMM
            offset_password = offset_time.strftime("%Y%m%d%H%M")
            expected_passwords.append(offset_password)
            # 生成对应的时间戳（用于防重放攻击）
            timestamp = offset_time.strftime("%Y%m%d%H%M")
            used_timestamps.append(timestamp)

        logger.info(f"用户认证尝试 - 用户名: {username}")
        logger.debug(f"输入密码: {password}")
        logger.debug(f"预期密码范围: {expected_passwords}")

        # 检查密码是否在预期范围内
        if password not in expected_passwords:
            logger.info("用户认证失败 - 密码不正确")
            return False

        # 防重放攻击检查：验证该时间戳是否已被使用
        timestamp_index = expected_passwords.index(password)
        timestamp = used_timestamps[timestamp_index]

        if timestamp in self.used_timestamps:
            logger.warning("用户认证失败 - 密码已被使用（防重放攻击）")
            return False

        # 记录已使用的时间戳
        self.used_timestamps.add(timestamp)
        logger.info(f"用户认证成功 - 用户名: {username}")
        return True

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
            auth_type, credentials = auth_header.split(" ", 1)

            if auth_type.lower() != "basic":
                return None, None

            # 解码base64
            decoded_credentials = base64.b64decode(credentials).decode("utf-8")
            username, password = decoded_credentials.split(":", 1)

            return username, password
        except Exception:
            return None, None

    def create_session(self, username, device_info=""):
        """创建新会话

        Args:
            username (str): 用户名
            device_info (str): 设备标识信息

        Returns:
            str: 会话ID
        """
        return self.config_manager.create_session(username, device_info)

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
    """文件索引器 - 生成和管理文件索引

    支持增量索引、异步索引和多级缓存机制
    """

    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.share_dirs = [
            Path(dir) for dir in config_manager.server_config["SHARE_DIRS"]
        ]
        self.cache = {}
        self.cache_time = 0
        self.cache_duration = 300  # 5分钟缓存

        # 增量索引相关
        self.last_index_time = 0
        self.file_metadata = {}  # 存储文件元数据，用于增量索引

        # 异步索引相关
        self.thread_pool = None
        self.current_index_task = None
        self.index_lock = threading.Lock()

        # 多级缓存相关
        self.enable_multi_level_cache = config_manager.caching_config.get(
            "ENABLE_MULTI_LEVEL_CACHE", True
        )
        self.memory_cache_size = config_manager.caching_config.get(
            "MEMORY_CACHE_SIZE", 100
        )
        self.disk_cache_enabled = config_manager.caching_config.get(
            "DISK_CACHE_ENABLED", False
        )

        # 内存缓存 - 使用LRU策略
        self.memory_cache = {}
        self.cache_access_order = []  # 用于LRU缓存

        # 磁盘缓存目录
        self.disk_cache_dir = Path(".cache")
        if self.disk_cache_enabled:
            self.disk_cache_dir.mkdir(exist_ok=True)

        # SQLite索引相关
        self.sqlite_enabled = config_manager.caching_config.get(
            "ENABLE_SQLITE_INDEX", True
        )
        self.sqlite_db_path = Path(".cache/index.db")
        self.sqlite_conn = None
        self.sqlite_cursor = None
        self.fts5_supported = False  # 标记FTS5是否支持

        # 初始化SQLite数据库
        if self.sqlite_enabled:
            self._init_sqlite_db()

        # 初始化线程池
        self._init_thread_pool()

    def _init_sqlite_db(self):
        """初始化SQLite数据库"""
        try:
            import sqlite3

            # 确保缓存目录存在
            self.sqlite_db_path.parent.mkdir(exist_ok=True)

            # 建立数据库连接
            self.sqlite_conn = sqlite3.connect(
                str(self.sqlite_db_path), check_same_thread=False
            )
            self.sqlite_conn.row_factory = sqlite3.Row
            self.sqlite_cursor = self.sqlite_conn.cursor()

            # 创建文件索引表
            self.sqlite_cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS file_index (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL,
                    full_path TEXT NOT NULL UNIQUE,
                    type TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    extension TEXT NOT NULL,
                    modified_time INTEGER NOT NULL,
                    is_directory INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
                )
            """
            )

            # 创建索引以提高查询性能
            self.sqlite_cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_file_index_name ON file_index(name)"
            )
            self.sqlite_cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_file_index_path ON file_index(path)"
            )
            self.sqlite_cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_file_index_full_path ON file_index(full_path)"
            )
            self.sqlite_cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_file_index_type ON file_index(type)"
            )
            self.sqlite_cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_file_index_extension ON file_index(extension)"
            )
            self.sqlite_cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_file_index_is_directory ON file_index(is_directory)"
            )

            # 创建全文搜索虚拟表（如果支持）
            try:
                self.sqlite_cursor.execute(
                    """
                    CREATE VIRTUAL TABLE IF NOT EXISTS file_fts USING fts5(
                        name,
                        content=file_index,
                        content_rowid=id
                    )
                """
                )
                self.fts5_supported = True  # FTS5创建成功，标记为支持
            except sqlite3.OperationalError:
                # 不支持FTS5，跳过
                logger.warning("SQLite FTS5不支持，全文搜索功能将受限")
                self.fts5_supported = False  # 明确标记为不支持

            self.sqlite_conn.commit()
            logger.info("SQLite索引数据库初始化成功")
        except Exception as e:
            logger.error(f"初始化SQLite数据库失败: {e}")
            # 禁用SQLite功能
            self.sqlite_enabled = False
            self.sqlite_conn = None
            self.sqlite_cursor = None
            return

        # 初始化数据库后，执行首次填充
        self._populate_sqlite_db()

        # 启动定期更新线程
        self._start_sqlite_update_thread()

    def _start_sqlite_update_thread(self):
        """启动定期更新SQLite数据库的后台线程"""
        if not self.sqlite_enabled:
            return

        try:
            # 每30分钟更新一次数据库
            update_interval = 30 * 60  # 30分钟，单位：秒

            # 添加停止标志
            self._stop_update_thread = False

            def update_thread_func():
                """定期更新数据库的线程函数"""
                while not self._stop_update_thread:
                    time.sleep(update_interval)
                    if not self._stop_update_thread:
                        logger.info("执行SQLite数据库定期更新...")
                        self._populate_sqlite_db()

            # 创建并启动后台线程
            self.sqlite_update_thread = threading.Thread(
                target=update_thread_func, daemon=True, name="SQLiteUpdateThread"
            )
            self.sqlite_update_thread.start()
            logger.info("SQLite数据库定期更新线程已启动")

        except Exception as e:
            logger.error(f"启动SQLite更新线程失败: {e}")

    def _cleanup(self):
        """清理资源，关闭线程池和SQLite连接，确保数据完整性"""
        logger.info("开始清理FileIndexer资源...")

        # 停止SQLite定期更新线程
        if hasattr(self, "_stop_update_thread"):
            self._stop_update_thread = True
            logger.info("SQLite定期更新线程已停止")
            # 等待更新线程退出
            if (
                hasattr(self, "sqlite_update_thread")
                and self.sqlite_update_thread.is_alive()
            ):
                logger.info("等待SQLite更新线程退出...")
                self.sqlite_update_thread.join(timeout=10)  # 最多等待10秒
                if self.sqlite_update_thread.is_alive():
                    logger.warning("SQLite更新线程未能及时退出")

        # 等待当前索引任务完成
        if hasattr(self, "current_index_task") and self.current_index_task:
            try:
                # 等待当前索引任务完成，最多等待5秒
                self.current_index_task.result(timeout=5)
                logger.info("当前索引任务已完成")
            except Exception as e:
                logger.warning(f"等待索引任务完成超时: {e}")

        # 关闭线程池
        if self.thread_pool:
            try:
                self.thread_pool.shutdown(wait=True, cancel_futures=True)
                logger.info("线程池已关闭")
            except Exception as e:
                logger.error(f"关闭线程池失败: {e}")

        # 在关闭前执行最后一次SQLite数据库更新，确保所有更改都被保存
        if self.sqlite_enabled:
            logger.info("执行最后一次SQLite数据库更新，确保数据完整性...")
            self._populate_sqlite_db()

        # 确保所有未提交的SQLite事务都被提交
        if self.sqlite_conn:
            try:
                self.sqlite_conn.commit()
                logger.info("所有未提交的SQLite事务已提交")
            except Exception as e:
                logger.error(f"提交SQLite事务失败: {e}")
                # 发生错误时回滚
                try:
                    self.sqlite_conn.rollback()
                    logger.info("SQLite事务已回滚")
                except Exception as e2:
                    logger.error(f"回滚SQLite事务失败: {e2}")

        # 关闭SQLite游标
        if self.sqlite_cursor:
            try:
                self.sqlite_cursor.close()
                logger.info("SQLite游标已关闭")
            except Exception as e:
                logger.error(f"关闭SQLite游标失败: {e}")

        # 关闭SQLite连接
        if self.sqlite_conn:
            try:
                self.sqlite_conn.close()
                logger.info("SQLite连接已关闭")
            except Exception as e:
                logger.error(f"关闭SQLite连接失败: {e}")

        logger.info("FileIndexer资源清理完成")

    def _populate_sqlite_db(self):
        """增量更新SQLite数据库 - 只更新变化的文件和目录"""
        if not self.sqlite_enabled:
            return

        logger.info("开始增量更新SQLite数据库...")
        start_time = time.time()

        try:
            # 获取数据库中当前的文件和目录信息，包含size字段
            self.sqlite_cursor.execute(
                "SELECT full_path, modified_time, is_directory, size FROM file_index"
            )
            db_files = {
                row[0]: (row[1], row[2], row[3])
                for row in self.sqlite_cursor.fetchall()
            }

            # 存储当前扫描到的所有文件和目录路径
            current_files = set()

            def scan_directory_recursive(share_dir, dir_path, relative_path=""):
                """递归扫描目录"""
                try:
                    with os.scandir(str(dir_path)) as scandir_iter:
                        for item in scandir_iter:
                            # 处理以点开头的文件和目录
                            if item.name.startswith("."):
                                if item.is_dir():
                                    # 跳过隐藏目录
                                    continue
                                else:
                                    # 对于以点开头的文件，允许白名单内的文件（如 .mp4）
                                    file_path = Path(item.path)
                                    file_name = file_path.name
                                    file_ext = file_path.suffix.lower()

                                    # 检查是否为白名单文件
                                    is_whitelisted = False
                                    if file_name.startswith(".") and len(file_name) > 1:
                                        # 对于 .mp4 这样的文件名，检查文件名本身是否在白名单中
                                        dot_ext = file_name.lower()
                                        is_whitelisted = (
                                            dot_ext
                                            in self.config_manager.ALL_WHITELIST_EXTENSIONS
                                        )
                                    else:
                                        is_whitelisted = (
                                            file_ext
                                            in self.config_manager.ALL_WHITELIST_EXTENSIONS
                                        )

                                    if not is_whitelisted:
                                        # 跳过不在白名单中的隐藏文件
                                        continue

                            # 确保item_name使用UTF-8编码
                            try:
                                item_name = str(item.name)
                            except UnicodeDecodeError:
                                logger.warning(f"文件名编码错误，跳过: {item}")
                                continue

                            # 构建相对路径
                            if relative_path and relative_path.strip():
                                item_relative_path = str(
                                    Path(relative_path) / item_name
                                )
                            else:
                                item_relative_path = item_name

                            # 检查路径安全性
                            if not self.config_manager.is_path_safe(
                                str(item), str(share_dir)
                            ):
                                logger.warning(f"跳过不安全的路径: {item}")
                                continue

                            # 添加到当前扫描的文件集合
                            current_files.add(item.path)

                            # 获取文件/目录的修改时间
                            try:
                                stat_info = item.stat()
                                modified_time = int(stat_info.st_mtime)
                            except Exception as e:
                                logger.warning(f"获取文件信息失败: {item} - {e}")
                                continue

                            if item.is_dir():
                                # 目录处理
                                is_dir = 1

                                # 检查是否需要更新
                                if (
                                    item.path not in db_files
                                    or db_files[item.path][0] != modified_time
                                    or db_files[item.path][1] != is_dir
                                ):
                                    # 插入或更新目录
                                    try:
                                        self.sqlite_cursor.execute(
                                            """
                                            INSERT OR REPLACE INTO file_index
                                            (name, path, full_path, type, size, extension, modified_time, is_directory, updated_at)
                                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'))
                                        """,
                                            (
                                                item_name,
                                                item_relative_path,
                                                item.path,
                                                "directory",
                                                0,
                                                "",
                                                modified_time,
                                                is_dir,
                                            ),
                                        )
                                    except Exception as e:
                                        logger.error(f"更新目录失败: {item} - {e}")

                                # 递归扫描子目录 - 传递实际路径而不是DirEntry对象
                                scan_directory_recursive(
                                    share_dir, item.path, item_relative_path
                                )

                            elif item.is_file():
                                # 文件处理
                                is_dir = 0
                                file_size = stat_info.st_size

                                # 检查是否需要更新
                                if (
                                    item.path not in db_files
                                    or db_files[item.path][0] != modified_time
                                    or db_files[item.path][1] != is_dir
                                    or db_files[item.path][2] != file_size
                                ):
                                    # 插入或更新文件
                                    try:
                                        # 正确获取文件扩展名
                                        file_ext = Path(item.name).suffix.lower()
                                        self.sqlite_cursor.execute(
                                            """
                                            INSERT OR REPLACE INTO file_index
                                            (name, path, full_path, type, size, extension, modified_time, is_directory, updated_at)
                                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'))
                                        """,
                                            (
                                                item_name,
                                                item_relative_path,
                                                item.path,
                                                self.config_manager.get_file_type(
                                                    item.path
                                                ),
                                                file_size,
                                                file_ext,
                                                modified_time,
                                                is_dir,
                                            ),
                                        )
                                    except Exception as e:
                                        logger.error(f"更新文件失败: {item} - {e}")

                except PermissionError:
                    logger.warning(f"权限不足，跳过目录: {dir_path}")
                except Exception as e:
                    logger.error(f"扫描目录失败: {dir_path} - {e}")

            # 遍历所有共享目录
            for share_dir in self.share_dirs:
                if share_dir.exists():
                    # 开始扫描根目录
                    scan_directory_recursive(share_dir, share_dir)

            # 删除数据库中存在但当前文件系统中不存在的文件和目录
            files_to_delete = db_files.keys() - current_files
            if files_to_delete:
                for file_path in files_to_delete:
                    try:
                        self.sqlite_cursor.execute(
                            "DELETE FROM file_index WHERE full_path = ?", (file_path,)
                        )
                    except Exception as e:
                        logger.error(f"删除文件记录失败: {file_path} - {e}")

            # 提交所有更改
            self.sqlite_conn.commit()

            end_time = time.time()
            logger.info(
                f"SQLite数据库增量更新完成，耗时: {end_time - start_time:.2f}秒"
            )
            logger.info(
                f"新增/更新文件数: {len(current_files) - len(db_files) + len(files_to_delete)}, 删除文件数: {len(files_to_delete)}"
            )

        except Exception as e:
            logger.error(f"更新SQLite数据库失败: {e}", exc_info=True)
            # 发生错误时回滚
            self.sqlite_conn.rollback()

    def _init_thread_pool(self):
        """初始化线程池"""
        try:
            from concurrent.futures import ThreadPoolExecutor
            import multiprocessing
            import psutil

            # 获取CPU核心数
            cpu_count = multiprocessing.cpu_count()

            # 获取系统内存大小（GB）
            total_memory = psutil.virtual_memory().total / (1024**3)

            # 索引和搜索任务是IO密集型的，线程数可以设置为CPU核心数的2-4倍
            # 根据内存大小调整上限：内存越大，允许的线程数越多
            if total_memory < 4:
                # 小于4GB内存，限制线程数
                max_workers = min(4, cpu_count * 2)
            elif total_memory < 8:
                # 4-8GB内存，中等线程数
                max_workers = min(8, cpu_count * 3)
            else:
                # 大于8GB内存，更多线程数
                max_workers = min(12, cpu_count * 4)

            logger.info(
                f"初始化线程池，CPU核心数: {cpu_count}, 内存: {total_memory:.2f}GB, 线程数: {max_workers}"
            )

            self.thread_pool = ThreadPoolExecutor(
                max_workers=max_workers,
                thread_name_prefix="IndexWorker",
                # 设置线程池线程的最大空闲时间，避免资源浪费
                # Python 3.8+支持timeout参数，这里暂时不使用
            )
        except ImportError:
            # psutil模块未安装，使用默认值
            cpu_count = multiprocessing.cpu_count()
            max_workers = min(6, cpu_count * 2)
            logger.info(
                f"psutil模块未安装，使用默认线程池设置，CPU核心数: {cpu_count}, 线程数: {max_workers}"
            )
            self.thread_pool = ThreadPoolExecutor(
                max_workers=max_workers, thread_name_prefix="IndexWorker"
            )
        except Exception as e:
            logger.error(f"初始化线程池失败: {e}")
            self.thread_pool = None

    def generate_index(
        self, search_term="", sort_by="name", sort_order="asc", use_async=False
    ):
        """生成文件索引

        Args:
            search_term (str): 搜索关键词（可选）
            sort_by (str): 排序字段 (name, size, modified, type)
            sort_order (str): 排序顺序 (asc, desc)
            use_async (bool): 是否使用异步索引

        Returns:
            dict: 索引数据
        """
        # 优化：先检查是否为简单情况（空搜索），快速返回缓存
        if not search_term:
            # 对于空搜索，直接返回根目录内容，不进行递归
            cached_data = self._get_cache("", sort_by, sort_order)  # 使用特殊缓存键
            if cached_data:
                return cached_data

        # 检查多级缓存，加入排序参数
        cached_data = self._get_cache(search_term, sort_by, sort_order)
        if cached_data:
            return cached_data

        # 移除短关键词限制，允许单字符搜索
        # 优化：SQLite已处理性能问题，无需手动限制

        if use_async and self.thread_pool:
            # 使用异步索引
            return self._generate_index_async(search_term, sort_by, sort_order)
        else:
            # 同步索引，添加超时保护
            start_time = time.time()
            index_data = self._generate_index_sync(search_term, sort_by, sort_order)

            # 记录索引生成时间
            generation_time = time.time() - start_time
            logger.debug(
                f"索引生成耗时: {
                    generation_time:.2f}秒，搜索词: '{search_term}'"
            )

            return index_data

    def _generate_index_sync(self, search_term="", sort_by="name", sort_order="asc"):
        """同步生成文件索引"""
        with self.index_lock:
            return self._generate_index_impl(search_term, sort_by, sort_order)

    def _generate_index_async(self, search_term="", sort_by="name", sort_order="asc"):
        """异步生成文件索引"""
        # 如果有当前任务且未完成，返回当前任务
        if self.current_index_task and not self.current_index_task.done():
            return self.cache  # 返回旧缓存

        # 提交新任务，包含排序参数
        self.current_index_task = self.thread_pool.submit(
            self._generate_index_impl, search_term, sort_by, sort_order
        )
        return self.cache  # 返回旧缓存，异步任务完成后会更新缓存

    def _generate_index_impl(self, search_term="", sort_by="name", sort_order="asc"):
        """索引生成实现"""
        current_time = time.time()

        index_data = {
            "search_term": search_term,
            "timestamp": current_time,
            "directories": [],
            "files": [],
        }

        # 检查是否有可用的共享目录
        if not self.share_dirs:
            return index_data

        try:
            # 首先尝试使用SQLite进行索引和搜索
            if self.sqlite_enabled:
                # 优化：如果排序字段是size，确保SQLite数据库中的size字段是最新的
                if sort_by == "size":
                    logger.debug("排序字段为size，更新SQLite数据库中的文件大小信息...")
                    self._populate_sqlite_db()

                # 使用SQLite索引加速搜索
                sqlite_index_data = self._generate_index_from_sqlite(
                    search_term, sort_by, sort_order
                )
                if sqlite_index_data["directories"] or sqlite_index_data["files"]:
                    # 更新缓存
                    self.cache = sqlite_index_data
                    self.cache_time = current_time
                    self.last_index_time = current_time

                    # 使用多级缓存，缓存键包含排序参数
                    self._set_cache(search_term, sqlite_index_data, sort_by, sort_order)

                    return sqlite_index_data

            # SQLite索引未命中或禁用，回退到传统文件系统遍历
            # 只显示根目录内容，模仿手机文件管理器体验
            for share_dir in self.share_dirs:
                if share_dir.exists():
                    self._index_directory_flat(
                        share_dir, share_dir, "", index_data, search_term
                    )

            # 为文件添加修改时间信息
            for file_info in index_data["files"]:
                try:
                    file_path = Path(file_info["full_path"])
                    file_info["modified_time"] = file_path.stat().st_mtime
                except Exception as e:
                    logger.warning(
                        f"获取文件修改时间失败: {
                            file_info['full_path']} - {e}"
                    )
                    file_info["modified_time"] = 0

            # 排序函数定义
            def get_sort_key(item, item_type):
                """获取排序键"""
                if item_type == "directory":
                    if sort_by == "name":
                        return item["name"].lower()
                    elif sort_by == "modified":
                        # 目录的修改时间使用最新子项的时间，这里简化处理
                        return 0
                    elif sort_by == "size":
                        # 目录大小，这里简化处理
                        return 0
                    elif sort_by == "type":
                        return "directory"
                    else:
                        return item["name"].lower()
                else:
                    if sort_by == "name":
                        return item["name"].lower()
                    elif sort_by == "size":
                        # 确保size字段的值是数字类型
                        return int(item.get("size", 0))
                    elif sort_by == "modified":
                        return item["modified_time"]
                    elif sort_by == "type":
                        return f"{item['type']}_{item['name'].lower()}"
                    else:
                        return item["name"].lower()

            # 执行排序
            reverse = sort_order == "desc"

            # 排序目录
            index_data["directories"].sort(
                key=lambda x: get_sort_key(x, "directory"), reverse=reverse
            )

            # 排序文件
            index_data["files"].sort(
                key=lambda x: get_sort_key(x, "file"), reverse=reverse
            )

            # 添加排序信息到索引数据
            index_data["sort_by"] = sort_by
            index_data["sort_order"] = sort_order

            # 更新缓存
            self.cache = index_data
            self.cache_time = current_time
            self.last_index_time = current_time

            # 使用多级缓存，缓存键包含排序参数
            self._set_cache(search_term, index_data, sort_by, sort_order)

            # 更新文件元数据（用于增量索引）
            self._update_file_metadata(index_data)

        except Exception as e:
            logger.error(f"生成索引时出错: {e}", exc_info=True)

        return index_data

    def _update_file_metadata(self, index_data):
        """更新文件元数据，用于增量索引"""
        new_metadata = {}

        # 处理文件
        for file_info in index_data["files"]:
            full_path = file_info["full_path"]
            mtime = Path(full_path).stat().st_mtime
            new_metadata[full_path] = {
                "size": file_info["size"],
                "mtime": mtime,
                "type": file_info["type"],
            }

        self.file_metadata = new_metadata

    def _is_file_changed(self, file_path):
        """检查文件是否已更改（用于增量索引）"""
        file_path_str = str(file_path)

        try:
            stat = file_path.stat()
            if file_path_str not in self.file_metadata:
                return True  # 新文件

            old_metadata = self.file_metadata[file_path_str]
            return (
                old_metadata["size"] != stat.st_size
                or old_metadata["mtime"] != stat.st_mtime
            )
        except Exception:
            return True  # 如果获取文件信息失败，认为文件已更改

    def _generate_index_from_sqlite(
        self, search_term="", sort_by="name", sort_order="asc"
    ):
        """从SQLite数据库生成索引"""
        index_data = {
            "search_term": search_term,
            "timestamp": time.time(),
            "directories": [],
            "files": [],
            "sort_by": sort_by,
            "sort_order": sort_order,
        }

        try:
            # 构建SQL查询
            base_query = "SELECT * FROM file_index WHERE 1=1"
            params = []

            # 添加路径条件：当没有搜索词时，只显示根目录下的一级文件和目录
            if not search_term:
                base_query += " AND path = ''"

            # 添加搜索条件
            if search_term:
                base_query += " AND (name LIKE ? OR path LIKE ?)"
                search_pattern = f"%{search_term}%"
                params.extend([search_pattern, search_pattern])

            # 排序逻辑
            order_map = {
                "name": "name",
                "size": "size",
                "modified": "modified_time",
                "type": "type",
            }
            order_field = order_map.get(sort_by, "name")
            order_dir = "DESC" if sort_order == "desc" else "ASC"

            # 目录在前，文件在后
            base_query += " ORDER BY is_directory DESC, {field} {dir}".format(
                field=order_field, dir=order_dir
            )

            # 执行查询
            self.sqlite_cursor.execute(base_query, params)
            rows = self.sqlite_cursor.fetchall()

            # 转换结果
            for row in rows:
                if row["is_directory"]:
                    # 目录
                    dir_info = {
                        "name": row["name"],
                        "path": row["path"],
                        "full_path": row["full_path"],
                        "type": "directory",
                    }
                    index_data["directories"].append(dir_info)
                else:
                    # 文件 - 只显示白名单内的文件
                    is_file_whitelisted = False
                    if row["extension"] in self.config_manager.ALL_WHITELIST_EXTENSIONS:
                        is_file_whitelisted = True
                    elif row["name"].startswith(".") and len(row["name"]) > 1:
                        # 对于点前缀文件，检查文件名本身是否在白名单中
                        dot_ext = row["name"].lower()
                        is_file_whitelisted = (
                            dot_ext in self.config_manager.ALL_WHITELIST_EXTENSIONS
                        )

                    if is_file_whitelisted:
                        file_info = {
                            "name": row["name"],
                            "path": row["path"],
                            "full_path": row["full_path"],
                            "type": row["type"],
                            "size": row["size"],
                            "modified_time": row["modified_time"],
                            "extension": (
                                row["extension"]
                                if row["extension"]
                                else row["name"].lower()
                            ),
                            "size_formatted": format_file_size(row["size"]),
                        }
                        index_data["files"].append(file_info)

        except Exception as e:
            logger.error(f"从SQLite生成索引时出错: {e}", exc_info=True)

        return index_data

    def _get_cache_key(self, search_term, sort_by="name", sort_order="asc"):
        """生成缓存键"""
        return f"index_{search_term}_{sort_by}_{sort_order}"

    def _get_cache(self, search_term, sort_by="name", sort_order="asc"):
        """从多级缓存中获取数据"""
        if not self.enable_multi_level_cache:
            return None

        cache_key = self._get_cache_key(search_term, sort_by, sort_order)

        # 1. 快速检查内存缓存（热点数据）
        if cache_key in self.memory_cache:
            # 更新访问顺序
            if cache_key in self.cache_access_order:
                self.cache_access_order.remove(cache_key)
            self.cache_access_order.append(cache_key)
            return self.memory_cache[cache_key]

        # 2. 检查磁盘缓存（冷数据）
        if self.disk_cache_enabled:
            cache_file = self.disk_cache_dir / f"{cache_key}.json"
            if cache_file.exists():
                try:
                    # 快速检查文件修改时间，避免不必要的文件读取
                    file_mtime = cache_file.stat().st_mtime
                    if time.time() - file_mtime < self.cache_duration:
                        # 读取缓存数据
                        with open(cache_file, "r", encoding="utf-8") as f:
                            cached_data = json.load(f)
                        # 将磁盘缓存加载到内存缓存
                        self._set_cache(search_term, cached_data, sort_by, sort_order)
                        return cached_data
                except Exception as e:
                    logger.error(f"读取磁盘缓存失败: {e}")

        return None

    def _set_cache(self, search_term, data, sort_by="name", sort_order="asc"):
        """设置多级缓存"""
        if not self.enable_multi_level_cache:
            return

        cache_key = self._get_cache_key(search_term, sort_by, sort_order)

        # 1. 设置内存缓存，使用LRU策略
        self.memory_cache[cache_key] = data

        # 更新访问顺序
        if cache_key in self.cache_access_order:
            self.cache_access_order.remove(cache_key)
        self.cache_access_order.append(cache_key)

        # 如果内存缓存超过大小限制，移除最久未使用的缓存
        if len(self.memory_cache) > self.memory_cache_size:
            oldest_key = self.cache_access_order.pop(0)
            if oldest_key in self.memory_cache:
                del self.memory_cache[oldest_key]

        # 2. 设置磁盘缓存
        if self.disk_cache_enabled:
            cache_file = self.disk_cache_dir / f"{cache_key}.json"
            try:
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                logger.error(f"写入磁盘缓存失败: {e}")

    def _index_directory_flat(
        self, share_dir, dir_path, relative_path, index_data, search_term
    ):
        """扁平化索引目录 - 正常浏览只显示当前目录，搜索时递归搜索所有子目录

        Args:
            share_dir (Path): 共享目录路径
            dir_path (Path): 目录路径
            relative_path (str): 相对路径
            index_data (dict): 索引数据
            search_term (str): 搜索关键词
        """
        try:
            # 严格检查目录是否在共享目录内
            dir_str = str(dir_path)
            if not self.config_manager.is_path_safe(dir_str, str(share_dir)):
                logger.warning(f"跳过目录遍历攻击尝试: {dir_path}")
                return

            # 预编译搜索条件，避免重复计算
            if search_term:
                search_lower = search_term.lower()
            else:
                search_lower = None

            # 批量获取目录内容，使用os.scandir提高性能
            items = []
            try:
                with os.scandir(dir_str) as scandir_iter:
                    # 批量转换为列表，减少IO操作次数
                    items = list(scandir_iter)
            except Exception as e:
                logger.error(f"读取目录内容失败: {dir_path} - {e}")
                return

            for item in items:
                # 确保item_name使用UTF-8编码，处理所有Unicode字符
                try:
                    item_name = str(item.name)
                except UnicodeDecodeError:
                    logger.warning(f"文件名编码错误，跳过: {item}")
                    continue

                # 处理以点开头的文件：跳过隐藏目录，但允许白名单文件（如 .mp4）
                if item.name.startswith("."):
                    if item.is_dir():
                        # 跳过隐藏目录
                        continue
                    else:
                        # 对于以点开头的文件，检查是否在白名单中
                        file_path = Path(item.path)
                        file_name = file_path.name
                        file_ext = file_path.suffix.lower()

                        # 处理 .mp4 这样的文件名，直接将其视为 .mp4 后缀
                        is_whitelisted = False
                        if file_name.startswith(".") and len(file_name) > 1:
                            dot_ext = file_name.lower()
                            is_whitelisted = (
                                dot_ext in self.config_manager.ALL_WHITELIST_EXTENSIONS
                            )
                        else:
                            is_whitelisted = (
                                file_ext in self.config_manager.ALL_WHITELIST_EXTENSIONS
                            )

                        if not is_whitelisted:
                            # 跳过不在白名单中的隐藏文件
                            continue

                # 正确构造相对路径：确保与share_dir的关联性
                if relative_path and relative_path.strip():
                    item_relative_path = str(Path(relative_path) / item_name)
                else:
                    item_relative_path = item_name

                # 只有在搜索时才检查子目录的路径安全性，正常浏览时信任父目录检查
                if search_term:
                    if not self.config_manager.is_path_safe(str(item), str(share_dir)):
                        logger.warning(f"跳过不安全的路径: {item}")
                        continue

                if item.is_dir():
                    # 检查目录名是否匹配搜索条件
                    directory_matches = True
                    if search_lower:
                        try:
                            name_lower = item_name.lower()
                            directory_matches = search_lower in name_lower
                        except Exception as e:
                            logger.error(f"搜索匹配错误: {e}")
                            directory_matches = False

                    # 如果目录名匹配搜索条件，或者没有搜索条件（正常浏览），添加目录
                    if directory_matches or not search_lower:
                        dir_info = {
                            "name": item_name,
                            "path": item_relative_path,
                            "full_path": str(item),
                            "type": "directory",
                        }
                        index_data["directories"].append(dir_info)

                    # 只有在搜索时才递归搜索子目录
                    if search_lower:
                        # 传递实际路径而不是DirEntry对象
                        self._index_directory_flat(
                            share_dir,
                            item.path,
                            item_relative_path,
                            index_data,
                            search_term,
                        )

                    # 插入目录到SQLite数据库
                    if self.sqlite_enabled:
                        try:
                            # 使用INSERT OR REPLACE确保数据更新
                            self.sqlite_cursor.execute(
                                """
                                INSERT OR REPLACE INTO file_index
                                (name, path, full_path, type, size, extension, modified_time, is_directory, updated_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'))
                            """,
                                (
                                    item_name,
                                    item_relative_path,
                                    item.path,
                                    "directory",
                                    0,  # 目录大小为0
                                    "",  # 目录没有扩展名
                                    int(item.stat().st_mtime),
                                    1,  # is_directory = 1表示目录
                                ),
                            )
                        except Exception as e:
                            logger.error(f"插入目录到SQLite失败: {item} - {e}")

                elif item.is_file():
                    # 只调用一次stat()，减少IO操作
                    try:
                        stat_info = item.stat()
                        size = stat_info.st_size
                        modified_time = int(stat_info.st_mtime)
                        # 获取文件基本信息，将DirEntry转换为Path对象
                        file_path = Path(item.path)
                        file_ext = file_path.suffix.lower()
                    except Exception as e:
                        logger.warning(f"获取文件信息失败: {item} - {e}")
                        continue

                    # 插入所有文件到SQLite数据库，不考虑白名单
                    if self.sqlite_enabled:
                        try:
                            # 使用INSERT OR REPLACE确保数据更新
                            self.sqlite_cursor.execute(
                                """
                                INSERT OR REPLACE INTO file_index
                                (name, path, full_path, type, size, extension, modified_time, is_directory, updated_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, strftime('%s', 'now'))
                            """,
                                (
                                    item_name,
                                    item_relative_path,
                                    item.path,
                                    self.config_manager.get_file_type(item.path),
                                    size,
                                    file_ext,
                                    modified_time,
                                    0,  # is_directory = 0表示文件
                                ),
                            )
                        except Exception as e:
                            logger.error(f"插入文件到SQLite失败: {item} - {e}")

                    # 检查文件名是否匹配搜索条件
                    file_matches = True
                    if search_lower:
                        try:
                            name_lower = item_name.lower()
                            file_matches = search_lower in name_lower
                        except Exception as e:
                            logger.warning(f"搜索匹配错误: {e}")
                            file_matches = False

                    # 对于UI显示和文件访问，只添加白名单内的文件
                    if file_ext in self.config_manager.ALL_WHITELIST_EXTENSIONS:
                        if file_matches:
                            # 添加白名单内的文件到搜索结果
                            try:
                                file_info = {
                                    "name": item_name,
                                    "path": item_relative_path,
                                    "full_path": item.path,
                                    "type": self.config_manager.get_file_type(
                                        item.path
                                    ),
                                    "size": size,
                                    "size_formatted": self.config_manager.format_file_size(
                                        size
                                    ),
                                    "extension": file_ext,
                                }
                                index_data["files"].append(file_info)
                            except Exception as e:
                                logger.warning(f"添加文件到索引失败: {item} - {e}")
                                continue

        except PermissionError:
            # 忽略权限错误
            logger.warning(f"权限不足，跳过目录: {dir_path}")
            pass
        except Exception as e:
            logger.error(f"索引目录 {dir_path} 时出错: {e}")
        finally:
            # 统一提交事务，提高性能
            if self.sqlite_enabled:
                try:
                    self.sqlite_conn.commit()
                except Exception as e:
                    logger.error(f"提交SQLite事务失败: {e}")
                    try:
                        self.sqlite_conn.rollback()
                    except Exception as e2:
                        logger.error(f"回滚SQLite事务失败: {e2}")

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

                # 检查搜索条件（支持Unicode字符搜索）
                if search_term:
                    try:
                        search_lower = search_term.lower()
                        name_lower = item_name.lower()
                        # 使用UTF-8编码确保Unicode字符正确比较
                        if isinstance(search_lower, str) and isinstance(
                            name_lower, str
                        ):
                            if search_lower not in name_lower:
                                continue
                    except Exception as e:
                        logger.warning(f"搜索匹配错误: {e}")
                        continue

                # 再次检查路径安全性
                if not self.config_manager.is_path_safe(str(item), str(self.share_dir)):
                    logger.warning(f"跳过不安全的路径: {item}")
                    continue

                if item.is_dir():
                    # 添加目录
                    dir_info = {
                        "name": item_name,
                        "path": item_relative_path,
                        "full_path": str(item),
                        "type": "directory",
                    }
                    index_data["directories"].append(dir_info)

                    # 递归索引子目录
                    self._index_directory(
                        item, item_relative_path, index_data, search_term
                    )

                elif item.is_file():
                    # 首先检查是否为白名单文件
                    if not self.config_manager.is_whitelisted_file(str(item)):
                        continue

                    try:
                        file_info = {
                            "name": item_name,
                            "path": item_relative_path,
                            "full_path": str(item),
                            "type": self.config_manager.get_file_type(str(item)),
                            "size": item.stat().st_size,
                            "size_formatted": self.config_manager.format_file_size(
                                item.stat().st_size
                            ),
                            "extension": item.suffix.lower(),
                        }
                        index_data["files"].append(file_info)
                    except Exception as e:
                        logger.warning(f"获取文件信息失败: {item} - {e}")
                        continue

        except PermissionError:
            # 忽略权限错误
            logger.warning(f"权限不足，跳过目录: {dir_path}")
            pass
        except Exception as e:
            logger.error(f"索引目录 {dir_path} 时出错: {e}")

    def get_directory_listing(self, dir_path="", sort_by="name", sort_order="asc"):
        """获取目录列表

        Args:
            dir_path (str): 相对目录路径
            sort_by (str): 排序字段 (name, size, modified, type)
            sort_order (str): 排序顺序 (asc, desc)

        Returns:
            dict: 目录列表数据
        """
        # 遍历所有共享目录，查找匹配的目录
        target_dir = None
        target_share_dir = None

        for share_dir in self.share_dirs:
            current_target_dir = share_dir / dir_path if dir_path else share_dir
            if current_target_dir.exists() and current_target_dir.is_dir():
                target_dir = current_target_dir
                target_share_dir = share_dir
                break

        if not target_dir:
            return None

        if not self.config_manager.is_path_safe(str(target_dir), str(target_share_dir)):
            return None

        listing_data = {
            "current_path": dir_path,
            "parent_path": str(Path(dir_path).parent) if dir_path else "",
            "directories": [],
            "files": [],
        }

        try:
            for item in target_dir.iterdir():
                # 确保item_name使用UTF-8编码，处理所有Unicode字符
                try:
                    item_name = str(item.name)
                except UnicodeDecodeError:
                    logger.warning(f"文件名编码错误，跳过: {item}")
                    continue

                # 正确构造路径，确保与当前目录的关联性
                if dir_path and dir_path.strip():
                    item_path = str(Path(dir_path) / item_name)
                else:
                    item_path = item_name

                # 获取修改时间
                try:
                    stat = item.stat()
                    modified_time = stat.st_mtime
                    size = stat.st_size
                except Exception as e:
                    logger.warning(f"获取文件/目录信息失败: {item} - {e}")
                    continue

                if item.is_dir():
                    dir_info = {
                        "name": item_name,
                        "path": item_path,
                        "type": "directory",
                        "size": 0,  # 目录大小设为0
                        "modified_time": modified_time,
                        "extension": "",
                    }
                    listing_data["directories"].append(dir_info)

                elif item.is_file():
                    # 首先检查是否为白名单文件
                    if not self.config_manager.is_whitelisted_file(str(item)):
                        continue

                    # 处理点前缀文件的扩展名
                    file_ext = item.suffix.lower()
                    if (
                        not file_ext
                        and item_name.startswith(".")
                        and len(item_name) > 1
                    ):
                        # 对于 .mp4 这样的文件名，使用文件名本身作为扩展名
                        file_ext = item_name.lower()

                    file_info = {
                        "name": item_name,
                        "path": item_path,
                        "type": self.config_manager.get_file_type(str(item)),
                        "size": size,
                        "size_formatted": self.config_manager.format_file_size(size),
                        "extension": file_ext,
                        "modified_time": modified_time,
                    }
                    listing_data["files"].append(file_info)

            # 合并目录和文件，保持目录在前
            all_items = [
                {"is_dir": True, **dir} for dir in listing_data["directories"]
            ] + [{"is_dir": False, **file} for file in listing_data["files"]]

            # 定义排序键函数
            def get_sort_key(item):
                if sort_by == "name":
                    return (not item["is_dir"], item["name"].lower())
                elif sort_by == "size":
                    # 确保size字段的值是数字类型
                    return (not item["is_dir"], int(item.get("size", 0)))
                elif sort_by == "modified":
                    return (not item["is_dir"], item["modified_time"])
                elif sort_by == "type":
                    if item["is_dir"]:
                        return (False, "directory")
                    else:
                        return (True, item["type"], item["name"].lower())
                else:
                    return (not item["is_dir"], item["name"].lower())

            # 执行排序
            reverse = sort_order == "desc"
            all_items.sort(key=get_sort_key, reverse=reverse)

            # 分离回目录和文件
            directories = [item for item in all_items if item["is_dir"]]
            files = [item for item in all_items if not item["is_dir"]]

            # 移除is_dir标记，恢复原有格式
            listing_data["directories"] = [
                {k: v for k, v in dir_item.items() if k != "is_dir"}
                for dir_item in directories
            ]
            listing_data["files"] = [
                {k: v for k, v in file_item.items() if k != "is_dir"}
                for file_item in files
            ]

            # 添加排序信息到返回数据中
            listing_data["sort_by"] = sort_by
            listing_data["sort_order"] = sort_order

        except Exception as e:
            logger.error(f"获取目录列表时出错: {e}")

        return listing_data

    def get_file_info(self, file_path):
        """获取文件信息

        Args:
            file_path (str): 相对文件路径

        Returns:
            dict: 文件信息或None
        """
        try:
            # 遍历所有共享目录，查找文件
            for share_dir in self.share_dirs:
                # 确保文件路径是安全的
                target_file = share_dir / file_path

                if not self.config_manager.is_path_safe(
                    str(target_file), str(share_dir)
                ):
                    logger.warning(f"文件路径不安全: {file_path}")
                    continue

                if target_file.exists() and target_file.is_file():
                    # 检查文件是否在白名单中
                    if not self.config_manager.is_whitelisted_file(str(target_file)):
                        logger.debug(f"文件不在白名单中: {target_file}")
                        continue

                    # 获取文件统计信息
                    stat = target_file.stat()

                    # 使用Path.name确保正确处理中文文件名
                    file_name = target_file.name

                    file_info = {
                        "name": file_name,
                        "path": file_path,
                        "full_path": str(target_file),
                        "type": self.config_manager.get_file_type(str(target_file)),
                        "size": stat.st_size,
                        "size_formatted": self.config_manager.format_file_size(
                            stat.st_size
                        ),
                        "extension": target_file.suffix.lower(),
                        "modified_time": stat.st_mtime,
                    }

                    logger.debug(f"成功获取文件信息: {file_name}")
                    return file_info

            # 所有共享目录都未找到文件
            logger.warning(f"文件不存在或不是文件: {file_path}")
            return None

        except Exception as e:
            logger.error(f"获取文件信息时出错: {file_path} - {e}")
            return None


class HTMLTemplate:
    """HTML模板生成器 - 生成所有页面的HTML内容"""

    # 新增：目录HTML缓存（类级属性，全局复用）
    _dir_html_cache = {}
    _CACHE_EXPIRE = 3600  # 缓存1小时（家庭场景足够）
    _MAX_CACHE_DIRS = 10  # 限制缓存目录数，避免内存占用

    # 新增：缓存清理方法（文件变动时调用）
    @staticmethod
    def clear_dir_cache(changed_path):
        """清理指定目录的HTML缓存"""
        if changed_path in HTMLTemplate._dir_html_cache:
            del HTMLTemplate._dir_html_cache[changed_path]

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

        // h1标题点击事件处理函数
        function handleTitleClick() {
            // 检查用户是否已登录 - 通过检查是否存在登出按钮来判断
            const logoutButton = document.querySelector('.logout-button');
            if (logoutButton) {
                // 用户已登录，跳转到首页
                window.location.href = '/index';
            }
            // 用户未登录，不执行任何操作
        }

        // 立即应用主题（在DOM加载前）
        ThemeManager.forceApplyTheme();

        // DOM加载完成后初始化
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
    <header class="header glass-effect">
        <div class="header-left">
            <h1 class="title" id="site-title" onclick="handleTitleClick()">LAN文件服务器</h1>
        </div>
        <div class="header-right">
            <button id="theme-toggle" class="theme-toggle" onclick="toggleTheme()" title="切换主题">🌙</button>
            <a href="/logout" class="logout-button" title="退出登录">🚪 登出</a>
        </div>
    </header>

    <main class="main-content glass-container">
        {content}
    </main>

    <footer class="footer glass-effect">
        <p>&copy; 2025 LAN文件服务器 - 轻量、美观、安全 | <a href="https://github.com/blycr/lan-file-server" target="_blank" rel="noopener noreferrer" class="github-link">GitHub</a></p>
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
        error_html = (
            f'<div class="error-message">{error_message}</div>' if error_message else ""
        )
        attempts_html = (
            f'<div class="attempts-info">剩余尝试次数: {remaining_attempts}</div>'
            if remaining_attempts <= 3
            else ""
        )

        content = f"""
        <div class="login-container glass-effect">
            <div class="login-card glass-card">
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

        # 统计信息 - 仅显示文件夹数量
        total_dirs = len(index_data["directories"])
        total_files = len(index_data["files"])
        stats_html = (
            f'<div class="stats">找到 {total_dirs} 个文件夹，{total_files} 个文件</div>'
        )

        # 添加新的排序和过滤下拉菜单
        filter_html = """
        <div class="filter-container">
            <div class="sort-and-filter">
                <div class="sort-options">
                    <select id="sort_by" onchange="changeSort()" aria-label="排序字段">
                        <option value="name" selected="">名称</option>
                        <option value="size">大小</option>
                        <option value="modified">修改时间</option>
                        <option value="type">文件类型</option>
                    </select>
                    <select id="sort_order" onchange="changeSort()" aria-label="排序顺序">
                        <option value="asc" selected="">升序</option>
                        <option value="desc">降序</option>
                    </select>
                    <select id="file_type_filter" onchange="filterByType()" aria-label="文件类型过滤">
                        <option value="all" selected="">全部</option>
                        <option value="image">图片</option>
                        <option value="audio">音频</option>
                        <option value="video">视频</option>
                    </select>
                </div>
            </div>
        </div>
        """

        # 目录列表
        directories_html = ""
        if index_data["directories"]:
            directories_html = """
            <div class="section">
                <h3>📁 文件夹 ({total_dirs})</h3>
                <ul class="file-list">
            """.format(
                total_dirs=total_dirs
            )

            for directory in index_data["directories"]:
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

        # 主页不显示文件列表
        files_html = ""
        if index_data["files"]:
            files_html = """
            <div class="section">
                <h3>📄 文件 ({total_files})</h3>
                <ul class="file-list">
            """.format(
                total_files=total_files
            )

            for file_info in index_data["files"]:
                type_icon = {"image": "🖼️", "audio": "🎵", "video": "🎬"}.get(
                    file_info["type"], "📄"
                )

                files_html += f"""
                    <li class="file-item file" data-size="{file_info['size']}">
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

        # 无结果提示 - 仅检查文件夹数量
        no_results_html = ""
        if total_dirs == 0:
            no_results_html = '<div class="no-results">未找到匹配的内容</div>'

        content = f"""
        <div class="index-container glass-effect">
            <div class="header-section">
                <div class="page-header">
                    <h2>文件浏览器</h2>
                    <p class="page-description">当前目录内容</p>
                </div>

                <div class="search-section">
                    {search_html}
                </div>
            </div>

            <div class="files-content glass-card">
                {stats_html}
                {filter_html}
                {directories_html}
                {files_html}
                {no_results_html}
            </div>
        </div>
        """

        # 添加搜索管理和文件过滤功能的JavaScript
        content += HTMLTemplate._get_search_management_js()
        content += """
        <script>
            /* 初始化搜索功能 */
            document.addEventListener('DOMContentLoaded', function() {{
                SearchManager.initSearch();
            }});

            /* 排序功能 */
            function changeSort() {
                const sortBy = document.getElementById('sort_by').value;
                const sortOrder = document.getElementById('sort_order').value;

                // 获取所有文件和文件夹项
                const fileSections = document.querySelectorAll('.section');

                fileSections.forEach(section => {
                    const list = section.querySelector('.file-list');
                    const items = Array.from(list.querySelectorAll('.file-item'));

                    // 对项目进行排序
                    items.sort((a, b) => {
                        let aValue, bValue;

                        // 获取排序值
                        switch (sortBy) {
                            case 'name':
                                aValue = a.querySelector('.file-link').textContent.trim().toLowerCase();
                                bValue = b.querySelector('.file-link').textContent.trim().toLowerCase();
                                break;
                            case 'size':
                                // 使用data-size属性进行精确排序
                                aValue = parseInt(a.dataset.size) || 0;
                                bValue = parseInt(b.dataset.size) || 0;
                                break;
                            case 'modified':
                                // 这里需要根据实际情况获取修改时间，当前示例中没有这个数据
                                aValue = 0;
                                bValue = 0;
                                break;
                            case 'type':
                                aValue = a.querySelector('.file-icon')?.textContent || '';
                                bValue = b.querySelector('.file-icon')?.textContent || '';
                                break;
                            default:
                                aValue = 0;
                                bValue = 0;
                        }

                        // 比较值
                        if (aValue < bValue) return sortOrder === 'asc' ? -1 : 1;
                        if (aValue > bValue) return sortOrder === 'asc' ? 1 : -1;
                        return 0;
                    });

                    // 重新添加排序后的项目
                    items.forEach(item => list.appendChild(item));
                });
            }

            /* 文件类型过滤功能 */
            function filterByType() {
                const filterType = document.getElementById('file_type_filter').value;

                // 获取所有文件项（排除文件夹）
                const fileItems = document.querySelectorAll('.file-item.file');

                // 根据过滤类型显示或隐藏文件项
                fileItems.forEach(item => {
                    const icon = item.querySelector('.file-icon')?.textContent;
                    let showItem = true;

                    switch (filterType) {
                        case 'all':
                            showItem = true;
                            break;
                        case 'image':
                            showItem = icon === '🖼️';
                            break;
                        case 'audio':
                            showItem = icon === '🎵';
                            break;
                        case 'video':
                            showItem = icon === '🎬';
                            break;
                    }

                    item.style.display = showItem ? 'flex' : 'none';
                });

                // 显示或隐藏空文件列表
                const sections = document.querySelectorAll('.section');
                sections.forEach(section => {
                    const list = section.querySelector('.file-list');
                    if (list) {
                        const items = list.querySelectorAll('.file-item');
                        const visibleItems = Array.from(items).filter(item => item.style.display !== 'none');

                        if (visibleItems.length === 0) {
                            list.style.display = 'none';
                        } else {
                            list.style.display = 'block';
                        }
                    }
                });
            }
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
        current_path = listing_data["current_path"]
        current_time = time.time()

        # 获取当前排序信息
        current_sort_by = listing_data.get("sort_by", "name")
        current_sort_order = listing_data.get("sort_order", "asc")

        # 生成缓存键，包含排序参数
        cache_key = f"{current_path}_{current_sort_by}_{current_sort_order}"

        # 1. 缓存有效性检查
        if cache_key in HTMLTemplate._dir_html_cache:
            cache_html, cache_time = HTMLTemplate._dir_html_cache[cache_key]
            if current_time - cache_time < HTMLTemplate._CACHE_EXPIRE:
                # 仅更新统计数（保证数据准确性）
                total_dirs = len(listing_data["directories"])
                total_files = len(listing_data["files"])
                cache_html = cache_html.replace(
                    r'<div class="stats">当前目录: .*? 个文件夹，.*? 个文件</div>',
                    f'<div class="stats">当前目录: {total_dirs} 个文件夹，{total_files} 个文件</div>',
                )
                title = f"浏览: {current_path if current_path else '根目录'} - LAN文件服务器"
                return HTMLTemplate.get_base_template(title, cache_html)

        # 简化路径导航生成
        def generate_breadcrumbs(current_path):
            """简化面包屑生成逻辑"""
            if not current_path:
                return "<span>首页</span>"

            path_parts = [p for p in current_path.split("/") if p]  # 过滤空字符串
            breadcrumbs = '<a href="/index">首页</a>'
            accumulated_path = ""

            for part in path_parts:
                accumulated_path += part + "/"
                breadcrumbs += f' / <a href="/browse/{urlquote(accumulated_path.rstrip("/"), encoding="utf-8", safe="")}">{part}</a>'

            return breadcrumbs

        path_breadcrumbs = generate_breadcrumbs(current_path)

        # 统计信息
        total_dirs = len(listing_data["directories"])
        total_files = len(listing_data["files"])

        # 获取当前排序信息
        current_sort_by = listing_data.get("sort_by", "name")
        current_sort_order = listing_data.get("sort_order", "asc")

        # 排序选择器

        sort_html = f"""
        <div class="sort-container">
            <div class="sort-options">
                <select id="sort_by" onchange="changeSort()" aria-label="排序字段">
                    <option value="name" {'selected' if current_sort_by == 'name' else ''}>名称</option>
                    <option value="size" {'selected' if current_sort_by == 'size' else ''}>大小</option>
                    <option value="modified" {'selected' if current_sort_by == 'modified' else ''}>修改时间</option>
                    <option value="type" {'selected' if current_sort_by == 'type' else ''}>文件类型</option>
                </select>
                <select id="sort_order" onchange="changeSort()" aria-label="排序顺序">
                    <option value="asc" {'selected' if current_sort_order == 'asc' else ''}>升序</option>
                    <option value="desc" {'selected' if current_sort_order == 'desc' else ''}>降序</option>
                </select>
            </div>
        </div>
        """

        stats_html = f'<div class="stats">当前目录: {total_dirs} 个文件夹，{total_files} 个文件</div>'

        # 目录列表
        directories_html = ""
        if listing_data["directories"]:
            directories_html = """
            <div class="section">
                <h3>📁 文件夹 ({total_dirs})</h3>
                <ul class="file-list">
            """.format(
                total_dirs=total_dirs
            )

            for directory in listing_data["directories"]:
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
        if listing_data["files"]:
            files_html = """
            <div class="section">
                <h3>📄 文件 ({total_files})</h3>
                <ul class="file-list">
            """.format(
                total_files=total_files
            )

            # 简化文件类型图标获取
            def get_file_icon(file_type):
                """简化文件类型图标获取"""
                if file_type == "image":
                    return "🖼️"
                elif file_type == "audio":
                    return "🎵"
                elif file_type == "video":
                    return "🎬"
                else:
                    return "📄"

            for file_info in listing_data["files"]:
                type_icon = get_file_icon(file_info["type"])

                files_html += f"""
                    <li class="file-item file" data-size="{file_info['size']}">
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
        <div class="browse-container glass-effect">
            <div class="header-section">
                <div class="page-header">
                    <h2>浏览目录</h2>
                    <div class="path-navigation">
                        {path_breadcrumbs}
                    </div>
                </div>

                {search_html}
            </div>

            <div class="files-content glass-card">
                {stats_html}
                {sort_html}
                {directories_html}
                {files_html}
            </div>
        </div>
        """

        title = f"浏览: {current_path if current_path else '根目录'} - LAN文件服务器"

        # 添加搜索管理和排序功能的JavaScript
        content += f"""
        {HTMLTemplate._get_search_management_js()}
        <script>
            // 初始化搜索功能
            document.addEventListener('DOMContentLoaded', function() {{
                SearchManager.initSearch();
            }});

            // 排序功能
            function changeSort() {{
                const sortBy = document.getElementById('sort_by').value;
                const sortOrder = document.getElementById('sort_order').value;

                // 获取当前URL路径
                const currentUrl = window.location.href;
                const url = new URL(currentUrl);

                // 更新查询参数
                url.searchParams.set('sort_by', sortBy);
                url.searchParams.set('sort_order', sortOrder);

                // 重新加载页面
                window.location.href = url.toString();
            }}
        </script>
        """

        # 3. 缓存生成的HTML（仅核心目录）
        if len(HTMLTemplate._dir_html_cache) < HTMLTemplate._MAX_CACHE_DIRS:
            HTMLTemplate._dir_html_cache[cache_key] = (content, current_time)

        return HTMLTemplate.get_base_template(title, content)

    @staticmethod
    def get_404_page():
        """获取404错误页面HTML

        Returns:
            str: 404页面HTML
        """
        content = """
        <div class="error-container glass-effect">
            <div class="error-card glass-card">
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
        <div class="error-container glass-effect">
            <div class="error-card glass-card">
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
    """文件服务器请求处理器

    处理所有HTTP请求，包括页面请求、API请求、文件下载等。
    提供安全认证、文件管理、搜索等功能。

    Attributes:
        config_manager: 配置管理器实例
        auth_manager: 认证管理器实例
        file_indexer: 文件索引器实例
        share_dir: 共享目录路径
        static_dir: 静态文件目录路径
    """

    def __init__(self, *args, config_manager=None, **kwargs):
        self.config_manager = config_manager
        self.auth_manager = AuthenticationManager(config_manager)
        self.file_indexer = FileIndexer(config_manager)

        # 设置静态文件目录
        if config_manager:
            self.share_dirs = [
                Path(dir) for dir in config_manager.server_config["SHARE_DIRS"]
            ]
            # 静态文件目录指向项目根目录下的static文件夹
            self.static_dir = Path(__file__).parent / "static"
        else:
            self.share_dirs = [Path(".")]
            self.static_dir = Path(".") / "static"

        super().__init__(*args, **kwargs)

    @error_handler
    def do_GET(self):
        """处理GET请求"""
        import time

        # 记录请求开始时间
        request_start_time = time.time()
        client_ip = self.client_address[0]
        method = "GET"

        # 解析URL
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query)

        # 记录请求信息
        logger.info(f"收到{method}请求，客户端IP: {client_ip}, 路径: {path}")

        # 检查是否需要HTTPS重定向
        # 获取SSL启用状态
        ssl_enabled = self.config_manager.server_config.get("SSL_ENABLED", True)

        # 只有在SSL启用时才进行重定向检查
        if ssl_enabled:
            # 通过请求头中的X-Forwarded-Proto判断是否为HTTPS
            is_https = self.headers.get("X-Forwarded-Proto") == "https"
            # 通过服务器socket是否使用SSL判断
            server_uses_ssl = hasattr(self.server.socket, "version") or hasattr(
                self.server.socket, "cipher"
            )

            # 修正重定向逻辑：只有当服务器使用SSL且请求不是HTTPS时才重定向
            if server_uses_ssl and not is_https:
                # 重定向到HTTPS
                host = self.headers.get("Host")
                if host:
                    # 保留原始端口或使用配置的HTTPS端口
                    ssl_port = self.config_manager.server_config.get("SSL_PORT")
                    host_parts = host.split(":")
                    if ssl_port:
                        # 使用配置的HTTPS端口
                        redirect_host = f"{host_parts[0]}:{ssl_port}"
                    elif len(host_parts) > 1:
                        # 保留原始端口
                        redirect_host = host
                    else:
                        # 使用默认HTTPS端口
                        redirect_host = f"{
                            host_parts[0]}:{
                            self.config_manager.server_config.get(
                                'PORT', 8000)}"

                redirect_url = f"https://{redirect_host}{self.path}"
                self.send_response(301)
                self.send_header("Location", redirect_url)
                self.end_headers()
                return

        # 检查IP封禁
        client_ip = self.client_address[0]
        if self.config_manager.is_ip_blocked(client_ip):
            remaining_time = self.config_manager.server_config["FAILED_AUTH_BLOCK_TIME"]
            if path.startswith("/api"):
                # API请求返回JSON格式的封禁响应
                self.send_response(429)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                import json

                error_data = json.dumps(
                    {
                        "success": False,
                        "data": None,
                        "error": {
                            "code": 429,
                            "message": f"IP已被封禁，请{remaining_time}秒后重试",
                        },
                    },
                    ensure_ascii=False,
                )
                self.send_header("Content-Length", str(len(error_data.encode("utf-8"))))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(error_data.encode("utf-8"))
            else:
                html = HTMLTemplate.get_blocked_page(remaining_time)
                self._send_html_response(html, 429)
            return

        # 检查认证
        is_api_request = path.startswith("/api")
        if not self._is_authenticated():
            if path.startswith("/static/") or path == "/favicon.ico":
                # 允许访问静态资源
                pass
            elif is_api_request:
                # API请求支持基本认证
                auth_header = self.headers.get("Authorization")
                if auth_header and auth_header.startswith("Basic "):
                    # 尝试基本认证
                    username, password = self.auth_manager.extract_credentials(
                        auth_header
                    )
                    if (
                        username
                        and password
                        and self.auth_manager.verify_credentials(username, password)
                    ):
                        # 基本认证成功
                        pass
                    else:
                        # 基本认证失败
                        self.send_response(401)
                        self.send_header(
                            "WWW-Authenticate", 'Basic realm="LAN File Server API"'
                        )
                        self.send_header(
                            "Content-Type", "application/json; charset=utf-8"
                        )
                        import json

                        error_data = json.dumps(
                            {
                                "success": False,
                                "data": None,
                                "error": {
                                    "code": 401,
                                    "message": "未授权访问，请提供有效的认证信息",
                                },
                            },
                            ensure_ascii=False,
                        )
                        self.send_header(
                            "Content-Length", str(len(error_data.encode("utf-8")))
                        )
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.end_headers()
                        self.wfile.write(error_data.encode("utf-8"))
                        return
                else:
                    # 没有提供认证信息
                    self.send_response(401)
                    self.send_header(
                        "WWW-Authenticate", 'Basic realm="LAN File Server API"'
                    )
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    import json

                    error_data = json.dumps(
                        {
                            "success": False,
                            "data": None,
                            "error": {
                                "code": 401,
                                "message": "未授权访问，请提供有效的认证信息",
                            },
                        },
                        ensure_ascii=False,
                    )
                    self.send_header(
                        "Content-Length", str(len(error_data.encode("utf-8")))
                    )
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(error_data.encode("utf-8"))
                    return
            else:
                # 重定向到登录页面
                if path != "/login":
                    self.send_response(302)
                    self.send_header("Location", "/login")
                    self.end_headers()
                    return
                else:
                    # 显示登录页面
                    html = HTMLTemplate.get_login_page()
                    self._send_html_response(html)
                    return

        # 路由处理
        import threading
        import time

        # 检查是否为大文件下载或API请求
        is_large_file = path.startswith("/download") or path.startswith("/api/download")
        is_api_request = path.startswith("/api") and not is_large_file
        is_page_request = path in ["/", "/index", "/search"] or path.startswith(
            "/browse"
        )

        def handle_request():
            """处理请求的内部函数"""
            if path == "/" or path == "/index":
                self._handle_index(query_params)
            elif path == "/search":
                self._handle_search(query_params)
            elif path == "/logout":
                self._handle_logout()
            elif path == "/.well-known/appspecific/com.chrome.devtools.json":
                # 处理Chrome DevTools 404请求，减少日志噪音
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            elif path.startswith("/browse"):
                self._handle_browse(path, query_params)
            elif path.startswith("/download"):
                self._handle_download(path)
            elif path.startswith("/static/"):
                self._handle_static(path)
            elif path == "/favicon.ico":
                self._handle_favicon()
            # API路由
            elif path.startswith("/api/files"):
                self._handle_api_files(path, query_params)
            elif path.startswith("/api/directories"):
                self._handle_api_directories(path, query_params)
            elif path == "/api/search":
                self._handle_api_search(query_params)
            elif path.startswith("/api/download"):
                self._handle_api_download(path)
            elif path == "/api":
                self._handle_api_docs()
            else:
                # 404页面
                if path.startswith("/api"):
                    # API请求返回JSON格式404
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    import json

                    error_data = json.dumps(
                        {
                            "success": False,
                            "data": None,
                            "error": {"code": 404, "message": "API端点未找到"},
                        },
                        ensure_ascii=False,
                    )
                    self.send_header(
                        "Content-Length", str(len(error_data.encode("utf-8")))
                    )
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(error_data.encode("utf-8"))
                else:
                    html = HTMLTemplate.get_404_page()
                    self._send_html_response(html, 404)
                return

        # 对API请求和页面请求添加超时保护，对视频流请求不设置超时
        if is_api_request or is_page_request:
            # 设置请求超时时间（5秒）
            timeout = 5
            request_completed = False

            def request_handler():
                nonlocal request_completed
                try:
                    handle_request()
                finally:
                    request_completed = True

            # 在单独的线程中处理请求
            thread = threading.Thread(target=request_handler)
            thread.start()
            thread.join(timeout)

            if not request_completed:
                # 请求超时
                logger.warning(f"请求处理超时: {path}")
                self.send_response(504)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                html = "<h1>504 Gateway Timeout</h1><p>请求处理超时，请稍后重试。</p>"
                self.send_header("Content-Length", str(len(html.encode("utf-8"))))
                self.end_headers()
                self.wfile.write(html.encode("utf-8"))
        else:
            # 视频流请求或大文件下载，不设置超时
            handle_request()

        # 记录请求处理时间
        request_end_time = time.time()
        request_duration = request_end_time - request_start_time
        logger.info(
            f"{method}请求处理完成，客户端IP: {client_ip}, 路径: {path}, 耗时: {request_duration:.2f}秒"
        )

    @error_handler
    def do_OPTIONS(self):
        """处理OPTIONS请求，用于CORS预检"""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Max-Age", "86400")  # 24小时
        self.end_headers()

    def _handle_api_files(self, path, query_params):
        """处理API文件请求

        支持：
        - GET /api/files - 获取文件列表
        - GET /api/files/{path} - 获取文件信息
        """
        # 提取文件路径
        if path == "/api/files":
            # 获取文件列表
            dir_path = query_params.get("path", [""])[0]
            sort_by = query_params.get("sort_by", ["name"])[0]
            sort_order = query_params.get("sort_order", ["asc"])[0]

            # 验证排序参数
            if sort_by not in ["name", "size", "modified", "type"]:
                sort_by = "name"
            if sort_order not in ["asc", "desc"]:
                sort_order = "asc"

            # 获取目录列表
            listing_data = self.file_indexer.get_directory_listing(
                dir_path, sort_by=sort_by, sort_order=sort_order
            )

            if listing_data is None:
                self.send_response(404)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                import json

                error_data = json.dumps(
                    {
                        "success": False,
                        "data": None,
                        "error": {"code": 404, "message": "目录不存在"},
                    },
                    ensure_ascii=False,
                )
                self.send_header("Content-Length", str(len(error_data.encode("utf-8"))))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(error_data.encode("utf-8"))
                return

            # 提取文件列表
            files = listing_data["files"]

            # 分页支持
            page = int(query_params.get("page", ["1"])[0])
            limit = int(query_params.get("limit", ["20"])[0])

            # 计算分页
            start = (page - 1) * limit
            end = start + limit
            paginated_files = files[start:end]

            response_data = {
                "files": paginated_files,
                "total": len(files),
                "page": page,
                "limit": limit,
                "dir_path": dir_path,
                "sort_by": sort_by,
                "sort_order": sort_order,
            }

            self._send_json_response(response_data)
        else:
            # 获取单个文件信息
            file_path = path[11:]  # 移除 "/api/files/" 前缀
            if file_path.startswith("/"):
                file_path = file_path[1:]

            file_info = self.file_indexer.get_file_info(file_path)

            if file_info is None:
                self.send_response(404)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                import json

                error_data = json.dumps(
                    {
                        "success": False,
                        "data": None,
                        "error": {"code": 404, "message": "文件不存在"},
                    },
                    ensure_ascii=False,
                )
                self.send_header("Content-Length", str(len(error_data.encode("utf-8"))))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(error_data.encode("utf-8"))
                return

            self._send_json_response(file_info)

    @error_handler
    def do_POST(self):
        """处理POST请求"""
        import time

        # 记录请求开始时间
        request_start_time = time.time()
        client_ip = self.client_address[0]
        method = "POST"
        path = self.path

        # 记录请求信息
        logger.info(f"收到{method}请求，客户端IP: {client_ip}, 路径: {path}")

        if self.path == "/login":
            self._handle_login()
        else:
            self._send_error_response(404, "页面未找到")

        # 记录请求处理时间
        request_end_time = time.time()
        request_duration = request_end_time - request_start_time
        logger.info(
            f"{method}请求处理完成，客户端IP: {client_ip}, 路径: {path}, 耗时: {request_duration:.2f}秒"
        )

    def _handle_api_directories(self, path, query_params):
        """处理API目录请求

        支持：
        - GET /api/directories - 获取目录列表
        - GET /api/directories/{path} - 获取目录信息
        """
        if path == "/api/directories":
            # 获取目录列表
            dir_path = query_params.get("path", [""])[0]
            sort_by = query_params.get("sort_by", ["name"])[0]
            sort_order = query_params.get("sort_order", ["asc"])[0]

            # 验证排序参数
            if sort_by not in ["name", "size", "modified", "type"]:
                sort_by = "name"
            if sort_order not in ["asc", "desc"]:
                sort_order = "asc"

            # 获取目录列表
            listing_data = self.file_indexer.get_directory_listing(
                dir_path, sort_by=sort_by, sort_order=sort_order
            )

            if listing_data is None:
                self.send_response(404)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                import json

                error_data = json.dumps(
                    {
                        "success": False,
                        "data": None,
                        "error": {"code": 404, "message": "目录不存在"},
                    },
                    ensure_ascii=False,
                )
                self.send_header("Content-Length", str(len(error_data.encode("utf-8"))))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(error_data.encode("utf-8"))
                return

            # 提取目录列表
            directories = listing_data["directories"]

            # 分页支持
            page = int(query_params.get("page", ["1"])[0])
            limit = int(query_params.get("limit", ["20"])[0])

            # 计算分页
            start = (page - 1) * limit
            end = start + limit
            paginated_dirs = directories[start:end]

            response_data = {
                "directories": paginated_dirs,
                "total": len(directories),
                "page": page,
                "limit": limit,
                "dir_path": dir_path,
                "sort_by": sort_by,
                "sort_order": sort_order,
            }

            self._send_json_response(response_data)
        else:
            # 获取目录信息（目录的内容）
            dir_path = path[17:]  # 移除 "/api/directories/" 前缀
            if dir_path.startswith("/"):
                dir_path = dir_path[1:]

            listing_data = self.file_indexer.get_directory_listing(dir_path)

            if listing_data is None:
                self.send_response(404)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                import json

                error_data = json.dumps(
                    {
                        "success": False,
                        "data": None,
                        "error": {"code": 404, "message": "目录不存在"},
                    },
                    ensure_ascii=False,
                )
                self.send_header("Content-Length", str(len(error_data.encode("utf-8"))))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(error_data.encode("utf-8"))
                return

            # 分页支持
            page = int(query_params.get("page", ["1"])[0])
            limit = int(query_params.get("limit", ["20"])[0])

            # 合并文件和目录
            all_items = []
            for dir_item in listing_data["directories"]:
                all_items.append(
                    {
                        "name": dir_item["name"],
                        "path": dir_item["path"],
                        "type": "directory",
                        "size": dir_item["size"],
                        "modified_time": dir_item["modified_time"],
                    }
                )

            for file_item in listing_data["files"]:
                all_items.append(
                    {
                        "name": file_item["name"],
                        "path": file_item["path"],
                        "type": "file",
                        "size": file_item["size"],
                        "modified_time": file_item["modified_time"],
                        "extension": file_item["extension"],
                        "file_type": file_item["type"],
                    }
                )

            # 计算分页
            start = (page - 1) * limit
            end = start + limit
            paginated_items = all_items[start:end]

            response_data = {
                "items": paginated_items,
                "total": len(all_items),
                "page": page,
                "limit": limit,
                "dir_path": dir_path,
                "directories_count": len(listing_data["directories"]),
                "files_count": len(listing_data["files"]),
            }

            self._send_json_response(response_data)

    def _handle_api_search(self, query_params):
        """处理API搜索请求

        支持：
        - GET /api/search?q={search_term} - 搜索文件和目录
        """
        search_term = query_params.get("q", [""])[0]
        search_term = unquote(search_term, encoding="utf-8", errors="replace")

        # 生成索引
        index_data = self.file_indexer.generate_index(search_term)

        # 分页支持
        page = int(query_params.get("page", ["1"])[0])
        limit = int(query_params.get("limit", ["20"])[0])

        # 合并文件和目录
        all_items = []

        for dir_item in index_data["directories"]:
            all_items.append(
                {
                    "name": dir_item["name"],
                    "path": dir_item["path"],
                    "type": "directory",
                }
            )

        for file_item in index_data["files"]:
            all_items.append(
                {
                    "name": file_item["name"],
                    "path": file_item["path"],
                    "type": "file",
                    "size": file_item["size"],
                    "extension": file_item["extension"],
                    "file_type": file_item["type"],
                }
            )

        # 计算分页
        start = (page - 1) * limit
        end = start + limit
        paginated_items = all_items[start:end]

        response_data = {
            "items": paginated_items,
            "total": len(all_items),
            "page": page,
            "limit": limit,
            "search_term": search_term,
            "directories_count": len(index_data["directories"]),
            "files_count": len(index_data["files"]),
        }

        self._send_json_response(response_data)

    def _handle_api_download(self, path):
        """处理API下载请求

        支持：
        - GET /api/download/{path} - 下载文件
        """
        # 提取文件路径
        file_path = path[16:]  # 移除 "/api/download/" 前缀
        if file_path.startswith("/"):
            file_path = file_path[1:]

        # URL解码处理中文文件名和特殊字符
        try:
            file_path = unquote(file_path, encoding="utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"URL解码失败: {e}")
            self.send_response(400)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            import json

            error_data = json.dumps(
                {
                    "success": False,
                    "data": None,
                    "error": {"code": 400, "message": "无效的文件路径"},
                },
                ensure_ascii=False,
            )
            self.send_header("Content-Length", str(len(error_data.encode("utf-8"))))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(error_data.encode("utf-8"))
            return

        # 调用现有的下载处理方法
        # 重写path，然后调用_handle_download
        original_path = self.path
        self.path = f"/download/{file_path}"

        try:
            self._handle_download(self.path)
        finally:
            self.path = original_path

    def _handle_api_docs(self):
        """处理API文档请求

        支持：
        - GET /api - 显示API文档
        """
        docs_html = """
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>LAN文件服务器API文档</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                h1 {
                    color: #333;
                    text-align: center;
                }
                .endpoint {
                    background-color: white;
                    padding: 20px;
                    margin: 20px 0;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .method {
                    display: inline-block;
                    padding: 5px 10px;
                    border-radius: 4px;
                    font-weight: bold;
                    color: white;
                }
                .get {
                    background-color: #28a745;
                }
                .path {
                    font-family: monospace;
                    font-size: 18px;
                    margin: 10px 0;
                    color: #007bff;
                }
                .description {
                    color: #666;
                    margin: 10px 0;
                }
                .params {
                    margin: 15px 0;
                }
                .param {
                    margin: 10px 0;
                    padding: 10px;
                    background-color: #f0f0f0;
                    border-radius: 4px;
                }
                .param-name {
                    font-weight: bold;
                }
                .param-type {
                    color: #666;
                    font-style: italic;
                }
                .example {
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 4px;
                    margin: 15px 0;
                }
                .example h4 {
                    margin-top: 0;
                }
                .example code {
                    font-family: monospace;
                    background-color: #e9ecef;
                    padding: 2px 5px;
                    border-radius: 3px;
                }
            </style>
        </head>
        <body>
            <h1>LAN文件服务器API文档</h1>

            <div class="endpoint">
                <h2>文件相关API</h2>

                <div class="endpoint">
                    <div class="method get">GET</div>
                    <div class="path">/api/files</div>
                    <div class="description">获取文件列表</div>
                    <div class="params">
                        <div class="param">
                            <div class="param-name">path</div>
                            <div class="param-type">string (可选)</div>
                            <div class="param-description">目录路径，默认根目录</div>
                        </div>
                        <div class="param">
                            <div class="param-name">sort_by</div>
                            <div class="param-type">string (可选)</div>
                            <div class="param-description">排序字段：name, size, modified, type，默认name</div>
                        </div>
                        <div class="param">
                            <div class="param-name">sort_order</div>
                            <div class="param-type">string (可选)</div>
                            <div class="param-description">排序顺序：asc, desc，默认asc</div>
                        </div>
                        <div class="param">
                            <div class="param-name">page</div>
                            <div class="param-type">integer (可选)</div>
                            <div class="param-description">页码，默认1</div>
                        </div>
                        <div class="param">
                            <div class="param-name">limit</div>
                            <div class="param-type">integer (可选)</div>
                            <div class="param-description">每页数量，默认20</div>
                        </div>
                    </div>
                    <div class="example">
                        <h4>示例请求：</h4>
                        <code>GET /api/files?path=documents&sort_by=modified&sort_order=desc</code>
                    </div>
                </div>

                <div class="endpoint">
                    <div class="method get">GET</div>
                    <div class="path">/api/files/{path}</div>
                    <div class="description">获取单个文件信息</div>
                    <div class="example">
                        <h4>示例请求：</h4>
                        <code>GET /api/files/documents/report.pdf</code>
                    </div>
                </div>
            </div>

            <div class="endpoint">
                <h2>目录相关API</h2>

                <div class="endpoint">
                    <div class="method get">GET</div>
                    <div class="path">/api/directories</div>
                    <div class="description">获取目录列表</div>
                    <div class="params">
                        <div class="param">
                            <div class="param-name">path</div>
                            <div class="param-type">string (可选)</div>
                            <div class="param-description">目录路径，默认根目录</div>
                        </div>
                        <div class="param">
                            <div class="param-name">sort_by</div>
                            <div class="param-type">string (可选)</div>
                            <div class="param-description">排序字段：name, size, modified, type，默认name</div>
                        </div>
                        <div class="param">
                            <div class="param-name">sort_order</div>
                            <div class="param-type">string (可选)</div>
                            <div class="param-description">排序顺序：asc, desc，默认asc</div>
                        </div>
                        <div class="param">
                            <div class="param-name">page</div>
                            <div class="param-type">integer (可选)</div>
                            <div class="param-description">页码，默认1</div>
                        </div>
                        <div class="param">
                            <div class="param-name">limit</div>
                            <div class="param-type">integer (可选)</div>
                            <div class="param-description">每页数量，默认20</div>
                        </div>
                    </div>
                    <div class="example">
                        <h4>示例请求：</h4>
                        <code>GET /api/directories?path=documents</code>
                    </div>
                </div>

                <div class="endpoint">
                    <div class="method get">GET</div>
                    <div class="path">/api/directories/{path}</div>
                    <div class="description">获取目录内容</div>
                    <div class="example">
                        <h4>示例请求：</h4>
                        <code>GET /api/directories/documents</code>
                    </div>
                </div>
            </div>

            <div class="endpoint">
                <h2>搜索API</h2>

                <div class="endpoint">
                    <div class="method get">GET</div>
                    <div class="path">/api/search</div>
                    <div class="description">搜索文件和目录</div>
                    <div class="params">
                        <div class="param">
                            <div class="param-name">q</div>
                            <div class="param-type">string (必填)</div>
                            <div class="param-description">搜索关键词</div>
                        </div>
                        <div class="param">
                            <div class="param-name">page</div>
                            <div class="param-type">integer (可选)</div>
                            <div class="param-description">页码，默认1</div>
                        </div>
                        <div class="param">
                            <div class="param-name">limit</div>
                            <div class="param-type">integer (可选)</div>
                            <div class="param-description">每页数量，默认20</div>
                        </div>
                    </div>
                    <div class="example">
                        <h4>示例请求：</h4>
                        <code>GET /api/search?q=report&page=1&limit=10</code>
                    </div>
                </div>
            </div>

            <div class="endpoint">
                <h2>下载API</h2>

                <div class="endpoint">
                    <div class="method get">GET</div>
                    <div class="path">/api/download/{path}</div>
                    <div class="description">下载文件</div>
                    <div class="example">
                        <h4>示例请求：</h4>
                        <code>GET /api/download/documents/report.pdf</code>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(docs_html.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(docs_html.encode("utf-8"))

    def _is_authenticated(self):
        """检查是否已认证"""
        # 首先检查Session Cookie
        cookie_header = self.headers.get("Cookie", "")
        session_id = self._extract_session_id(cookie_header)

        logger.debug(f"Cookie header: {cookie_header}")
        logger.debug(f"Session ID: {session_id}")

        if session_id:
            is_valid = self.auth_manager.validate_session(session_id)
            logger.debug(f"Session valid: {is_valid}")
            if is_valid:
                return True

        # 回退到HTTP Basic Auth（向后兼容）
        auth_header = self.headers.get("Authorization")
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
            for cookie in cookie_header.split(";"):
                cookie = cookie.strip()
                if cookie.startswith("lan_session="):
                    return cookie.split("=", 1)[1]
            return None
        except Exception:
            return None

    @error_handler
    def _handle_logout(self):
        """处理登出请求"""
        # 提取session_id
        cookie_header = self.headers.get("Cookie", "")
        session_id = self._extract_session_id(cookie_header)

        # 删除服务器端session
        if session_id:
            self.auth_manager.delete_session(session_id)

        # 设置过期的session cookie
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Set-Cookie", "lan_session=; Path=/; HttpOnly; Max-Age=0")
        self.end_headers()

    def _handle_index(self, query_params):
        """处理索引页面请求"""
        search_term = query_params.get("search", [""])[0]
        search_term = unquote(search_term, encoding="utf-8", errors="replace")

        # 获取排序参数
        sort_by = query_params.get("sort_by", ["name"])[0]
        sort_order = query_params.get("sort_order", ["asc"])[0].lower()

        # 验证排序参数
        if sort_by not in ["name", "size", "modified", "type"]:
            sort_by = "name"
        if sort_order not in ["asc", "desc"]:
            sort_order = "asc"

        index_data = self.file_indexer.generate_index(
            search_term, sort_by=sort_by, sort_order=sort_order
        )
        html = HTMLTemplate.get_index_page(index_data, search_term)
        self._send_html_response(html)

    def _handle_search(self, query_params):
        """处理搜索页面请求"""
        search_term = query_params.get("q", [""])[0]
        search_term = unquote(search_term, encoding="utf-8", errors="replace")

        # 获取排序参数
        sort_by = query_params.get("sort_by", ["name"])[0]
        sort_order = query_params.get("sort_order", ["asc"])[0].lower()

        # 验证排序参数
        if sort_by not in ["name", "size", "modified", "type"]:
            sort_by = "name"
        if sort_order not in ["asc", "desc"]:
            sort_order = "asc"

        index_data = self.file_indexer.generate_index(
            search_term, sort_by=sort_by, sort_order=sort_order
        )
        html = HTMLTemplate.get_index_page(index_data, search_term)
        self._send_html_response(html)

    def _handle_browse(self, path, query_params):
        """处理目录浏览请求"""
        # 提取相对路径
        relative_path = path[8:]  # 移除 "/browse/" 前缀
        if relative_path.startswith("/"):
            relative_path = relative_path[1:]

        # URL解码处理中文文件夹名和特殊字符
        try:
            relative_path = unquote(relative_path)
        except Exception as e:
            logger.warning(f"URL解码失败: {e}")
            html = HTMLTemplate.get_404_page()
            self._send_html_response(html, 404)
            return

        # 获取排序参数，默认按名称升序
        sort_by = query_params.get("sort_by", ["name"])[0]
        sort_order = query_params.get("sort_order", ["asc"])[0].lower()

        # 验证排序参数
        if sort_by not in ["name", "size", "modified", "type"]:
            sort_by = "name"
        if sort_order not in ["asc", "desc"]:
            sort_order = "asc"

        listing_data = self.file_indexer.get_directory_listing(
            relative_path, sort_by=sort_by, sort_order=sort_order
        )

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
        if file_path.startswith("/"):
            file_path = file_path[1:]

        # 检查Range请求（用于视频流播放）
        range_header = self.headers.get("Range")
        range_info = None
        if range_header:
            range_info = self._parse_range_header(range_header)

        # URL解码处理中文文件名和特殊字符
        try:
            file_path = unquote(file_path, encoding="utf-8", errors="replace")
            logger.info(f"处理下载请求: {file_path}")
            if range_info:
                logger.info(f"Range请求: {range_info}")
        except Exception as e:
            logger.warning(f"URL解码失败: {e}")
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
            is_safe = False
            for share_dir in self.file_indexer.share_dirs:
                if self.config_manager.is_path_safe(
                    file_info["full_path"], str(share_dir)
                ):
                    is_safe = True
                    break

            if not is_safe:
                logger.warning(f"下载请求路径不安全: {file_info['full_path']}")
                html = HTMLTemplate.get_404_page()
                self._send_html_response(html, 404)
                return

            # 大文件处理：支持流式传输
            file_size = os.path.getsize(file_info["full_path"])

            # 优先使用我们的自定义MIME类型映射
            content_type = None
            file_path_lower = file_info["full_path"].lower()
            file_name = os.path.basename(file_path_lower)

            # 视频扩展名列表，包括点开头的文件名情况
            video_exts = [
                ".mp4",
                ".mkv",
                ".avi",
                ".mov",
                ".wmv",
                ".flv",
                ".webm",
                ".ogg",
            ]

            # 检查文件名是否为以点开头的视频文件，如 .mp4
            is_dot_video_file = file_name.startswith(".") and file_name in video_exts

            # 检查文件是否以视频扩展名结尾
            ends_with_video_ext = any(
                file_path_lower.endswith(ext) for ext in video_exts
            )

            if is_dot_video_file or ends_with_video_ext:
                # 将所有视频格式统一设置为video/mp4
                content_type = "video/mp4"

            # 如果没有匹配到预定义的视频类型，则使用mimetypes.guess_type
            if content_type is None:
                content_type = (
                    mimetypes.guess_type(file_info["full_path"])[0]
                    or "application/octet-stream"
                )

            # 检测文件类型决定是否inline显示
            # 增强文件预览支持，添加更多文件类型
            inline_types = {
                # 图片类型
                "image/jpeg",
                "image/jpg",
                "image/png",
                "image/gif",
                "image/webp",
                "image/bmp",
                "image/svg+xml",
                # 视频类型
                "video/mp4",
                "video/webm",
                "video/ogg",
                "video/avi",
                "video/x-msvideo",  # 标准.avi文件MIME类型
                "video/mov",
                "video/mkv",
                "video/x-matroska",  # MKV文件的实际MIME类型
                "video/wmv",
                "video/flv",
                # 音频类型
                "audio/mpeg",
                "audio/wav",
                "audio/ogg",
                "audio/mp3",
                "audio/wma",
                "audio/m4a",
                "audio/flac",
                # 文本和代码类型
                "text/plain",
                "text/html",
                "text/css",
                "text/javascript",
                "application/javascript",
                "application/json",
                "application/xml",
                "text/xml",
                "text/x-python",
                "text/x-c",
                "text/x-c++",
                "text/x-java",
                "text/x-javascript",
                "text/x-html",
                "text/x-css",
                # 文档类型
                "application/pdf",
                # 其他可预览类型
                "application/rtf",
            }
            # 简化逻辑：强制所有视频文件使用inline预览
            # 直接检查文件扩展名，绕过MIME类型判断的复杂性
            file_path_lower = file_info["full_path"].lower()
            file_name = os.path.basename(file_path_lower)
            video_exts = (
                ".mp4",
                ".mkv",
                ".avi",
                ".mov",
                ".wmv",
                ".flv",
                ".webm",
                ".ogg",
            )

            # 检查文件名是否为以点开头的视频文件，如 .mp4
            is_dot_video_file = file_name.startswith(".") and file_name in video_exts

            # 检查文件是否以视频扩展名结尾
            ends_with_video_ext = file_path_lower.endswith(video_exts)

            is_video_file = is_dot_video_file or ends_with_video_ext

            # 原有逻辑加上视频文件强制inline
            is_inline = (
                content_type in inline_types
                or content_type.startswith("text/")
                or is_video_file
            )

            # 调试日志：输出所有视频文件的实际MIME类型
            if is_video_file:
                logger.info(f"视频文件: {file_info['full_path']}")
                logger.info(f"最终MIME类型: {content_type}")
                logger.info(f"is_video_file: {is_video_file}")
                logger.info(f"is_inline最终判断: {is_inline}")
                logger.info(
                    f"Content-Disposition将设置: {'inline' if is_inline else 'attachment'}"
                )

            # 处理Range请求
            if range_info:
                # Range请求返回206状态码
                self.send_response(206)

                # 处理end为None的情况（从start到文件末尾）
                range_end = range_info["end"]
                if range_end is None:
                    range_end = file_size - 1

                # 设置Content-Range头
                content_range = f"bytes {
                    range_info['start']}-{range_end}/{file_size}"
                self.send_header("Content-Range", content_range)

                # 对于视频文件，使用chunked传输编码，不设置Content-Length
                if content_type.startswith("video/"):
                    # 视频文件使用chunked传输编码
                    self.send_header("Transfer-Encoding", "chunked")
                else:
                    # 其他文件设置Content-Length
                    content_length = range_end - range_info["start"] + 1
                    self.send_header("Content-Length", str(content_length))
            else:
                # 正常请求返回200状态码
                self.send_response(200)

                # 根据文件类型设置传输方式
                if content_type.startswith("video/"):
                    # 视频文件使用chunked传输编码
                    self.send_header("Transfer-Encoding", "chunked")
                else:
                    # 其他文件根据大小设置Content-Length
                    if (
                        file_size < 100 * 1024 * 1024
                    ):  # 小于100MB的文件才设置Content-Length
                        self.send_header("Content-Length", str(file_size))

            # 设置Content-Type
            self.send_header("Content-Type", content_type)

            # 使用RFC 2231标准处理Unicode字符（中文、日文、韩文、生僻字、特殊符号）
            filename_encoded = urlquote(file_info["name"], encoding="utf-8", safe="")
            if is_inline:
                # 浏览器原生预览
                self.send_header(
                    "Content-Disposition",
                    f"inline; filename*=UTF-8''{filename_encoded}",
                )
            else:
                # 强制下载
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename*=UTF-8''{filename_encoded}",
                )

            # 支持Range请求，允许视频流播放
            if content_type.startswith("video/") or content_type.startswith("audio/"):
                self.send_header("Accept-Ranges", "bytes")
                # 优化视频播放的缓存控制
                self.send_header(
                    "Cache-Control", "public, max-age=3600, must-revalidate"
                )
                # 添加视频流优化头
                self.send_header("Content-Type", content_type)
                # 允许跨域请求，解决某些浏览器的CORS问题
                self.send_header("Access-Control-Allow-Origin", "*")
                # 添加视频播放优化头
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "SAMEORIGIN")
                # 优化视频缓冲区管理
                self.send_header("Transfer-Encoding", "chunked")
                # 预加载机制：对于视频文件，设置适当的预加载大小
                if content_type.startswith("video/"):
                    # 对于视频文件，添加更多优化头
                    self.send_header("X-Accel-Buffering", "no")
                    self.send_header("X-Player-Buffer", "auto")
                    # 实现自适应比特率支持
                    self.send_header("Accept-CH", "DPR, Width, Viewport-Width")
                    self.send_header("Vary", "Accept-Encoding, Origin")
            elif is_inline:
                # 设置缓存控制头
                self.send_header("Cache-Control", "public, max-age=3600")

            self.end_headers()

            # 发送文件内容
            self._send_file_content(file_info["full_path"], range_info)

        except FileNotFoundError:
            logger.warning(f"文件未找到: {file_info['full_path']}")
            html = HTMLTemplate.get_404_page()
            self._send_html_response(html, 404)
        except Exception as e:
            logger.info(f"发送文件时出错: {e}")
            self._send_error_response(500, "文件读取错误")

    def _send_file_stream(self, file_path):
        """流式发送大文件"""
        try:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(8192)  # 8KB块
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except Exception as e:
            logger.info(f"流式发送文件时出错: {e}")

    def _parse_range_header(self, range_header):
        """解析Range请求头

        Args:
            range_header (str): Range请求头，如 "bytes=0-1023"

        Returns:
            dict: 包含start和end的字典，如果解析失败返回None
        """
        try:
            if not range_header.startswith("bytes="):
                return None

            range_spec = range_header[6:]  # 移除 "bytes=" 前缀

            if "-" not in range_spec:
                return None

            parts = range_spec.split("-", 1)
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

            return {"start": start, "end": end}
        except (ValueError, IndexError):
            return None

    def _send_file_content(self, file_path, range_info=None):
        """发送文件内容（支持Range请求和sendfile系统调用优化）

        Args:
            file_path (str): 文件路径
            range_info (dict): Range信息，包含start和end
        """
        try:
            file_size = os.path.getsize(file_path)

            # 获取文件类型
            content_type = (
                mimetypes.guess_type(file_path)[0] or "application/octet-stream"
            )

            # 根据文件类型和大小调整传输参数
            if content_type.startswith("video/"):
                # 视频文件使用更大的块大小，提高传输效率
                # 根据文件大小动态调整块大小
                if file_size < 100 * 1024 * 1024:  # 小于100MB的视频文件
                    chunk_size = 65536  # 64KB块
                    preload_size = 1024 * 1024  # 1MB预加载
                elif file_size < 500 * 1024 * 1024:  # 100MB-500MB的视频文件
                    chunk_size = 131072  # 128KB块
                    preload_size = 2 * 1024 * 1024  # 2MB预加载
                else:  # 大于500MB的视频文件
                    chunk_size = 262144  # 256KB块
                    preload_size = 4 * 1024 * 1024  # 4MB预加载
            elif content_type.startswith("audio/"):
                # 音频文件使用中等块大小
                chunk_size = 32768  # 32KB块
                preload_size = 512 * 1024  # 512KB预加载
            else:
                # 其他文件使用默认块大小
                chunk_size = 8192  # 8KB块
                preload_size = 0  # 不预加载

            # 尝试使用sendfile系统调用优化传输
            if hasattr(os, "sendfile") and not range_info:
                # 只在非Range请求时使用sendfile
                try:
                    with open(file_path, "rb") as f:
                        # 获取文件描述符
                        src_fd = f.fileno()
                        # 获取socket文件描述符
                        dst_fd = self.wfile.fileno()

                        # 使用sendfile系统调用传输文件
                        sent = 0
                        while sent < file_size:
                            # 根据文件类型调整sendfile块大小
                            sendfile_chunk = min(
                                chunk_size * 16, file_size - sent
                            )  # 最多1MB per sendfile call
                            sent_bytes = os.sendfile(
                                dst_fd, src_fd, sent, sendfile_chunk
                            )
                            if sent_bytes == 0:  # 文件传输完成
                                break
                            sent += sent_bytes
                        return
                except (AttributeError, OSError, IOError) as e:
                    # sendfile不支持或出错，回退到普通传输方式
                    logger.debug(f"sendfile系统调用失败，使用普通传输方式: {e}")

            # 普通传输方式
            with open(file_path, "rb") as f:
                if range_info:
                    # Range请求：跳转到指定位置
                    start = range_info["start"]
                    end = range_info["end"]

                    if end is None:
                        # 范围请求的结尾未指定，读取到文件末尾
                        f.seek(start)

                        # 实现预加载机制：对于视频文件，提前加载一部分内容
                        if content_type.startswith("video/") or content_type.startswith(
                            "audio/"
                        ):
                            # 预加载一定大小的数据
                            preload_data = f.read(preload_size)
                            if preload_data:
                                self.wfile.write(preload_data)
                                self.wfile.flush()

                        # 继续传输剩余内容
                        while True:
                            chunk = f.read(chunk_size)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            self.wfile.flush()
                    else:
                        # 指定的范围
                        end = min(end, file_size - 1)  # 确保不超过文件大小

                        f.seek(start)
                        remaining = end - start + 1

                        # 实现预加载机制：对于视频文件，提前加载一部分内容
                        if (
                            content_type.startswith("video/")
                            or content_type.startswith("audio/")
                        ) and remaining > preload_size:
                            # 预加载一定大小的数据
                            preload_data = f.read(preload_size)
                            if preload_data:
                                self.wfile.write(preload_data)
                                self.wfile.flush()
                                remaining -= len(preload_data)

                        # 继续传输剩余内容
                        while remaining > 0:
                            current_chunk = min(chunk_size, remaining)
                            chunk = f.read(current_chunk)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            self.wfile.flush()
                            remaining -= len(chunk)
                else:
                    # 正常请求：根据文件大小决定传输方式
                    if file_size >= 100 * 1024 * 1024:  # 大文件流式传输
                        # 实现预加载机制
                        if content_type.startswith("video/") or content_type.startswith(
                            "audio/"
                        ):
                            # 预加载一定大小的数据
                            preload_data = f.read(preload_size)
                            if preload_data:
                                self.wfile.write(preload_data)
                                self.wfile.flush()

                        # 继续传输剩余内容
                        while True:
                            chunk = f.read(chunk_size)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            self.wfile.flush()
                    else:
                        # 小文件直接读取发送
                        content = f.read()
                        self.wfile.write(content)
        except Exception as e:
            logger.info(f"发送文件内容时出错: {e}")

    def _handle_static(self, path):
        """处理静态资源请求"""
        try:
            # 移除 /static/ 前缀
            static_file = path.replace("/static/", "")
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
            with open(static_path, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "public, max-age=3600")  # 缓存1小时
            self.end_headers()
            self.wfile.write(content)

        except Exception as e:
            logger.info(f"处理静态文件时出错: {e}")
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
            remaining_time = self.config_manager.server_config["FAILED_AUTH_BLOCK_TIME"]
            html = HTMLTemplate.get_blocked_page(remaining_time)
            self._send_html_response(html, 429)
            return

        # 读取POST数据
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            post_data = self.rfile.read(content_length).decode("utf-8")

            # 解析表单数据
            form_data = {}
            for param in post_data.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    form_data[unquote(key)] = unquote(value)

            username = form_data.get("username", "")
            password = form_data.get("password", "")

            # 验证凭据
            if self.auth_manager.verify_credentials(username, password):
                # 认证成功，清除失败记录，创建session
                self.config_manager.reset_failed_attempts(client_ip)

                # 提取设备信息
                user_agent = self.headers.get("User-Agent", "")
                device_info = f"{client_ip} - {user_agent[:100]}"  # 限制长度

                session_id = self.auth_manager.create_session(username, device_info)

                # 设置session cookie
                # 24小时
                cookie_value = (
                    f"lan_session={session_id}; Path=/; HttpOnly; Max-Age=86400"
                )

                self.send_response(302)
                self.send_header("Location", "/index")
                self.send_header("Set-Cookie", cookie_value)
                self.end_headers()
                return
            else:
                # 认证失败，记录失败尝试
                self.config_manager.record_failed_attempt(client_ip)
                remaining_attempts = self.config_manager.get_remaining_attempts(
                    client_ip
                )

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

        向客户端发送HTML格式的响应，包括设置适当的响应头和状态码。

        Args:
            html_content (str): HTML内容字符串
            status_code (int): HTTP状态码，默认为200

        Returns:
            None

        Raises:
            Exception: 发送响应时可能发生的任何异常
        """
        try:
            self.send_response(status_code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_content.encode("utf-8"))))

            # 添加浏览器缓存头（浏览页面缓存10分钟）
            self.send_header("Cache-Control", "public, max-age=600")
            self.send_header(
                "Expires",
                time.strftime(
                    "%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + 600)
                ),
            )

            # 添加安全响应头
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("X-XSS-Protection", "1; mode=block")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")

            self.end_headers()
            self.wfile.write(html_content.encode("utf-8"))
        except Exception as e:
            logger.info(f"发送HTML响应时出错: {e}")

    def _get_content_type(self, file_extension):
        """获取文件MIME类型

        Args:
            file_extension (str): 文件扩展名

        Returns:
            str: MIME类型
        """
        content_types = {
            ".css": "text/css",
            ".js": "application/javascript",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
            ".woff": "font/woff",
            ".woff2": "font/woff2",
            ".ttf": "font/ttf",
            ".otf": "font/otf",
        }
        return content_types.get(file_extension.lower(), "application/octet-stream")

    def _send_json_response(self, data, status_code=200):
        """发送JSON格式响应

        向客户端发送JSON格式的响应，包括设置适当的响应头和状态码。
        响应格式遵循统一的API格式：{"success": true/false, "data": ..., "error": ...}

        Args:
            data (dict): 响应数据
            status_code (int): HTTP状态码，默认为200

        Returns:
            None

        Raises:
            Exception: 发送响应时可能发生的任何异常
        """
        try:
            import json

            response = {"success": True, "data": data, "error": None}
            json_data = json.dumps(response, ensure_ascii=False, indent=2)

            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(json_data.encode("utf-8"))))
            self.send_header("Access-Control-Allow-Origin", "*")  # 允许跨域请求
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers", "Content-Type, Authorization"
            )

            # 添加安全响应头
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("X-XSS-Protection", "1; mode=block")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")

            self.end_headers()
            self.wfile.write(json_data.encode("utf-8"))
        except Exception as e:
            logger.error(f"发送JSON响应时出错: {e}")
            # 发送简单的错误响应
            self.send_response(500)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            error_data = json.dumps(
                {
                    "success": False,
                    "data": None,
                    "error": {"code": 500, "message": "服务器内部错误"},
                },
                ensure_ascii=False,
            )
            self.send_header("Content-Length", str(len(error_data.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(error_data.encode("utf-8"))

    def _send_error_response(self, status_code, message):
        """发送错误响应

        Args:
            status_code (int): HTTP状态码
            message (str): 错误信息
        """
        # 使用新的HTTPError异常机制
        raise HTTPError(status_code, message, {"description": message})

    def log_message(self, format, *args):
        """重写日志方法，减少输出"""
        if args[1] != "200":  # 只记录非200状态码的请求
            super().log_message(format, *args)


class FileServer:
    """文件服务器主类"""

    def __init__(self, config_manager=None):
        self.config_manager = config_manager or get_config_manager()
        self.server = None
        self.server_thread = None
        self.running = False

    def _generate_self_signed_cert(self, cert_file, key_file):
        """生成自签名SSL证书

        Args:
            cert_file (str): 证书文件路径
            key_file (str): 密钥文件路径
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            from datetime import datetime, timedelta, UTC
            import socket

            # 生成私钥
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )

            # 获取当前主机名
            hostname = socket.gethostname()

            # 生成证书签名请求
            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LAN File Server"),
                    x509.NameAttribute(NameOID.COMMON_NAME, hostname),
                ]
            )

            # 生成证书
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(UTC))
                .not_valid_after(
                    # 证书有效期为1年
                    datetime.now(UTC)
                    + timedelta(days=365)
                )
                .add_extension(
                    x509.SubjectAlternativeName(
                        [x509.DNSName(hostname), x509.DNSName("localhost")]
                    ),
                    critical=False,
                )
                .sign(private_key, hashes.SHA256(), default_backend())
            )

            # 保存证书
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            # 保存私钥
            with open(key_file, "wb") as f:
                f.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )

            logger.info(f"已生成自签名SSL证书: {cert_file}")
            logger.info(f"已生成SSL密钥: {key_file}")
            return True
        except ImportError as e:
            logger.warning(f"生成自签名证书失败：缺少依赖库: {e}")
            logger.warning("请安装cryptography库: pip install cryptography")
            return False
        except Exception as e:
            logger.error(f"生成自签名证书失败: {e}")
            return False

    def start(self):
        """启动服务器"""
        try:
            # 获取有效端口
            port = self.config_manager.get_effective_port()
            if not port:
                logger.error("无法启动服务器：没有可用端口")
                return False

            # 创建服务器
            def create_handler(*args, **kwargs):
                return FileServerHandler(
                    *args, config_manager=self.config_manager, **kwargs
                )

            # 检查是否启用SSL
            ssl_enabled = self.config_manager.server_config.get("SSL_ENABLED", True)

            if ssl_enabled:
                # SSL启用时的逻辑
                # 检查是否配置了SSL证书和密钥
                ssl_cert_file = self.config_manager.server_config.get(
                    "SSL_CERT_FILE", ""
                )
                ssl_key_file = self.config_manager.server_config.get("SSL_KEY_FILE", "")

                # 尝试生成自签名证书（如果没有配置证书）
                if (
                    not ssl_cert_file
                    or not ssl_key_file
                    or not Path(ssl_cert_file).exists()
                    or not Path(ssl_key_file).exists()
                ):
                    logger.info("没有找到SSL证书，尝试生成自签名证书...")
                    # 生成默认的证书和密钥文件路径
                    default_cert_file = str(Path(".") / "ssl_cert.pem")
                    default_key_file = str(Path(".") / "ssl_key.pem")

                    # 更新配置
                    self.config_manager.server_config["SSL_CERT_FILE"] = (
                        default_cert_file
                    )
                    self.config_manager.server_config["SSL_KEY_FILE"] = default_key_file

                    # 生成自签名证书
                    self._generate_self_signed_cert(default_cert_file, default_key_file)

                    # 重新检查证书和密钥
                    ssl_cert_file = default_cert_file
                    ssl_key_file = default_key_file

                # 检查证书和密钥是否存在
                use_https = (
                    ssl_cert_file
                    and ssl_key_file
                    and Path(ssl_cert_file).exists()
                    and Path(ssl_key_file).exists()
                )

                if use_https:
                    # 使用HTTPS服务器
                    import ssl

                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(ssl_cert_file, ssl_key_file)

                    self.server = ThreadingHTTPServer(("0.0.0.0", port), create_handler)
                    self.server.socket = context.wrap_socket(
                        self.server.socket, server_side=True
                    )

                    protocol = "https"
                else:
                    # 证书不存在，回退到HTTP
                    logger.warning("SSL证书或密钥不存在，回退到HTTP模式")
                    self.server = ThreadingHTTPServer(("0.0.0.0", port), create_handler)
                    protocol = "http"
            else:
                # SSL禁用时，直接使用HTTP服务器
                logger.info("SSL已禁用，使用HTTP服务器")
                self.server = ThreadingHTTPServer(("0.0.0.0", port), create_handler)
                protocol = "http"

            self.running = True

            logger.info("=== LAN文件服务器启动成功 ===")
            logger.info(f"本地访问: {protocol}://localhost:{port}")
            logger.info(f"局域网访问: {protocol}://[本机IP]:{port}")
            logger.info(
                f"共享目录: {
                    self.config_manager.server_config['SHARE_DIRS']}"
            )
            logger.info(
                f"白名单文件类型: {len(self.config_manager.ALL_WHITELIST_EXTENSIONS)} 种"
            )
            logger.info(f"使用协议: {protocol.upper()}")
            logger.info("按 Ctrl+C 停止服务器")
            # 使用章节标题样式展示启动信息
            logger.section("LAN文件服务器启动成功")
            logger.success(f"本地访问: {protocol}://localhost:{port}")
            logger.success(f"局域网访问: {protocol}://[本机IP]:{port}")
            logger.info(
                f"共享目录: {
                    self.config_manager.server_config['SHARE_DIRS']}"
            )
            logger.info(
                f"白名单文件类型: {len(self.config_manager.ALL_WHITELIST_EXTENSIONS)} 种"
            )
            logger.info(f"使用协议: {protocol.upper()}")
            logger.info("按 Ctrl+C 停止服务器")

            # 在新线程中启动服务器
            self.server_thread = threading.Thread(
                target=self.server.serve_forever, daemon=True
            )
            self.server_thread.start()

            return True

        except Exception as e:
            logger.error(f"启动服务器时出错: {e}", exc_info=True)
            return False

    def stop(self):
        """停止服务器"""
        if self.server and self.running:
            logger.info("正在停止服务器...")
            self.running = False

            # 清理FileIndexer资源
            try:
                if hasattr(self, "file_indexer"):
                    self.file_indexer._cleanup()
            except Exception as e:
                logger.error(f"清理FileIndexer资源失败: {e}")

            # 设置超时保护，确保服务器能在10秒内停止
            def server_shutdown_with_timeout():
                try:
                    self.server.shutdown()
                    return True
                except Exception as e:
                    logger.error(f"服务器关闭超时或失败: {e}")
                    return False

            import threading

            shutdown_thread = threading.Thread(target=server_shutdown_with_timeout)
            shutdown_thread.daemon = True
            shutdown_thread.start()

            # 等待最长10秒
            shutdown_thread.join(timeout=10)

            # 关闭服务器
            try:
                self.server.server_close()
            except Exception as e:
                logger.error(f"关闭服务器套接字失败: {e}")

            logger.info("服务器已停止")


# 全局变量用于信号处理
server_instance = None


def signal_handler(signum, _frame):
    """信号处理器"""
    logger.info(f"\n收到信号 {signum}，正在退出...")
    if server_instance:
        server_instance.stop()
    # 移除sys.exit(0)，让服务器自然停止
    # 主线程会在server_thread结束后退出


def _check_critical_files():
    """检查关键文件完整性"""
    critical_files = ["config.json", "server.py", "config.py", "color_logger.py"]

    damaged_files = []

    for file_path in critical_files:
        full_path = Path(file_path)

        # 检查文件是否存在
        if not full_path.exists():
            damaged_files.append(f"{file_path} - 文件不存在")
            continue

        # 检查文件是否为空
        if full_path.stat().st_size == 0:
            damaged_files.append(f"{file_path} - 文件为空")
            continue

        # 针对不同类型文件进行特定检查
        if file_path == "config.json":
            # 检查JSON格式是否正确
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    json.load(f)
            except json.JSONDecodeError as e:
                damaged_files.append(f"{file_path} - JSON格式错误: {e}")
        elif file_path.endswith(".py"):
            # 检查Python文件语法是否正确
            try:
                compile(full_path.read_text(encoding="utf-8"), file_path, "exec")
            except SyntaxError as e:
                damaged_files.append(f"{file_path} - Python语法错误: {e}")

    # 处理检测结果
    if damaged_files:
        print("\n⚠️  检测到以下关键文件损坏:")
        for damage in damaged_files:
            print(f"   - {damage}")

        while True:
            choice = input("\n请选择操作: [i] 忽略并继续, [e] 退出: ").lower()
            if choice == "i":
                logger.warning("用户选择忽略损坏的关键文件，继续运行服务器")
                return True
            elif choice == "e":
                logger.error("用户选择退出，服务器未启动")
                return False
            else:
                print("无效选择，请重新输入")

    return True


def main():
    """主函数"""
    global server_instance

    # 检测关键文件完整性
    if not _check_critical_files():
        sys.exit(1)

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
                logger.info("\n收到中断信号，正在停止服务器...")
                server_instance.stop()
    except Exception as e:
        logger.error(f"服务器运行出错: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
