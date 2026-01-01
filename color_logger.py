#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
彩色日志工具
提供富文本彩色输出功能，支持不同日志级别
"""

import sys
import os
import logging
from datetime import datetime


class ColorFormatter(logging.Formatter):
    """彩色日志格式化器"""
    
    # 颜色代码
    COLORS = {
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'DIM': '\033[2m',
        'RED': '\033[31m',
        'GREEN': '\033[32m',
        'YELLOW': '\033[33m',
        'BLUE': '\033[34m',
        'MAGENTA': '\033[35m',
        'CYAN': '\033[36m',
        'WHITE': '\033[37m',
        'ORANGE': '\033[38;5;208m',
        'PURPLE': '\033[38;5;141m',
        'PINK': '\033[38;5;205m',
    }
    
    # 日志级别颜色映射
    LEVEL_COLORS = {
        logging.DEBUG: 'DIM',
        logging.INFO: 'WHITE',
        logging.WARNING: 'YELLOW',
        logging.ERROR: 'RED',
        logging.CRITICAL: 'BOLD+RED'
    }
    
    def __init__(self, use_colors=True, show_timestamp=True, show_level=True):
        super().__init__()
        self.use_colors = use_colors and self._supports_color()
        self.original_use_colors = use_colors
        self.show_timestamp = show_timestamp
        self.show_level = show_level
    
    def _supports_color(self):
        """检查终端是否支持颜色输出"""
        return (
            hasattr(sys.stdout, 'isatty') and sys.stdout.isatty() and
            'TERM' in os.environ and os.environ['TERM'] != 'dumb'
        )
    
    def _colorize(self, text, color):
        """应用颜色到文本"""
        if not self.use_colors:
            return text
        
        color_code = self.COLORS.get(color, '')
        reset_code = self.COLORS['RESET']
        
        # 处理复合颜色（如 BOLD+RED）
        if '+' in color:
            colors = color.split('+')
            for c in colors:
                color_code += self.COLORS.get(c, '')
        
        return f"{color_code}{text}{reset_code}"
    
    def format(self, record):
        """格式化日志记录"""
        # 构建日志消息
        parts = []
        
        # 时间戳
        if self.show_timestamp:
            timestamp = datetime.now().strftime('%H:%M:%S')
            parts.append(self._colorize(timestamp, 'DIM'))
        
        # 日志级别
        if self.show_level:
            level_name = record.levelname
            level_color = self.LEVEL_COLORS.get(record.levelno, 'WHITE')
            level_text = f"[{level_name}]"
            parts.append(self._colorize(level_text, level_color))
        
        # 记录器名称
        if record.name and record.name != 'root':
            logger_name = f"[{record.name}]"
            parts.append(self._colorize(logger_name, 'DIM'))
        
        # 消息内容
        message = record.getMessage()
        if record.levelno >= logging.ERROR:
            message_color = 'RED'
        elif record.levelno >= logging.WARNING:
            message_color = 'YELLOW'
        elif record.levelno >= logging.INFO:
            message_color = 'WHITE'
        else:
            message_color = 'DIM'
        
        parts.append(self._colorize(message, message_color))
        
        # 异常信息
        if record.exc_info:
            parts.append('\n')
            parts.append(self.formatException(record.exc_info))
        
        return ' '.join(parts)


class RichLogger:
    """富文本日志器"""
    
    def __init__(self, name="LANFileServer", level=logging.INFO, use_colors=True):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.use_colors = use_colors
        
        # 清除现有处理器
        self.logger.handlers.clear()
        
        # 控制台处理器（彩色）
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_formatter = ColorFormatter(use_colors=use_colors)
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # 文件处理器（无颜色）
        self.setup_file_handler()
    
    def setup_file_handler(self, log_file="lan_file_server.log"):
        """设置文件处理器"""
        try:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)  # 文件记录所有级别
            
            # 文件格式器（无颜色）
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
        except Exception as e:
            self.logger.warning(f"无法创建文件日志处理器: {e}")
    
    def debug(self, message, **kwargs):
        """调试级别日志"""
        self.logger.debug(message, **kwargs)
    
    def info(self, message, **kwargs):
        """信息级别日志"""
        self.logger.info(message, **kwargs)
    
    def warning(self, message, **kwargs):
        """警告级别日志"""
        self.logger.warning(message, **kwargs)
    
    def error(self, message, **kwargs):
        """错误级别日志"""
        self.logger.error(message, **kwargs)
    
    def critical(self, message, **kwargs):
        """严重错误级别日志"""
        self.logger.critical(message, **kwargs)
    
    def success(self, message, **kwargs):
        """成功信息（自定义级别，使用INFO + 绿色）"""
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info(self._colorize_text(message, 'GREEN'), **kwargs)
    
    def section(self, title, **kwargs):
        """章节标题（使用INFO + 橙色）"""
        if self.logger.isEnabledFor(logging.INFO):
            separator = '=' * 60
            self.logger.info(f"\n{separator}", **kwargs)
            self.logger.info(self._colorize_text(title, 'ORANGE'), **kwargs)
            self.logger.info(f"{separator}", **kwargs)
    
    def _colorize_text(self, text, color):
        """内部方法：彩色化文本"""
        # 仅为显示用途，在实际日志记录中不会生效
        if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
            colors = {
                'RED': '\033[31m',
                'GREEN': '\033[32m',
                'YELLOW': '\033[33m',
                'BLUE': '\033[34m',
                'MAGENTA': '\033[35m',
                'CYAN': '\033[36m',
                'ORANGE': '\033[38;5;208m',
                'PURPLE': '\033[38;5;141m',
                'RESET': '\033[0m'
            }
            return f"{colors.get(color, '')}{text}{colors['RESET']}"
        return text


# 全局富文本日志器实例
rich_logger = None

def get_rich_logger(name="LANFileServer", level=logging.INFO, use_colors=True):
    """获取全局富文本日志器实例"""
    global rich_logger
    if rich_logger is None:
        rich_logger = RichLogger(name, level, use_colors)
    elif use_colors != rich_logger.original_use_colors:
        # 如果需要不同颜色设置，重新创建日志器
        rich_logger = RichLogger(name, level, use_colors)
    return rich_logger


# 便利函数
def log_section(title):
    """记录章节标题"""
    get_rich_logger().section(title)

def log_success(message):
    """记录成功信息"""
    get_rich_logger().success(message)

def log_info(message):
    """记录信息"""
    get_rich_logger().info(message)

def log_warning(message):
    """记录警告"""
    get_rich_logger().warning(message)

def log_error(message):
    """记录错误"""
    get_rich_logger().error(message)


if __name__ == "__main__":
    # 测试彩色日志
    print("=== 彩色日志测试 ===")
    
    logger = get_rich_logger("TestLogger")
    
    logger.section("开始测试")
    logger.info("这是一条信息日志")
    logger.success("这是一条成功日志")
    logger.warning("这是一条警告日志")
    logger.error("这是一条错误日志")
    logger.debug("这是一条调试日志")
    
    print("\n" + "="*50)
    print("测试完成")