#!/usr/bin/env python3
"""
测试脚本：验证 _index_directory_flat 方法是否能正确处理点前缀文件
"""
import os
import sys
from pathlib import Path

# 添加当前目录到Python路径
sys.path.append(".")

# 导入配置管理器
from config import ConfigManager

# 创建配置管理器
config_manager = ConfigManager()

# 测试Videos目录
videos_dir = Path(r"C:\Users\blycr\Videos")

print("=== 测试点前缀文件处理 ===")
print(f"测试目录: {videos_dir}")
print(f"白名单扩展名: {config_manager.ALL_WHITELIST_EXTENSIONS}")

# 列出目录中的所有文件
print(f"\n目录中的所有文件:")
for item in videos_dir.iterdir():
    if item.is_file():
        file_name = item.name
        file_ext = item.suffix.lower()
        
        # 检查文件是否为白名单文件
        is_whitelisted = config_manager.is_whitelisted_file(str(item))
        file_type = config_manager.get_file_type(str(item))
        
        print(f"  - {file_name}")
        print(f"    扩展名: {file_ext}")
        print(f"    白名单文件: {is_whitelisted}")
        print(f"    文件类型: {file_type}")
