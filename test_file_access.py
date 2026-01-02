#!/usr/bin/env python3
"""
测试文件访问控制机制

该脚本用于测试非白名单文件请求是否返回404错误
"""

import os
import sys
import tempfile
import importlib
from pathlib import Path

# 将当前目录添加到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 先导入模块
from config import get_config_manager

# 然后重新加载server模块，确保使用最新的代码
if 'server' in sys.modules:
    importlib.reload(sys.modules['server'])

# 导入FileIndexer类
from server import FileIndexer


def test_file_access_control():
    """测试文件访问控制机制"""
    print("=== 测试文件访问控制机制 ===")
    
    # 获取配置管理器
    config_manager = get_config_manager()
    
    # 创建临时目录和测试文件
    with tempfile.TemporaryDirectory() as temp_dir:
        # 创建FileIndexer实例
        file_indexer = FileIndexer(config_manager)
        file_indexer.share_dir = Path(temp_dir)
        
        # 创建测试文件
        test_files = [
            ("test.jpg", ".jpg"),  # 白名单文件
            ("test.mp3", ".mp3"),  # 白名单文件
            ("test.md", ".md"),    # 非白名单文件
            ("test.txt", ".txt"),  # 非白名单文件
        ]
        
        for file_name, ext in test_files:
            file_path = Path(temp_dir) / file_name
            file_path.write_text(f"Test content for {file_name}")
            print(f"创建测试文件: {file_path}")
        
        print()
        
        # 直接测试FileIndexer类的get_file_info方法
        print("=== 直接测试FileIndexer.get_file_info方法 ===")
        print(f"白名单扩展名: {config_manager.ALL_WHITELIST_EXTENSIONS}")
        print()
        
        for file_name, ext in test_files:
            print(f"测试访问文件: {file_name}")
            print(f"文件扩展名: {ext}")
            print(f"是否在白名单中: {ext in config_manager.ALL_WHITELIST_EXTENSIONS}")
            
            # 直接测试 is_whitelisted_file 方法
            file_path = Path(temp_dir) / file_name
            is_whitelisted = config_manager.is_whitelisted_file(str(file_path))
            print(f"is_whitelisted_file 返回: {is_whitelisted}")
            
            # 直接测试 get_file_type 方法
            file_type = config_manager.get_file_type(str(file_path))
            print(f"get_file_type 返回: {file_type}")
            
            # 手动检查文件扩展名
            manual_check = file_path.suffix.lower() in config_manager.ALL_WHITELIST_EXTENSIONS
            print(f"手动检查结果: {manual_check}")
            
            file_info = file_indexer.get_file_info(file_name)
            
            if file_info is None:
                print(f"  ✓ 文件访问被拒绝，返回None（模拟404）")
                print(f"  预期结果: {'正确' if ext not in config_manager.ALL_WHITELIST_EXTENSIONS else '错误'}")
            else:
                print(f"  ✗ 文件访问被允许")
                print(f"  文件信息: {file_info['name']} ({file_info['type']})")
                print(f"  预期结果: {'正确' if ext in config_manager.ALL_WHITELIST_EXTENSIONS else '错误'}")
            
            print()
    
    print("=== 测试完成 ===")


if __name__ == "__main__":
    test_file_access_control()
