#!/usr/bin/env python3
"""
简单测试文件访问控制机制

该脚本直接测试FileIndexer.get_file_info方法的白名单检查逻辑
"""

import os
import sys
import tempfile
from pathlib import Path

# 将当前目录添加到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 导入配置管理器
from config import get_config_manager

# 重新加载server模块
if 'server' in sys.modules:
    del sys.modules['server']

# 导入FileIndexer类
from server import FileIndexer


def test_file_access():
    """测试文件访问控制机制"""
    print("=== 测试文件访问控制机制 ===")
    
    # 获取配置管理器
    config_manager = get_config_manager()
    
    # 创建临时目录
    with tempfile.TemporaryDirectory() as temp_dir:
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
        
        # 创建FileIndexer实例
        file_indexer = FileIndexer(config_manager)
        file_indexer.share_dir = Path(temp_dir)
        
        # 测试文件访问
        print("=== 测试文件访问 ===")
        print(f"白名单扩展名: {config_manager.ALL_WHITELIST_EXTENSIONS}")
        print()
        
        for file_name, ext in test_files:
            print(f"测试访问文件: {file_name}")
            print(f"文件扩展名: {ext}")
            print(f"是否在白名单中: {ext in config_manager.ALL_WHITELIST_EXTENSIONS}")
            
            # 直接测试is_whitelisted_file方法
            file_path = Path(temp_dir) / file_name
            is_whitelisted = config_manager.is_whitelisted_file(str(file_path))
            print(f"is_whitelisted_file返回: {is_whitelisted}")
            
            # 调用get_file_info方法
            file_info = file_indexer.get_file_info(file_name)
            
            if file_info is None:
                print(f"✓ 文件访问被拒绝，返回None（模拟404）")
                print(f"预期结果: {'正确' if ext not in config_manager.ALL_WHITELIST_EXTENSIONS else '错误'}")
            else:
                print(f"✗ 文件访问被允许")
                print(f"文件信息: {file_info}")
                print(f"预期结果: {'正确' if ext in config_manager.ALL_WHITELIST_EXTENSIONS else '错误'}")
            
            print()
    
    print("=== 测试完成 ===")


if __name__ == "__main__":
    test_file_access()
