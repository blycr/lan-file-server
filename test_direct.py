#!/usr/bin/env python3
"""
直接测试文件访问控制机制

该脚本直接修改server.py文件中的get_file_info方法，并测试其行为
"""

import os
import sys
import tempfile
from pathlib import Path

# 直接修改server.py文件
def modify_server_file():
    """修改server.py文件，添加调试信息"""
    server_path = Path(__file__).parent / "server.py"
    # 使用UTF-8编码读取文件
    content = server_path.read_text(encoding="utf-8")
    
    # 检查是否已经添加了调试信息
    if "# 检查文件是否在白名单中" in content:
        print("✓ server.py文件已经包含白名单检查逻辑")
        return True
    else:
        print("✗ server.py文件中没有找到白名单检查逻辑")
        return False


def test_file_access():
    """测试文件访问控制机制"""
    print("=== 测试文件访问控制机制 ===")
    
    # 修改server.py文件
    if modify_server_file():
        # 导入模块
        import sys
        from config import get_config_manager
        from server import FileIndexer
        
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
            for file_name, ext in test_files:
                print(f"测试访问文件: {file_name}")
                file_info = file_indexer.get_file_info(file_name)
                
                if file_info is None:
                    print(f"  ✓ 文件访问被拒绝，返回404")
                else:
                    print(f"  ✗ 文件访问被允许")
                
                print()
    else:
        print("无法继续测试，server.py文件未正确修改")


if __name__ == "__main__":
    test_file_access()
