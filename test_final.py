#!/usr/bin/env python3
"""
最终测试文件访问控制机制

该脚本直接测试FileIndexer.get_file_info方法的白名单检查逻辑，确保非白名单文件请求返回None
"""

import os
import sys
import tempfile
from pathlib import Path

# 将当前目录添加到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 移除已加载的server模块
def remove_server_module():
    """移除已加载的server模块"""
    if 'server' in sys.modules:
        del sys.modules['server']
        print("✓ 已移除server模块")
    else:
        print("✓ server模块未加载")

# 测试文件访问控制机制
def test_file_access_control():
    """测试文件访问控制机制"""
    print("=== 最终测试文件访问控制机制 ===")
    
    # 移除已加载的server模块
    remove_server_module()
    
    # 导入配置管理器
    from config import get_config_manager
    
    # 获取配置管理器
    config_manager = get_config_manager()
    
    # 导入FileIndexer类
    from server import FileIndexer
    
    # 创建临时目录
    with tempfile.TemporaryDirectory() as temp_dir:
        # 创建测试文件
        test_files = [
            ("test.jpg", ".jpg"),  # 白名单文件
            ("test.mp3", ".mp3"),  # 白名单文件
            ("test.md", ".md"),    # 非白名单文件
            ("test.txt", ".txt"),  # 非白名单文件
            ("test.pdf", ".pdf"),  # 非白名单文件
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
        print("=== 测试FileIndexer.get_file_info方法 ===")
        print(f"白名单扩展名: {config_manager.ALL_WHITELIST_EXTENSIONS}")
        print()
        
        # 统计测试结果
        passed = 0
        total = len(test_files)
        
        for file_name, ext in test_files:
            print(f"测试文件: {file_name}")
            print(f"文件扩展名: {ext}")
            print(f"预期结果: {'白名单文件，应该返回文件信息' if ext in config_manager.ALL_WHITELIST_EXTENSIONS else '非白名单文件，应该返回None'}")
            
            # 调用get_file_info方法
            file_info = file_indexer.get_file_info(file_name)
            
            if ext in config_manager.ALL_WHITELIST_EXTENSIONS:
                # 白名单文件，应该返回文件信息
                if file_info is not None:
                    print(f"✓ 正确：返回了文件信息")
                    passed += 1
                else:
                    print(f"✗ 错误：返回了None")
            else:
                # 非白名单文件，应该返回None
                if file_info is None:
                    print(f"✓ 正确：返回了None（模拟404）")
                    passed += 1
                else:
                    print(f"✗ 错误：返回了文件信息")
            
            print()
        
        # 打印测试结果
        print(f"=== 测试结果 ===")
        print(f"通过：{passed}/{total}")
        print(f"成功率：{passed/total*100:.1f}%")
        
        if passed == total:
            print("✓ 所有测试都通过了！")
            print("✓ 文件访问控制机制已正确实现")
            print("✓ 非白名单文件请求将返回404错误")
        else:
            print("✗ 测试未全部通过")
            print("✗ 文件访问控制机制未正确实现")

# 运行测试
if __name__ == "__main__":
    test_file_access_control()
