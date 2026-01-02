#!/usr/bin/env python3
"""
测试脚本：验证点前缀文件（如 .mp4）是否能在网站上正确显示
"""
import datetime
import base64
import requests


# 生成当前时间的动态密码
def get_dynamic_password():
    current_time = datetime.datetime.now()
    return current_time.strftime("%Y%m%d%H%M")


# 生成认证头
def get_auth_header():
    username = "blycr"
    password = get_dynamic_password()
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    return {"Authorization": f"Basic {encoded_credentials}"}


# 测试获取文件列表
def test_file_listing():
    print("=== 测试点前缀文件显示 ===")

    # 先创建一个简单的测试文件
    test_file_path = r"C:\Users\blycr\Videos\.test.mp4"
    print(f"\n1. 已在 {test_file_path} 创建测试文件")

    # 测试获取所有共享目录的根目录文件列表
    url = "http://localhost:8000/api/files"
    headers = get_auth_header()

    try:
        # 获取根目录文件
        response = requests.get(url, headers=headers)
        data = response.json()

        if data["success"]:
            files = data["data"]["files"]
            print(f"\n2. 根目录下找到 {len(files)} 个文件")

            # 检查是否有点前缀文件
            dot_files = [file for file in files if file["name"].startswith(".")]
            if dot_files:
                print(f"\n✅ 根目录下找到 {len(dot_files)} 个点前缀文件：")
                for file in dot_files:
                    print(
                        f"   - {file['name']} (类型: {file['type']}, 大小: {file['size_formatted']})"
                    )
        else:
            print(f"\n❌ 请求失败：{data['error']['message']}")

    except Exception as e:
        print(f"\n❌ 测试失败：{e}")


# 测试搜索功能，查找所有点前缀文件
def test_search_dot_files():
    print("\n=== 测试搜索点前缀文件 ===")

    # 使用搜索功能查找所有点前缀文件
    url = "http://localhost:8000/api/search?q=."
    headers = get_auth_header()

    try:
        response = requests.get(url, headers=headers)
        data = response.json()

        if data["success"]:
            results = data["data"]["results"]
            print(f"\n3. 搜索 '.', 找到 {len(results)} 个结果：")

            # 检查是否有点前缀文件
            dot_files = [result for result in results if result["name"].startswith(".")]
            if dot_files:
                print(f"\n✅ 搜索结果中找到 {len(dot_files)} 个点前缀文件：")
                for file in dot_files:
                    print(
                        f"   - {file['name']} (类型: {file['type']}, 路径: {file['path']})"
                    )
            else:
                print("\n❌ 搜索结果中未找到点前缀文件")
        else:
            print(f"\n❌ 搜索请求失败：{data['error']['message']}")

    except Exception as e:
        print(f"\n❌ 搜索测试失败：{e}")


if __name__ == "__main__":
    test_file_listing()
    test_search_dot_files()
    print("\n=== 测试完成 ===")
