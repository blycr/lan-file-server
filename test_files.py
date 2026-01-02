import requests
import json
import os

# 登录获取session
login_url = "http://localhost:8000/login"
login_data = {
    "username": "blycr",
    "password": "202601021751"
}

# 创建会话
session = requests.Session()
login_response = session.post(login_url, data=login_data, allow_redirects=True)

# 在当前目录创建测试文件
print("创建测试文件...")
with open(".test_mp4.mp4", "w") as f:
    f.write("test content")

with open(".mp4", "w") as f:
    f.write("test content")

# 直接访问API，查看响应结构
api_url = "http://localhost:8000/api/directories?path="
response = session.get(api_url)

# 解析响应
if response.status_code == 200:
    data = response.json()
    if data["success"]:
        print("\nAPI响应结构:")
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print(f"API请求失败: {data['error']['message']}")
else:
    print(f"HTTP请求失败，状态码: {response.status_code}")
    print("响应内容:")
    print(response.text)

# 清理测试文件
print("\n清理测试文件...")
os.remove(".test_mp4.mp4")
os.remove(".mp4")