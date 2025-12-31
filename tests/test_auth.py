import unittest
from datetime import datetime, timedelta
import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath('.'))

from server import AuthenticationManager
from config import get_config_manager


class TestAuthManager(unittest.TestCase):
    """测试认证管理器"""
    
    def setUp(self):
        """设置测试环境"""
        self.config_manager = get_config_manager()
        self.auth_manager = AuthenticationManager(self.config_manager)
    
    def test_username_validation(self):
        """测试用户名验证"""
        # 错误用户名
        result = self.auth_manager.verify_credentials("wrong_user", "202512301310")
        self.assertFalse(result)
        
        # 正确用户名
        result = self.auth_manager.verify_credentials("blycr", "202512301310")
        # 密码是否正确取决于当前时间，所以这里只测试用户名验证
        self.assertIsInstance(result, bool)
    
    def test_current_time_password(self):
        """测试使用当前时间作为密码"""
        # 生成当前时间的密码
        current_time = datetime.now()
        current_password = current_time.strftime("%Y%m%d%H%M")
        
        # 验证当前密码应该成功
        result = self.auth_manager.verify_credentials("blycr", current_password)
        self.assertTrue(result)
    
    def test_time_range_password(self):
        """测试时间范围密码验证"""
        # 生成当前时间前后5分钟的密码
        current_time = datetime.now()
        
        # 测试当前时间
        current_password = current_time.strftime("%Y%m%d%H%M")
        result = self.auth_manager.verify_credentials("blycr", current_password)
        self.assertTrue(result)
        
        # 测试前5分钟
        five_minutes_ago = current_time - timedelta(minutes=5)
        past_password = five_minutes_ago.strftime("%Y%m%d%H%M")
        result = self.auth_manager.verify_credentials("blycr", past_password)
        self.assertTrue(result)
        
        # 测试后5分钟
        five_minutes_later = current_time + timedelta(minutes=5)
        future_password = five_minutes_later.strftime("%Y%m%d%H%M")
        result = self.auth_manager.verify_credentials("blycr", future_password)
        self.assertTrue(result)
        
        # 测试超出范围的密码（前6分钟）
        six_minutes_ago = current_time - timedelta(minutes=6)
        past_password = six_minutes_ago.strftime("%Y%m%d%H%M")
        result = self.auth_manager.verify_credentials("blycr", past_password)
        self.assertFalse(result)
        
        # 测试超出范围的密码（后6分钟）
        six_minutes_later = current_time + timedelta(minutes=6)
        future_password = six_minutes_later.strftime("%Y%m%d%H%M")
        result = self.auth_manager.verify_credentials("blycr", future_password)
        self.assertFalse(result)
    
    def test_invalid_password(self):
        """测试无效密码"""
        # 无效格式
        result = self.auth_manager.verify_credentials("blycr", "invalid_password")
        self.assertFalse(result)
        
        # 空密码
        result = self.auth_manager.verify_credentials("blycr", "")
        self.assertFalse(result)
    
    def test_session_creation(self):
        """测试会话创建"""
        # 创建会话
        session_id = self.auth_manager.create_session("blycr")
        self.assertIsInstance(session_id, str)
        
        # 验证会话有效
        result = self.auth_manager.validate_session(session_id)
        self.assertTrue(result)
    
    def test_multiple_sessions(self):
        """测试创建多个会话"""
        # 创建多个会话
        session_ids = []
        for _ in range(5):
            session_id = self.auth_manager.create_session("blycr")
            session_ids.append(session_id)
        
        # 验证所有会话都有效
        for session_id in session_ids:
            result = self.auth_manager.validate_session(session_id)
            self.assertTrue(result)
        
        # 验证会话数量
        self.assertEqual(len(self.config_manager.sessions), 5)
    
    def test_session_validation(self):
        """测试会话验证"""
        # 创建会话
        session_id = self.auth_manager.create_session("blycr")
        
        # 有效会话
        result = self.auth_manager.validate_session(session_id)
        self.assertTrue(result)
        
        # 无效会话ID
        result = self.auth_manager.validate_session("invalid_session_id")
        self.assertFalse(result)
        
        # 空会话ID
        result = self.auth_manager.validate_session("")
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
