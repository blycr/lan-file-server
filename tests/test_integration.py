import unittest
import time
import threading
from http.server import HTTPServer
import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath('.'))

from server import FileServerHandler, get_config_manager
from config import ConfigManager


class TestIntegration(unittest.TestCase):
    """集成测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.config_manager = get_config_manager()
    
    def test_server_initialization(self):
        """测试服务器初始化"""
        # 验证配置管理器初始化
        self.assertIsInstance(self.config_manager, ConfigManager)
        
        # 验证服务器配置加载
        self.assertIsInstance(self.config_manager.server_config['PORT'], int)
        self.assertIsInstance(self.config_manager.server_config['SHARE_DIR'], str)
        
        # 验证认证配置
        self.assertEqual(self.config_manager.auth_config['username'], 'blycr')
    
    def test_session_management(self):
        """测试会话管理"""
        # 清除现有会话
        self.config_manager.sessions.clear()
        
        # 创建多个会话
        sessions = []
        for i in range(3):
            session_id = self.config_manager.create_session(f"blycr", f"device_{i}")
            sessions.append(session_id)
        
        # 验证会话创建
        self.assertEqual(len(self.config_manager.sessions), 3)
        
        # 验证所有会话有效
        for session_id in sessions:
            self.assertTrue(self.config_manager.validate_session(session_id))
        
        # 验证会话设备信息
        for i, session_id in enumerate(sessions):
            session = self.config_manager.sessions[session_id]
            self.assertEqual(session['username'], "blycr")
            self.assertEqual(session['device_info'], f"device_{i}")
        
        # 清除会话
        for session_id in sessions:
            self.config_manager.delete_session(session_id)
        
        # 验证会话已清除
        self.assertEqual(len(self.config_manager.sessions), 0)
    
    def test_session_expiration(self):
        """测试会话过期"""
        # 清除现有会话
        self.config_manager.sessions.clear()
        
        # 创建会话
        session_id = self.config_manager.create_session("blycr")
        
        # 修改会话最后访问时间为过去
        import time
        session = self.config_manager.sessions[session_id]
        session['last_access'] = time.time() - (24 * 3600 + 60)  # 24小时1分钟前
        session['created_at'] = time.time() - (24 * 3600 + 60)  # 同时修改创建时间
        
        # 验证会话已过期
        self.assertFalse(self.config_manager.validate_session(session_id))
        self.assertNotIn(session_id, self.config_manager.sessions)
    
    def test_cleanup_expired_sessions(self):
        """测试清理过期会话"""
        # 清除现有会话
        self.config_manager.sessions.clear()
        
        # 创建多个会话，其中一些已过期
        import time
        current_time = time.time()
        
        # 有效会话
        session_id1 = self.config_manager.create_session("blycr")
        self.config_manager.sessions[session_id1]['last_access'] = current_time  # 最近访问
        
        # 过期会话
        session_id2 = self.config_manager.create_session("blycr")
        self.config_manager.sessions[session_id2]['last_access'] = current_time - (24 * 3600 + 60)  # 24小时1分钟前
        
        session_id3 = self.config_manager.create_session("blycr")
        self.config_manager.sessions[session_id3]['last_access'] = current_time - (24 * 3600 + 120)  # 24小时2分钟前
        
        # 验证初始会话数量
        self.assertEqual(len(self.config_manager.sessions), 3)
        
        # 清理过期会话
        self.config_manager.cleanup_expired_sessions()
        
        # 验证只保留了有效会话
        self.assertEqual(len(self.config_manager.sessions), 1)
        self.assertIn(session_id1, self.config_manager.sessions)
        self.assertNotIn(session_id2, self.config_manager.sessions)
        self.assertNotIn(session_id3, self.config_manager.sessions)
    
    def test_password_generation(self):
        """测试密码生成与验证"""
        from server import AuthenticationManager
        
        auth_manager = AuthenticationManager(self.config_manager)
        
        # 生成当前时间前后5分钟的密码
        from datetime import datetime, timedelta
        current_time = datetime.now()
        
        # 测试所有允许的密码
        success_count = 0
        for minutes_offset in range(-5, 6):
            offset_time = current_time + timedelta(minutes=minutes_offset)
            offset_password = offset_time.strftime("%Y%m%d%H%M")
            
            result = auth_manager.verify_credentials("blycr", offset_password)
            if result:
                success_count += 1
        
        # 应该有11个密码（当前时间±5分钟）
        self.assertEqual(success_count, 11)
        
        # 测试超出范围的密码
        offset_time = current_time + timedelta(minutes=6)
        offset_password = offset_time.strftime("%Y%m%d%H%M")
        result = auth_manager.verify_credentials("blycr", offset_password)
        self.assertFalse(result)
        
        offset_time = current_time + timedelta(minutes=-6)
        offset_password = offset_time.strftime("%Y%m%d%H%M")
        result = auth_manager.verify_credentials("blycr", offset_password)
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
