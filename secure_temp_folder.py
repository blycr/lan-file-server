import tempfile
import os
import shutil
from contextlib import contextmanager

class SecureTempFolder:
    """安全临时文件夹管理器
    
    用于安全地创建、使用和清理临时文件夹，防止路径遍历攻击，确保资源正确释放。
    
    用法示例：
    with SecureTempFolder(prefix="myapp_") as temp:
        temp_path = temp.get_path()
        temp_file = temp.create_temp_file(prefix="data_", suffix=".txt")
        # 安全的路径拼接
        safe_path = temp.safe_join("subfolder", "file.txt")
    """
    
    def __init__(self, prefix="secure_", suffix="", dir=None):
        """初始化临时文件夹管理器
        
        Args:
            prefix (str): 临时文件夹名称前缀
            suffix (str): 临时文件夹名称后缀
            dir (str): 临时文件夹的父目录，None表示使用系统默认
        """
        self.prefix = prefix
        self.suffix = suffix
        self.dir = dir
        self.temp_dir = None
    
    def __enter__(self):
        """进入上下文，创建安全的临时文件夹
        
        Returns:
            SecureTempFolder: 自身实例，用于链式调用
        """
        # 创建安全的临时文件夹，权限设置为仅所有者可读写执行
        self.temp_dir = tempfile.mkdtemp(prefix=self.prefix, suffix=self.suffix, dir=self.dir)
        # 确保权限正确（仅所有者可读写执行）
        os.chmod(self.temp_dir, 0o700)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """退出上下文，清理临时文件夹
        
        Args:
            exc_type: 异常类型
            exc_val: 异常值
            exc_tb: 异常回溯
        """
        # 清理临时文件夹，即使发生异常
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            self.temp_dir = None
    
    def get_path(self):
        """获取临时文件夹路径
        
        Returns:
            str: 临时文件夹的绝对路径
        
        Raises:
            RuntimeError: 如果临时文件夹未创建
        """
        if not self.temp_dir:
            raise RuntimeError("临时文件夹未创建或已被清理")
        return self.temp_dir
    
    def create_temp_file(self, prefix="", suffix=""):
        """在临时文件夹内创建安全的临时文件
        
        Args:
            prefix (str): 临时文件名称前缀
            suffix (str): 临时文件名称后缀
        
        Returns:
            str: 临时文件的绝对路径
        
        Raises:
            RuntimeError: 如果临时文件夹未创建
        """
        if not self.temp_dir:
            raise RuntimeError("临时文件夹未创建或已被清理")
        
        # 在临时文件夹内创建文件
        fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=self.temp_dir)
        os.close(fd)
        # 确保文件权限正确（仅所有者可读写）
        os.chmod(path, 0o600)
        return path
    
    def safe_join(self, *paths):
        """安全的路径拼接，防止路径遍历攻击
        
        Args:
            *paths: 要拼接的路径组件
        
        Returns:
            str: 安全的绝对路径
        
        Raises:
            RuntimeError: 如果临时文件夹未创建
            ValueError: 如果检测到路径遍历攻击
        """
        if not self.temp_dir:
            raise RuntimeError("临时文件夹未创建或已被清理")
        
        # 确保所有路径都在临时文件夹内
        full_path = os.path.abspath(os.path.join(self.temp_dir, *paths))
        temp_dir_abs = os.path.abspath(self.temp_dir)
        
        if not full_path.startswith(temp_dir_abs):
            raise ValueError("检测到路径遍历攻击尝试")
        
        return full_path
    
    def create_subdirectory(self, *paths):
        """在临时文件夹内创建子目录
        
        Args:
            *paths: 子目录路径
        
        Returns:
            str: 子目录的绝对路径
        
        Raises:
            RuntimeError: 如果临时文件夹未创建
            ValueError: 如果检测到路径遍历攻击
        """
        subdir_path = self.safe_join(*paths)
        os.makedirs(subdir_path, exist_ok=True)
        # 确保目录权限正确
        os.chmod(subdir_path, 0o700)
        return subdir_path
    
    def list_files(self, pattern="*"):
        """列出临时文件夹内的文件
        
        Args:
            pattern: 文件匹配模式
        
        Returns:
            list: 匹配的文件路径列表
        
        Raises:
            RuntimeError: 如果临时文件夹未创建
        """
        if not self.temp_dir:
            raise RuntimeError("临时文件夹未创建或已被清理")
        
        import glob
        return glob.glob(os.path.join(self.temp_dir, pattern))


# 上下文管理器快捷函数
@contextmanager
def secure_temp_folder(prefix="secure_", suffix="", dir=None):
    """安全临时文件夹的上下文管理器快捷函数
    
    用法示例：
    with secure_temp_folder() as temp_dir:
        # 使用临时文件夹
        pass
    """
    temp_dir = tempfile.mkdtemp(prefix=prefix, suffix=suffix, dir=dir)
    os.chmod(temp_dir, 0o700)
    try:
        yield temp_dir
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)