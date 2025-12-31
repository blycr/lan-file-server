#!/usr/bin/env python3
"""
自动化同步脚本 - 同步修改到所有分支，过滤敏感信息并推送到GitHub

功能：
1. 检测并过滤敏感信息
2. 同步修改到所有本地分支
3. 推送到GitHub的main分支
4. 支持配置文件和命令行参数

使用说明：
    python sync_script.py [--repo REPO_PATH] [--log-level LOG_LEVEL] [--no-push]

参数：
    --repo REPO_PATH    仓库路径，默认当前目录
    --log-level LEVEL   日志级别：DEBUG, INFO, WARNING, ERROR
    --no-push           仅执行同步，不推送到GitHub
    --help              显示帮助信息
"""

import os
import re
import sys
import logging
import argparse
from pathlib import Path
import configparser

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SyncScript:
    """自动化同步脚本主类"""
    
    def __init__(self, repo_path='.', config_path=None):
        """初始化脚本
        
        Args:
            repo_path (str): Git仓库路径
            config_path (str): 配置文件路径
        """
        self.repo_path = repo_path
        self.config_path = config_path
        self.config = self._load_config()
        self.git_executable = self._find_git_executable()
        
    def _load_config(self):
        """加载配置文件
        
        Returns:
            dict: 配置字典
        """
        # 默认配置
        config = {
            'sensitive_patterns': [
                r'(?i)(password[_-]?hash|salt|api[_-]?key|secret|token)\s*=\s*["\']([^"\']+)["\']',
                r'(?i)share[_-]?dir\s*=\s*["\']([^"\']+)["\']',
                r'D:\\SteamLibrary',
                r'\\b(?:admin|root|user|test)\\b\s*=\s*["\']([^"\']+)["\']',
            ],
            'ignore_files': [
                '.gitignore',
                '*.pyc',
                '__pycache__/',
                '*.log',
                'config.json',
                'sessions.json',
                '.DS_Store',
                'Thumbs.db',
            ],
            'protected_branches': ['main', 'master'],
            'git_user': os.environ.get('GIT_USER', 'Automation Script'),
            'git_email': os.environ.get('GIT_EMAIL', 'automation@example.com'),
        }
        
        # 加载配置文件（如果存在）
        if self.config_path and Path(self.config_path).exists():
            try:
                config_parser = configparser.ConfigParser()
                config_parser.read(self.config_path)
                
                if 'SENSITIVE' in config_parser:
                    patterns = config_parser['SENSITIVE'].get('patterns', '')
                    if patterns:
                        config['sensitive_patterns'] = [p.strip() for p in patterns.split('\n') if p.strip()]
                
                if 'IGNORE' in config_parser:
                    files = config_parser['IGNORE'].get('files', '')
                    if files:
                        config['ignore_files'] = [f.strip() for f in files.split('\n') if f.strip()]
                
                if 'GIT' in config_parser:
                    config['git_user'] = config_parser['GIT'].get('user', config['git_user'])
                    config['git_email'] = config_parser['GIT'].get('email', config['git_email'])
                    
                logger.info(f"已加载配置文件: {self.config_path}")
            except Exception as e:
                logger.error(f"加载配置文件失败: {e}")
        
        return config
    
    def _find_git_executable(self):
        """查找Git可执行文件
        
        Returns:
            str: Git可执行文件路径
        
        Raises:
            RuntimeError: 如果未找到Git
        """
        git_cmd = 'git.exe' if sys.platform == 'win32' else 'git'
        
        # 检查是否在PATH中
        import shutil
        git_path = shutil.which(git_cmd)
        if git_path:
            return git_path
        
        # 检查常见位置
        common_paths = [
            '/usr/bin/git',
            '/usr/local/bin/git',
            'C:\\Program Files\\Git\\bin\\git.exe',
            'C:\\Program Files (x86)\\Git\\bin\\git.exe',
        ]
        
        for path in common_paths:
            if Path(path).exists():
                return path
        
        raise RuntimeError("未找到Git可执行文件，请确保Git已安装并添加到PATH中")
    
    def _run_git_command(self, args, cwd=None, check=True):
        """运行Git命令
        
        Args:
            args (list): Git命令参数
            cwd (str): 工作目录
            check (bool): 是否检查返回码
        
        Returns:
            tuple: (stdout, stderr, returncode)
        
        Raises:
            subprocess.CalledProcessError: 如果check=True且命令失败
        """
        import subprocess
        
        cmd = [self.git_executable] + args
        cwd = cwd or self.repo_path
        
        logger.debug(f"执行Git命令: {' '.join(cmd)} (cwd: {cwd})")
        
        result = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=check
        )
        
        return result.stdout, result.stderr, result.returncode
    
    def filter_sensitive_info(self):
        """过滤敏感信息
        
        Returns:
            bool: 是否成功
        """
        logger.info("开始过滤敏感信息...")
        
        try:
            # 获取所有修改的文件
            stdout, stderr, _ = self._run_git_command(['status', '--porcelain'])
            
            modified_files = []
            for line in stdout.splitlines():
                if not line.strip():
                    continue
                
                # 解析status输出
                status_code = line[:2].strip()
                file_path = line[3:].strip()
                
                # 跳过删除的文件
                if status_code.startswith('D'):
                    continue
                
                modified_files.append(file_path)
            
            logger.info(f"检测到 {len(modified_files)} 个修改的文件")
            
            for file_path in modified_files:
                # 检查是否在忽略列表中
                if any(pattern in file_path for pattern in self.config['ignore_files']):
                    logger.debug(f"跳过忽略的文件: {file_path}")
                    continue
                
                full_path = Path(self.repo_path) / file_path
                if not full_path.exists():
                    continue
                
                try:
                    # 读取文件内容
                    content = full_path.read_text(encoding='utf-8', errors='replace')
                    
                    # 应用敏感信息过滤
                    original_content = content
                    for pattern in self.config['sensitive_patterns']:
                        # 替换为占位符
                        content = re.sub(pattern, r'\1 = "[REDACTED]"', content)
                    
                    # 如果内容有变化，写回文件
                    if content != original_content:
                        logger.info(f"已过滤敏感信息: {file_path}")
                        full_path.write_text(content, encoding='utf-8')
                        # 添加到Git索引
                        self._run_git_command(['add', file_path])
                except Exception as e:
                    logger.error(f"处理文件时出错 {file_path}: {e}")
                    continue
            
            logger.info("敏感信息过滤完成")
            return True
        except Exception as e:
            logger.error(f"过滤敏感信息失败: {e}")
            return False
    
    def _get_local_branches(self):
        """获取所有本地分支
        
        Returns:
            list: 分支名称列表
        """
        stdout, stderr, _ = self._run_git_command(['branch', '--format', '%(refname:short)'])
        return [branch.strip() for branch in stdout.splitlines() if branch.strip()]
    
    def _get_current_branch(self):
        """获取当前分支
        
        Returns:
            str: 当前分支名称
        """
        stdout, stderr, _ = self._run_git_command(['rev-parse', '--abbrev-ref', 'HEAD'])
        return stdout.strip()
    
    def sync_to_all_branches(self):
        """同步修改到所有本地分支
        
        Returns:
            bool: 是否成功
        """
        logger.info("开始同步修改到所有分支...")
        
        try:
            # 设置Git用户信息
            self._run_git_command(['config', 'user.name', self.config['git_user']])
            self._run_git_command(['config', 'user.email', self.config['git_email']])
            
            # 获取当前分支
            current_branch = self._get_current_branch()
            logger.info(f"当前分支: {current_branch}")
            
            # 获取所有本地分支
            local_branches = self._get_local_branches()
            logger.info(f"本地分支: {local_branches}")
            
            # 提交当前分支的修改
            self._run_git_command(['add', '.'])
            
            # 检查是否有修改需要提交
            stdout, stderr, _ = self._run_git_command(['status', '--porcelain'])
            if stdout.strip():
                self._run_git_command(['commit', '-m', 'Sync changes from automation script'])
                logger.info(f"已提交当前分支 {current_branch} 的修改")
            else:
                logger.info(f"当前分支 {current_branch} 没有修改")
            
            # 同步到其他分支
            for branch in local_branches:
                if branch == current_branch:
                    continue
                
                logger.info(f"同步修改到分支: {branch}")
                
                try:
                    # 切换到目标分支
                    self._run_git_command(['checkout', branch])
                    
                    # 合并当前分支的修改
                    self._run_git_command(['merge', current_branch, '--no-ff', '-m', f"Merge changes from {current_branch}"])
                    logger.info(f"已合并修改到分支 {branch}")
                except Exception as e:
                    logger.error(f"同步到分支 {branch} 失败: {e}")
                    # 尝试回滚
                    try:
                        self._run_git_command(['merge', '--abort'], check=False)
                        logger.debug(f"已回滚分支 {branch} 的合并")
                    except Exception:
                        pass
            
            # 切换回原分支
            self._run_git_command(['checkout', current_branch])
            logger.info("分支同步完成")
            return True
        except Exception as e:
            logger.error(f"同步到分支失败: {e}")
            return False
    
    def push_to_github(self, branch='main'):
        """推送到GitHub
        
        Args:
            branch (str): 要推送的分支名称
        
        Returns:
            bool: 是否成功
        """
        logger.info(f"推送修改到GitHub的 {branch} 分支...")
        
        try:
            # 推送当前分支到远程
            stdout, stderr, _ = self._run_git_command(['push', 'origin', branch])
            logger.info(f"已成功推送到GitHub的 {branch} 分支")
            logger.debug(f"推送输出: {stdout.strip()}")
            return True
        except Exception as e:
            logger.error(f"推送失败: {e}")
            return False
    
    def run(self, push_to_github=True):
        """运行完整流程
        
        Args:
            push_to_github (bool): 是否推送到GitHub
        
        Returns:
            bool: 执行是否成功
        """
        logger.info("=== 自动化同步脚本开始执行 ===")
        
        success = True
        
        # 步骤1: 过滤敏感信息
        if not self.filter_sensitive_info():
            success = False
        
        # 步骤2: 同步到所有分支
        if not self.sync_to_all_branches():
            success = False
        
        # 步骤3: 推送到GitHub
        if push_to_github:
            if not self.push_to_github('main'):
                success = False
        
        logger.info("=== 自动化同步脚本执行完成 ===")
        return success

    def _run_shell_command(self, cmd, cwd=None):
        """运行shell命令
        
        Args:
            cmd (str): 要执行的命令
            cwd (str): 工作目录
        
        Returns:
            tuple: (stdout, stderr, returncode)
        """
        import subprocess
        
        logger.debug(f"执行命令: {cmd} (cwd: {cwd})")
        result = subprocess.run(
            cmd,
            cwd=cwd or self.repo_path,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        return result.stdout, result.stderr, result.returncode

def main():
    """主函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="自动化同步脚本")
    parser.add_argument('--repo', default='.', help='Git仓库路径')
    parser.add_argument('--config', help='配置文件路径')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='日志级别')
    parser.add_argument('--no-push', action='store_true', help='仅执行同步，不推送到GitHub')
    parser.add_argument('--test', action='store_true', help='测试模式，不执行实际操作')
    
    args = parser.parse_args()
    
    # 设置日志级别
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # 创建脚本实例
    script = SyncScript(repo_path=args.repo, config_path=args.config)
    
    # 运行脚本
    if args.test:
        logger.info("测试模式：跳过实际操作")
        sys.exit(0)
    
    success = script.run(push_to_github=not args.no_push)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()