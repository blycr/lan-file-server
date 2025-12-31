#!/usr/bin/env python3
"""
GitHub Wiki 更新脚本

功能：
1. 克隆GitHub Wiki仓库到临时目录
2. 复制本地wiki文件夹内容到Wiki仓库
3. 提交并推送更改到Wiki仓库
4. 清理临时目录

使用说明：
    python update_wiki.py [--wiki-url WIKI_URL] [--local-wiki LOCAL_WIKI] [--log-level LOG_LEVEL]

参数：
    --wiki-url WIKI_URL      GitHub Wiki仓库URL，默认从当前仓库推断
    --local-wiki LOCAL_WIKI  本地wiki文件夹路径，默认当前目录下的wiki文件夹
    --log-level LEVEL        日志级别：DEBUG, INFO, WARNING, ERROR
    --help                   显示帮助信息
"""

import os
import sys
import logging
import argparse
import tempfile
import shutil
from pathlib import Path
import subprocess

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WikiUpdater:
    """GitHub Wiki更新器"""
    
    def __init__(self, wiki_url=None, local_wiki_path=None):
        """初始化Wiki更新器
        
        Args:
            wiki_url (str): GitHub Wiki仓库URL
            local_wiki_path (str): 本地wiki文件夹路径
        """
        self.wiki_url = wiki_url or self._get_wiki_url_from_origin()
        self.local_wiki_path = Path(local_wiki_path or "wiki")
        self.temp_dir = None
        
    def _get_wiki_url_from_origin(self):
        """从当前Git仓库的origin URL推断Wiki仓库URL
        
        Returns:
            str: GitHub Wiki仓库URL
        """
        try:
            # 获取当前仓库的origin URL
            result = subprocess.run(
                ["git", "config", "--get", "remote.origin.url"],
                capture_output=True,
                text=True,
                check=True
            )
            origin_url = result.stdout.strip()
            
            # 将.git后缀替换为.wiki.git，生成Wiki仓库URL
            if origin_url.endswith(".git"):
                return origin_url[:-4] + ".wiki.git"
            else:
                return origin_url + ".wiki.git"
        except subprocess.CalledProcessError:
            logger.error("无法获取当前仓库的origin URL，请手动指定Wiki URL")
            sys.exit(1)
    
    def _run_git_command(self, cmd, cwd=None):
        """运行Git命令
        
        Args:
            cmd (list): Git命令参数
            cwd (str): 工作目录
        
        Returns:
            subprocess.CompletedProcess: 命令执行结果
        
        Raises:
            subprocess.CalledProcessError: 如果命令执行失败
        """
        logger.debug(f"执行Git命令: {' '.join(cmd)} (cwd: {cwd})")
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            logger.error(f"Git命令失败: {' '.join(cmd)}")
            logger.error(f"stdout: {result.stdout}")
            logger.error(f"stderr: {result.stderr}")
            raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout, stderr=result.stderr)
        return result
    
    def _copy_wiki_content(self):
        """复制本地wiki文件夹内容到Wiki仓库"""
        if not self.local_wiki_path.exists():
            logger.error(f"本地wiki文件夹不存在: {self.local_wiki_path}")
            sys.exit(1)
        
        # 获取所有本地wiki文件
        wiki_files = list(self.local_wiki_path.glob("*.md"))
        logger.info(f"找到 {len(wiki_files)} 个本地wiki文件")
        
        # 复制到Wiki仓库
        for file_path in wiki_files:
            dest_path = self.temp_dir / file_path.name
            shutil.copy2(file_path, dest_path)
            logger.debug(f"复制文件: {file_path.name} → {dest_path}")
    
    def _update_wiki_repo(self):
        """更新Wiki仓库"""
        # 克隆Wiki仓库到临时目录
        logger.info(f"克隆Wiki仓库: {self.wiki_url}")
        self._run_git_command(["git", "clone", self.wiki_url, str(self.temp_dir)])
        
        # 复制本地内容
        self._copy_wiki_content()
        
        # 检查是否有更改
        status_result = self._run_git_command(["git", "status", "--porcelain"], cwd=self.temp_dir)
        if not status_result.stdout.strip():
            logger.info("没有检测到Wiki内容更改，跳过提交")
            return True
        
        # 添加所有更改
        self._run_git_command(["git", "add", "."], cwd=self.temp_dir)
        
        # 再次检查状态，确保有更改要提交
        status_result = self._run_git_command(["git", "status"], cwd=self.temp_dir)
        if "nothing to commit, working tree clean" in status_result.stdout:
            logger.info("工作树已干净，没有需要提交的更改")
            return True
        
        # 提交更改
        commit_message = "Update Wiki content from local wiki folder"
        self._run_git_command(["git", "commit", "-m", commit_message], cwd=self.temp_dir)
        
        # 推送更改
        logger.info("推送更改到GitHub Wiki")
        self._run_git_command(["git", "push"], cwd=self.temp_dir)
        
        return True
    
    def update_wiki(self):
        """执行Wiki更新流程"""
        logger.info("=== GitHub Wiki更新脚本开始执行 ===")
        
        success = False
        try:
            # 创建临时目录
            with tempfile.TemporaryDirectory() as temp_dir:
                self.temp_dir = Path(temp_dir)
                logger.info(f"创建临时目录: {self.temp_dir}")
                
                # 更新Wiki仓库
                success = self._update_wiki_repo()
        except Exception as e:
            logger.error(f"更新Wiki失败: {e}")
        finally:
            # 确保临时目录已清理
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir, ignore_errors=True)
                logger.info(f"清理临时目录: {self.temp_dir}")
        
        if success:
            logger.info("=== GitHub Wiki更新成功 ===")
            return 0
        else:
            logger.error("=== GitHub Wiki更新失败 ===")
            return 1

def main():
    """主函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="GitHub Wiki更新脚本")
    parser.add_argument('--wiki-url', help='GitHub Wiki仓库URL')
    parser.add_argument('--local-wiki', default='wiki', help='本地wiki文件夹路径')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='日志级别')
    
    args = parser.parse_args()
    
    # 设置日志级别
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # 创建Wiki更新器实例
    updater = WikiUpdater(args.wiki_url, args.local_wiki)
    
    # 执行更新
    return updater.update_wiki()

if __name__ == "__main__":
    sys.exit(main())