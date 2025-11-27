#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shell Interface Module - EXEC模块专门负责shell交互
项目组: Seraphiel
作者: lilith项目组Seraphiel
创建时间: 2025
"""

import subprocess
import os
import time
import signal
import threading
from typing import Tuple, Optional, List

class ShellInterface:
    """Shell交互接口 - 专门负责执行shell命令并显示交互界面"""

    def __init__(self, show_terminal: bool = True):
        self.show_terminal = show_terminal
        self.active_terminals = {}  # 跟踪活跃的终端进程

    def _has_graphical_environment(self) -> bool:
        """检查是否有图形界面环境"""
        return (os.environ.get('DISPLAY') is not None and
                self._find_terminal_executable() is not None)

    def _find_terminal_executable(self) -> Optional[str]:
        """查找可用的终端程序"""
        terminals = ['gnome-terminal', 'konsole', 'xterm', 'xfce4-terminal']
        for terminal in terminals:
            try:
                result = subprocess.run(['which', terminal],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    return terminal
            except:
                continue
        return None

    def execute_command(self, command: str, wait_for_completion: bool = True) -> Tuple[str, int]:
        """
        执行shell命令

        Args:
            command: 要执行的命令
            wait_for_completion: 是否等待命令完成

        Returns:
            Tuple[str, int]: (输出内容, 返回码)
        """
        if self.show_terminal and self._has_graphical_environment():
            return self._execute_in_terminal(command, wait_for_completion)
        else:
            return self._execute_background(command)

    def _execute_in_terminal(self, command: str, wait_for_completion: bool) -> Tuple[str, int]:
        """在图形终端中直接执行命令"""
        try:
            terminal_exec = self._find_terminal_executable()
            if not terminal_exec:
                return self._execute_background(command)

            # 准备终端命令，直接执行命令
            terminal_title = f"Shell Agent: {command[:30]}..."

            if terminal_exec == 'gnome-terminal':
                # gnome-terminal 使用 -- 执行命令
                terminal_cmd = [
                    'gnome-terminal',
                    '--title', terminal_title,
                    '--',
                    'bash', '-c', f'cd ~ && echo "执行命令: {command}" && {command} && echo "命令完成，按回车关闭..." && read'
                ]
            elif terminal_exec == 'konsole':
                # konsole 使用 -e 执行命令
                terminal_cmd = [
                    'konsole',
                    '--title', terminal_title,
                    '-e', 'bash', '-c', f'cd ~ && echo "执行命令: {command}" && {command} && echo "命令完成，按回车关闭..." && read'
                ]
            else:  # xterm 或其他
                # xterm 使用 -e 执行命令
                terminal_cmd = [
                    terminal_exec,
                    '-title', terminal_title,
                    '-e', 'bash', '-c', f'cd ~ && echo "执行命令: {command}" && {command} && echo "命令完成，按回车关闭..." && read'
                ]

            # 启动终端进程
            terminal_process = subprocess.Popen(terminal_cmd)
            process_id = terminal_process.pid

            if wait_for_completion:
                # 等待终端窗口关闭
                try:
                    terminal_process.wait(timeout=300)
                    if process_id in self.active_terminals:
                        del self.active_terminals[process_id]
                    return f"命令已在终端窗口中执行完成: {command}", 0
                except subprocess.TimeoutExpired:
                    terminal_process.terminate()
                    return "命令执行超时，已终止", 1
            else:
                # 不等待完成，记录进程
                self.active_terminals[process_id] = terminal_process

                # 启动监控线程，在进程结束后清理
                monitor_thread = threading.Thread(
                    target=self._monitor_process,
                    args=(terminal_process, process_id)
                )
                monitor_thread.daemon = True
                monitor_thread.start()

                return f"命令已在终端窗口中启动 (PID: {process_id}): {command}", 0

        except Exception as e:
            return f"终端执行错误: {str(e)}", 1

    def _execute_background(self, command: str) -> Tuple[str, int]:
        """在后台执行命令"""
        try:
            result = subprocess.run(
                ['bash', '-c', f'cd ~ && {command}'],
                capture_output=True,
                text=True,
                timeout=300,
                encoding='utf-8',
                errors='ignore'
            )
            output = result.stdout + result.stderr
            return output.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "命令执行超时", 1
        except Exception as e:
            return f"后台执行错误: {str(e)}", 1

    def _monitor_process(self, process: subprocess.Popen, pid: int):
        """监控进程状态，结束后清理"""
        try:
            process.wait(timeout=600)  # 最多等待10分钟
            if pid in self.active_terminals:
                del self.active_terminals[pid]
        except:
            if pid in self.active_terminals:
                try:
                    del self.active_terminals[pid]
                except:
                    pass

    def execute_interactive_command(self, command: str) -> Tuple[str, int]:
        """执行交互式命令（始终在终端中显示）"""
        return self._execute_in_terminal(command, wait_for_completion=True)

    def execute_background_command(self, command: str) -> Tuple[str, int]:
        """执行后台命令（不等待完成）"""
        if self.show_terminal and self._has_graphical_environment():
            return self._execute_in_terminal(command, wait_for_completion=False)
        else:
            return self._execute_background(command)

    def get_active_terminals(self) -> List[int]:
        """获取活跃终端进程ID列表"""
        return list(self.active_terminals.keys())

    def kill_terminal(self, pid: int) -> bool:
        """终止指定的终端进程"""
        if pid in self.active_terminals:
            try:
                process = self.active_terminals[pid]
                process.terminate()
                # 等待进程终止
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                return True
            except:
                return False
        return False

    def cleanup(self):
        """清理所有资源"""
        # 终止所有活跃终端
        for pid in list(self.active_terminals.keys()):
            self.kill_terminal(pid)

    def set_terminal_mode(self, show_terminal: bool):
        """设置是否显示终端"""
        self.show_terminal = show_terminal

    def get_terminal_info(self) -> dict:
        """获取终端接口信息"""
        return {
            "has_graphical_env": self._has_graphical_environment(),
            "terminal_executable": self._find_terminal_executable(),
            "show_terminal": self.show_terminal,
            "active_terminals": len(self.active_terminals)
        }

# 全局shell接口实例
_shell_interface = None

def get_shell_interface(show_terminal: bool = True) -> ShellInterface:
    """获取全局shell接口实例"""
    global _shell_interface
    if _shell_interface is None:
        _shell_interface = ShellInterface(show_terminal)
    return _shell_interface

def cleanup_shell_interface():
    """清理全局shell接口"""
    global _shell_interface
    if _shell_interface is not None:
        _shell_interface.cleanup()
        _shell_interface = None