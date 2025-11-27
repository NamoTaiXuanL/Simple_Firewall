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
        self.shared_terminal = None  # 共享终端实例
        self.shared_terminal_process = None  # 共享终端进程

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
            return self._execute_in_shared_terminal(command, wait_for_completion)
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

    def _execute_in_shared_terminal(self, command: str, wait_for_completion: bool) -> Tuple[str, int]:
        """在共享终端中执行命令"""
        try:
            # 检查是否使用单个持久终端
            if not hasattr(self, '_persistent_terminal_created') or not self.shared_terminal_process:
                terminal_exec = self._find_terminal_executable()
                if not terminal_exec:
                    return self._execute_background(command)

                # 创建命令管道目录
                self.command_dir = f"/tmp/shell_agent_commands_{os.getpid()}"
                os.makedirs(self.command_dir, exist_ok=True)

                # 创建命令脚本
                command_script = os.path.join(self.command_dir, "command_script.sh")
                with open(command_script, 'w') as f:
                    f.write('''#!/bin/bash
# Shell Agent 命令执行脚本
echo "Shell Agent 终端已启动"
echo "等待命令执行..."

# 监听命令文件
while true; do
    if [ -f "/tmp/shell_agent_commands_{pid}/current_command" ]; then
        echo ""
        echo "=================="
        echo "执行命令: $(cat /tmp/shell_agent_commands_{pid}/current_command)"
        echo "=================="

        # 执行命令
        bash "/tmp/shell_agent_commands_{pid}/current_command"
        echo "命令执行完成"
        echo ""

        # 清理命令文件
        rm -f "/tmp/shell_agent_commands_{pid}/current_command"
    fi
    sleep 0.5
done
'''.format(pid=os.getpid()))

                os.chmod(command_script, 0o755)

                terminal_title = "Shell Agent - 命令执行终端"

                if terminal_exec == 'gnome-terminal':
                    terminal_cmd = [
                        'gnome-terminal',
                        '--title', terminal_title,
                        '--', 'bash', command_script
                    ]
                elif terminal_exec == 'konsole':
                    terminal_cmd = [
                        'konsole',
                        '--title', terminal_title,
                        '-e', 'bash', command_script
                    ]
                else:  # xterm 或其他
                    terminal_cmd = [
                        terminal_exec,
                        '-title', terminal_title,
                        '-e', 'bash', command_script
                    ]

                # 启动共享终端
                self.shared_terminal_process = subprocess.Popen(terminal_cmd)
                self._persistent_terminal_created = True
                time.sleep(2)  # 给终端时间启动

            # 创建当前命令文件
            current_command_file = os.path.join(self.command_dir, "current_command")
            with open(current_command_file, 'w') as f:
                f.write(f'cd ~ && {command}')

            # 等待命令执行完成（通过检查文件是否存在）
            if wait_for_completion:
                max_wait = 300  # 最多等待5分钟
                wait_time = 0
                while os.path.exists(current_command_file) and wait_time < max_wait:
                    time.sleep(1)
                    wait_time += 1

                if wait_time >= max_wait:
                    # 超时，清理命令文件
                    try:
                        os.unlink(current_command_file)
                    except:
                        pass
                    return "命令执行超时", 1

                # 在后台执行同样的命令来获取结果
                return self._execute_background(command)
            else:
                # 不等待完成，直接返回
                return f"命令已发送到终端执行: {command}", 0

        except Exception as e:
            return f"共享终端执行错误: {str(e)}", 1

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

        # 清理共享终端
        if hasattr(self, 'shared_terminal_process') and self.shared_terminal_process:
            try:
                self.shared_terminal_process.terminate()
                self.shared_terminal_process = None
            except:
                pass

        # 清理命令目录
        if hasattr(self, 'command_dir'):
            try:
                import shutil
                shutil.rmtree(self.command_dir, ignore_errors=True)
            except:
                pass

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