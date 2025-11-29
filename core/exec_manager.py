#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EXEC管理器 - 负责执行Linux命令和处理结果
项目组: Seraphiel
作者: lilith项目组Seraphiel
创建时间: 2025
"""

import re
import subprocess
from typing import Dict, List, Tuple, Optional


class ExecManager:
    """EXEC管理器 - 负责命令执行和解析"""

    def __init__(self, shell_interface=None):
        """初始化EXEC管理器"""
        self.shell_interface = shell_interface

    def parse_exec_commands(self, response: str) -> List[str]:
        """从Agent响应中提取EXEC命令"""
        exec_pattern = r'\[EXEC\](.*?)\[/EXEC\]'
        return re.findall(exec_pattern, response, re.DOTALL)

    def execute_linux_command(self, command: str) -> Tuple[str, int]:
        """使用Shell接口执行命令"""
        try:
            if self.shell_interface:
                # 使用Shell接口执行命令，在终端中显示
                output, return_code = self.shell_interface.execute_command(command)
                return output, return_code
            else:
                # 备用执行方式
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='ignore',
                    cwd='~'  # 在用户主目录执行
                )
                return result.stdout, result.returncode
        except Exception as e:
            return f"Shell接口执行错误: {str(e)}", 1

    def execute_command_and_get_output(self, command: str) -> Tuple[str, int, str]:
        """执行命令并获取格式化的输出信息"""
        output, return_code = self.execute_linux_command(command)

        # 格式化输出信息
        if output:
            output_info = f"命令输出:\n{output}"
        else:
            output_info = "命令无输出"

        return output, return_code, output_info

    def has_exec_commands(self, response: str) -> bool:
        """检查响应中是否包含EXEC命令"""
        exec_commands = self.parse_exec_commands(response)
        return bool(exec_commands)

    def get_first_exec_command(self, response: str) -> Optional[str]:
        """获取第一个EXEC命令"""
        exec_commands = self.parse_exec_commands(response)
        if exec_commands:
            return exec_commands[0].strip()
        return None

    def format_command_output(self, command: str, output: str, return_code: int) -> str:
        """格式化命令执行结果的显示信息"""
        result = f"执行命令: {command}\n"

        if output:
            result += f"命令输出:\n{output}\n"
        else:
            result += "命令无输出\n"

        result += f"返回码: {return_code}"

        return result