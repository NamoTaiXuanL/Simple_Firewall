#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
系统命令管理器 - 处理系统级命令
项目组: Seraphiel
作者: lilith项目组Seraphiel
创建时间: 2025
"""

import re
from typing import Dict, Tuple, Optional, Any
from datetime import datetime


class SystemCommandsManager:
    """系统命令管理器 - 处理以/开头的系统级命令"""

    def __init__(self, basic_shell_agent=None):
        """初始化系统命令管理器"""
        self.basic_shell_agent = basic_shell_agent
        self.commands = {
            '/new': self._handle_new_command,
        }

    def is_system_command(self, user_input: str) -> bool:
        """检查输入是否为系统命令"""
        return user_input.strip().startswith('/') and user_input.strip() in self.commands

    def execute_system_command(self, user_input: str) -> Tuple[bool, Optional[str], Optional[Any]]:
        """
        执行系统命令

        Args:
            user_input: 用户输入

        Returns:
            (is_system_command, result_message, should_continue)
        """
        command = user_input.strip()

        if command in self.commands:
            return self.commands[command](command)

        return False, f"未知的系统命令: {command}", True

    def _handle_new_command(self, command: str) -> Tuple[bool, str, bool]:
        """
        处理/new命令 - 新建对话

        Returns:
            (is_system_command, result_message, should_continue)
        """
        try:
            if self.basic_shell_agent:
                # 重新初始化对话管理器
                print("正在创建新的对话...")

                # 清空当前对话记录
                self.basic_shell_agent.conversation_manager.clear_conversations()

                # 重新构建初始上下文（不包含历史对话，只包含系统提示词）
                new_context = self.basic_shell_agent.context_manager.build_initial_context()

                # 将新的系统提示词保存到记录中
                self.basic_shell_agent.conversation_manager.add_conversation_entry(
                    role="system",
                    content=f"【系统提示词】\n{self.basic_shell_agent.system_prompt}\n【系统提示词结束】",
                    metadata={"type": "system_prompt", "length": len(self.basic_shell_agent.system_prompt)}
                )

                # 记录新建对话操作
                self.basic_shell_agent.conversation_manager.add_conversation_entry(
                    role="system",
                    content="【新建对话】用户执行了 /new 命令，开始了新的对话会话。",
                    metadata={
                        "type": "new_conversation",
                        "command": "/new",
                        "timestamp": datetime.now().isoformat()
                    }
                )

                print("✓ 新对话已创建，之前的上下文已清空")
                print("✓ 系统提示词已重新注入")
                print("✓ 新的记录文件已启动")

                return True, "新对话已创建成功，请开始新的任务", False
            else:
                return True, "错误: 无法访问BasicShellAgent实例", True

        except Exception as e:
            error_msg = f"创建新对话时出错: {str(e)}"
            print(f"✗ {error_msg}")
            return True, error_msg, True

    def list_available_commands(self) -> Dict[str, str]:
        """列出所有可用的系统命令"""
        return {
            '/new': '创建新的对话会话，清空之前的上下文和记录',
        }

    def get_help_text(self) -> str:
        """获取系统命令帮助文本"""
        commands_info = self.list_available_commands()
        help_text = "可用的系统命令:\n"

        for cmd, desc in commands_info.items():
            help_text += f"  {cmd}: {desc}\n"

        help_text += "\n使用方法: 直接输入命令即可执行"
        return help_text