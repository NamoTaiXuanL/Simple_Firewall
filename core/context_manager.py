#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
上下文管理模块
用于管理agent的对话上下文
项目组: Seraphiel
作者: lilith项目组Seraphiel
创建时间: 2025
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from conversation_manager import ConversationManager

class ContextManager:
    """上下文管理器"""

    def __init__(self, conversation_manager: ConversationManager, context_limit: int = 8000):
        """
        初始化上下文管理器

        Args:
            conversation_manager: 对话记录管理器实例
            context_limit: 上下文token限制，默认8000
        """
        self.conversation_manager = conversation_manager
        self.context_limit = context_limit
        self.system_prompt = ""

    def set_system_prompt(self, system_prompt: str):
        """
        设置系统提示词

        Args:
            system_prompt: 系统提示词内容
        """
        self.system_prompt = system_prompt

    def build_initial_context(self) -> List[Dict[str, str]]:
        """
        构建初始对话上下文
        新对话时使用，注入系统提示词和尾部截断的历史对话

        Returns:
            对话上下文列表
        """
        context = []

        # 添加系统提示词
        if self.system_prompt:
            context.append({
                "role": "system",
                "content": self.system_prompt
            })

        # 获取历史对话（尾部截断）
        recent_conversations = self.conversation_manager.get_recent_conversations(
            limit=self.context_limit
        )

        # 转换为API格式
        for conv in recent_conversations:
            context.append({
                "role": conv["role"],
                "content": conv["content"]
            })

        return context

    def build_continuation_context(self, base_context: List[Dict]) -> List[Dict]:
        """
        构建继续对话的上下文
        在现有对话基础上继续

        Args:
            base_context: 基础对话上下文

        Returns:
            更新后的对话上下文
        """
        return base_context.copy()

    def add_user_message(self, context: List[Dict], message: str, save_record: bool = True) -> List[Dict]:
        """
        添加用户消息到上下文

        Args:
            context: 当前上下文
            message: 用户消息
            save_record: 是否保存到对话记录

        Returns:
            更新后的上下文
        """
        # 添加到上下文
        updated_context = context.copy()
        updated_context.append({
            "role": "user",
            "content": message
        })

        # 保存到对话记录
        if save_record:
            self.conversation_manager.add_conversation_entry(
                role="user",
                content=message,
                metadata={"timestamp": datetime.now().isoformat()}
            )

        return updated_context

    def add_assistant_message(self, context: List[Dict], message: str, save_record: bool = True) -> List[Dict]:
        """
        添加助手消息到上下文

        Args:
            context: 当前上下文
            message: 助手消息
            save_record: 是否保存到对话记录

        Returns:
            更新后的上下文
        """
        # 添加到上下文
        updated_context = context.copy()
        updated_context.append({
            "role": "assistant",
            "content": message
        })

        # 保存到对话记录
        if save_record:
            self.conversation_manager.add_conversation_entry(
                role="assistant",
                content=message,
                metadata={"timestamp": datetime.now().isoformat()}
            )

        return updated_context

    def add_command_execution_result(self, context: List[Dict], command: str,
                                   output: str, return_code: int, save_record: bool = True) -> List[Dict]:
        """
        添加命令执行结果到上下文

        Args:
            context: 当前上下文
            command: 执行的命令
            output: 命令输出
            return_code: 返回码
            save_record: 是否保存到对话记录

        Returns:
            更新后的上下文
        """
        result_message = f"命令 '{command}' 执行结果:\n输出: {output}\n返回码: {return_code}\n\n请基于这个真实的执行结果继续思考下一步操作。"

        # 添加到上下文
        updated_context = context.copy()
        updated_context.append({
            "role": "user",
            "content": result_message
        })

        # 保存到对话记录
        if save_record:
            self.conversation_manager.add_conversation_entry(
                role="system",  # 使用system角色表示命令执行结果
                content=result_message,
                metadata={
                    "type": "command_execution",
                    "command": command,
                    "return_code": return_code,
                    "timestamp": datetime.now().isoformat()
                }
            )

        return updated_context

    def should_start_new_conversation(self) -> bool:
        """
        判断是否应该开始新对话
        基于文件大小和时间间隔

        Returns:
            是否开始新对话
        """
        stats = self.conversation_manager.get_conversation_stats()

        # 如果没有对话记录，需要新对话
        if stats.get("total_conversations", 0) == 0:
            return True

        # 如果token数超过限制，需要新对话
        if stats.get("estimated_tokens", 0) >= self.conversation_manager.max_tokens:
            return True

        # 检查时间间隔（超过24小时可以考虑新对话）
        last_updated = stats.get("last_updated")
        if last_updated:
            try:
                last_time = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
                current_time = datetime.now()
                time_diff = (current_time - last_time).total_seconds()

                # 超过24小时
                if time_diff > 24 * 3600:
                    return True
            except:
                pass

        return False

    def truncate_context_if_needed(self, context: List[Dict]) -> List[Dict]:
        """
        如果需要，截断上下文以适应token限制

        Args:
            context: 原始上下文

        Returns:
            截断后的上下文
        """
        def estimate_tokens(text: str) -> int:
            """简单估算token数"""
            chinese_chars = len([c for c in text if '\u4e00' <= c <= '\u9fff'])
            other_chars = len(text) - chinese_chars
            return chinese_chars + int(other_chars / 1.3)

        # 计算总token数
        total_tokens = 0
        for msg in context:
            total_tokens += estimate_tokens(msg.get("content", ""))

        # 如果没有超过限制，直接返回
        if total_tokens <= self.context_limit:
            return context

        # 需要截断
        truncated_context = []
        current_tokens = 0

        # 保留系统消息
        system_messages = [msg for msg in context if msg.get("role") == "system"]
        for msg in system_messages:
            truncated_context.append(msg)
            current_tokens += estimate_tokens(msg.get("content", ""))

        # 从尾部开始添加消息，直到达到token限制
        for msg in reversed(context):
            if msg.get("role") == "system":
                continue  # 系统消息已经添加

            msg_tokens = estimate_tokens(msg.get("content", ""))

            if current_tokens + msg_tokens > self.context_limit:
                break

            truncated_context.insert(len(system_messages), msg)  # 插入到系统消息之后
            current_tokens += msg_tokens

        return truncated_context

    def get_context_info(self) -> Dict[str, Any]:
        """
        获取上下文信息

        Returns:
            上下文统计信息
        """
        stats = self.conversation_manager.get_conversation_stats()

        return {
            "context_limit": self.context_limit,
            "current_tokens": stats.get("estimated_tokens", 0),
            "total_conversations": stats.get("total_conversations", 0),
            "should_start_new": self.should_start_new_conversation(),
            "last_updated": stats.get("last_updated"),
            "file_path": str(self.conversation_manager.current_file) if self.conversation_manager.current_file else None
        }