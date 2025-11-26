#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
对话记录管理模块
用于保存和管理agent的对话记录
项目组: Seraphiel
作者: lilith项目组Seraphiel
创建时间: 2025
"""

import json
import os
import time
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

class ConversationManager:
    """对话记录管理器"""

    def __init__(self, storage_dir: str = None, max_tokens: int = 80000):
        """
        初始化对话记录管理器

        Args:
            storage_dir: 存储目录路径，默认为 ~/.AGENTS/System_Network_Security/main/state
            max_tokens: 单个文件最大token数，默认80000
        """
        self.storage_dir = Path(storage_dir or os.path.expanduser("~/.AGENTS/System_Network_Security/main/state"))
        self.max_tokens = max_tokens
        self.current_file = None
        self.lock = threading.Lock()

        # 确保存储目录存在
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # 初始化当前文件
        self._init_current_file()

    def _init_current_file(self):
        """初始化当前对话记录文件"""
        current_file_path = self.storage_dir / "conversation_state.json"

        # 检查当前文件是否存在且未超过大小限制
        if current_file_path.exists():
            try:
                with open(current_file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # 简单估算token数（中文大概1字符=1token）
                    content = json.dumps(data, ensure_ascii=False)
                    estimated_tokens = len(content)

                if estimated_tokens < self.max_tokens:
                    self.current_file = current_file_path
                    return
                else:
                    # 文件过大，重命名为备份文件
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    backup_file = self.storage_dir / f"conversation_state.last.{timestamp}.json"
                    current_file_path.rename(backup_file)

            except (json.JSONDecodeError, Exception) as e:
                # 文件损坏，重命名为备份文件
                timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                backup_file = self.storage_dir / f"conversation_state.corrupt.{timestamp}.json"
                current_file_path.rename(backup_file)

        # 创建新文件
        self.current_file = current_file_path
        self._write_atomic({"conversations": [], "metadata": {"created": datetime.now().isoformat()}})

    def _write_atomic(self, data: Dict[str, Any]):
        """原子写入文件"""
        temp_file = self.current_file.with_suffix('.tmp')

        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            # 原子性移动
            temp_file.replace(self.current_file)

        except Exception as e:
            # 清理临时文件
            if temp_file.exists():
                temp_file.unlink()
            raise e

    def _estimate_tokens(self, text: str) -> int:
        """估算文本的token数量"""
        # 简单估算：中文字符1个token，英文单词平均1.3个token
        chinese_chars = len([c for c in text if '\u4e00' <= c <= '\u9fff'])
        other_chars = len(text) - chinese_chars
        return chinese_chars + int(other_chars / 1.3)

    def _check_file_size(self, new_content: Dict[str, Any]):
        """检查文件大小，必要时创建新文件"""
        content = json.dumps(new_content, ensure_ascii=False)
        estimated_tokens = self._estimate_tokens(content)

        if estimated_tokens >= self.max_tokens:
            # 备份当前文件
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup_file = self.storage_dir / f"conversation_state.last.{timestamp}.json"

            if self.current_file.exists():
                self.current_file.rename(backup_file)

            # 创建新文件
            self.current_file = self.storage_dir / "conversation_state.json"
            initial_data = {
                "conversations": [],
                "metadata": {
                    "created": datetime.now().isoformat(),
                    "previous_file": str(backup_file)
                }
            }
            self._write_atomic(initial_data)

    def add_conversation_entry(self, role: str, content: str, metadata: Optional[Dict] = None):
        """
        添加对话记录

        Args:
            role: 角色 (user/assistant/system)
            content: 内容
            metadata: 可选的元数据
        """
        with self.lock:
            try:
                # 读取现有数据
                if self.current_file.exists():
                    with open(self.current_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                else:
                    data = {"conversations": [], "metadata": {"created": datetime.now().isoformat()}}

                # 添加新条目
                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "role": role,
                    "content": content,
                    "metadata": metadata or {}
                }

                data["conversations"].append(entry)
                data["metadata"]["last_updated"] = datetime.now().isoformat()

                # 检查文件大小
                self._check_file_size(data)

                # 原子写入
                self._write_atomic(data)

            except Exception as e:
                print(f"保存对话记录失败: {e}")

    def get_recent_conversations(self, limit: int = 8000) -> List[Dict]:
        """
        获取最近的对话记录，用于上下文注入

        Args:
            limit: token限制，默认8000

        Returns:
            对话记录列表
        """
        with self.lock:
            try:
                if not self.current_file.exists():
                    return []

                with open(self.current_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                conversations = data.get("conversations", [])
                if not conversations:
                    return []

                # 从尾部开始，截取不超过token限制的对话
                result = []
                current_tokens = 0

                for conv in reversed(conversations):
                    conv_text = json.dumps(conv, ensure_ascii=False)
                    conv_tokens = self._estimate_tokens(conv_text)

                    if current_tokens + conv_tokens > limit:
                        break

                    result.insert(0, conv)  # 插入到开头，保持时间顺序
                    current_tokens += conv_tokens

                return result

            except Exception as e:
                print(f"读取对话记录失败: {e}")
                return []

    def get_system_context(self) -> List[Dict]:
        """
        获取系统上下文，用于新对话初始化

        Returns:
            系统上下文消息列表
        """
        recent_conversations = self.get_recent_conversations()

        # 转换为API格式
        context = []
        for conv in recent_conversations:
            context.append({
                "role": conv["role"],
                "content": conv["content"]
            })

        return context

    def clear_conversations(self):
        """清空对话记录"""
        with self.lock:
            try:
                # 备份当前文件
                if self.current_file.exists():
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    backup_file = self.storage_dir / f"conversation_state.backup.{timestamp}.json"
                    self.current_file.rename(backup_file)

                # 创建新的空文件
                initial_data = {
                    "conversations": [],
                    "metadata": {
                        "created": datetime.now().isoformat(),
                        "cleared": datetime.now().isoformat()
                    }
                }
                self._write_atomic(initial_data)

            except Exception as e:
                print(f"清空对话记录失败: {e}")

    def get_conversation_stats(self) -> Dict[str, Any]:
        """获取对话统计信息"""
        with self.lock:
            try:
                if not self.current_file.exists():
                    return {"total_conversations": 0, "file_size": 0}

                with open(self.current_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                conversations = data.get("conversations", [])
                content = json.dumps(data, ensure_ascii=False)

                return {
                    "total_conversations": len(conversations),
                    "estimated_tokens": self._estimate_tokens(content),
                    "file_size": self.current_file.stat().st_size,
                    "last_updated": data.get("metadata", {}).get("last_updated"),
                    "created": data.get("metadata", {}).get("created")
                }

            except Exception as e:
                print(f"获取对话统计失败: {e}")
                return {"error": str(e)}