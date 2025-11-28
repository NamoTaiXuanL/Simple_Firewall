#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
附加提示词管理模块 - 管理附加提示词的注入和删除
项目组: Seraphiel
作者: lilith项目组Seraphiel
创建时间: 2025
"""

import os
import re


class AdditionalPromptManager:
    """附加提示词管理器"""

    def __init__(self):
        self.additional_prompts = {}
        self.prompts_dir = "Additional_prompts"

        # 确保提示词目录存在
        os.makedirs(self.prompts_dir, exist_ok=True)

        # 加载所有附加提示词
        self._load_all_prompts()

    def _load_all_prompts(self):
        """加载所有附加提示词文件"""
        self.additional_prompts = {}

        try:
            for filename in os.listdir(self.prompts_dir):
                if filename.endswith('.txt') and filename != 'README.md':
                    prompt_name = filename[:-4]  # 去掉.txt扩展名
                    file_path = os.path.join(self.prompts_dir, filename)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read().strip()
                        if content:  # 只加载非空文件
                            self.additional_prompts[prompt_name] = content
        except Exception as e:
            print(f"加载附加提示词时出错: {str(e)}")

    def get_prompt(self, prompt_name):
        """获取指定的附加提示词"""
        return self.additional_prompts.get(prompt_name, "")

    def list_prompts(self):
        """列出所有可用的附加提示词"""
        return list(self.additional_prompts.keys())

    def reload_prompts(self):
        """重新加载所有附加提示词"""
        self._load_all_prompts()

    def get_all_prompts(self):
        """获取所有附加提示词字典"""
        return self.additional_prompts.copy()

    def parse_additional_prompt_command(self, response: str) -> list:
        """解析[EXEC] Additional prompts <prompt_name> [/EXEC]命令"""
        # 匹配格式: [EXEC] Additional prompts <prompt_name> [/EXEC]
        # 支持多词提示词名称
        pattern = r'\[EXEC\]\s*Additional prompts\s+([^/]+?)\s*\[/EXEC\]'
        matches = re.findall(pattern, response, re.IGNORECASE)
        # 清理匹配结果中的空格
        return [match.strip() for match in matches]

    def inject_additional_prompt(self, messages: list, prompt_name: str) -> tuple:
        """将指定的附加提示词注入到对话上下文中"""
        # 尝试直接匹配
        if prompt_name in self.additional_prompts:
            additional_prompt = self.additional_prompts[prompt_name]
        else:
            # 尝试模糊匹配，忽略大小写和下划线
            matched_key = None
            prompt_lower = prompt_name.lower().replace(' ', '').replace('_', '')

            for key in self.additional_prompts.keys():
                key_lower = key.lower().replace(' ', '').replace('_', '')
                if prompt_lower == key_lower or prompt_lower in key_lower or key_lower in prompt_lower:
                    matched_key = key
                    break

            if matched_key:
                additional_prompt = self.additional_prompts[matched_key]
                prompt_name = matched_key  # 更新为实际的键名
            else:
                print(f"✗ 未找到附加提示词: {prompt_name}")
                print(f"可用的提示词: {', '.join(self.list_prompts())}")
                return messages, False

        # 创建系统消息来注入附加提示词
        injection_message = {
            "role": "system",
            "content": f"【附加提示词注入 - {prompt_name}】\n{additional_prompt}\n【附加提示词结束】"
        }

        # 将注入消息添加到对话历史中
        messages.append(injection_message)

        print(f"✓ 已注入附加提示词: {prompt_name}")
        return messages, True

    def check_and_inject_additional_prompt(self, response: str, messages: list) -> tuple:
        """检查响应中是否有附加提示词命令，如果有则注入相应的提示词"""
        additional_prompts = self.parse_additional_prompt_command(response)

        if additional_prompts:
            # 注入第一个找到的附加提示词
            prompt_name = additional_prompts[0]
            return self.inject_additional_prompt(messages, prompt_name)

        return messages, False


# 全局实例
additional_prompt_manager = AdditionalPromptManager()