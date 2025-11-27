#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
附加提示词管理模块 - 管理附加提示词的注入和删除
项目组: Seraphiel
作者: lilith项目组Seraphiel
创建时间: 2025
"""

import os


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


# 全局实例
additional_prompt_manager = AdditionalPromptManager()