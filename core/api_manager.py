#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API管理器 - 负责调用DeepSeek API和处理响应
项目组: Seraphiel
作者: lilith项目组Seraphiel
创建时间: 2025
"""

import json
import requests
import time
from typing import List, Dict


class ApiManager:
    """API管理器 - 负责API调用和错误处理"""

    def __init__(self, api_key: str = "sk-615198837d52492db5c5970904a35776",
                 api_url: str = "https://api.deepseek.com/v1/chat/completions"):
        """初始化API管理器"""
        self.api_key = api_key
        self.api_url = api_url
        self.max_retries = 3
        self.retry_delays = [5, 10, 15]  # 重试延迟（秒）
        self.default_model = "deepseek-chat"
        self.default_max_tokens = 4000
        self.default_temperature = 0.3
        self.default_timeout = 60

    def call_deepseek_api(self, messages: List[Dict]) -> str:
        """调用DeepSeek API，带重试机制"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        data = {
            "model": self.default_model,
            "messages": messages,
            "max_tokens": self.default_max_tokens,
            "temperature": self.default_temperature
        }

        for attempt in range(self.max_retries + 1):  # 包括初始尝试
            try:
                if attempt > 0:
                    print(f"正在进行第 {attempt} 次重试...（等待 {self.retry_delays[attempt-1]} 秒）")
                    time.sleep(self.retry_delays[attempt-1])

                # 增加超时时间
                response = requests.post(
                    self.api_url,
                    headers=headers,
                    json=data,
                    timeout=self.default_timeout,  # 增加到60秒
                    verify=True  # 确保SSL验证
                )
                response.raise_for_status()

                result = response.json()["choices"][0]["message"]["content"]

                if attempt > 0:
                    print(f"第 {attempt} 次重试成功！")

                return result

            except requests.exceptions.Timeout as e:
                error_msg = f"API调用超时: {str(e)}"
                if attempt < self.max_retries:
                    print(f"警告: {error_msg}")
                    continue
                else:
                    print(f"错误: 所有重试均失败: {error_msg}")
                    return f"API调用错误: {error_msg}"

            except requests.exceptions.ConnectionError as e:
                error_msg = f"网络连接错误: {str(e)}"
                if attempt < self.max_retries:
                    print(f"警告: {error_msg}")
                    continue
                else:
                    print(f"错误: 所有重试均失败: {error_msg}")
                    return f"API调用错误: {error_msg}"

            except requests.exceptions.HTTPError as e:
                error_msg = f"HTTP错误: {e.response.status_code} - {str(e)}"
                if attempt < self.max_retries and e.response.status_code >= 500:
                    # 服务器错误可以重试
                    print(f"警告: {error_msg}")
                    continue
                else:
                    print(f"错误: HTTP错误，无法重试: {error_msg}")
                    return f"API调用错误: {error_msg}"

            except requests.exceptions.RequestException as e:
                error_msg = f"请求异常: {str(e)}"
                if attempt < self.max_retries:
                    print(f"警告: {error_msg}")
                    continue
                else:
                    print(f"错误: 所有重试均失败: {error_msg}")
                    return f"API调用错误: {error_msg}"

            except (KeyError, ValueError, json.JSONDecodeError) as e:
                error_msg = f"响应解析错误: {str(e)}"
                print(f"错误: 响应格式错误: {error_msg}")
                return f"API调用错误: {error_msg}"

            except Exception as e:
                error_msg = f"未知错误: {str(e)}"
                print(f"错误: 未知错误: {error_msg}")
                return f"API调用错误: {error_msg}"

    def set_api_config(self, max_retries: int = None, retry_delays: List[int] = None,
                      model: str = None, max_tokens: int = None,
                      temperature: float = None, timeout: int = None):
        """设置API配置参数"""
        if max_retries is not None:
            self.max_retries = max_retries
        if retry_delays is not None:
            self.retry_delays = retry_delays
        if model is not None:
            self.default_model = model
        if max_tokens is not None:
            self.default_max_tokens = max_tokens
        if temperature is not None:
            self.default_temperature = temperature
        if timeout is not None:
            self.default_timeout = timeout

    def get_api_status(self) -> Dict[str, any]:
        """获取当前API配置状态"""
        return {
            "api_url": self.api_url,
            "max_retries": self.max_retries,
            "retry_delays": self.retry_delays,
            "default_model": self.default_model,
            "default_max_tokens": self.default_max_tokens,
            "default_temperature": self.default_temperature,
            "default_timeout": self.default_timeout
        }