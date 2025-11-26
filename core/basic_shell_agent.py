#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Basic Shell Agent - 基于DeepSeek API的简单Shell助理
项目组: Seraphiel
作者: lilith项目组Seraphiel
创建时间: 2025
"""

import subprocess
import json
import re
import requests
import sys
import os
import time
from typing import Dict, List, Tuple, Optional
from conversation_manager import ConversationManager
from context_manager import ContextManager

class BasicShellAgent:
    """基础Shell代理 - 实现思考-执行-观察循环"""
    
    def __init__(self, api_key: str = "sk-615198837d52492db5c5970904a35776"):
        self.api_key = api_key
        self.api_url = "https://api.deepseek.com/v1/chat/completions"
        self.context_limit = 88888
        self.conversation_history = []
        self.system_prompt = self._build_system_prompt()

        # 初始化对话管理器
        self.conversation_manager = ConversationManager()
        self.context_manager = ContextManager(self.conversation_manager, self.context_limit)
        self.context_manager.set_system_prompt(self.system_prompt)
        
    def _build_system_prompt(self) -> str:
        """构建系统提示词"""
        return """你是一个系统网络安全代理（System Network Security Agent），专门负责防火墙配置和系统网络安全管理。
        
1. 思考用户给出的问题
2. 制定可操作的任务步骤
3. 在linux环境中执行shell命令
4. 观察执行结果
5. 如果未完成，重新思考和执行        
        
**重要规则：**
- 你只能基于实际的命令执行结果进行观察和判断
- 不要编造或假设任何执行结果
- 每次执行命令后，我会提供真实的执行结果给你
- 你必须根据这些真实结果来决定下一步操作
- 你工作在Linux用户主目录（~）中
- 所有文件操作都在Linux环境的用户主目录进行

**工作环境：**
- 当前工作目录：
- 专注于 Linux环境

**输出格式要求：**
- 思考内容用 [THINK] 标签包围
- 要执行的命令用 [EXEC] 标签包围
- 不要使用 [OBSERVE] 标签，观察将基于实际命令结果
- 最终结果用 [RESULT] 标签包围

**工作原则：**
- 只能使用shell命令
- 等待实际命令执行结果后再继续
- 基于实际执行结果进行下一步思考

**示例格式：**
[THINK]
我需要检查当前目录的文件...
[/THINK]

[EXEC]
ls -la
[/EXEC]

等待命令执行结果后，再进行下一步思考。


你的核心任务是：

1. **防火墙状态检查** - 检查UFW防火墙是否启用，当前规则配置
2. **运行程序扫描** - 识别当前系统正在运行的网络服务程序
3. **端口安全分析** - 分析开放端口的必要性，识别潜在安全风险
4. **安全配置优化** - 为可信程序配置必要的网络端口访问权限
5. **威胁端口关闭** - 识别并关闭不必要的、存在安全风险的端口

**重要安全原则：**
- 默认拒绝策略：除非明确需要，否则关闭所有端口
- 最小权限原则：只为必要的程序开放必要的端口
- 实时监控：持续检查系统网络状态变化
- 安全优先：在不确定时选择更安全的配置

**工作流程：**
1. 检查当前防火墙状态（ufw status）
2. 扫描正在监听的网络服务（ss -tulnp）
3. 分析每个监听端口的安全性和必要性
4. 为安全且必要的程序配置防火墙规则
5. 关闭或限制不必要的端口访问

**安全判断标准：**
- 系统核心服务（SSH、HTTP/HTTPS、DNS等）- 允许但需限制访问
- 开发工具服务（数据库、缓存等）- 仅本地访问
- 未知或不必要的服务 - 立即关闭并调查
- 高风险端口（如远程桌面、文件共享等）- 严格限制

**输出格式要求：**
- 思考过程用 [THINK] 标签包围
- 执行的命令用 [EXEC] 标签包围
- 安全分析结果用 [ANALYSIS] 标签包围
- 最终安全配置结果用 [RESULT] 标签包围

**安全工作原则：**
- 每个操作都要考虑安全影响
- 优先保障系统安全性和稳定性
- 详细记录每个安全决策的理由
- 基于实际的系统状态进行安全判断
- 给自己的进程留下端口 保证自身可以正常连接

**权限**
如果需要sudo 密码为888999

**任务完成**
-配置完成以后输出[RESULT] 
-最终结果用 [RESULT] 标签包围

现在开始执行系统网络安全检查任务。"""

    def _call_deepseek_api(self, messages: List[Dict]) -> str:
        """调用DeepSeek API，带重试机制"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        data = {
            "model": "deepseek-chat",
            "messages": messages,
            "max_tokens": 4000,
            "temperature": 0.3
        }

        max_retries = 3
        retry_delays = [5, 10, 15]  # 重试延迟（秒）

        for attempt in range(max_retries + 1):  # 包括初始尝试
            try:
                if attempt > 0:
                    print(f"正在进行第 {attempt} 次重试...（等待 {retry_delays[attempt-1]} 秒）")
                    time.sleep(retry_delays[attempt-1])

                # 增加超时时间
                response = requests.post(
                    self.api_url,
                    headers=headers,
                    json=data,
                    timeout=60,  # 增加到60秒
                    verify=True  # 确保SSL验证
                )
                response.raise_for_status()

                result = response.json()["choices"][0]["message"]["content"]

                if attempt > 0:
                    print(f"第 {attempt} 次重试成功！")

                return result

            except requests.exceptions.Timeout as e:
                error_msg = f"API调用超时: {str(e)}"
                if attempt < max_retries:
                    print(f"警告: {error_msg}")
                    continue
                else:
                    print(f"错误: 所有重试均失败: {error_msg}")
                    return f"API调用错误: {error_msg}"

            except requests.exceptions.ConnectionError as e:
                error_msg = f"网络连接错误: {str(e)}"
                if attempt < max_retries:
                    print(f"警告: {error_msg}")
                    continue
                else:
                    print(f"错误: 所有重试均失败: {error_msg}")
                    return f"API调用错误: {error_msg}"

            except requests.exceptions.HTTPError as e:
                error_msg = f"HTTP错误: {e.response.status_code} - {str(e)}"
                if attempt < max_retries and e.response.status_code >= 500:
                    # 服务器错误可以重试
                    print(f"警告: {error_msg}")
                    continue
                else:
                    print(f"错误: HTTP错误，无法重试: {error_msg}")
                    return f"API调用错误: {error_msg}"

            except requests.exceptions.RequestException as e:
                error_msg = f"请求异常: {str(e)}"
                if attempt < max_retries:
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

    def _execute_linux_command(self, command: str) -> Tuple[str, int]:
        """在Linux中执行命令"""
        try:
            # 确保在Linux用户主目录中执行命令
            # 使用bash -c确保能正确处理复杂命令
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
            return f"执行错误: {str(e)}", 1

    def _parse_agent_response(self, response: str) -> Dict[str, List[str]]:
        """解析Agent响应，提取不同类型的内容"""
        parsed = {
            "think": [],
            "exec": [],
            "observe": [],
            "result": []
        }
        
        # 提取THINK内容
        think_pattern = r'\[THINK\](.*?)\[/THINK\]'
        parsed["think"] = re.findall(think_pattern, response, re.DOTALL)
        
        # 提取EXEC内容
        exec_pattern = r'\[EXEC\](.*?)\[/EXEC\]'
        parsed["exec"] = re.findall(exec_pattern, response, re.DOTALL)
        
        # 提取OBSERVE内容
        observe_pattern = r'\[OBSERVE\](.*?)\[/OBSERVE\]'
        parsed["observe"] = re.findall(observe_pattern, response, re.DOTALL)
        
        # 提取RESULT内容
        result_pattern = r'\[RESULT\](.*?)\[/RESULT\]'
        parsed["result"] = re.findall(result_pattern, response, re.DOTALL)
        
        return parsed

    def _format_output(self, content: str, tag_type: str) -> None:
        """格式化输出不同类型的内容"""
        colors = {
            "think": "\033[94m",    # 蓝色
            "exec": "\033[92m",     # 绿色
            "observe": "\033[93m",  # 黄色
            "result": "\033[95m",   # 紫色
            "error": "\033[91m"     # 红色
        }
        reset = "\033[0m"
        
        print(f"{colors.get(tag_type, '')}{tag_type.upper()}: {content.strip()}{reset}")

    def _check_linux_environment(self) -> bool:
        """检查Linux环境是否可用"""
        try:
            # 执行简单测试，确保在Linux用户主目录工作
            result = subprocess.run(
                ['bash', '-c', 'cd ~ && pwd && echo "Linux环境检查"'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )

            # 检查命令是否成功执行且包含预期输出
            success = (result.returncode == 0 and
                      "Linux环境检查" in result.stdout and
                      "/home/" in result.stdout)

            if not success:
                print(f"Linux检查失败 - 返回码: {result.returncode}")
                print(f"标准输出: {result.stdout}")
                print(f"错误输出: {result.stderr}")

            return success
        except Exception as e:
            print(f"Linux环境检查异常: {str(e)}")
            return False

    def run_task(self, user_task: str) -> None:
        """执行用户任务"""
        print("=" * 60)
        print("Basic Shell Agent 启动")
        print("=" * 60)

        # 检查Linux环境
        print("正在检查Linux环境...")
        if not self._check_linux_environment():
            print("错误: Linux环境不可用")
            print("请检查:")
            print("1. 系统是否正常运行")
            print("2. 是否有bash环境")
            print("3. 用户主目录是否可访问")
            return

        print("✓ Linux环境检查通过")

        # 获取上下文信息
        context_info = self.context_manager.get_context_info()
        print(f"对话记录: {context_info['total_conversations']} 条, "
              f"Token: {context_info['current_tokens']}/{context_info['context_limit']}")

        # 初始化对话上下文
        if context_info['should_start_new'] or context_info['total_conversations'] == 0:
            print("开始新的对话...")
            messages = self.context_manager.build_initial_context()
        else:
            print("继续之前的对话...")
            messages = self.context_manager.build_initial_context()

        # 添加用户任务到上下文
        messages = self.context_manager.add_user_message(
            context=messages,
            message=f"任务: {user_task}",
            save_record=True
        )
        
        max_iterations = 30  # 防止无限循环
        iteration = 0
        
        while iteration < max_iterations:
            iteration += 1
            print(f"\n--- 第 {iteration} 轮思考-执行-观察 ---")

            # 截断上下文以适应token限制
            messages = self.context_manager.truncate_context_if_needed(messages)

            # 获取AI响应
            ai_response = self._call_deepseek_api(messages)
            if "API调用错误" in ai_response:
                self._format_output(ai_response, "error")
                # 保存错误到对话记录
                self.context_manager.add_assistant_message(
                    context=messages,
                    message=ai_response,
                    save_record=True
                )
                break

            # 保存AI响应到对话记录
            messages = self.context_manager.add_assistant_message(
                context=messages,
                message=ai_response,
                save_record=True
            )

            # 解析响应
            parsed = self._parse_agent_response(ai_response)

            # 显示思考过程
            for think in parsed["think"]:
                self._format_output(think, "think")

            # 执行命令
            command_executed = False
            for exec_cmd in parsed["exec"]:
                command = exec_cmd.strip()
                if command:
                    self._format_output(f"执行命令: {command}", "exec")
                    output, return_code = self._execute_linux_command(command)

                    # 显示命令输出
                    if output:
                        print(f"命令输出:\n{output}")
                    else:
                        print("命令无输出")
                    print(f"返回码: {return_code}")

                    # 将执行结果添加到上下文和对话记录
                    messages = self.context_manager.add_command_execution_result(
                        context=messages,
                        command=command,
                        output=output,
                        return_code=return_code,
                        save_record=True
                    )
                    command_executed = True
                    break  # 一次只执行一个命令，等待AI基于结果思考下一步

            # 不再显示观察结果，因为AI不应该自己编造观察内容

            # 检查是否有最终结果
            if parsed["result"]:
                for result in parsed["result"]:
                    self._format_output(result, "result")
                print("\n任务完成!")
                # 保存最终结果到对话记录
                final_result = "\n".join(parsed["result"])
                self.context_manager.add_assistant_message(
                    context=messages,
                    message=f"[RESULT]\n{final_result}\n[/RESULT]",
                    save_record=True
                )
                break

            # 如果没有执行命令，可能任务已完成或需要更多信息
            if not command_executed:
                if "完成" in ai_response or "结束" in ai_response:
                    print("\n任务完成!")
                    break
                else:
                    # 询问是否需要更多信息
                    messages = self.context_manager.add_user_message(
                        context=messages,
                        message="请继续思考并执行下一步操作，或者如果任务已完成请用[RESULT]标签说明结果。",
                        save_record=True
                    )
        
        if iteration >= max_iterations:
            print(f"\n达到最大迭代次数 ({max_iterations})，任务可能未完全完成。")

def main():
    """主函数"""
    print("Basic Shell Agent")
    print("专注于Linux环境的思考-执行-观察循环")
    print("-" * 40)
    
    agent = BasicShellAgent()
    
    while True:
        try:
            user_input = input("\n请输入任务 (输入 'quit' 退出): ").strip()
            if user_input.lower() in ['quit', 'exit', '退出']:
                print("再见!")
                break
            
            if user_input:
                agent.run_task(user_input)
            
        except KeyboardInterrupt:
            print("\n\n程序被用户中断")
            break
        except Exception as e:
            print(f"发生错误: {str(e)}")

if __name__ == "__main__":
    main()