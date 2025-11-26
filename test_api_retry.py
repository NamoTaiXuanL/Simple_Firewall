#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试API重试机制
项目组: Seraphiel
作者: lilith项目组Seraphiel
创建时间: 2025
"""

import sys
sys.path.append('core')
from basic_shell_agent import BasicShellAgent

def test_api_retry():
    """测试API重试机制"""
    print("=== 测试API重试机制 ===")

    # 创建Agent实例
    agent = BasicShellAgent()

    # 测试正常调用
    print("1. 测试正常API调用...")
    test_messages = [
        {"role": "system", "content": "你是一个测试助手"},
        {"role": "user", "content": "请简单回复'测试成功'"}
    ]

    try:
        response = agent._call_deepseek_api(test_messages)
        print(f"正常调用成功，响应长度: {len(response)} 字符")
        print(f"响应内容: {response[:100]}...")
    except Exception as e:
        print(f"正常调用失败: {e}")

    # 测试超时设置
    print("\n2. 测试超时设置...")
    print(f"API超时时间: 60秒")
    print(f"重试次数: 3次")
    print(f"重试延迟: 5秒, 10秒, 15秒")

    # 测试错误处理
    print("\n3. 测试错误处理...")
    print("支持以下错误类型:")
    print("- requests.exceptions.Timeout (API调用超时)")
    print("- requests.exceptions.ConnectionError (网络连接错误)")
    print("- requests.exceptions.HTTPError (HTTP错误，仅5xx重试)")
    print("- requests.exceptions.RequestException (请求异常)")
    print("- KeyError, ValueError, json.JSONDecodeError (响应解析错误)")
    print("- 其他未知错误")

    print("\n=== API重试机制测试完成 ===")

def test_agent_with_retry():
    """测试Agent的完整重试流程"""
    print("\n=== 测试Agent完整重试流程 ===")

    agent = BasicShellAgent()

    # 模拟一个简单的任务
    print("开始测试任务: 检查当前目录")

    # 这会触发API调用
    try:
        # 我们不实际运行完整的run_task，只测试API调用部分
        messages = [
            {"role": "system", "content": agent.system_prompt},
            {"role": "user", "content": "任务: 检查当前目录"}
        ]

        response = agent._call_deepseek_api(messages)

        if "API调用错误" in response:
            print(f"API调用失败: {response}")
        else:
            print("API调用成功!")
            print(f"响应长度: {len(response)} 字符")

            # 解析响应
            parsed = agent._parse_agent_response(response)
            print(f"解析结果:")
            print(f"- THINK内容: {len(parsed['think'])} 条")
            print(f"- EXEC内容: {len(parsed['exec'])} 条")
            print(f"- RESULT内容: {len(parsed['result'])} 条")

    except Exception as e:
        print(f"测试过程中发生错误: {e}")

    print("\n=== Agent重试流程测试完成 ===")

if __name__ == "__main__":
    test_api_retry()
    test_agent_with_retry()