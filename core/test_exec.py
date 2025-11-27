#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试EXEC模块功能
"""

from basic_shell_agent import BasicShellAgent

def test_exec_integration():
    """测试EXEC模块与agent的集成"""
    print("=" * 50)
    print("测试EXEC模块与BasicShellAgent集成")
    print("=" * 50)

    # 创建agent实例
    agent = BasicShellAgent()

    # 测试简单命令
    print("\n1. 测试简单命令执行...")
    agent.run_task("显示当前日期和系统信息")

    print("\n2. 测试网络相关命令...")
    agent.run_task("检查当前监听的端口")

    print("\n3. 测试文件操作命令...")
    agent.run_task("列出当前目录的文件")

if __name__ == "__main__":
    test_exec_integration()