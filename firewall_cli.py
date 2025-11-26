#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
防火墙命令行工具
支持详细调试输出
"""

import argparse
import sys
from ufw_manager import UFWManager

class FirewallCLI:
    """防火墙命令行界面"""

    def __init__(self, debug=False):
        self.debug = debug
        self.ufw = UFWManager(debug=debug)

        if debug:
            print("=== 防火墙命令行工具 - 调试模式 ===")
            self.log_debug("CLI初始化完成")

    def log_debug(self, message):
        """输出调试信息"""
        if self.debug:
            print(f"[DEBUG] {message}")

    def log_info(self, message):
        """输出信息"""
        print(f"[INFO] {message}")

    def log_error(self, message):
        """输出错误信息"""
        print(f"[ERROR] {message}")

    def show_status(self):
        """显示防火墙状态"""
        self.log_info("获取防火墙状态...")
        status = self.ufw.get_status()

        if "error" in status:
            self.log_error(f"获取状态失败: {status['error']}")
            return False

        print("\n=== 防火墙状态 ===")
        print(f"状态: {'已启用' if status['active'] else '已禁用'}")
        print(f"日志: {'已启用' if status['logging'] else '已禁用'}")

        print("\n=== 规则列表 ===")
        if status['rules']:
            for i, rule in enumerate(status['rules'], 1):
                print(f"{i:2d}. {rule}")
        else:
            print("暂无规则")

        print(f"\n规则总数: {len(status['rules'])}")
        self.log_debug("状态显示完成")
        return True

    def enable_firewall(self):
        """启用防火墙"""
        self.log_info("正在启用防火墙...")
        success, output = self.ufw.enable_firewall()

        if success:
            self.log_info("防火墙启用成功")
            if output:
                print(f"输出: {output}")
        else:
            self.log_error(f"防火墙启用失败: {output}")

        return success

    def disable_firewall(self):
        """禁用防火墙"""
        self.log_info("正在禁用防火墙...")
        success, output = self.ufw.disable_firewall()

        if success:
            self.log_info("防火墙禁用成功")
            if output:
                print(f"输出: {output}")
        else:
            self.log_error(f"防火墙禁用失败: {output}")

        return success

    def add_rule(self, rule):
        """添加规则"""
        self.log_info(f"正在添加规则: {rule}")
        success, output = self.ufw.add_rule(rule)

        if success:
            self.log_info(f"规则添加成功: {rule}")
            if output:
                print(f"输出: {output}")
        else:
            self.log_error(f"规则添加失败: {rule} - {output}")

        return success

    def delete_rule(self, rule_num):
        """删除规则"""
        self.log_info(f"正在删除规则 #{rule_num}")
        success, output = self.ufw.delete_rule(int(rule_num))

        if success:
            self.log_info(f"规则删除成功: #{rule_num}")
            if output:
                print(f"输出: {output}")
        else:
            self.log_error(f"规则删除失败: #{rule_num} - {output}")

        return success

    def show_rules(self):
        """显示规则列表"""
        self.log_info("获取规则列表...")
        rules = self.ufw.get_rules_with_numbers()

        print("\n=== 规则列表 ===")
        if rules:
            for rule in rules:
                print(f"[{rule['number']}] {rule['content']}")
        else:
            print("暂无规则")

        print(f"\n规则总数: {len(rules)}")
        self.log_debug("规则列表显示完成")
        return rules

    def show_logs(self, lines=50):
        """显示日志"""
        self.log_info(f"获取最近 {lines} 条日志...")
        logs = self.ufw.get_log_entries(lines)

        print(f"\n=== 最近 {lines} 条防火墙日志 ===")
        if logs:
            for i, log in enumerate(logs, 1):
                if log.strip():
                    print(f"{i:3d}. {log}")
        else:
            print("暂无日志记录")

        self.log_debug(f"日志显示完成，共 {len(logs)} 条")
        return logs

    def test_ufw_connection(self):
        """测试UFW连接"""
        self.log_info("测试UFW连接...")

        # 测试基本命令
        success, output = self.ufw.run_command("ufw --version")
        if success:
            self.log_info("UFW连接测试成功")
            print(f"UFW版本信息:\n{output}")
            return True
        else:
            self.log_error("UFW连接测试失败")
            print(f"错误信息: {output}")
            return False

    def reset_firewall(self):
        """重置防火墙"""
        self.log_info("警告：即将重置防火墙，所有规则将被删除")

        confirm = input("确认重置防火墙？(y/N): ").strip().lower()
        if confirm != 'y':
            self.log_info("用户取消重置操作")
            return False

        self.log_info("正在重置防火墙...")
        success, output = self.ufw.reset_firewall()

        if success:
            self.log_info("防火墙重置成功")
            if output:
                print(f"输出: {output}")
        else:
            self.log_error(f"防火墙重置失败: {output}")

        return success

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='防火墙命令行工具')
    parser.add_argument('--debug', '-d', action='store_true', help='启用调试模式')

    subparsers = parser.add_subparsers(dest='command', help='可用命令')

    # 状态命令
    subparsers.add_parser('status', help='显示防火墙状态')

    # 启用/禁用命令
    subparsers.add_parser('enable', help='启用防火墙')
    subparsers.add_parser('disable', help='禁用防火墙')

    # 规则命令
    rule_parser = subparsers.add_parser('add-rule', help='添加规则')
    rule_parser.add_argument('rule', help='规则内容，例如: allow 22/tcp')

    delete_parser = subparsers.add_parser('delete-rule', help='删除规则')
    delete_parser.add_argument('number', type=int, help='规则编号')

    subparsers.add_parser('list-rules', help='列出所有规则')

    # 日志命令
    log_parser = subparsers.add_parser('logs', help='显示防火墙日志')
    log_parser.add_argument('--lines', '-n', type=int, default=50, help='显示的日志行数')

    # 测试命令
    subparsers.add_parser('test', help='测试UFW连接')

    # 重置命令
    subparsers.add_parser('reset', help='重置防火墙（慎用）')

    args = parser.parse_args()

    # 创建CLI实例
    cli = FirewallCLI(debug=args.debug)

    # 执行相应命令
    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == 'status':
            cli.show_status()
        elif args.command == 'enable':
            cli.enable_firewall()
        elif args.command == 'disable':
            cli.disable_firewall()
        elif args.command == 'add-rule':
            cli.add_rule(args.rule)
        elif args.command == 'delete-rule':
            cli.delete_rule(args.number)
        elif args.command == 'list-rules':
            cli.show_rules()
        elif args.command == 'logs':
            cli.show_logs(args.lines)
        elif args.command == 'test':
            cli.test_ufw_connection()
        elif args.command == 'reset':
            cli.reset_firewall()
        else:
            print(f"未知命令: {args.command}")
            parser.print_help()

    except KeyboardInterrupt:
        print("\n操作被用户中断")
    except Exception as e:
        print(f"执行命令时发生错误: {e}")

if __name__ == "__main__":
    main()