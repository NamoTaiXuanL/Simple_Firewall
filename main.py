#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
简易防火墙工具主程序
基于UFW的图形化防火墙管理工具
"""

import tkinter as tk
from tkinter import messagebox
import argparse
import os
import sys

def check_requirements():
    """检查运行环境"""
    # 检查是否为Linux系统
    if os.name != 'posix':
        messagebox.showerror("错误", "此工具仅支持Linux系统")
        return False

    # 检查UFW是否安装
    try:
        import subprocess
        result = subprocess.run(["which", "ufw"], capture_output=True)
        if result.returncode != 0:
            messagebox.showerror("错误", "未找到UFW防火墙，请先安装：\nsudo apt install ufw")
            return False
    except Exception:
        pass

    return True

def main():
    """主函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='简易防火墙工具')
    parser.add_argument('--debug', '-d', action='store_true', help='启用调试模式')
    parser.add_argument('--cli', action='store_true', help='使用命令行模式')
    args = parser.parse_args()

    # 命令行模式
    if args.cli:
        try:
            from firewall_cli import main as cli_main
            # 设置调试参数
            if args.debug:
                sys.argv = ['firewall_cli.py', '--debug']
            else:
                sys.argv = ['firewall_cli.py']
            cli_main()
        except ImportError as e:
            print(f"导入CLI模块失败：{e}")
        except Exception as e:
            print(f"CLI运行错误：{e}")
        return

    # 图形界面模式
    if not check_requirements():
        return

    try:
        from firewall_gui import FirewallGUI

        root = tk.Tk()
        app = FirewallGUI(root, debug=args.debug)

        # 居中窗口
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f'{width}x{height}+{x}+{y}')

        if args.debug:
            print("调试模式已启用，界面中将显示详细的调试信息")

        root.mainloop()

    except ImportError as e:
        messagebox.showerror("错误", f"导入模块失败：{e}")
    except Exception as e:
        messagebox.showerror("错误", f"程序运行错误：{e}")

if __name__ == "__main__":
    main()