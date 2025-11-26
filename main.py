#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
简易防火墙工具主程序
基于UFW的图形化防火墙管理工具
"""

import tkinter as tk
from tkinter import messagebox
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
    print("[MAIN] 启动防火墙管理工具")

    # 检查命令行参数中的密码
    sudo_password = None
    if len(sys.argv) > 1:
        if sys.argv[1] == "--password" and len(sys.argv) > 2:
            sudo_password = sys.argv[2]
            print("[MAIN] 从命令行获取sudo密码")

    if not check_requirements():
        return

    try:
        from firewall_gui import FirewallGUI

        root = tk.Tk()
        app = FirewallGUI(root, sudo_password)

        # 居中窗口
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f'{width}x{height}+{x}+{y}')

        print("[MAIN] 图形界面已启动")
        root.mainloop()

    except ImportError as e:
        print(f"[ERROR] 导入模块失败：{e}")
        messagebox.showerror("错误", f"导入模块失败：{e}")
    except Exception as e:
        print(f"[ERROR] 程序运行错误：{e}")
        messagebox.showerror("错误", f"程序运行错误：{e}")

if __name__ == "__main__":
    main()