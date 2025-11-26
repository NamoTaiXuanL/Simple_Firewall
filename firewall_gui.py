#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from ufw_manager import UFWManager

class FirewallGUI:
    """简易防火墙图形界面"""

    def __init__(self, root, debug=False):
        self.root = root
        self.debug = debug
        self.ufw = UFWManager(debug=debug)

        # 设置窗口
        self.root.title(f"简易防火墙管理工具{' - 调试模式' if debug else ''}")
        self.root.geometry("900x700" if debug else "800x600")
        self.root.resizable(True, True)

        # 创建主框架
        self.create_widgets()

        # 初始加载状态
        self.refresh_status()

        if debug:
            self.log_debug("防火墙图形界面初始化完成")

    def log_debug(self, message):
        """记录调试信息到界面"""
        if self.debug and hasattr(self, 'debug_text'):
            import datetime
            timestamp = datetime.datetime.now().strftime('%H:%M:%S')
            debug_msg = f"[{timestamp}] {message}\n"
            self.root.after(0, lambda: self._append_debug(debug_msg))

    def _append_debug(self, message):
        """在调试文本框中追加信息"""
        if hasattr(self, 'debug_text'):
            self.debug_text.insert(tk.END, message)
            self.debug_text.see(tk.END)

            # 限制调试信息长度，避免内存占用过多
            lines = int(self.debug_text.index('end-1c').split('.')[0])
            if lines > 1000:
                self.debug_text.delete('1.0', '100.0')

    def create_widgets(self):
        """创建界面组件"""

        # 主容器 - 使用pack布局
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 配置网格权重
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4 if self.debug else 3, weight=1)

        # 状态区域
        self.create_status_section(main_frame)

        # 快速操作区域
        self.create_quick_actions_section(main_frame)

        # 规则管理区域
        self.create_rules_section(main_frame)

        # 日志区域
        self.create_log_section(main_frame)

        # 调试信息区域（仅在调试模式下显示）
        if self.debug:
            self.create_debug_section(main_frame)

    def create_status_section(self, parent):
        """创建状态显示区域"""
        status_frame = ttk.LabelFrame(parent, text="防火墙状态", padding="10")
        status_frame.pack(fill=tk.X, pady=(0, 10))

        self.status_label = ttk.Label(status_frame, text="状态：检查中...", font=("Arial", 12))
        self.status_label.pack(anchor=tk.W)

        self.logging_label = ttk.Label(status_frame, text="日志：检查中...")
        self.logging_label.pack(anchor=tk.W)

    def create_quick_actions_section(self, parent):
        """创建快速操作区域"""
        actions_frame = ttk.LabelFrame(parent, text="快速操作", padding="10")
        actions_frame.pack(fill=tk.X, pady=(0, 10))

        # 第一行按钮
        btn_frame1 = ttk.Frame(actions_frame)
        btn_frame1.pack(fill=tk.X, pady=(0, 5))

        self.enable_btn = ttk.Button(btn_frame1, text="启用防火墙", command=self.enable_firewall)
        self.enable_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.disable_btn = ttk.Button(btn_frame1, text="禁用防火墙", command=self.disable_firewall)
        self.disable_btn.pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(btn_frame1, text="刷新状态", command=self.refresh_status).pack(side=tk.LEFT)

        # 第二行按钮 - 预设配置
        btn_frame2 = ttk.Frame(actions_frame)
        btn_frame2.pack(fill=tk.X)

        ttk.Label(btn_frame2, text="预设配置：").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame2, text="高安全", command=lambda: self.apply_preset("high")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame2, text="中等安全", command=lambda: self.apply_preset("medium")).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame2, text="低安全", command=lambda: self.apply_preset("low")).pack(side=tk.LEFT)

    def create_rules_section(self, parent):
        """创建规则管理区域"""
        rules_frame = ttk.LabelFrame(parent, text="规则管理", padding="10")
        rules_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # 添加规则区域
        add_frame = ttk.Frame(rules_frame)
        add_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(add_frame, text="添加规则：").pack(side=tk.LEFT, padx=(0, 5))
        self.rule_entry = ttk.Entry(add_frame, width=40)
        self.rule_entry.pack(side=tk.LEFT, padx=(0, 5), fill=tk.X, expand=True)
        self.rule_entry.insert(0, "allow 22/tcp")

        ttk.Button(add_frame, text="添加", command=self.add_rule).pack(side=tk.LEFT)

        # 规则列表
        self.rules_tree = ttk.Treeview(rules_frame, columns=("rule",), show="headings", height=8)
        self.rules_tree.heading("rule", text="规则")
        self.rules_tree.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # 规则操作按钮
        rules_btn_frame = ttk.Frame(rules_frame)
        rules_btn_frame.pack(fill=tk.X)

        ttk.Button(rules_btn_frame, text="删除选中", command=self.delete_selected_rule).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(rules_btn_frame, text="刷新规则", command=self.refresh_rules).pack(side=tk.LEFT)

    def create_log_section(self, parent):
        """创建日志显示区域"""
        log_frame = ttk.LabelFrame(parent, text="防火墙日志", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=8 if self.debug else 10, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        ttk.Button(log_frame, text="刷新日志", command=self.refresh_logs).pack(anchor=tk.W)

    def create_debug_section(self, parent):
        """创建调试信息显示区域"""
        debug_frame = ttk.LabelFrame(parent, text="调试信息", padding="10")
        debug_frame.pack(fill=tk.BOTH, expand=True)

        # 调试控制按钮
        debug_btn_frame = ttk.Frame(debug_frame)
        debug_btn_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(debug_btn_frame, text="清空调试信息", command=self.clear_debug).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(debug_btn_frame, text="保存调试日志", command=self.save_debug_log).pack(side=tk.LEFT)

        # 调试信息文本框
        self.debug_text = scrolledtext.ScrolledText(debug_frame, height=8, wrap=tk.WORD)
        self.debug_text.pack(fill=tk.BOTH, expand=True)

        # 设置字体为等宽字体，便于查看调试信息
        import tkinter.font as tkFont
        mono_font = tkFont.Font(family="Courier New", size=9)
        self.debug_text.configure(font=mono_font)

        self.log_debug("调试面板初始化完成")

    def clear_debug(self):
        """清空调试信息"""
        if hasattr(self, 'debug_text'):
            self.debug_text.delete(1.0, tk.END)
            self.log_debug("调试信息已清空")

    def save_debug_log(self):
        """保存调试日志到文件"""
        try:
            import datetime
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'AGENTS/gui_debug_{timestamp}.log'

            if hasattr(self, 'debug_text'):
                content = self.debug_text.get(1.0, tk.END)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)

                messagebox.showinfo("成功", f"调试日志已保存到: {filename}")
                self.log_debug(f"调试日志已保存到: {filename}")
        except Exception as e:
            messagebox.showerror("错误", f"保存调试日志失败: {e}")
            self.log_debug(f"保存调试日志失败: {e}")

    def refresh_status(self):
        """刷新防火墙状态"""
        self.log_debug("开始刷新防火墙状态")

        def update():
            self.log_debug("执行状态获取操作")
            status = self.ufw.get_status()

            if "error" in status:
                self.log_debug(f"状态获取失败: {status['error']}")
                self.root.after(0, lambda: self.status_label.config(text=f"错误：{status['error']}", foreground="red"))
            else:
                self.log_debug(f"状态获取成功: active={status.get('active', False)}, logging={status.get('logging', False)}")
                self.root.after(0, lambda: self._update_status_display(status))

            self.root.after(0, self.refresh_rules)

        threading.Thread(target=update, daemon=True).start()

    def _update_status_display(self, status):
        """更新状态显示"""
        try:
            if status.get("active", False):
                self.status_label.config(text="状态：已启用", foreground="green")
                self.enable_btn.config(state="disabled")
                self.disable_btn.config(state="normal")
                self.log_debug("状态显示更新为: 已启用")
            else:
                self.status_label.config(text="状态：已禁用", foreground="orange")
                self.enable_btn.config(state="normal")
                self.disable_btn.config(state="disabled")
                self.log_debug("状态显示更新为: 已禁用")

            logging_status = "已启用" if status.get("logging", False) else "已禁用"
            self.logging_label.config(text=f"日志：{logging_status}")
            self.log_debug(f"日志状态显示更新为: {logging_status}")
        except Exception as e:
            self.log_debug(f"状态显示更新失败: {e}")

    def enable_firewall(self):
        """启用防火墙"""
        def worker():
            success, output = self.ufw.enable_firewall()
            self.root.after(0, lambda: self.show_result("启用防火墙", success, output))
            if success:
                self.root.after(0, self.refresh_status)

        threading.Thread(target=worker, daemon=True).start()

    def disable_firewall(self):
        """禁用防火墙"""
        def worker():
            success, output = self.ufw.disable_firewall()
            self.root.after(0, lambda: self.show_result("禁用防火墙", success, output))
            if success:
                self.root.after(0, self.refresh_status)

        threading.Thread(target=worker, daemon=True).start()

    def add_rule(self):
        """添加规则"""
        rule = self.rule_entry.get().strip()
        if not rule:
            messagebox.showwarning("警告", "请输入规则")
            return

        def worker():
            success, output = self.ufw.add_rule(rule)
            self.root.after(0, lambda: self.show_result(f"添加规则：{rule}", success, output))
            if success:
                self.root.after(0, self.refresh_rules)
                self.root.after(0, lambda: self.rule_entry.delete(0, tk.END))

        threading.Thread(target=worker, daemon=True).start()

    def refresh_rules(self):
        """刷新规则列表"""
        def update():
            rules = self.ufw.get_rules_with_numbers()

            # 清空现有项目
            for item in self.rules_tree.get_children():
                self.rules_tree.delete(item)

            # 添加新项目
            for rule in rules:
                self.rules_tree.insert("", "end", iid=rule["number"],
                                     values=(f"[{rule['number']}] {rule['content']}",))

        threading.Thread(target=update, daemon=True).start()

    def delete_selected_rule(self):
        """删除选中的规则"""
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("警告", "请选择要删除的规则")
            return

        rule_num = selected[0]

        def worker():
            success, output = self.ufw.delete_rule(int(rule_num))
            self.root.after(0, lambda: self.show_result(f"删除规则 #{rule_num}", success, output))
            if success:
                self.root.after(0, self.refresh_rules)

        threading.Thread(target=worker, daemon=True).start()

    def apply_preset(self, level):
        """应用预设配置"""
        presets = {
            "high": [
                "default deny incoming",
                "allow out to any",
                "allow in from 127.0.0.1"
            ],
            "medium": [
                "default deny incoming",
                "default allow outgoing",
                "allow 22/tcp",
                "allow 80/tcp",
                "allow 443/tcp"
            ],
            "low": [
                "default allow incoming",
                "default allow outgoing"
            ]
        }

        rules = presets.get(level, [])

        def worker():
            # 先重置防火墙
            self.ufw.reset_firewall()

            # 应用预设规则
            for rule in rules:
                success, output = self.ufw.add_rule(rule)
                if not success:
                    self.root.after(0, lambda: self.show_result(f"应用预设失败：{rule}", False, output))
                    return

            self.root.after(0, lambda: messagebox.showinfo("成功", f"已应用{level}安全预设"))
            self.root.after(0, self.refresh_status)
            self.root.after(0, self.refresh_rules)

        threading.Thread(target=worker, daemon=True).start()

    def refresh_logs(self):
        """刷新日志"""
        def update():
            logs = self.ufw.get_log_entries(50)

            self.log_text.delete(1.0, tk.END)
            if logs:
                for log in logs:
                    if log.strip():
                        self.log_text.insert(tk.END, log + "\n")
            else:
                self.log_text.insert(tk.END, "暂无日志记录\n")

        threading.Thread(target=update, daemon=True).start()

    def show_result(self, operation, success, output):
        """显示操作结果"""
        if success:
            messagebox.showinfo("成功", f"{operation}成功")
        else:
            messagebox.showerror("错误", f"{operation}失败\n{output}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()