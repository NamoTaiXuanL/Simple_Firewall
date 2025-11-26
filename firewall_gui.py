#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from ufw_manager import UFWManager

class FirewallGUI:
    """简易防火墙图形界面"""

    def __init__(self, root, sudo_password=None):
        self.root = root
        self.ufw = UFWManager()

        # 设置窗口
        self.root.title("简易防火墙管理工具")
        self.root.geometry("800x600")
        self.root.resizable(True, True)

        print("[GUI] 防火墙界面初始化")

        # 获取sudo密码
        if sudo_password:
            print("[GUI] 使用命令行提供的密码")
            self.ufw.set_sudo_password(sudo_password)
        else:
            if not self.get_sudo_password():
                return

        # 创建主框架
        self.create_widgets()

        # 初始加载状态
        self.refresh_status()

    def get_sudo_password(self):
        """获取sudo密码"""
        password_dialog = PasswordDialog(self.root)
        password = password_dialog.get_password()

        if password:
            self.ufw.set_sudo_password(password)
            print("[GUI] sudo密码已设置")
            return True
        else:
            print("[GUI] 用户取消密码输入，程序退出")
            self.root.destroy()
            return False

    def create_widgets(self):
        """创建界面组件"""

        # 主容器 - 使用pack布局
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 状态区域
        self.create_status_section(main_frame)

        # 快速操作区域
        self.create_quick_actions_section(main_frame)

        # 规则管理区域
        self.create_rules_section(main_frame)

        # 日志区域
        self.create_log_section(main_frame)

        # 程序豁免区域
        self.create_program_exemption_section(main_frame)

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

        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        ttk.Button(log_frame, text="刷新日志", command=self.refresh_logs).pack(anchor=tk.W)

    def create_program_exemption_section(self, parent):
        """创建程序豁免区域"""
        program_frame = ttk.LabelFrame(parent, text="程序豁免管理", padding="10")
        program_frame.pack(fill=tk.BOTH, expand=True)

        # 控制按钮
        btn_frame = ttk.Frame(program_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(btn_frame, text="获取活动程序", command=self.load_programs).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="允许选中程序", command=self.allow_selected_programs).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(btn_frame, text="刷新", command=self.load_programs).pack(side=tk.LEFT)

        # 程序列表
        columns = ('name', 'pid', 'port', 'protocol', 'address')
        self.programs_tree = ttk.Treeview(program_frame, columns=columns, show='headings', height=10)

        # 设置列标题
        self.programs_tree.heading('name', text='程序名称')
        self.programs_tree.heading('pid', text='PID')
        self.programs_tree.heading('port', text='端口')
        self.programs_tree.heading('protocol', text='协议')
        self.programs_tree.heading('address', text='监听地址')

        # 设置列宽
        self.programs_tree.column('name', width=200)
        self.programs_tree.column('pid', width=80)
        self.programs_tree.column('port', width=80)
        self.programs_tree.column('protocol', width=80)
        self.programs_tree.column('address', width=200)

        self.programs_tree.pack(fill=tk.BOTH, expand=True)

        # 启用多选
        self.programs_tree.configure(selectmode='extended')

        # 初始加载
        self.load_programs()

    def load_programs(self):
        """加载程序列表"""
        print("[GUI] 开始加载程序列表")

        def worker():
            try:
                print("[GUI] 正在获取活动程序...")
                programs = self.ufw.get_all_listening_programs()

                def update_ui():
                    # 清空现有项目
                    for item in self.programs_tree.get_children():
                        self.programs_tree.delete(item)

                    # 添加程序项目
                    for prog in programs:
                        self.programs_tree.insert("", "end", values=(
                            prog['name'],
                            prog['pid'],
                            prog['port'],
                            prog['protocol'],
                            prog['address']
                        ))

                    print(f"[GUI] 已加载 {len(programs)} 个程序")

                self.root.after(0, update_ui)

            except Exception as e:
                print(f"[GUI] 加载程序列表失败: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def allow_selected_programs(self):
        """允许选中的程序通过防火墙"""
        selected = self.programs_tree.selection()
        if not selected:
            messagebox.showwarning("警告", "请选择要豁免的程序")
            return

        # 获取选中程序的端口信息
        ports_to_allow = []
        for item in selected:
            values = self.programs_tree.item(item, 'values')
            if len(values) >= 4:
                program_name = values[0]
                port = values[2]
                protocol = values[3]
                ports_to_allow.append((program_name, port, protocol))

        def worker():
            success_count = 0
            total_count = len(ports_to_allow)

            for program_name, port, protocol in ports_to_allow:
                try:
                    print(f"[GUI] 允许程序 {program_name} 端口 {port}/{protocol}")
                    success, output = self.ufw.allow_program_by_port(port, protocol)
                    if success:
                        success_count += 1
                    else:
                        print(f"[GUI] 允许端口失败: {output}")
                except Exception as e:
                    print(f"[GUI] 允许程序端口异常: {e}")

            def update_ui():
                if success_count > 0:
                    messagebox.showinfo("成功", f"已为 {success_count}/{total_count} 个程序添加防火墙豁免")
                    print(f"[GUI] 成功为 {success_count}/{total_count} 个程序添加豁免")
                    self.refresh_status()
                    self.refresh_rules()
                else:
                    messagebox.showerror("失败", "添加防火墙豁免失败")

            self.root.after(0, update_ui)

        threading.Thread(target=worker, daemon=True).start()

    def refresh_status(self):
        """刷新防火墙状态"""
        print("[GUI] 开始刷新防火墙状态")

        def update():
            try:
                print("[GUI] 正在获取防火墙状态...")
                status = self.ufw.get_status()

                def update_ui():
                    try:
                        if "error" in status:
                            self.status_label.config(text=f"错误：{status['error']}", foreground="red")
                            print(f"[GUI] 状态获取失败: {status['error']}")
                        else:
                            print(f"[GUI] 状态获取成功: {status}")
                            if status.get('active', False):
                                self.status_label.config(text="状态：已启用", foreground="green")
                                self.enable_btn.config(state="disabled")
                                self.disable_btn.config(state="normal")
                                print("[GUI] 状态显示: 已启用")
                            else:
                                self.status_label.config(text="状态：已禁用", foreground="orange")
                                self.enable_btn.config(state="normal")
                                self.disable_btn.config(state="disabled")
                                print("[GUI] 状态显示: 已禁用")

                            logging_status = "已启用" if status.get('logging', False) else "已禁用"
                            self.logging_label.config(text=f"日志：{logging_status}")

                        self.refresh_rules()
                    except Exception as e:
                        print(f"[GUI] 界面更新失败: {e}")

                self.root.after(0, update_ui)

            except Exception as e:
                print(f"[GUI] 状态刷新失败: {e}")

        threading.Thread(target=update, daemon=True).start()

    def enable_firewall(self):
        """启用防火墙"""
        print("[GUI] 用户点击启用防火墙")

        def worker():
            try:
                print("[GUI] 正在启用防火墙...")
                success, output = self.ufw.enable_firewall()

                def update_ui():
                    if success:
                        messagebox.showinfo("成功", "防火墙启用成功")
                        print("[GUI] 防火墙启用成功")
                        self.refresh_status()
                    else:
                        messagebox.showerror("错误", f"防火墙启用失败\n{output}")
                        print(f"[GUI] 防火墙启用失败: {output}")

                self.root.after(0, update_ui)

            except Exception as e:
                print(f"[GUI] 启用防火墙异常: {e}")
                self.root.after(0, lambda: messagebox.showerror("错误", f"启用防火墙时发生异常: {e}"))

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

class PasswordDialog:
    """密码输入对话框"""

    def __init__(self, parent):
        self.password = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("需要管理员权限")
        self.dialog.geometry("400x200")
        self.dialog.resizable(False, False)

        # 模态对话框
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # 居中显示
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (self.dialog.winfo_width() // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")

        self.create_widgets()

        # 绑定Enter键
        self.dialog.bind('<Return>', lambda e: self.ok_button_clicked())
        self.dialog.bind('<Escape>', lambda e: self.cancel_button_clicked())

        # 等待对话框关闭
        self.dialog.wait_window()

    def create_widgets(self):
        """创建界面组件"""
        # 说明文字
        label = ttk.Label(self.dialog, text="防火墙管理需要管理员权限\n请输入sudo密码：",
                         font=("Arial", 12), justify="center")
        label.pack(pady=20)

        # 密码输入框
        password_frame = ttk.Frame(self.dialog)
        password_frame.pack(pady=10)

        ttk.Label(password_frame, text="密码：").pack(side=tk.LEFT, padx=(0, 10))
        self.password_entry = ttk.Entry(password_frame, show="*", width=20, font=("Arial", 12))
        self.password_entry.pack(side=tk.LEFT)

        # 焦点设置到密码框
        self.password_entry.focus()

        # 按钮区域
        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(pady=20)

        self.ok_button = ttk.Button(button_frame, text="确定", command=self.ok_button_clicked)
        self.ok_button.pack(side=tk.LEFT, padx=(0, 10))

        self.cancel_button = ttk.Button(button_frame, text="取消", command=self.cancel_button_clicked)
        self.cancel_button.pack(side=tk.LEFT)

    def ok_button_clicked(self):
        """确定按钮点击"""
        password = self.password_entry.get().strip()
        if password:
            self.password = password
            print("[GUI] 用户输入了密码")
        else:
            messagebox.showwarning("警告", "请输入密码")
            return

        self.dialog.destroy()

    def cancel_button_clicked(self):
        """取消按钮点击"""
        print("[GUI] 用户取消输入密码")
        self.dialog.destroy()

    def get_password(self):
        """获取密码"""
        return self.password

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    if hasattr(app, 'ufw'):  # 检查程序是否正常初始化
        root.mainloop()