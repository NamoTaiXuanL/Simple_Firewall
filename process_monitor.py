#!/usr/bin/env python3
# 项目名称：Task Process Manager
# 作者：Mamoniel 项目组
# 日期：2025-11-27
# 版本：1.1
# 描述：Linux系统进程监控工具，类似Windows任务管理器，支持两种CPU计算方式

import psutil
import time
import os
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
import threading

class ProcessMonitor:
    def __init__(self):
        self.processes = []
        self.is_running = False
        self.refresh_interval = 2000  # 2秒刷新间隔
        self.use_relative_cpu = True  # 默认使用相对CPU计算方式（当前100%基准）

    def get_process_info(self):
        """获取所有进程信息"""
        processes = []

        try:
            # 获取所有进程
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'status']):
                try:
                    # 获取进程基本信息
                    pinfo = proc.info

                    # 使用interval=0来避免阻塞，但可能需要一些时间才能获得准确值
                    cpu_percent = proc.cpu_percent(interval=0)

                    # 如果是第一次调用，CPU使用率可能为0，这是正常的
                    if cpu_percent < 0:
                        cpu_percent = 0.0

                    memory_info = proc.memory_info()
                    memory_mb = memory_info.rss / 1024 / 1024  # 转换为MB

                    # 获取进程创建时间
                    create_time = datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S')

                    process_data = {
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'cpu_percent': round(cpu_percent, 1),
                        'memory_mb': round(memory_mb, 1),
                        'memory_percent': round(pinfo['memory_percent'], 1),
                        'status': pinfo['status'],
                        'create_time': create_time
                    }
                    processes.append(process_data)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        except Exception as e:
            print(f"获取进程信息时出错: {e}")

        return processes

    def get_system_cpu_info(self):
        """获取系统总CPU使用率（用于传统计算方式）"""
        try:
            return psutil.cpu_percent(interval=0)
        except:
            return 0.0

    def get_process_info_with_delay(self, delay=0.1):
        """获取所有进程信息（带延迟以获得准确的CPU使用率）"""
        processes = []

        try:
            # 第一次调用建立基准
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'status']):
                try:
                    # 第一次调用建立基准
                    proc.cpu_percent(interval=0)
                except:
                    continue

            # 等待一段时间
            time.sleep(delay)

            # 获取系统总CPU使用率（用于传统计算方式）
            system_cpu_percent = self.get_system_cpu_info()

            # 第二次调用获取实际值
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'status']):
                try:
                    pinfo = proc.info
                    raw_cpu_percent = proc.cpu_percent(interval=0)

                    # 根据选择的计算方式处理CPU使用率
                    if self.use_relative_cpu:
                        # 相对CPU计算方式（当前方式）：基于100%的活跃CPU计算
                        cpu_percent = raw_cpu_percent
                    else:
                        # 传统CPU计算方式：基于系统总CPU计算
                        # 如果系统CPU使用率很低，进程CPU使用率也会相应较低
                        if system_cpu_percent > 0:
                            cpu_percent = (raw_cpu_percent * system_cpu_percent) / 100
                        else:
                            cpu_percent = raw_cpu_percent

                    memory_info = proc.memory_info()
                    memory_mb = memory_info.rss / 1024 / 1024

                    create_time = datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S')

                    process_data = {
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'cpu_percent': round(cpu_percent, 1),
                        'memory_mb': round(memory_mb, 1),
                        'memory_percent': round(pinfo['memory_percent'], 1),
                        'status': pinfo['status'],
                        'create_time': create_time
                    }
                    processes.append(process_data)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        except Exception as e:
            print(f"获取进程信息时出错: {e}")

        return processes

    def get_system_info(self):
        """获取系统资源信息"""
        try:
            # 不使用interval参数，避免阻塞
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            system_info = {
                'cpu_percent': cpu_percent,
                'memory_total': round(memory.total / 1024 / 1024 / 1024, 1),  # GB
                'memory_used': round(memory.used / 1024 / 1024 / 1024, 1),    # GB
                'memory_percent': memory.percent,
                'disk_total': round(disk.total / 1024 / 1024 / 1024, 1),     # GB
                'disk_used': round(disk.used / 1024 / 1024 / 1024, 1),       # GB
                'disk_percent': round((disk.used / disk.total) * 100, 1)
            }
            return system_info

        except Exception as e:
            print(f"获取系统信息时出错: {e}")
            return None

    def display_processes(self, limit=20):
        """显示进程信息"""
        # 清屏
        os.system('clear' if os.name == 'posix' else 'cls')

        # 获取系统信息
        system_info = self.get_system_info()
        if system_info:
            print("=" * 100)
            print(f"{'系统资源信息':^100}")
            print(f"CPU使用率: {system_info['cpu_percent']}% | "
                  f"内存: {system_info['memory_used']}/{system_info['memory_total']}GB ({system_info['memory_percent']}%) | "
                  f"磁盘: {system_info['disk_used']}/{system_info['disk_total']}GB ({system_info['disk_percent']}%)")
            print("=" * 100)

        # 获取进程信息
        processes = self.get_process_info()

        # 按CPU使用率排序
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)

        # 显示表头
        print(f"{'PID':<8} {'进程名称':<20} {'CPU%':<8} {'内存(MB)':<12} {'内存%':<8} {'状态':<10} {'创建时间':<20}")
        print("-" * 100)

        # 显示进程信息
        for i, proc in enumerate(processes[:limit]):
            print(f"{proc['pid']:<8} {proc['name'][:18]:<20} {proc['cpu_percent']:<8} "
                  f"{proc['memory_mb']:<12} {proc['memory_percent']:<8} "
                  f"{proc['status']:<10} {proc['create_time']:<20}")

        print(f"\n显示前 {limit} 个进程 (总计 {len(processes)} 个进程)")
        print("按 Ctrl+C 退出")

    def run(self):
        """运行进程监控器"""
        print("Task Process Manager - Linux进程监控工具")
        print("正在初始化...")

        try:
            while True:
                self.display_processes()
                time.sleep(2)  # 每2秒刷新一次

        except KeyboardInterrupt:
            print("\n\n程序已退出")
        except Exception as e:
            print(f"\n运行时出错: {e}")


class ProcessMonitorGUI:
    def __init__(self):
        self.monitor = ProcessMonitor()
        self.root = tk.Tk()
        self.setup_window()
        self.create_widgets()
        self.is_updating = False

    def setup_window(self):
        """设置主窗口"""
        self.root.title("Task Process Manager - Linux进程监控工具")
        self.root.geometry("1200x700")
        self.root.resizable(True, True)

        # 设置关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        """创建界面组件"""
        # 创建主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 创建系统资源监控面板
        self.create_system_panel(main_frame)

        # 创建进程列表
        self.create_process_list(main_frame)

        # 创建控制按钮
        self.create_control_buttons(main_frame)

    def create_system_panel(self, parent):
        """创建系统资源监控面板"""
        system_frame = ttk.LabelFrame(parent, text="系统资源使用情况", padding=10)
        system_frame.pack(fill=tk.X, padx=5, pady=5)

        # CPU使用率
        cpu_frame = ttk.Frame(system_frame)
        cpu_frame.pack(fill=tk.X, pady=2)
        ttk.Label(cpu_frame, text="CPU使用率:", width=15).pack(side=tk.LEFT)
        self.cpu_var = tk.StringVar(value="0%")
        self.cpu_label = ttk.Label(cpu_frame, textvariable=self.cpu_var, foreground="blue")
        self.cpu_label.pack(side=tk.LEFT)
        self.cpu_progress = ttk.Progressbar(cpu_frame, length=200, mode='determinate')
        self.cpu_progress.pack(side=tk.LEFT, padx=10)

        # 内存使用率
        memory_frame = ttk.Frame(system_frame)
        memory_frame.pack(fill=tk.X, pady=2)
        ttk.Label(memory_frame, text="内存使用:", width=15).pack(side=tk.LEFT)
        self.memory_var = tk.StringVar(value="0GB / 0GB (0%)")
        self.memory_label = ttk.Label(memory_frame, textvariable=self.memory_var, foreground="green")
        self.memory_label.pack(side=tk.LEFT)
        self.memory_progress = ttk.Progressbar(memory_frame, length=200, mode='determinate')
        self.memory_progress.pack(side=tk.LEFT, padx=10)

        # 磁盘使用率
        disk_frame = ttk.Frame(system_frame)
        disk_frame.pack(fill=tk.X, pady=2)
        ttk.Label(disk_frame, text="磁盘使用:", width=15).pack(side=tk.LEFT)
        self.disk_var = tk.StringVar(value="0GB / 0GB (0%)")
        self.disk_label = ttk.Label(disk_frame, textvariable=self.disk_var, foreground="orange")
        self.disk_label.pack(side=tk.LEFT)
        self.disk_progress = ttk.Progressbar(disk_frame, length=200, mode='determinate')
        self.disk_progress.pack(side=tk.LEFT, padx=10)

    def create_process_list(self, parent):
        """创建进程列表"""
        list_frame = ttk.LabelFrame(parent, text="进程列表", padding=5)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 创建Treeview
        columns = ('PID', '名称', 'CPU%', '内存(MB)', '内存%', '状态', '创建时间')
        self.process_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=20)

        # 设置列标题和宽度
        column_widths = {'PID': 80, '名称': 200, 'CPU%': 80, '内存(MB)': 100,
                        '内存%': 80, '状态': 100, '创建时间': 150}

        for col in columns:
            self.process_tree.heading(col, text=col, command=lambda c=col: self.sort_by_column(c))
            self.process_tree.column(col, width=column_widths.get(col, 100), anchor=tk.CENTER)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scrollbar.set)

        # 布局
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 绑定双击事件
        self.process_tree.bind('<Double-1>', self.on_process_double_click)

        # 设置排序状态
        self.sort_column = 'CPU%'
        self.sort_reverse = True

    def create_control_buttons(self, parent):
        """创建控制按钮"""
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        # 左侧按钮组
        left_frame = ttk.Frame(control_frame)
        left_frame.pack(side=tk.LEFT)

        # 刷新按钮
        self.refresh_btn = ttk.Button(left_frame, text="刷新", command=self.refresh_data)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)

        # 结束进程按钮
        self.kill_btn = ttk.Button(left_frame, text="结束选中进程", command=self.kill_selected_process)
        self.kill_btn.pack(side=tk.LEFT, padx=5)

        # 刷新间隔设置
        ttk.Label(left_frame, text="刷新间隔(秒):").pack(side=tk.LEFT, padx=5)
        self.interval_var = tk.StringVar(value="2")
        interval_spin = ttk.Spinbox(left_frame, from_=1, to=10, textvariable=self.interval_var, width=5)
        interval_spin.pack(side=tk.LEFT, padx=5)

        # 中间设置组
        middle_frame = ttk.Frame(control_frame)
        middle_frame.pack(side=tk.LEFT, padx=20)

        # CPU计算方式选择
        ttk.Label(middle_frame, text="CPU计算方式:").pack(side=tk.LEFT, padx=5)
        self.cpu_mode_var = tk.StringVar(value="relative")
        cpu_relative_rb = ttk.Radiobutton(middle_frame, text="相对(100%基准)",
                                        variable=self.cpu_mode_var, value="relative",
                                        command=self.toggle_cpu_mode)
        cpu_relative_rb.pack(side=tk.LEFT, padx=5)
        cpu_absolute_rb = ttk.Radiobutton(middle_frame, text="传统(总CPU%)",
                                        variable=self.cpu_mode_var, value="absolute",
                                        command=self.toggle_cpu_mode)
        cpu_absolute_rb.pack(side=tk.LEFT, padx=5)

        # 右侧设置组
        right_frame = ttk.Frame(control_frame)
        right_frame.pack(side=tk.LEFT)

        # 自动刷新复选框
        self.auto_refresh_var = tk.BooleanVar(value=True)
        auto_refresh_check = ttk.Checkbutton(right_frame, text="自动刷新",
                                           variable=self.auto_refresh_var,
                                           command=self.toggle_auto_refresh)
        auto_refresh_check.pack(side=tk.LEFT, padx=5)

        # 状态标签
        self.status_var = tk.StringVar(value="就绪")
        status_label = ttk.Label(control_frame, textvariable=self.status_var)
        status_label.pack(side=tk.RIGHT, padx=5)

    def update_system_info(self):
        """更新系统资源信息"""
        try:
            system_info = self.monitor.get_system_info()
            if system_info:
                # 更新CPU
                self.cpu_var.set(f"{system_info['cpu_percent']:.1f}%")
                self.cpu_progress['value'] = system_info['cpu_percent']

                # 更新内存
                self.memory_var.set(f"{system_info['memory_used']:.1f}GB / {system_info['memory_total']:.1f}GB ({system_info['memory_percent']:.1f}%)")
                self.memory_progress['value'] = system_info['memory_percent']

                # 更新磁盘
                self.disk_var.set(f"{system_info['disk_used']:.1f}GB / {system_info['disk_total']:.1f}GB ({system_info['disk_percent']:.1f}%)")
                self.disk_progress['value'] = system_info['disk_percent']

        except Exception as e:
            print(f"更新系统信息时出错: {e}")

    def update_process_list(self):
        """更新进程列表"""
        try:
            # 清空现有项目
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)

            # 获取进程信息（使用带延迟的方法获得准确的CPU使用率）
            processes = self.monitor.get_process_info_with_delay(delay=0.2)

            # 排序
            processes.sort(key=lambda x: x.get(self.sort_column.lower().replace('%', '_percent'), 0),
                         reverse=self.sort_reverse)

            # 添加到Treeview
            for proc in processes:
                values = (
                    proc['pid'],
                    proc['name'],
                    f"{proc['cpu_percent']:.1f}%",
                    f"{proc['memory_mb']:.1f}",
                    f"{proc['memory_percent']:.1f}%",
                    proc['status'],
                    proc['create_time']
                )
                self.process_tree.insert('', tk.END, values=values)

            # 更新状态
            self.status_var.set(f"已更新 {len(processes)} 个进程")

        except Exception as e:
            self.status_var.set(f"更新进程列表时出错: {e}")

    def refresh_data(self):
        """刷新数据"""
        self.status_var.set("正在更新...")
        self.update_system_info()
        self.update_process_list()

    def auto_refresh(self):
        """自动刷新"""
        if self.auto_refresh_var.get() and not self.is_updating:
            try:
                self.is_updating = True
                self.refresh_data()
                # 获取刷新间隔
                interval = int(self.interval_var.get()) * 1000
                self.root.after(interval, self.auto_refresh)
            except Exception as e:
                print(f"自动刷新时出错: {e}")
            finally:
                self.is_updating = False

    def toggle_auto_refresh(self):
        """切换自动刷新"""
        if self.auto_refresh_var.get():
            self.auto_refresh()
        else:
            self.status_var.set("自动刷新已停止")

    def toggle_cpu_mode(self):
        """切换CPU计算模式"""
        cpu_mode = self.cpu_mode_var.get()
        if cpu_mode == "relative":
            self.monitor.use_relative_cpu = True
            self.status_var.set("使用相对CPU计算方式（100%基准）")
        else:
            self.monitor.use_relative_cpu = False
            self.status_var.set("使用传统CPU计算方式（总CPU%）")

        # 立即刷新数据
        self.refresh_data()

    def sort_by_column(self, column):
        """按列排序"""
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = True
        self.update_process_list()

    def kill_selected_process(self):
        """结束选中的进程"""
        selected_item = self.process_tree.selection()
        if not selected_item:
            messagebox.showwarning("警告", "请先选择要结束的进程")
            return

        item = self.process_tree.item(selected_item[0])
        pid = int(item['values'][0])
        process_name = item['values'][1]

        # 确认对话框
        if messagebox.askyesno("确认", f"确定要结束进程 '{process_name}' (PID: {pid}) 吗？"):
            try:
                # 尝试正常终止
                process = psutil.Process(pid)
                process.terminate()

                # 等待一段时间，如果还没结束就强制杀死
                time.sleep(1)
                if process.is_running():
                    process.kill()

                messagebox.showinfo("成功", f"进程 {process_name} (PID: {pid}) 已结束")
                self.refresh_data()

            except psutil.NoSuchProcess:
                messagebox.showinfo("信息", f"进程 {pid} 已不存在")
            except psutil.AccessDenied:
                messagebox.showerror("错误", f"没有权限结束进程 {pid}")
            except Exception as e:
                messagebox.showerror("错误", f"结束进程时出错: {e}")

    def on_process_double_click(self, event):
        """进程双击事件"""
        selected_item = self.process_tree.selection()
        if selected_item:
            item = self.process_tree.item(selected_item[0])
            pid = int(item['values'][0])
            process_name = item['values'][1]

            # 显示进程详细信息
            self.show_process_details(pid, process_name)

    def show_process_details(self, pid, process_name):
        """显示进程详细信息"""
        try:
            process = psutil.Process(pid)

            # 获取详细信息
            details = f"进程名称: {process_name}\n"
            details += f"PID: {pid}\n"
            details += f"状态: {process.status()}\n"
            details += f"CPU使用率: {process.cpu_percent():.1f}%\n"
            details += f"内存使用: {process.memory_info().rss / 1024 / 1024:.1f} MB\n"
            details += f"创建时间: {datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S')}\n"
            details += f"父进程PID: {process.ppid()}\n"

            # 获取命令行参数
            try:
                cmdline = ' '.join(process.cmdline())
                if cmdline:
                    details += f"命令行: {cmdline}\n"
            except:
                pass

            messagebox.showinfo(f"进程详情 - {process_name}", details)

        except psutil.NoSuchProcess:
            messagebox.showinfo("信息", f"进程 {pid} 已不存在")
        except Exception as e:
            messagebox.showerror("错误", f"获取进程详情时出错: {e}")

    def on_closing(self):
        """窗口关闭事件"""
        self.auto_refresh_var.set(False)
        self.root.destroy()

    def run(self):
        """运行GUI"""
        # 初始数据
        self.refresh_data()

        # 启动自动刷新
        self.auto_refresh()

        # 运行主循环
        self.root.mainloop()


def main():
    import sys

    # 检查是否有命令行参数
    if len(sys.argv) > 1 and sys.argv[1] == '--cli':
        # 命令行模式
        monitor = ProcessMonitor()
        monitor.run()
    else:
        # GUI模式（默认）
        try:
            app = ProcessMonitorGUI()
            app.run()
        except Exception as e:
            print(f"启动GUI时出错: {e}")
            print("切换到命令行模式...")
            monitor = ProcessMonitor()
            monitor.run()

if __name__ == "__main__":
    main()