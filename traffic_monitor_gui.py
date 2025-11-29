#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
流量监控图形界面
提供实时网络流量监控的可视化界面
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
from datetime import datetime
from collections import deque
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.dates as mdates
from traffic_monitor import TrafficMonitor
import logging

class TrafficMonitorGUI:
    """流量监控图形界面"""

    def __init__(self, root):
        self.root = root
        self.monitor = TrafficMonitor(history_length=300)  # 保存5分钟历史

        # 设置窗口
        self.root.title("网络流量监控工具")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)

        # GUI状态
        self.monitoring = False
        self.update_thread = None
        self.update_interval = 1000  # 1秒更新一次

        # 数据存储
        self.traffic_history = deque(maxlen=60)  # 保存60个数据点用于绘图
        self.alerts_history = deque(maxlen=100)  # 保存告警历史

        # 创建界面
        self.create_widgets()

        # 设置关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        """创建界面组件"""
        print("[GUI] 创建流量监控界面")

        # 创建主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 创建标题框架
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))

        title_label = ttk.Label(title_frame, text="网络流量监控", font=("Arial", 16, "bold"))
        title_label.pack(side=tk.LEFT)

        # 控制按钮框架
        control_frame = ttk.Frame(title_frame)
        control_frame.pack(side=tk.RIGHT)

        self.start_button = ttk.Button(control_frame, text="开始监控", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="停止监控", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        config_button = ttk.Button(control_frame, text="配置", command=self.show_config_dialog)
        config_button.pack(side=tk.LEFT, padx=5)

        # 创建选项卡
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        # 实时监控选项卡
        self.create_realtime_tab(notebook)

        # 网络接口选项卡
        self.create_interface_tab(notebook)

        # 进程流量选项卡
        self.create_process_tab(notebook)

        # 告警选项卡
        self.create_alert_tab(notebook)

        # 状态栏
        self.create_status_bar(main_frame)

    def create_realtime_tab(self, notebook):
        """创建实时监控选项卡"""
        realtime_frame = ttk.Frame(notebook)
        notebook.add(realtime_frame, text="实时监控")

        # 当前流量显示框架
        current_frame = ttk.LabelFrame(realtime_frame, text="当前流量状态", padding=10)
        current_frame.pack(fill=tk.X, pady=(0, 10))

        # 流量状态标签
        status_grid = ttk.Frame(current_frame)
        status_grid.pack(fill=tk.X)

        # 上传流量显示
        upload_frame = ttk.Frame(status_grid)
        upload_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        ttk.Label(upload_frame, text="上传速度:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        self.upload_speed_label = ttk.Label(upload_frame, text="0 B/s", font=("Arial", 14), foreground="green")
        self.upload_speed_label.pack(anchor=tk.W)

        ttk.Label(upload_frame, text="总上传:", font=("Arial", 10)).pack(anchor=tk.W)
        self.upload_total_label = ttk.Label(upload_frame, text="0 B", font=("Arial", 10))
        self.upload_total_label.pack(anchor=tk.W)

        # 下载流量显示
        download_frame = ttk.Frame(status_grid)
        download_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        ttk.Label(download_frame, text="下载速度:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        self.download_speed_label = ttk.Label(download_frame, text="0 B/s", font=("Arial", 14), foreground="blue")
        self.download_speed_label.pack(anchor=tk.W)

        ttk.Label(download_frame, text="总下载:", font=("Arial", 10)).pack(anchor=tk.W)
        self.download_total_label = ttk.Label(download_frame, text="0 B", font=("Arial", 10))
        self.download_total_label.pack(anchor=tk.W)

        # 监控状态显示
        status_frame = ttk.Frame(status_grid)
        status_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        ttk.Label(status_frame, text="监控状态:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        self.monitor_status_label = ttk.Label(status_frame, text="未启动", font=("Arial", 12), foreground="red")
        self.monitor_status_label.pack(anchor=tk.W)

        ttk.Label(status_frame, text="运行时间:", font=("Arial", 10)).pack(anchor=tk.W)
        self.uptime_label = ttk.Label(status_frame, text="0秒", font=("Arial", 10))
        self.uptime_label.pack(anchor=tk.W)

        # 流量图表
        chart_frame = ttk.LabelFrame(realtime_frame, text="流量历史图表", padding=5)
        chart_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # 创建matplotlib图表
        self.figure = Figure(figsize=(10, 4), dpi=80)
        self.ax = self.figure.add_subplot(111)
        self.ax.set_title("网络流量趋势")
        self.ax.set_xlabel("时间")
        self.ax.set_ylabel("流量 (B/s)")
        self.ax.grid(True, alpha=0.3)

        self.canvas = FigureCanvasTkAgg(self.figure, chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # 统计信息框架
        stats_frame = ttk.LabelFrame(realtime_frame, text="统计信息", padding=10)
        stats_frame.pack(fill=tk.X)

        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X)

        # 平均速度
        avg_frame = ttk.Frame(stats_grid)
        avg_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        ttk.Label(avg_frame, text="平均上传:", font=("Arial", 10)).pack(anchor=tk.W)
        self.avg_upload_label = ttk.Label(avg_frame, text="0 B/s", font=("Arial", 10))
        self.avg_upload_label.pack(anchor=tk.W)

        ttk.Label(avg_frame, text="平均下载:", font=("Arial", 10)).pack(anchor=tk.W)
        self.avg_download_label = ttk.Label(avg_frame, text="0 B/s", font=("Arial", 10))
        self.avg_download_label.pack(anchor=tk.W)

        # 峰值速度
        peak_frame = ttk.Frame(stats_grid)
        peak_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        ttk.Label(peak_frame, text="峰值上传:", font=("Arial", 10)).pack(anchor=tk.W)
        self.peak_upload_label = ttk.Label(peak_frame, text="0 B/s", font=("Arial", 10), foreground="green")
        self.peak_upload_label.pack(anchor=tk.W)

        ttk.Label(peak_frame, text="峰值下载:", font=("Arial", 10)).pack(anchor=tk.W)
        self.peak_download_label = ttk.Label(peak_frame, text="0 B/s", font=("Arial", 10), foreground="blue")
        self.peak_download_label.pack(anchor=tk.W)

        # 数据点数量
        data_frame = ttk.Frame(stats_grid)
        data_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        ttk.Label(data_frame, text="数据点数:", font=("Arial", 10)).pack(anchor=tk.W)
        self.data_points_label = ttk.Label(data_frame, text="0", font=("Arial", 10))
        self.data_points_label.pack(anchor=tk.W)

    def create_interface_tab(self, notebook):
        """创建网络接口选项卡"""
        interface_frame = ttk.Frame(notebook)
        notebook.add(interface_frame, text="网络接口")

        # 创建Treeview显示接口信息
        tree_frame = ttk.Frame(interface_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 创建Treeview
        columns = ('Interface', 'UploadSpeed', 'DownloadSpeed', 'TotalUpload', 'TotalDownload')
        self.interface_tree = ttk.Treeview(tree_frame, columns=columns, show='headings')

        # 设置列标题
        self.interface_tree.heading('Interface', text='接口名称')
        self.interface_tree.heading('UploadSpeed', text='上传速度')
        self.interface_tree.heading('DownloadSpeed', text='下载速度')
        self.interface_tree.heading('TotalUpload', text='总上传')
        self.interface_tree.heading('TotalDownload', text='总下载')

        # 设置列宽
        self.interface_tree.column('Interface', width=150)
        self.interface_tree.column('UploadSpeed', width=120)
        self.interface_tree.column('DownloadSpeed', width=120)
        self.interface_tree.column('TotalUpload', width=150)
        self.interface_tree.column('TotalDownload', width=150)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.interface_tree.yview)
        self.interface_tree.configure(yscrollcommand=scrollbar.set)

        # 布局
        self.interface_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def create_process_tab(self, notebook):
        """创建进程流量选项卡"""
        process_frame = ttk.Frame(notebook)
        notebook.add(process_frame, text="进程流量")

        # 创建Treeview显示进程信息
        tree_frame = ttk.Frame(process_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 创建Treeview
        columns = ('PID', 'ProcessName', 'UploadSpeed', 'DownloadSpeed', 'TotalUpload', 'TotalDownload')
        self.process_tree = ttk.Treeview(tree_frame, columns=columns, show='headings')

        # 设置列标题
        self.process_tree.heading('PID', text='PID')
        self.process_tree.heading('ProcessName', text='进程名称')
        self.process_tree.heading('UploadSpeed', text='上传速度')
        self.process_tree.heading('DownloadSpeed', text='下载速度')
        self.process_tree.heading('TotalUpload', text='总上传')
        self.process_tree.heading('TotalDownload', text='总下载')

        # 设置列宽
        self.process_tree.column('PID', width=80)
        self.process_tree.column('ProcessName', width=200)
        self.process_tree.column('UploadSpeed', width=120)
        self.process_tree.column('DownloadSpeed', width=120)
        self.process_tree.column('TotalUpload', width=120)
        self.process_tree.column('TotalDownload', width=120)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scrollbar.set)

        # 布局
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def create_alert_tab(self, notebook):
        """创建告警选项卡"""
        alert_frame = ttk.Frame(notebook)
        notebook.add(alert_frame, text="告警信息")

        # 告警控制框架
        control_frame = ttk.Frame(alert_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        self.alert_enabled_var = tk.BooleanVar(value=True)
        alert_checkbox = ttk.Checkbutton(control_frame, text="启用告警", variable=self.alert_enabled_var,
                                       command=self.toggle_alerts)
        alert_checkbox.pack(side=tk.LEFT, padx=5)

        clear_button = ttk.Button(control_frame, text="清除历史", command=self.clear_alert_history)
        clear_button.pack(side=tk.LEFT, padx=5)

        # 告警列表
        list_frame = ttk.Frame(alert_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 创建告警文本框
        self.alert_text = scrolledtext.ScrolledText(list_frame, height=20, wrap=tk.WORD)
        self.alert_text.pack(fill=tk.BOTH, expand=True)

        # 配置标签样式
        self.alert_text.tag_configure('warning', foreground='orange')
        self.alert_text.tag_configure('error', foreground='red')
        self.alert_text.tag_configure('info', foreground='blue')

    def create_status_bar(self, parent):
        """创建状态栏"""
        status_frame = ttk.Frame(parent)
        status_frame.pack(fill=tk.X, pady=(10, 0))

        self.status_label = ttk.Label(status_frame, text="就绪", relief=tk.SUNKEN)
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.time_label = ttk.Label(status_frame, text="", relief=tk.SUNKEN)
        self.time_label.pack(side=tk.RIGHT)

    def start_monitoring(self):
        """开始监控"""
        if self.monitoring:
            return

        try:
            self.monitor.start_monitoring()
            self.monitoring = True

            # 更新按钮状态
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

            # 更新状态显示
            self.monitor_status_label.config(text="运行中", foreground="green")

            # 启动更新线程
            self.update_thread = threading.Thread(target=self.update_loop, daemon=True)
            self.update_thread.start()

            self.update_status("流量监控已启动")
            print("[GUI] 流量监控已启动")

        except Exception as e:
            messagebox.showerror("错误", f"启动监控失败: {str(e)}")
            print(f"[GUI] 启动监控失败: {e}")

    def stop_monitoring(self):
        """停止监控"""
        if not self.monitoring:
            return

        try:
            self.monitor.stop_monitoring()
            self.monitoring = False

            # 更新按钮状态
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

            # 更新状态显示
            self.monitor_status_label.config(text="已停止", foreground="red")

            self.update_status("流量监控已停止")
            print("[GUI] 流量监控已停止")

        except Exception as e:
            messagebox.showerror("错误", f"停止监控失败: {str(e)}")
            print(f"[GUI] 停止监控失败: {e}")

    def update_loop(self):
        """更新循环"""
        while self.monitoring:
            try:
                self.update_display()
                time.sleep(self.update_interval / 1000.0)
            except Exception as e:
                print(f"[GUI] 更新显示时出错: {e}")
                time.sleep(1)

    def update_display(self):
        """更新显示"""
        if not self.monitoring:
            return

        try:
            # 获取当前流量数据
            current_speed = self.monitor.get_current_speed()
            summary = self.monitor.get_traffic_summary(5)

            # 更新流量显示
            self.root.after(0, self._update_traffic_display, current_speed, summary)

            # 更新网络接口信息
            interface_stats = self.monitor.get_interface_stats()
            self.root.after(0, self._update_interface_display, interface_stats)

            # 更新进程流量信息
            process_stats = self.monitor.get_process_traffic_stats()
            self.root.after(0, self._update_process_display, process_stats)

            # 更新图表
            self.root.after(0, self._update_chart, current_speed)

            # 更新运行时间
            uptime = len(self.monitor.traffic_history)
            self.root.after(0, self._update_uptime, uptime)

        except Exception as e:
            print(f"[GUI] 更新显示时出错: {e}")

    def _update_traffic_display(self, current_speed, summary):
        """更新流量显示"""
        try:
            # 更新速度显示
            self.upload_speed_label.config(text=current_speed['upload_speed_human'])
            self.download_speed_label.config(text=current_speed['download_speed_human'])

            # 更新总流量显示（从最新历史记录获取）
            if len(self.monitor.traffic_history) > 0:
                latest = self.monitor.traffic_history[-1]
                self.upload_total_label.config(text=self.monitor.format_bytes(latest['total_upload']))
                self.download_total_label.config(text=self.monitor.format_bytes(latest['total_download']))

            # 更新统计信息
            self.avg_upload_label.config(text=self.monitor.format_bytes(summary['avg_upload_speed']) + '/s')
            self.avg_download_label.config(text=self.monitor.format_bytes(summary['avg_download_speed']) + '/s')
            self.peak_upload_label.config(text=self.monitor.format_bytes(summary['max_upload_speed']) + '/s')
            self.peak_download_label.config(text=self.monitor.format_bytes(summary['max_download_speed']) + '/s')
            self.data_points_label.config(text=str(summary['data_points']))

        except Exception as e:
            print(f"[GUI] 更新流量显示时出错: {e}")

    def _update_interface_display(self, interface_stats):
        """更新接口显示"""
        try:
            # 清除现有数据
            for item in self.interface_tree.get_children():
                self.interface_tree.delete(item)

            # 添加新数据
            for interface in interface_stats:
                self.interface_tree.insert('', tk.END, values=(
                    interface['interface'],
                    interface['upload_speed_human'],
                    interface['download_speed_human'],
                    interface['upload_human'],
                    interface['download_human']
                ))

        except Exception as e:
            print(f"[GUI] 更新接口显示时出错: {e}")

    def _update_process_display(self, process_stats):
        """更新进程显示"""
        try:
            # 清除现有数据
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)

            # 添加新数据（只显示前20个进程）
            for process in process_stats[:20]:
                self.process_tree.insert('', tk.END, values=(
                    process['pid'],
                    process['name'],
                    process['upload_speed_human'],
                    process['download_speed_human'],
                    process['upload_human'],
                    process['download_human']
                ))

        except Exception as e:
            print(f"[GUI] 更新进程显示时出错: {e}")

    def _update_chart(self, current_speed):
        """更新图表"""
        try:
            # 添加当前数据点到历史记录
            current_time = datetime.now()
            self.traffic_history.append({
                'time': current_time,
                'upload': current_speed['upload_speed'],
                'download': current_speed['download_speed']
            })

            # 清除并重绘图表
            self.ax.clear()

            if len(self.traffic_history) > 1:
                times = [record['time'] for record in self.traffic_history]
                uploads = [record['upload'] for record in self.traffic_history]
                downloads = [record['download'] for record in self.traffic_history]

                # 绘制图表
                self.ax.plot(times, uploads, 'g-', label='上传速度', linewidth=2)
                self.ax.plot(times, downloads, 'b-', label='下载速度', linewidth=2)

                # 格式化时间轴
                self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
                self.ax.figure.autofmt_xdate()

                # 设置标签和图例
                self.ax.set_title("网络流量趋势")
                self.ax.set_xlabel("时间")
                self.ax.set_ylabel("流量 (B/s)")
                self.ax.legend()
                self.ax.grid(True, alpha=0.3)

            self.canvas.draw()

        except Exception as e:
            print(f"[GUI] 更新图表时出错: {e}")

    def _update_uptime(self, uptime):
        """更新运行时间"""
        try:
            hours = uptime // 3600
            minutes = (uptime % 3600) // 60
            seconds = uptime % 60

            if hours > 0:
                uptime_text = f"{hours}小时{minutes}分钟{seconds}秒"
            elif minutes > 0:
                uptime_text = f"{minutes}分钟{seconds}秒"
            else:
                uptime_text = f"{seconds}秒"

            self.uptime_label.config(text=uptime_text)

        except Exception as e:
            print(f"[GUI] 更新运行时间时出错: {e}")

    def show_config_dialog(self):
        """显示配置对话框"""
        dialog = ConfigDialog(self.root, self.monitor)
        self.root.wait_window(dialog.dialog)

    def toggle_alerts(self):
        """切换告警状态"""
        enabled = self.alert_enabled_var.get()
        self.monitor.enable_alerts(enabled)
        self.update_status(f"告警已{'启用' if enabled else '禁用'}")

    def clear_alert_history(self):
        """清除告警历史"""
        self.alerts_history.clear()
        self.alert_text.delete(1.0, tk.END)
        self.update_status("告警历史已清除")

    def add_alert(self, message, level='info'):
        """添加告警消息"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        alert_message = f"[{timestamp}] {message}\n"

        self.alerts_history.append({
            'time': timestamp,
            'message': message,
            'level': level
        })

        # 更新告警显示
        self.root.after(0, self._update_alert_display, alert_message, level)

    def _update_alert_display(self, message, level):
        """更新告警显示"""
        try:
            self.alert_text.insert(tk.END, message, level)
            self.alert_text.see(tk.END)
        except Exception as e:
            print(f"[GUI] 更新告警显示时出错: {e}")

    def update_status(self, message):
        """更新状态栏"""
        self.status_label.config(text=message)

    def update_time(self):
        """更新时间显示"""
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.time_label.config(text=current_time)

    def on_closing(self):
        """关闭窗口时的处理"""
        try:
            if self.monitoring:
                self.stop_monitoring()
            self.root.destroy()
        except Exception as e:
            print(f"[GUI] 关闭窗口时出错: {e}")
            self.root.destroy()


class ConfigDialog:
    """配置对话框"""

    def __init__(self, parent, monitor):
        self.monitor = monitor
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("流量监控配置")
        self.dialog.geometry("400x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # 居中显示
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (self.dialog.winfo_width() // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")

        self.create_widgets()

    def create_widgets(self):
        """创建配置界面组件"""
        main_frame = ttk.Frame(self.dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # 告警设置框架
        alert_frame = ttk.LabelFrame(main_frame, text="告警设置", padding=10)
        alert_frame.pack(fill=tk.X, pady=(0, 20))

        # 上传速度阈值
        ttk.Label(alert_frame, text="上传速度阈值:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.upload_threshold_var = tk.StringVar(value=str(self.monitor.upload_threshold))
        upload_entry = ttk.Entry(alert_frame, textvariable=self.upload_threshold_var, width=15)
        upload_entry.grid(row=0, column=1, pady=5, padx=5)
        ttk.Label(alert_frame, text="字节/秒").grid(row=0, column=2, sticky=tk.W, pady=5)

        # 下载速度阈值
        ttk.Label(alert_frame, text="下载速度阈值:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.download_threshold_var = tk.StringVar(value=str(self.monitor.download_threshold))
        download_entry = ttk.Entry(alert_frame, textvariable=self.download_threshold_var, width=15)
        download_entry.grid(row=1, column=1, pady=5, padx=5)
        ttk.Label(alert_frame, text="字节/秒").grid(row=1, column=2, sticky=tk.W, pady=5)

        # 告警冷却时间
        ttk.Label(alert_frame, text="告警冷却时间:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.cooldown_var = tk.StringVar(value=str(self.monitor.alert_cooldown))
        cooldown_entry = ttk.Entry(alert_frame, textvariable=self.cooldown_var, width=15)
        cooldown_entry.grid(row=2, column=1, pady=5, padx=5)
        ttk.Label(alert_frame, text="秒").grid(row=2, column=2, sticky=tk.W, pady=5)

        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))

        ttk.Button(button_frame, text="确定", command=self.save_config).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="取消", command=self.dialog.destroy).pack(side=tk.RIGHT, padx=5)

    def save_config(self):
        """保存配置"""
        try:
            upload_threshold = int(self.upload_threshold_var.get())
            download_threshold = int(self.download_threshold_var.get())
            cooldown = int(self.cooldown_var.get())

            # 验证输入
            if upload_threshold < 0 or download_threshold < 0 or cooldown < 0:
                messagebox.showerror("错误", "配置值必须大于等于0")
                return

            # 应用配置
            self.monitor.set_alert_thresholds(upload_threshold, download_threshold, cooldown)
            messagebox.showinfo("成功", "配置已保存")
            self.dialog.destroy()

        except ValueError:
            messagebox.showerror("错误", "请输入有效的数字")


def main():
    """主函数"""
    print("启动流量监控图形界面...")

    # 创建主窗口
    root = tk.Tk()

    # 创建GUI
    gui = TrafficMonitorGUI(root)

    # 更新时间显示
    def update_time():
        gui.update_time()
        root.after(1000, update_time)

    update_time()

    # 运行主循环
    root.mainloop()

    print("流量监控图形界面已关闭")


if __name__ == "__main__":
    main()