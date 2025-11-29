#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
流量监控模块
提供实时网络流量监控、历史记录和进程流量统计功能
独立模块，便于维护和复用
"""

import psutil
import time
import threading
from datetime import datetime
from collections import defaultdict, deque
import json
import logging
import os
import sys

# GUI相关导入
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("警告: tkinter不可用，GUI功能将被禁用")


class TrafficMonitor:
    """流量监控核心类"""

    def __init__(self, history_length=300, log_level=logging.INFO):
        """
        初始化流量监控器

        Args:
            history_length (int): 历史记录保存的秒数，默认300秒(5分钟)
            log_level (int): 日志级别
        """
        self.history_length = history_length

        # 流量监控相关
        self.traffic_history = deque(maxlen=history_length)  # 保存历史记录
        self.process_traffic = defaultdict(lambda: {
            'upload': 0, 'download': 0,
            'upload_speed': 0, 'download_speed': 0,
            'last_update': time.time()
        })

        # 网络接口流量统计
        self.interface_traffic = defaultdict(lambda: {
            'upload': 0, 'download': 0,
            'upload_speed': 0, 'download_speed': 0,
            'last_update': time.time()
        })

        self.last_network_stats = psutil.net_io_counters()
        self.last_interface_stats = {}
        self.last_process_stats = {}
        self.traffic_monitoring = False
        self.traffic_lock = threading.Lock()

        # 监控线程
        self.monitor_thread = None

        # 异常检测和告警
        self.alerts_enabled = True
        self.upload_threshold = 10 * 1024 * 1024  # 10MB/s 上传阈值
        self.download_threshold = 50 * 1024 * 1024  # 50MB/s 下载阈值
        self.alert_cooldown = 60  # 告警冷却时间（秒）
        self.last_alert_time = {}

        # 设置日志
        self.setup_logging(log_level)

    def setup_logging(self, log_level):
        """设置日志系统"""
        self.logger = logging.getLogger('TrafficMonitor')
        self.logger.setLevel(log_level)

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log(self, message, level=logging.INFO):
        """日志输出"""
        self.logger.log(level, message)

    def start_monitoring(self):
        """开始流量监控"""
        if self.traffic_monitoring:
            self.log("流量监控已在运行中")
            return

        self.traffic_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitoring_worker, daemon=True)
        self.monitor_thread.start()
        self.log("流量监控已启动")

    def stop_monitoring(self):
        """停止流量监控"""
        if not self.traffic_monitoring:
            self.log("流量监控未在运行")
            return

        self.traffic_monitoring = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)
        self.log("流量监控已停止")

    def is_monitoring(self):
        """检查监控是否正在运行"""
        return self.traffic_monitoring

    def _monitoring_worker(self):
        """流量监控工作线程"""
        self.log("监控线程已启动")

        while self.traffic_monitoring:
            try:
                self._update_traffic_stats()
                time.sleep(1)  # 每秒更新一次
            except Exception as e:
                self.log(f"监控线程出错: {e}")
                time.sleep(1)

        self.log("监控线程已退出")

    def _update_traffic_stats(self):
        """更新流量统计"""
        current_time = time.time()

        # 获取系统总流量
        current_network_stats = psutil.net_io_counters()
        current_interface_stats = psutil.net_io_counters(pernic=True)

        # 计算系统流量速度（字节/秒）
        time_diff = current_time - getattr(self, '_last_system_update', current_time)
        upload_speed = 0
        download_speed = 0

        if time_diff > 0:
            bytes_sent_diff = current_network_stats.bytes_sent - self.last_network_stats.bytes_sent
            bytes_recv_diff = current_network_stats.bytes_recv - self.last_network_stats.bytes_recv

            upload_speed = bytes_sent_diff / time_diff
            download_speed = bytes_recv_diff / time_diff

            # 添加到历史记录
            with self.traffic_lock:
                self.traffic_history.append({
                    'timestamp': current_time,
                    'upload_speed': upload_speed,
                    'download_speed': download_speed,
                    'total_upload': current_network_stats.bytes_sent,
                    'total_download': current_network_stats.bytes_recv,
                    'interface_stats': dict(current_interface_stats)
                })

            self.last_network_stats = current_network_stats
            self._last_system_update = current_time

        # 更新网络接口流量统计
        self._update_interface_traffic(current_interface_stats, current_time)

        # 异常检测和告警
        if self.alerts_enabled:
            self._check_traffic_alerts(upload_speed, download_speed, current_time)

        # 更新进程流量统计
        self._update_process_traffic(current_time)

    def _update_interface_traffic(self, current_interface_stats, current_time):
        """更新网络接口流量统计"""
        try:
            with self.traffic_lock:
                for interface, stats in current_interface_stats.items():
                    if interface in self.last_interface_stats:
                        last_stats = self.last_interface_stats[interface]
                        time_diff = current_time - self.interface_traffic[interface]['last_update']

                        if time_diff > 0:
                            bytes_sent_diff = stats.bytes_sent - last_stats['bytes_sent']
                            bytes_recv_diff = stats.bytes_recv - last_stats['bytes_recv']

                            # 更新接口流量速度（字节/秒）
                            self.interface_traffic[interface]['upload_speed'] = bytes_sent_diff / time_diff
                            self.interface_traffic[interface]['download_speed'] = bytes_recv_diff / time_diff

                            # 累计总流量
                            self.interface_traffic[interface]['upload'] += bytes_sent_diff
                            self.interface_traffic[interface]['download'] += bytes_recv_diff

                    self.interface_traffic[interface]['last_update'] = current_time

            self.last_interface_stats = {name: {
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv
            } for name, stats in current_interface_stats.items()}

        except Exception as e:
            self.log(f"更新接口流量统计时出错: {e}", logging.ERROR)

    def _check_traffic_alerts(self, upload_speed, download_speed, current_time):
        """检查流量异常并发送告警"""
        try:
            # 检查上传速度异常
            if upload_speed > self.upload_threshold:
                alert_key = 'high_upload'
                if self._should_send_alert(alert_key, current_time):
                    self.log(f"⚠️ 流量告警: 上传速度过高 - {self.format_bytes(upload_speed)}/s (阈值: {self.format_bytes(self.upload_threshold)}/s)", logging.WARNING)

            # 检查下载速度异常
            if download_speed > self.download_threshold:
                alert_key = 'high_download'
                if self._should_send_alert(alert_key, current_time):
                    self.log(f"⚠️ 流量告警: 下载速度过高 - {self.format_bytes(download_speed)}/s (阈值: {self.format_bytes(self.download_threshold)}/s)", logging.WARNING)

            # 检查接口流量异常
            with self.traffic_lock:
                for interface, stats in self.interface_traffic.items():
                    if stats['upload_speed'] > self.upload_threshold:
                        alert_key = f'high_upload_{interface}'
                        if self._should_send_alert(alert_key, current_time):
                            self.log(f"⚠️ 接口告警: {interface} 上传速度过高 - {self.format_bytes(stats['upload_speed'])}/s", logging.WARNING)

                    if stats['download_speed'] > self.download_threshold:
                        alert_key = f'high_download_{interface}'
                        if self._should_send_alert(alert_key, current_time):
                            self.log(f"⚠️ 接口告警: {interface} 下载速度过高 - {self.format_bytes(stats['download_speed'])}/s", logging.WARNING)

        except Exception as e:
            self.log(f"流量异常检测时出错: {e}", logging.ERROR)

    def _should_send_alert(self, alert_key, current_time):
        """检查是否应该发送告警（考虑冷却时间）"""
        if alert_key not in self.last_alert_time:
            self.last_alert_time[alert_key] = 0

        time_since_last = current_time - self.last_alert_time[alert_key]
        if time_since_last >= self.alert_cooldown:
            self.last_alert_time[alert_key] = current_time
            return True
        return False

    def set_alert_thresholds(self, upload_threshold=None, download_threshold=None, cooldown=None):
        """设置告警阈值"""
        if upload_threshold is not None:
            self.upload_threshold = upload_threshold
            self.log(f"上传告警阈值已设置为: {self.format_bytes(upload_threshold)}/s")

        if download_threshold is not None:
            self.download_threshold = download_threshold
            self.log(f"下载告警阈值已设置为: {self.format_bytes(download_threshold)}/s")

        if cooldown is not None:
            self.alert_cooldown = cooldown
            self.log(f"告警冷却时间已设置为: {cooldown}秒")

    def enable_alerts(self, enabled=True):
        """启用/禁用告警"""
        self.alerts_enabled = enabled
        status = "启用" if enabled else "禁用"
        self.log(f"流量告警已{status}")

    def _update_process_traffic(self, current_time):
        """更新进程流量统计"""
        current_process_stats = {}

        try:
            for proc in psutil.process_iter(['pid', 'name', 'io_counters']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    io_counters = proc.info['io_counters']

                    if io_counters:
                        current_process_stats[pid] = {
                            'name': name,
                            'bytes_sent': io_counters.bytes_sent,
                            'bytes_recv': io_counters.bytes_recv
                        }
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    continue

            # 更新进程流量速度
            with self.traffic_lock:
                for pid, current_stat in current_process_stats.items():
                    if pid in self.last_process_stats:
                        last_stat = self.last_process_stats[pid]
                        time_diff = current_time - self.process_traffic[pid]['last_update']

                        if time_diff > 0:
                            bytes_sent_diff = current_stat['bytes_sent'] - last_stat['bytes_sent']
                            bytes_recv_diff = current_stat['bytes_recv'] - last_stat['bytes_recv']

                            # 更新流量速度（字节/秒）
                            self.process_traffic[pid]['upload_speed'] = bytes_sent_diff / time_diff
                            self.process_traffic[pid]['download_speed'] = bytes_recv_diff / time_diff

                            # 累计总流量
                            self.process_traffic[pid]['upload'] += bytes_sent_diff
                            self.process_traffic[pid]['download'] += bytes_recv_diff

                    self.process_traffic[pid]['last_update'] = current_time

            self.last_process_stats = current_process_stats

        except Exception as e:
            self.log(f"更新进程流量统计时出错: {e}")

    def get_current_speed(self):
        """获取当前流量速度

        Returns:
            dict: 包含上传/下载速度信息的字典
        """
        with self.traffic_lock:
            if len(self.traffic_history) >= 1:
                latest = self.traffic_history[-1]
                return {
                    'upload_speed': latest['upload_speed'],
                    'download_speed': latest['download_speed'],
                    'upload_speed_human': self.format_bytes(latest['upload_speed']) + '/s',
                    'download_speed_human': self.format_bytes(latest['download_speed']) + '/s'
                }

        return {
            'upload_speed': 0,
            'download_speed': 0,
            'upload_speed_human': '0 B/s',
            'download_speed_human': '0 B/s'
        }

    def get_interface_stats(self, min_speed=1024):
        """获取网络接口流量统计

        Args:
            min_speed (int): 最小速度阈值（字节/秒），默认1KB/s

        Returns:
            list: 网络接口流量统计列表，按总流量排序
        """
        interface_stats = []

        with self.traffic_lock:
            for interface, stats in self.interface_traffic.items():
                # 过滤条件：速度达到阈值
                if (stats['upload_speed'] > min_speed or
                    stats['download_speed'] > min_speed or
                    stats['upload'] > 0 or
                    stats['download'] > 0):

                    interface_stats.append({
                        'interface': interface,
                        'upload_speed': stats['upload_speed'],
                        'download_speed': stats['download_speed'],
                        'total_upload': stats['upload'],
                        'total_download': stats['download'],
                        'upload_speed_human': self.format_bytes(stats['upload_speed']) + '/s',
                        'download_speed_human': self.format_bytes(stats['download_speed']) + '/s',
                        'upload_human': self.format_bytes(stats['upload']),
                        'download_human': self.format_bytes(stats['download'])
                    })

        # 按总流量排序
        interface_stats.sort(key=lambda x: x['total_upload'] + x['total_download'], reverse=True)
        return interface_stats

    def get_process_traffic_stats(self, min_speed=1024, min_total=1024*1024):
        """获取进程流量统计

        Args:
            min_speed (int): 最小速度阈值（字节/秒），默认1KB/s
            min_total (int): 最小总流量阈值（字节），默认1MB

        Returns:
            list: 进程流量统计列表，按总流量排序
        """
        process_stats = []

        with self.traffic_lock:
            for pid, stats in self.process_traffic.items():
                # 过滤条件：速度或总流量达到阈值
                if (stats['upload_speed'] > min_speed or
                    stats['download_speed'] > min_speed or
                    stats['upload'] > min_total or
                    stats['download'] > min_total):

                    try:
                        process = psutil.Process(pid)
                        name = process.name()
                    except:
                        name = f"PID_{pid}"

                    process_stats.append({
                        'pid': pid,
                        'name': name,
                        'upload_speed': stats['upload_speed'],
                        'download_speed': stats['download_speed'],
                        'total_upload': stats['upload'],
                        'total_download': stats['download'],
                        'upload_speed_human': self.format_bytes(stats['upload_speed']) + '/s',
                        'download_speed_human': self.format_bytes(stats['download_speed']) + '/s',
                        'upload_human': self.format_bytes(stats['upload']),
                        'download_human': self.format_bytes(stats['download'])
                    })

        # 按总流量排序
        process_stats.sort(key=lambda x: x['total_upload'] + x['total_download'], reverse=True)
        return process_stats

    def get_traffic_history(self, minutes=5):
        """获取流量历史记录

        Args:
            minutes (int): 获取最近多少分钟的历史记录

        Returns:
            list: 流量历史记录列表
        """
        history = []
        current_time = time.time()
        cutoff_time = current_time - minutes * 60

        with self.traffic_lock:
            for record in self.traffic_history:
                if record['timestamp'] >= cutoff_time:
                    history.append({
                        'time': datetime.fromtimestamp(record['timestamp']).strftime('%H:%M:%S'),
                        'timestamp': record['timestamp'],
                        'upload_speed': record['upload_speed'],
                        'download_speed': record['download_speed'],
                        'upload_speed_human': self.format_bytes(record['upload_speed']) + '/s',
                        'download_speed_human': self.format_bytes(record['download_speed']) + '/s'
                    })

        return history

    def get_traffic_summary(self, minutes=5):
        """获取流量统计摘要

        Args:
            minutes (int): 统计时间范围（分钟）

        Returns:
            dict: 流量统计摘要
        """
        history = self.get_traffic_history(minutes)

        if not history:
            return {
                'avg_upload_speed': 0,
                'avg_download_speed': 0,
                'max_upload_speed': 0,
                'max_download_speed': 0,
                'data_points': 0
            }

        upload_speeds = [record['upload_speed'] for record in history]
        download_speeds = [record['download_speed'] for record in history]

        return {
            'avg_upload_speed': sum(upload_speeds) / len(upload_speeds),
            'avg_download_speed': sum(download_speeds) / len(download_speeds),
            'max_upload_speed': max(upload_speeds),
            'max_download_speed': max(download_speeds),
            'data_points': len(history),
            'time_range': f'{minutes}分钟'
        }

    def format_bytes(self, bytes_value):
        """格式化字节数为人类可读格式

        Args:
            bytes_value (float): 字节数

        Returns:
            str: 格式化后的字符串
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"

    def export_history(self, filename, minutes=10, format='json'):
        """导出流量历史记录

        Args:
            filename (str): 导出文件名
            minutes (int): 导出的时间范围（分钟）
            format (str): 导出格式，支持 'json' 或 'csv'
        """
        history = self.get_traffic_history(minutes)

        if format.lower() == 'json':
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(history, f, ensure_ascii=False, indent=2)

        elif format.lower() == 'csv':
            import csv
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['时间', '上传速度(B/s)', '下载速度(B/s)', '上传速度(格式化)', '下载速度(格式化)'])
                for record in history:
                    writer.writerow([
                        record['time'],
                        record['upload_speed'],
                        record['download_speed'],
                        record['upload_speed_human'],
                        record['download_speed_human']
                    ])

        self.log(f"流量历史记录已导出到: {filename}")

    def export_process_traffic(self, filename, format='json'):
        """导出进程流量统计

        Args:
            filename (str): 导出文件名
            format (str): 导出格式，支持 'json' 或 'csv'
        """
        process_stats = self.get_process_traffic_stats()

        if format.lower() == 'json':
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(process_stats, f, ensure_ascii=False, indent=2)

        elif format.lower() == 'csv':
            import csv
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'PID', '进程名称', '上传速度(B/s)', '下载速度(B/s)',
                    '总上传(B)', '总下载(B)', '上传速度(格式化)',
                    '下载速度(格式化)', '总上传(格式化)', '总下载(格式化)'
                ])
                for record in process_stats:
                    writer.writerow([
                        record['pid'],
                        record['name'],
                        record['upload_speed'],
                        record['download_speed'],
                        record['total_upload'],
                        record['total_download'],
                        record['upload_speed_human'],
                        record['download_speed_human'],
                        record['upload_human'],
                        record['download_human']
                    ])

        self.log(f"进程流量统计已导出到: {filename}")

    def get_status_info(self):
        """获取监控状态信息

        Returns:
            dict: 包含监控状态信息的字典
        """
        current_speed = self.get_current_speed()
        summary = self.get_traffic_summary(5)
        process_count = len(self.get_process_traffic_stats())

        return {
            'monitoring': self.traffic_monitoring,
            'current_upload_speed': current_speed['upload_speed_human'],
            'current_download_speed': current_speed['download_speed_human'],
            'avg_upload_speed_5min': self.format_bytes(summary['avg_upload_speed']) + '/s',
            'avg_download_speed_5min': self.format_bytes(summary['avg_download_speed']) + '/s',
            'max_upload_speed_5min': self.format_bytes(summary['max_upload_speed']) + '/s',
            'max_download_speed_5min': self.format_bytes(summary['max_download_speed']) + '/s',
            'active_processes': process_count,
            'history_points': len(self.traffic_history),
            'uptime': f"{len(self.traffic_history)}秒" if self.traffic_history else "0秒"
        }


# 便捷函数
def create_traffic_monitor(history_length=300):
    """创建流量监控器实例的便捷函数

    Args:
        history_length (int): 历史记录长度（秒）

    Returns:
        TrafficMonitor: 流量监控器实例
    """
    return TrafficMonitor(history_length)


def main():
    """测试流量监控模块"""
    print("流量监控模块测试")
    print("=" * 50)

    # 创建监控器
    monitor = TrafficMonitor(history_length=60)  # 保存1分钟历史

    # 启动监控
    monitor.start_monitoring()

    print("监控已启动，将运行10秒进行测试...")

    # 运行10秒
    for i in range(10):
        time.sleep(1)
        speed = monitor.get_current_speed()
        print(f"第{i+1}秒: 上传 {speed['upload_speed_human']}, 下载 {speed['download_speed_human']}")

    # 显示统计信息
    print("\n流量统计摘要:")
    summary = monitor.get_traffic_summary(1)
    print(f"平均上传: {monitor.format_bytes(summary['avg_upload_speed'])}/s")
    print(f"平均下载: {monitor.format_bytes(summary['avg_download_speed'])}/s")
    print(f"最大上传: {monitor.format_bytes(summary['max_upload_speed'])}/s")
    print(f"最大下载: {monitor.format_bytes(summary['max_download_speed'])}/s")

    # 显示进程流量
    print("\n进程流量统计:")
    process_stats = monitor.get_process_traffic_stats()
    for i, proc in enumerate(process_stats[:5]):
        print(f"{i+1}. {proc['name']}: 上传 {proc['upload_speed_human']}, 下载 {proc['download_speed_human']}")

    # 停止监控
    monitor.stop_monitoring()
    print("\n测试完成")


# GUI界面功能
class TrafficMonitorGUI:
    """流量监控图形界面 - 集成版本"""

    def __init__(self, root=None):
        self.root = root
        if self.root is None:
            self.root = tk.Tk()
            self.root_created = True
        else:
            self.root_created = False

        self.monitor = TrafficMonitor(history_length=300)  # 保存5分钟历史

        # 设置窗口
        self.root.title("网络流量监控工具")
        self.root.geometry("900x700")
        self.root.resizable(True, True)

        # GUI状态
        self.monitoring = False
        self.update_thread = None
        self.update_interval = 1000  # 1秒更新一次

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

        # 流量历史显示（文本版本）
        history_frame = ttk.LabelFrame(realtime_frame, text="流量历史记录", padding=10)
        history_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # 创建历史记录文本框
        self.history_text = scrolledtext.ScrolledText(history_frame, height=15, wrap=tk.WORD, font=("Courier", 9))
        self.history_text.pack(fill=tk.BOTH, expand=True)

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

            # 更新历史记录显示
            self.root.after(0, self._update_history_display)

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

            # 更新总流量显示
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

    def _update_history_display(self):
        """更新历史记录显示"""
        try:
            # 获取最近20条历史记录
            history = self.monitor.get_traffic_history(5)

            # 清除现有内容
            self.history_text.delete(1.0, tk.END)

            # 添加标题
            self.history_text.insert(tk.END, "时间        \t上传速度\t下载速度\n", 'header')
            self.history_text.insert(tk.END, "-" * 50 + "\n", 'header')

            # 添加历史记录
            for record in history[-20:]:  # 显示最近20条记录
                line = f"{record['time']}\t{record['upload_speed_human']}\t{record['download_speed_human']}\n"
                self.history_text.insert(tk.END, line)

            # 滚动到底部
            self.history_text.see(tk.END)

        except Exception as e:
            print(f"[GUI] 更新历史记录显示时出错: {e}")

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
        self.alert_text.delete(1.0, tk.END)
        self.update_status("告警历史已清除")

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

    def run(self):
        """运行GUI"""
        # 更新时间显示
        def update_time():
            self.update_time()
            self.root.after(1000, update_time)

        update_time()
        self.root.mainloop()


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


def run_gui():
    """运行GUI界面"""
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox, scrolledtext
        gui = TrafficMonitorGUI()
        gui.run()
    except ImportError as e:
        print(f"GUI启动失败: {e}")
        print("请确保已安装tkinter库")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == '--cli':
        main()
    else:
        run_gui()