#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
进程网络检测工具
监测进程的网络连接情况（端口、监听端口、远程连接等）
实现最小化功能
"""

import psutil
import socket
import time
import os
import subprocess
from datetime import datetime, timedelta
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from collections import defaultdict, deque
import json

class NetworkMonitor:
    """进程网络检测核心类"""

    def __init__(self):
        self.refresh_interval = 3  # 3秒刷新间隔
        # 流量监控相关
        self.traffic_history = deque(maxlen=300)  # 保存5分钟历史记录（每秒记录）
        self.process_traffic = defaultdict(lambda: {'upload': 0, 'download': 0, 'upload_speed': 0, 'download_speed': 0, 'last_update': time.time()})
        self.last_network_stats = psutil.net_io_counters()
        self.last_process_stats = {}
        self.traffic_monitoring = False
        self.traffic_lock = threading.Lock()

    def log(self, message):
        """日志输出"""
        print(f"[网络监控] {message}")

    def get_listening_ports(self):
        """获取所有监听端口的进程"""
        listening_ports = []

        try:
            # 使用psutil获取所有网络连接
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_LISTEN:
                    try:
                        # 获取进程信息
                        process = psutil.Process(conn.pid) if conn.pid else None
                        if process:
                            # 获取进程名称
                            process_name = process.name()

                            # 获取本地地址和端口
                            local_addr = conn.laddr
                            ip = local_addr.ip
                            port = local_addr.port

                            # 获取协议类型
                            protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'

                            listening_ports.append({
                                'pid': conn.pid,
                                'name': process_name,
                                'protocol': protocol,
                                'address': f"{ip}:{port}",
                                'ip': ip,
                                'port': port,
                                'status': 'LISTEN'
                            })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

        except Exception as e:
            self.log(f"获取监听端口时出错: {e}")

        return listening_ports

    def get_active_connections(self):
        """获取活跃的网络连接"""
        active_connections = []

        try:
            # 获取所有网络连接
            for conn in psutil.net_connections(kind='inet'):
                if conn.status != psutil.CONN_LISTEN:
                    try:
                        # 获取进程信息
                        process = psutil.Process(conn.pid) if conn.pid else None
                        if process:
                            process_name = process.name()

                            # 获取连接信息
                            local_addr = conn.laddr
                            remote_addr = conn.raddr if conn.raddr else None

                            # 获取协议类型
                            protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'

                            # 获取状态
                            status_map = {
                                psutil.CONN_ESTABLISHED: 'ESTABLISHED',
                                psutil.CONN_SYN_SENT: 'SYN_SENT',
                                psutil.CONN_SYN_RECV: 'SYN_RECV',
                                psutil.CONN_FIN_WAIT1: 'FIN_WAIT1',
                                psutil.CONN_FIN_WAIT2: 'FIN_WAIT2',
                                psutil.CONN_TIME_WAIT: 'TIME_WAIT',
                                psutil.CONN_CLOSE: 'CLOSE',
                                psutil.CONN_CLOSE_WAIT: 'CLOSE_WAIT',
                                psutil.CONN_LAST_ACK: 'LAST_ACK',
                                psutil.CONN_LISTEN: 'LISTEN',
                                psutil.CONN_CLOSING: 'CLOSING'
                            }
                            status = status_map.get(conn.status, str(conn.status))

                            connection_info = {
                                'pid': conn.pid,
                                'name': process_name,
                                'protocol': protocol,
                                'local_address': f"{local_addr.ip}:{local_addr.port}",
                                'remote_address': f"{remote_addr.ip}:{remote_addr.port}" if remote_addr else "N/A",
                                'status': status
                            }

                            active_connections.append(connection_info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

        except Exception as e:
            self.log(f"获取活跃连接时出错: {e}")

        return active_connections

    def get_port_statistics(self):
        """获取端口使用统计"""
        port_stats = {}

        try:
            # 统计监听端口
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == psutil.CONN_LISTEN:
                    port = conn.laddr.port
                    if port not in port_stats:
                        port_stats[port] = {
                            'port': port,
                            'process_count': 0,
                            'processes': [],
                            'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                        }

                    try:
                        process = psutil.Process(conn.pid) if conn.pid else None
                        if process:
                            process_name = process.name()
                            if process_name not in port_stats[port]['processes']:
                                port_stats[port]['processes'].append(process_name)
                                port_stats[port]['process_count'] += 1
                    except:
                        pass

        except Exception as e:
            self.log(f"获取端口统计时出错: {e}")

        return list(port_stats.values())

    def start_traffic_monitoring(self):
        """开始流量监控"""
        if not self.traffic_monitoring:
            self.traffic_monitoring = True
            thread = threading.Thread(target=self._traffic_monitor_worker, daemon=True)
            thread.start()
            self.log("流量监控已启动")

    def stop_traffic_monitoring(self):
        """停止流量监控"""
        self.traffic_monitoring = False

    def _traffic_monitor_worker(self):
        """流量监控工作线程"""
        while self.traffic_monitoring:
            try:
                self._update_traffic_stats()
                time.sleep(1)  # 每秒更新一次
            except Exception as e:
                self.log(f"流量监控出错: {e}")
                time.sleep(1)

    def _update_traffic_stats(self):
        """更新流量统计"""
        current_time = time.time()

        # 获取系统总流量
        current_network_stats = psutil.net_io_counters()

        # 计算系统流量速度（字节/秒）
        time_diff = current_time - getattr(self, '_last_system_update', current_time)
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
                    'total_download': current_network_stats.bytes_recv
                })

            self.last_network_stats = current_network_stats
            self._last_system_update = current_time

        # 更新进程流量统计
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

    def get_current_traffic_speed(self):
        """获取当前流量速度"""
        with self.traffic_lock:
            if len(self.traffic_history) >= 2:
                latest = self.traffic_history[-1]
                return {
                    'upload_speed': latest['upload_speed'],
                    'download_speed': latest['download_speed'],
                    'upload_speed_human': self._format_bytes(latest['upload_speed']) + '/s',
                    'download_speed_human': self._format_bytes(latest['download_speed']) + '/s'
                }
        return {
            'upload_speed': 0,
            'download_speed': 0,
            'upload_speed_human': '0 B/s',
            'download_speed_human': '0 B/s'
        }

    def get_process_traffic_stats(self):
        """获取进程流量统计"""
        process_stats = []

        with self.traffic_lock:
            for pid, stats in self.process_traffic.items():
                # 跳过流量太小的进程
                if stats['upload_speed'] > 1024 or stats['download_speed'] > 1024 or stats['upload'] > 1024*1024 or stats['download'] > 1024*1024:
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
                        'upload_speed_human': self._format_bytes(stats['upload_speed']) + '/s',
                        'download_speed_human': self._format_bytes(stats['download_speed']) + '/s',
                        'upload_human': self._format_bytes(stats['upload']),
                        'download_human': self._format_bytes(stats['download'])
                    })

        # 按总流量排序
        process_stats.sort(key=lambda x: x['total_upload'] + x['total_download'], reverse=True)
        return process_stats

    def get_traffic_history(self, minutes=5):
        """获取流量历史记录"""
        history = []
        current_time = time.time()
        cutoff_time = current_time - minutes * 60

        with self.traffic_lock:
            for record in self.traffic_history:
                if record['timestamp'] >= cutoff_time:
                    history.append({
                        'time': datetime.fromtimestamp(record['timestamp']).strftime('%H:%M:%S'),
                        'upload_speed': record['upload_speed'],
                        'download_speed': record['download_speed'],
                        'upload_speed_human': self._format_bytes(record['upload_speed']) + '/s',
                        'download_speed_human': self._format_bytes(record['download_speed']) + '/s'
                    })

        return history

    def _format_bytes(self, bytes_value):
        """格式化字节数为人类可读格式"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"

    def get_process_network_info(self, pid=None):
        """获取指定进程或所有进程的网络信息"""
        network_info = []

        try:
            # 如果指定了PID，只获取该进程的信息
            if pid:
                processes = [psutil.Process(pid)]
            else:
                processes = psutil.process_iter(['pid', 'name'])

            for proc in processes:
                try:
                    if isinstance(proc, dict):
                        proc = psutil.Process(proc.info['pid'])

                    # 获取该进程的所有网络连接
                    connections = proc.connections(kind='inet')

                    if connections:
                        listening_count = 0
                        established_count = 0

                        for conn in connections:
                            if conn.status == psutil.CONN_LISTEN:
                                listening_count += 1
                            elif conn.status == psutil.CONN_ESTABLISHED:
                                established_count += 1

                        # 获取流量信息
                        traffic_info = {'upload_speed': 0, 'download_speed': 0, 'total_upload': 0, 'total_download': 0}
                        if proc.pid in self.process_traffic:
                            traffic_info = self.process_traffic[proc.pid]

                        network_info.append({
                            'pid': proc.pid,
                            'name': proc.name(),
                            'listening_ports': listening_count,
                            'active_connections': established_count,
                            'total_connections': len(connections),
                            'upload_speed': traffic_info['upload_speed'],
                            'download_speed': traffic_info['download_speed'],
                            'total_upload': traffic_info['upload'],
                            'total_download': traffic_info['download']
                        })

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            self.log(f"获取进程网络信息时出错: {e}")

        return network_info

    def display_listening_ports(self, limit=20):
        """显示监听端口信息（命令行模式）"""
        # 清屏
        os.system('clear' if os.name == 'posix' else 'cls')

        print("=" * 120)
        print(f"{'进程网络检测 - 监听端口':^120}")
        print(f"{'更新时间: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^120}")
        print("=" * 120)

        # 获取监听端口信息
        listening_ports = self.get_listening_ports()

        # 按端口排序
        listening_ports.sort(key=lambda x: x['port'])

        # 显示表头
        print(f"{'PID':<8} {'进程名称':<20} {'协议':<8} {'IP地址:端口':<25} {'状态':<12}")
        print("-" * 120)

        # 显示监听端口
        for port_info in listening_ports[:limit]:
            print(f"{port_info['pid']:<8} {port_info['name'][:18]:<20} "
                  f"{port_info['protocol']:<8} {port_info['address']:<25} "
                  f"{port_info['status']:<12}")

        print(f"\n显示前 {limit} 个监听端口 (总计 {len(listening_ports)} 个)")
        print("按 Ctrl+C 退出")

    def display_active_connections(self, limit=20):
        """显示活跃连接信息（命令行模式）"""
        # 清屏
        os.system('clear' if os.name == 'posix' else 'cls')

        print("=" * 140)
        print(f"{'进程网络检测 - 活跃连接':^140}")
        print(f"{'更新时间: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^140}")
        print("=" * 140)

        # 获取活跃连接信息
        active_connections = self.get_active_connections()

        # 按进程名称排序
        active_connections.sort(key=lambda x: x['name'])

        # 显示表头
        print(f"{'PID':<8} {'进程名称':<20} {'协议':<8} {'本地地址':<25} {'远程地址':<25} {'状态':<15}")
        print("-" * 140)

        # 显示活跃连接
        for conn in active_connections[:limit]:
            print(f"{conn['pid']:<8} {conn['name'][:18]:<20} "
                  f"{conn['protocol']:<8} {conn['local_address']:<25} "
                  f"{conn['remote_address']:<25} {conn['status']:<15}")

        print(f"\n显示前 {limit} 个活跃连接 (总计 {len(active_connections)} 个)")
        print("按 Ctrl+C 退出")

    def run_cli(self, mode='listening'):
        """运行命令行模式"""
        print("进程网络检测工具 - 命令行模式")
        print(f"监控模式: {mode}")

        # 如果是流量监控模式，启动流量监控
        if mode in ['traffic', 'process-traffic']:
            print("启动流量监控...")
            self.start_traffic_monitoring()

        try:
            while True:
                if mode == 'listening':
                    self.display_listening_ports()
                elif mode == 'connections':
                    self.display_active_connections()
                elif mode == 'process':
                    self.display_process_network()
                elif mode == 'traffic':
                    self.display_traffic_info()
                elif mode == 'process-traffic':
                    self.display_process_traffic_cli()
                time.sleep(self.refresh_interval)

        except KeyboardInterrupt:
            print("\n\n程序已退出")
        except Exception as e:
            print(f"\n运行时出错: {e}")
        finally:
            # 停止流量监控
            if mode in ['traffic', 'process-traffic']:
                self.stop_traffic_monitoring()

    def display_traffic_info(self):
        """显示流量信息（命令行模式）"""
        # 清屏
        os.system('clear' if os.name == 'posix' else 'cls')

        print("=" * 100)
        print(f"{'进程网络检测 - 实时流量':^100}")
        print(f"{'更新时间: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^100}")
        print("=" * 100)

        # 获取流量信息
        traffic_speed = self.get_current_traffic_speed()

        # 显示流量信息
        print(f"{'上传速度:':<15} {traffic_speed['upload_speed_human']:^30} {'下载速度:':<15} {traffic_speed['download_speed_human']:^30}")
        print("-" * 100)

        # 显示流量历史
        print("\n流量历史趋势（最近10次记录）:")
        history = self.get_traffic_history(minutes=1)
        if history:
            print(f"{'时间':<12} {'上传速度':<20} {'下载速度':<20}")
            print("-" * 60)
            for record in history[-10:]:
                print(f"{record['time']:<12} {record['upload_speed_human']:<20} {record['download_speed_human']:<20}")
        else:
            print("暂无流量历史数据")

        print(f"\n刷新间隔: {self.refresh_interval}秒 | 按Ctrl+C退出")

    def display_process_traffic_cli(self):
        """显示进程流量统计（命令行模式）"""
        # 清屏
        os.system('clear' if os.name == 'posix' else 'cls')

        print("=" * 120)
        print(f"{'进程网络检测 - 进程流量统计':^120}")
        print(f"{'更新时间: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^120}")
        print("=" * 120)

        # 获取进程流量数据
        process_traffic = self.get_process_traffic_stats()

        # 显示表头
        print(f"{'PID':<8} {'进程名称':<25} {'上传速度':<15} {'下载速度':<15} {'总上传':<15} {'总下载':<15}")
        print("-" * 120)

        # 显示进程流量信息
        for traffic_info in process_traffic[:20]:  # 显示前20个
            print(f"{traffic_info['pid']:<8} {traffic_info['name'][:23]:<25} "
                  f"{traffic_info['upload_speed_human']:<15} {traffic_info['download_speed_human']:<15} "
                  f"{traffic_info['upload_human']:<15} {traffic_info['download_human']:<15}")

        print(f"\n显示前 {len(process_traffic[:20])} 个进程 (总计 {len(process_traffic)} 个活跃进程)")
        print(f"刷新间隔: {self.refresh_interval}秒 | 按Ctrl+C退出")

    def display_process_network(self, limit=20):
        """显示进程网络信息（命令行模式）"""
        # 清屏
        os.system('clear' if os.name == 'posix' else 'cls')

        print("=" * 100)
        print(f"{'进程网络检测 - 进程网络统计':^100}")
        print(f"{'更新时间: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'):^100}")
        print("=" * 100)

        # 获取进程网络信息
        network_info = self.get_process_network_info()

        # 按连接数排序
        network_info.sort(key=lambda x: x['total_connections'], reverse=True)

        # 显示表头
        print(f"{'PID':<8} {'进程名称':<20} {'监听端口':<10} {'活跃连接':<10} {'总连接数':<10}")
        print("-" * 100)

        # 显示进程网络信息
        for proc_info in network_info[:limit]:
            print(f"{proc_info['pid']:<8} {proc_info['name'][:18]:<20} "
                  f"{proc_info['listening_ports']:<10} {proc_info['active_connections']:<10} "
                  f"{proc_info['total_connections']:<10}")

        print(f"\n显示前 {limit} 个进程 (总计 {len(network_info)} 个网络活跃进程)")
        print("按 Ctrl+C 退出")


class NetworkMonitorGUI:
    """进程网络检测GUI界面"""

    def __init__(self):
        self.monitor = NetworkMonitor()
        self.root = tk.Tk()
        self.setup_window()
        self.create_widgets()
        self.is_updating = False
        self.traffic_chart_data = {'time': [], 'upload': [], 'download': []}

    def setup_window(self):
        """设置主窗口"""
        self.root.title("进程网络检测工具")
        self.root.geometry("1400x800")
        self.root.resizable(True, True)

        # 设置关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self):
        """创建界面组件"""
        # 创建主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 创建选项卡
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 创建监听端口选项卡
        self.create_listening_tab()

        # 创建活跃连接选项卡
        self.create_connections_tab()

        # 创建进程网络选项卡
        self.create_process_tab()

        # 创建流量监控选项卡
        self.create_traffic_tab()

        # 创建流量统计选项卡
        self.create_process_traffic_tab()

        # 创建控制面板
        self.create_control_panel(main_frame)

    def create_listening_tab(self):
        """创建监听端口选项卡"""
        listening_frame = ttk.Frame(self.notebook)
        self.notebook.add(listening_frame, text="监听端口")

        # 创建Treeview
        columns = ('PID', '进程名称', '协议', 'IP地址', '端口', '状态')
        self.listening_tree = ttk.Treeview(listening_frame, columns=columns, show='headings', height=20)

        # 设置列标题和宽度
        column_widths = {'PID': 80, '进程名称': 200, '协议': 80, 'IP地址': 150, '端口': 80, '状态': 100}

        for col in columns:
            self.listening_tree.heading(col, text=col, command=lambda c=col: self.sort_listening_by_column(c))
            self.listening_tree.column(col, width=column_widths.get(col, 100), anchor=tk.CENTER)

        # 添加滚动条
        listening_scrollbar = ttk.Scrollbar(listening_frame, orient=tk.VERTICAL, command=self.listening_tree.yview)
        self.listening_tree.configure(yscrollcommand=listening_scrollbar.set)

        # 布局
        self.listening_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        listening_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def create_connections_tab(self):
        """创建活跃连接选项卡"""
        connections_frame = ttk.Frame(self.notebook)
        self.notebook.add(connections_frame, text="活跃连接")

        # 创建Treeview
        columns = ('PID', '进程名称', '协议', '本地地址', '远程地址', '状态')
        self.connections_tree = ttk.Treeview(connections_frame, columns=columns, show='headings', height=20)

        # 设置列标题和宽度
        column_widths = {'PID': 80, '进程名称': 180, '协议': 80, '本地地址': 150, '远程地址': 150, '状态': 120}

        for col in columns:
            self.connections_tree.heading(col, text=col)
            self.connections_tree.column(col, width=column_widths.get(col, 100), anchor=tk.CENTER)

        # 添加滚动条
        connections_scrollbar = ttk.Scrollbar(connections_frame, orient=tk.VERTICAL, command=self.connections_tree.yview)
        self.connections_tree.configure(yscrollcommand=connections_scrollbar.set)

        # 布局
        self.connections_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        connections_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def create_process_tab(self):
        """创建进程网络选项卡"""
        process_frame = ttk.Frame(self.notebook)
        self.notebook.add(process_frame, text="进程网络")

        # 创建Treeview
        columns = ('PID', '进程名称', '监听端口', '活跃连接', '总连接数')
        self.process_tree = ttk.Treeview(process_frame, columns=columns, show='headings', height=20)

        # 设置列标题和宽度
        column_widths = {'PID': 80, '进程名称': 200, '监听端口': 100, '活跃连接': 100, '总连接数': 100}

        for col in columns:
            self.process_tree.heading(col, text=col, command=lambda c=col: self.sort_process_by_column(c))
            self.process_tree.column(col, width=column_widths.get(col, 100), anchor=tk.CENTER)

        # 添加滚动条
        process_scrollbar = ttk.Scrollbar(process_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=process_scrollbar.set)

        # 布局
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        process_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def create_traffic_tab(self):
        """创建流量监控选项卡"""
        traffic_frame = ttk.Frame(self.notebook)
        self.notebook.add(traffic_frame, text="实时流量")

        # 创建流量显示面板
        traffic_info_frame = ttk.LabelFrame(traffic_frame, text="当前流量速度", padding=10)
        traffic_info_frame.pack(fill=tk.X, padx=5, pady=5)

        # 上传速度显示
        upload_frame = ttk.Frame(traffic_info_frame)
        upload_frame.pack(fill=tk.X, pady=5)
        ttk.Label(upload_frame, text="上传速度:", width=15).pack(side=tk.LEFT)
        self.upload_speed_var = tk.StringVar(value="0 B/s")
        self.upload_label = ttk.Label(upload_frame, textvariable=self.upload_speed_var, foreground="red", font=("Arial", 14, "bold"))
        self.upload_label.pack(side=tk.LEFT)
        self.upload_progress = ttk.Progressbar(upload_frame, length=300, mode='determinate', maximum=10485760)  # 10MB/s
        self.upload_progress.pack(side=tk.LEFT, padx=10)

        # 下载速度显示
        download_frame = ttk.Frame(traffic_info_frame)
        download_frame.pack(fill=tk.X, pady=5)
        ttk.Label(download_frame, text="下载速度:", width=15).pack(side=tk.LEFT)
        self.download_speed_var = tk.StringVar(value="0 B/s")
        self.download_label = ttk.Label(download_frame, textvariable=self.download_speed_var, foreground="green", font=("Arial", 14, "bold"))
        self.download_label.pack(side=tk.LEFT)
        self.download_progress = ttk.Progressbar(download_frame, length=300, mode='determinate', maximum=10485760)  # 10MB/s
        self.download_progress.pack(side=tk.LEFT, padx=10)

        # 创建流量历史图表
        chart_frame = ttk.LabelFrame(traffic_frame, text="流量历史趋势（最近5分钟）", padding=10)
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 创建图表画布
        self.traffic_canvas = tk.Canvas(chart_frame, bg='white', height=300)
        self.traffic_canvas.pack(fill=tk.BOTH, expand=True)

        # 图例
        legend_frame = ttk.Frame(chart_frame)
        legend_frame.pack(fill=tk.X, pady=5)
        ttk.Label(legend_frame, text="■", foreground="red").pack(side=tk.LEFT, padx=5)
        ttk.Label(legend_frame, text="上传速度").pack(side=tk.LEFT, padx=5)
        ttk.Label(legend_frame, text="■", foreground="green").pack(side=tk.LEFT, padx=20)
        ttk.Label(legend_frame, text="下载速度").pack(side=tk.LEFT, padx=5)

    def create_process_traffic_tab(self):
        """创建进程流量统计选项卡"""
        process_traffic_frame = ttk.Frame(self.notebook)
        self.notebook.add(process_traffic_frame, text="进程流量")

        # 创建Treeview
        columns = ('PID', '进程名称', '上传速度', '下载速度', '总上传', '总下载')
        self.process_traffic_tree = ttk.Treeview(process_traffic_frame, columns=columns, show='headings', height=20)

        # 设置列标题和宽度
        column_widths = {
            'PID': 80,
            '进程名称': 200,
            '上传速度': 120,
            '下载速度': 120,
            '总上传': 120,
            '总下载': 120
        }

        for col in columns:
            self.process_traffic_tree.heading(col, text=col, command=lambda c=col: self.sort_process_traffic_by_column(c))
            self.process_traffic_tree.column(col, width=column_widths.get(col, 100), anchor=tk.CENTER)

        # 添加滚动条
        process_traffic_scrollbar = ttk.Scrollbar(process_traffic_frame, orient=tk.VERTICAL, command=self.process_traffic_tree.yview)
        self.process_traffic_tree.configure(yscrollcommand=process_traffic_scrollbar.set)

        # 布局
        self.process_traffic_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        process_traffic_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 绑定双击事件
        self.process_traffic_tree.bind('<Double-1>', self.on_process_traffic_double_click)

    def draw_traffic_chart(self):
        """绘制流量历史图表"""
        try:
            # 获取流量历史数据
            history = self.monitor.get_traffic_history(minutes=5)

            if len(history) < 2:
                return

            # 清除画布
            self.traffic_canvas.delete("all")

            # 获取画布尺寸
            canvas_width = self.traffic_canvas.winfo_width()
            canvas_height = self.traffic_canvas.winfo_height()

            if canvas_width <= 1 or canvas_height <= 1:
                return

            # 设置边距
            margin = 40
            chart_width = canvas_width - 2 * margin
            chart_height = canvas_height - 2 * margin

            # 找出最大值用于缩放
            max_upload = max(1, max(record['upload_speed'] for record in history))
            max_download = max(1, max(record['download_speed'] for record in history))
            max_speed = max(max_upload, max_download)

            # 绘制坐标轴
            self.traffic_canvas.create_line(margin, margin, margin, canvas_height - margin, fill="black")  # Y轴
            self.traffic_canvas.create_line(margin, canvas_height - margin, canvas_width - margin, canvas_height - margin, fill="black")  # X轴

            # 绘制刻度标签
            for i in range(5):
                y = margin + i * chart_height / 4
                speed_label = self.monitor._format_bytes(max_speed * (1 - i/4)) + "/s"
                self.traffic_canvas.create_text(margin - 5, y, text=speed_label, anchor="e", font=("Arial", 8))

            # 绘制数据点和连线
            if len(history) > 0:
                # 上传速度曲线
                upload_points = []
                download_points = []

                for i, record in enumerate(history):
                    x = margin + i * chart_width / (len(history) - 1)
                    upload_y = canvas_height - margin - (record['upload_speed'] / max_speed) * chart_height
                    download_y = canvas_height - margin - (record['download_speed'] / max_speed) * chart_height

                    upload_points.extend([x, upload_y])
                    download_points.extend([x, download_y])

                # 绘制上传速度曲线
                if len(upload_points) >= 4:
                    self.traffic_canvas.create_line(upload_points, fill="red", width=2, smooth=True)

                # 绘制下载速度曲线
                if len(download_points) >= 4:
                    self.traffic_canvas.create_line(download_points, fill="green", width=2, smooth=True)

        except Exception as e:
            print(f"绘制流量图表出错: {e}")

    def update_traffic_info(self):
        """更新流量信息"""
        try:
            # 获取当前流量速度
            traffic_speed = self.monitor.get_current_traffic_speed()

            # 更新显示
            self.upload_speed_var.set(traffic_speed['upload_speed_human'])
            self.download_speed_var.set(traffic_speed['download_speed_human'])

            # 更新进度条（最大值为10MB/s）
            max_bandwidth = 10 * 1024 * 1024  # 10MB/s in bytes
            self.upload_progress['value'] = min(traffic_speed['upload_speed'], max_bandwidth)
            self.download_progress['value'] = min(traffic_speed['download_speed'], max_bandwidth)

        except Exception as e:
            self.status_var.set(f"更新流量信息时出错: {e}")

    def update_process_traffic(self):
        """更新进程流量统计"""
        try:
            # 清空现有项目
            for item in self.process_traffic_tree.get_children():
                self.process_traffic_tree.delete(item)

            # 获取进程流量数据
            process_traffic = self.monitor.get_process_traffic_stats()

            # 添加到Treeview
            for traffic_info in process_traffic:
                values = (
                    traffic_info['pid'],
                    traffic_info['name'][:30],  # 限制名称长度
                    traffic_info['upload_speed_human'],
                    traffic_info['download_speed_human'],
                    traffic_info['upload_human'],
                    traffic_info['download_human']
                )
                self.process_traffic_tree.insert('', tk.END, values=values)

            return len(process_traffic)

        except Exception as e:
            self.status_var.set(f"更新进程流量统计时出错: {e}")
            return 0

    def on_process_traffic_double_click(self, event):
        """进程流量双击事件"""
        selected_item = self.process_traffic_tree.selection()
        if selected_item:
            item = self.process_traffic_tree.item(selected_item[0])
            pid = int(item['values'][0])
            process_name = item['values'][1]

            # 获取详细的流量信息
            try:
                if pid in self.monitor.process_traffic:
                    traffic_info = self.monitor.process_traffic[pid]
                    details = f"进程: {process_name}\n"
                    details += f"PID: {pid}\n"
                    details += f"当前上传速度: {self.monitor._format_bytes(traffic_info['upload_speed'])}/s\n"
                    details += f"当前下载速度: {self.monitor._format_bytes(traffic_info['download_speed'])}/s\n"
                    details += f"累计上传: {self.monitor._format_bytes(traffic_info['upload'])}\n"
                    details += f"累计下载: {self.monitor._format_bytes(traffic_info['download'])}\n"

                    messagebox.showinfo(f"流量详情 - {process_name}", details)
            except Exception as e:
                messagebox.showerror("错误", f"获取流量详情时出错: {e}")

    def sort_process_traffic_by_column(self, column):
        """进程流量排序"""
        # 这里可以实现排序逻辑，为了最小化实现，暂时不实现
        pass

    def create_control_panel(self, parent):
        """创建控制面板"""
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        # 左侧按钮组
        left_frame = ttk.Frame(control_frame)
        left_frame.pack(side=tk.LEFT)

        # 刷新按钮
        self.refresh_btn = ttk.Button(left_frame, text="刷新", command=self.refresh_all_data)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)

        # 刷新间隔设置
        ttk.Label(left_frame, text="刷新间隔(秒):").pack(side=tk.LEFT, padx=5)
        self.interval_var = tk.StringVar(value="3")
        interval_spin = ttk.Spinbox(left_frame, from_=1, to=10, textvariable=self.interval_var, width=5)
        interval_spin.pack(side=tk.LEFT, padx=5)

        # 自动刷新复选框
        self.auto_refresh_var = tk.BooleanVar(value=True)
        auto_refresh_check = ttk.Checkbutton(left_frame, text="自动刷新",
                                           variable=self.auto_refresh_var,
                                           command=self.toggle_auto_refresh)
        auto_refresh_check.pack(side=tk.LEFT, padx=5)

        # 右侧状态信息
        right_frame = ttk.Frame(control_frame)
        right_frame.pack(side=tk.RIGHT)

        # 状态标签
        self.status_var = tk.StringVar(value="就绪")
        status_label = ttk.Label(right_frame, textvariable=self.status_var)
        status_label.pack(side=tk.RIGHT, padx=5)

        # 更新时间标签
        self.time_var = tk.StringVar(value="")
        time_label = ttk.Label(right_frame, textvariable=self.time_var)
        time_label.pack(side=tk.RIGHT, padx=5)

    def update_listening_ports(self):
        """更新监听端口数据"""
        try:
            # 清空现有项目
            for item in self.listening_tree.get_children():
                self.listening_tree.delete(item)

            # 获取监听端口数据
            listening_ports = self.monitor.get_listening_ports()

            # 添加到Treeview
            for port_info in listening_ports:
                values = (
                    port_info['pid'],
                    port_info['name'],
                    port_info['protocol'],
                    port_info['ip'],
                    port_info['port'],
                    port_info['status']
                )
                self.listening_tree.insert('', tk.END, values=values)

            return len(listening_ports)

        except Exception as e:
            self.status_var.set(f"更新监听端口数据时出错: {e}")
            return 0

    def update_active_connections(self):
        """更新活跃连接数据"""
        try:
            # 清空现有项目
            for item in self.connections_tree.get_children():
                self.connections_tree.delete(item)

            # 获取活跃连接数据
            active_connections = self.monitor.get_active_connections()

            # 添加到Treeview
            for conn in active_connections:
                values = (
                    conn['pid'],
                    conn['name'],
                    conn['protocol'],
                    conn['local_address'],
                    conn['remote_address'],
                    conn['status']
                )
                self.connections_tree.insert('', tk.END, values=values)

            return len(active_connections)

        except Exception as e:
            self.status_var.set(f"更新活跃连接数据时出错: {e}")
            return 0

    def update_process_network(self):
        """更新进程网络数据"""
        try:
            # 清空现有项目
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)

            # 获取进程网络数据
            network_info = self.monitor.get_process_network_info()

            # 添加到Treeview
            for proc_info in network_info:
                values = (
                    proc_info['pid'],
                    proc_info['name'],
                    proc_info['listening_ports'],
                    proc_info['active_connections'],
                    proc_info['total_connections']
                )
                self.process_tree.insert('', tk.END, values=values)

            return len(network_info)

        except Exception as e:
            self.status_var.set(f"更新进程网络数据时出错: {e}")
            return 0

    def refresh_all_data(self):
        """刷新所有数据"""
        if self.is_updating:
            return

        self.is_updating = True
        self.status_var.set("正在更新...")

        try:
            # 更新时间
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.time_var.set(f"更新时间: {current_time}")

            # 更新各选项卡数据
            listening_count = self.update_listening_ports()
            connections_count = self.update_active_connections()
            process_count = self.update_process_network()

            # 更新流量监控数据
            self.update_traffic_info()
            self.draw_traffic_chart()
            process_traffic_count = self.update_process_traffic()

            # 更新状态
            self.status_var.set(f"监听端口: {listening_count} | 活跃连接: {connections_count} | 网络进程: {process_count} | 流量进程: {process_traffic_count}")

        except Exception as e:
            self.status_var.set(f"刷新数据时出错: {e}")
        finally:
            self.is_updating = False

    def auto_refresh(self):
        """自动刷新"""
        if self.auto_refresh_var.get() and not self.is_updating:
            try:
                self.refresh_all_data()
                # 获取刷新间隔
                interval = int(self.interval_var.get()) * 1000
                self.root.after(interval, self.auto_refresh)
            except Exception as e:
                print(f"自动刷新时出错: {e}")

    def toggle_auto_refresh(self):
        """切换自动刷新"""
        if self.auto_refresh_var.get():
            self.auto_refresh()
        else:
            self.status_var.set("自动刷新已停止")

    def sort_listening_by_column(self, column):
        """监听端口排序"""
        # 这里可以实现排序逻辑，为了最小化实现，暂时不实现
        pass

    def sort_process_by_column(self, column):
        """进程网络排序"""
        # 这里可以实现排序逻辑，为了最小化实现，暂时不实现
        pass

    def on_closing(self):
        """窗口关闭事件"""
        self.auto_refresh_var.set(False)
        self.monitor.stop_traffic_monitoring()
        self.root.destroy()

    def run(self):
        """运行GUI"""
        print("[GUI] 开始初始化图形界面...")

        # 启动流量监控
        print("[GUI] 启动流量监控...")
        self.monitor.start_traffic_monitoring()

        # 初始数据
        print("[GUI] 正在加载初始数据...")
        self.refresh_all_data()

        # 确保窗口显示
        print("[GUI] 正在显示窗口...")
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

        # 启动自动刷新
        print("[GUI] 启动自动刷新...")
        self.auto_refresh()

        print("[GUI] 进入主循环...")
        # 运行主循环
        self.root.mainloop()


def main():
    """主函数"""
    import sys

    print(f"[MAIN] 启动参数: {sys.argv}")

    # 检查命令行参数
    if len(sys.argv) > 1 and sys.argv[1] == '--cli':
        # 命令行模式
        print("[MAIN] 启动命令行模式")
        mode = 'listening'  # 默认显示监听端口
        if len(sys.argv) > 2:
            mode = sys.argv[2]

        monitor = NetworkMonitor()
        monitor.run_cli(mode)
    else:
        # GUI模式（默认）
        print("[MAIN] 启动GUI模式")
        try:
            print("[MAIN] 正在创建GUI实例...")
            app = NetworkMonitorGUI()
            print("[MAIN] GUI实例创建成功，开始运行...")
            app.run()
        except Exception as e:
            print(f"[ERROR] 启动GUI时出错: {e}")
            import traceback
            traceback.print_exc()
            print("[MAIN] 切换到命令行模式...")
            monitor = NetworkMonitor()
            monitor.run_cli()


if __name__ == "__main__":
    main()