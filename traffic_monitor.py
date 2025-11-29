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


if __name__ == "__main__":
    main()