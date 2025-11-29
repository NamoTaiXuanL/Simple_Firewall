# 进程网络检测工具开发记录

**任务**: 创建一个进程网络检测工具，主要监测进程的网络连接情况（端口、监听端口、远程连接等）
**时间**: 2025-11-29 11:43
**类型**: 开发

## 实现功能

### 核心功能 (最小化实现)
1. **监听端口检测** - 获取所有正在监听的进程和端口信息
2. **活跃连接检测** - 获取当前所有网络连接状态
3. **进程网络统计** - 统计每个进程的网络连接数量

### 支持的运行模式
- **GUI模式** - 图形界面，包含三个选项卡
  - 监听端口选项卡
  - 活跃连接选项卡
  - 进程网络选项卡
- **命令行模式** - 支持三种模式
  - 监听端口检测: `python3 network_monitor.py --cli listening`
  - 活跃连接检测: `python3 network_monitor.py --cli connections`
  - 进程网络统计: `python3 network_monitor.py --cli process`

## 技术实现

### 使用的库
- `psutil` - 获取系统进程和网络连接信息
- `tkinter` - GUI界面开发
- `socket` - 网络协议处理

### 核心类设计
- `NetworkMonitor` - 网络检测核心类
  - `get_listening_ports()` - 获取监听端口
  - `get_active_connections()` - 获取活跃连接
  - `get_process_network_info()` - 获取进程网络信息
- `NetworkMonitorGUI` - 图形界面类
  - 三个选项卡显示不同信息
  - 自动刷新功能
  - 可配置刷新间隔

## 测试结果

- ✅ 监听端口检测正常 (检测到5个监听端口)
- ✅ 活跃连接检测正常 (检测到136个活跃连接)
- ✅ 进程网络统计功能正常
- ✅ GUI界面加载正常
- ✅ 命令行模式运行正常

## 使用方法

1. **GUI模式**: `python3 network_monitor.py` 或运行 `./run_network_monitor.sh`
2. **命令行模式**: `python3 network_monitor.py --cli [mode]`
3. **快捷启动**: `./run_network_monitor.sh`

## 文件结构
- `network_monitor.py` - 主程序文件
- `run_network_monitor.sh` - 启动脚本
- 与现有 `ufw_manager.py` 和 `process_monitor.py` 集成

## 特点
- 实现最小化功能，只包含必要的网络检测功能
- 支持实时刷新，可配置刷新间隔
- 中文界面，符合项目要求
- 代码结构清晰，易于扩展