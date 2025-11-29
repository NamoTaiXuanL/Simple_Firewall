#!/bin/bash

# 进程网络检测工具启动脚本

echo "进程网络检测工具启动选项："
echo "1) GUI模式 - 图形界面 (默认)"
echo "2) 监听端口检测 - 命令行模式"
echo "3) 活跃连接检测 - 命令行模式"
echo "4) 进程网络统计 - 命令行模式"
echo "5) 退出"
echo ""

read -p "请选择模式 (1-5): " choice

case $choice in
    1)
        echo "启动GUI模式..."
        python3 network_monitor.py
        ;;
    2)
        echo "启动监听端口检测..."
        python3 network_monitor.py --cli listening
        ;;
    3)
        echo "启动活跃连接检测..."
        python3 network_monitor.py --cli connections
        ;;
    4)
        echo "启动进程网络统计..."
        python3 network_monitor.py --cli process
        ;;
    5)
        echo "退出"
        exit 0
        ;;
    *)
        echo "无效选择，启动默认GUI模式..."
        python3 network_monitor.py
        ;;
esac