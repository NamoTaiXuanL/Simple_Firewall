#!/bin/bash
# Simple_Firewall启动脚本

# 切换到脚本所在目录
cd "$(dirname "$0")"

# 启动防火墙工具
exec python3 main.py "$@"