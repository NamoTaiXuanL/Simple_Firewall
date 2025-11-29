# 防火墙工具调试功能增强记录

## 增强内容

### 1. UFW管理器调试功能
- **文件**: `ufw_manager.py`
- **功能**:
  - 添加日志记录系统（logging模块）
  - 详细的命令执行调试信息
  - 异常捕获和错误追踪
  - 自动创建时间戳调试日志文件

### 2. 图形界面调试面板
- **文件**: `firewall_gui.py`
- **功能**:
  - 实时调试信息显示面板
  - 调试信息保存功能
  - 界面操作状态追踪
  - 等宽字体便于查看日志

### 3. 命令行工具
- **文件**: `firewall_cli.py`
- **功能**:
  - 完整的命令行接口
  - 详细的调试输出
  - 多种操作支持（状态、规则、日志等）
  - UFW连接测试

### 4. 主程序增强
- **文件**: `main.py`
- **功能**:
  - 调试模式参数支持
  - 命令行模式选择
  - 参数解析和模式切换

## 使用方法

### 图形界面调试模式
```bash
python3 main.py --debug
```

### 命令行模式
```bash
# 普通模式
python3 main.py --cli status

# 调试模式
python3 main.py --cli --debug status
```

### 命令行工具直接使用
```bash
python3 firewall_cli.py --debug status
python3 firewall_cli.py --debug logs
python3 firewall_cli.py --debug test
```

## 调试文件位置
- UFW调试日志: `AGENTS/ufw_debug_YYYYMMDD_HHMMSS.log`
- GUI调试日志: `AGENTS/gui_debug_YYYYMMDD_HHMMSS.log`

## 调试信息级别
- **DEBUG**: 详细的执行步骤和命令输出
- **INFO**: 重要的操作状态和结果
- **ERROR**: 错误信息和异常处理

功能已全部完成，调试系统运行正常。