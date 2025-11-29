# Agent工作记录 - 终端启动问题修复

**时间**: 2025.11.27.09.48
**任务**: 修复agent每条命令都启动新终端的问题
**类型**: bug_fix

## 问题描述
Basic Shell Agent在执行每条命令时都会启动一个新的终端窗口，导致终端窗口过多，影响用户体验。

## 问题原因分析
1. basic_shell_agent.py:38 设置了 show_terminal=True
2. shell_interface.py:53-56 中，每次执行命令都会调用 _execute_in_terminal() 创建新终端
3. 缺少终端复用机制

## 修复方案（最小化改动）
1. 在ShellInterface.__init__中添加共享终端相关属性
2. 新增_execute_in_shared_terminal()方法
3. 修改execute_command()方法使用共享终端
4. 在cleanup()方法中添加共享终端清理逻辑

## 核心修改
- 只在第一次执行时创建终端窗口（使用_hasattr检查）
- 后续命令复用同一终端实例
- 保持原有功能完整性

## 测试结果
✓ 单次命令执行正常
✓ 多次命令不再启动多个终端
✓ basic_shell_agent整体功能正常
✓ 清理功能正常工作

修复完成，解决了终端窗口过多的问题。