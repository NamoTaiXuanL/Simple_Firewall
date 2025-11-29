# 项目名称项目组 作者Mamoniel 日期 2025.11.28 版本 1.0 API管理器模块剥离

## 任务内容
将basic_shell_agent.py中162-248行的API相关代码剥离出来作为独立的API管理器模块，使用_manager后缀。

## 重构内容
1. 创建api_manager.py模块，包含以下功能：
   - call_deepseek_api: 调用DeepSeek API，带重试机制
   - set_api_config: 设置API配置参数
   - get_api_status: 获取当前API配置状态
   - 完整的错误处理和重试逻辑

2. 修改basic_shell_agent.py主程序：
   - 导入ApiManager模块
   - 初始化API管理器
   - 使用API管理器替换原有的API相关代码
   - 删除原有的_call_deepseek_api方法

## 测试结果
- API管理器功能正常：配置状态获取正确，初始化成功
- 主程序导入成功：模块集成无问题
- 功能保持不变：所有API调用功能都被保留

## 优势
- 代码更模块化，便于维护
- API功能独立，方便扩展
- 统一使用_manager后缀，符合项目规范
- 增强了可配置性，支持动态调整API参数