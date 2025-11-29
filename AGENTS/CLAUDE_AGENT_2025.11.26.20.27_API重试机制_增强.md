# API重试机制增强

## 任务概述
为basic_shell_agent.py增加API调用重试机制，解决网络超时和连接问题

## 问题背景
原始API调用遇到超时问题：
```
ERROR: API调用错误: HTTPSConnectionPool(host='api.deepseek.com', port=443): Read timed out.
```

## 实现内容

### 1. 导入time模块
增加时间控制功能：
```python
import time
```

### 2. 重试机制设计
- 重试次数：3次
- 重试延迟：5秒, 10秒, 15秒（递增）
- 超时时间：增加到60秒
- SSL验证：确保安全连接

### 3. 错误分类处理

#### 可重试错误：
- `requests.exceptions.Timeout` (API调用超时)
- `requests.exceptions.ConnectionError` (网络连接错误)
- `requests.exceptions.HTTPError` (仅5xx服务器错误)

#### 不可重试错误：
- HTTP 4xx客户端错误
- `KeyError, ValueError, json.JSONDecodeError` (响应解析错误)
- 其他未知错误

### 4. 重试逻辑
```python
for attempt in range(max_retries + 1):  # 包括初始尝试
    try:
        if attempt > 0:
            print(f"正在进行第 {attempt} 次重试...（等待 {retry_delays[attempt-1]} 秒）")
            time.sleep(retry_delays[attempt-1])

        # API调用逻辑
        response = requests.post(..., timeout=60, verify=True)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]

    except 可重试错误:
        if attempt < max_retries:
            print(f"警告: {error_msg}")
            continue
        else:
            print(f"错误: 所有重试均失败")
            return f"API调用错误: {error_msg}"
```

### 5. 调试信息
- 重试过程提示
- 错误分类显示
- 成功重试确认

## 功能特性

✅ 智能重试：区分可重试和不可重试错误
✅ 递增延迟：5秒, 10秒, 15秒避免频繁请求
✅ 超时优化：30秒增加到60秒
✅ SSL安全：确保连接安全
✅ 详细日志：完整重试过程记录
✅ 错误分类：不同错误类型不同处理策略

## 测试验证

- 正常API调用：通过
- 重试机制：通过
- 错误处理：通过
- Agent集成：通过

## 改进效果

1. **稳定性提升**：网络问题自动恢复
2. **用户体验**：重试过程透明可见
3. **错误处理**：精确分类不同错误类型
4. **性能优化**：智能延迟避免服务器压力
5. **连接安全**：SSL验证确保数据安全

## 使用方式

重试机制自动生效，无需额外配置：
- 遇到网络超时自动重试
- 服务器错误智能重试
- 客户端错误立即返回
- 重试过程实时显示

## 后续建议

1. 可考虑配置化重试参数
2. 增加网络检测机制
3. 支持指数退避算法
4. 增加熔断器模式