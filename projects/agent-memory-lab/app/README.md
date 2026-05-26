# app 目录说明

建议最少拆成这些文件：

- `memory_store.py`：记忆读写
- `memory_policy.py`：写入规则、TTL、来源控制
- `session_runner.py`：模拟多会话测试

这个项目最核心的不是模型，而是：

- 什么会被写进去
- 写进去之后多久还在
- 将来会不会被重新拿出来当事实用
