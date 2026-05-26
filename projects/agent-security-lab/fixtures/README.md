# fixtures 目录说明

这里放本地实验素材。

建议包括：

- `docs/`：给 `search_docs` 用的知识材料
- `files/`：给 `read_file` 用的本地文件
- `outbox/`：给 `send_email_mock` 落地输出

注意：

- 不要接真实邮箱
- 不要读取真实敏感文件
- 所有高风险行为都做 mock
