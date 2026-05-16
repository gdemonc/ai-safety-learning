# Skills Used

这个文件记录本仓库学习过程中使用或建议使用的 skill，目的是让环境可复现、学习过程可追踪。

## 当前建议安装的 skills

### 1. security-best-practices

来源：`openai/skills@security-best-practices`

安装命令：

```bash
npx skills add openai/skills@security-best-practices -g -y
```

用途：

- 补安全工程基本功
- 帮助给练习项目补充防守视角
- 用于整理最基础的安全检查点

## 2. security-threat-model

来源：`openai/skills@security-threat-model`

安装命令：

```bash
npx skills add openai/skills@security-threat-model -g -y
```

用途：

- 做威胁建模
- 梳理资产、信任边界、攻击路径和缓解建议
- 配合《AI Red 攻防指南》第 10 章使用

## 3. langchain-rag

来源：`langchain-ai/langchain-skills@langchain-rag`

安装命令：

```bash
npx skills add langchain-ai/langchain-skills@langchain-rag -g -y
```

用途：

- 补 RAG 工程实现思路
- 辅助 `projects/rag-security-lab/` 的实现和扩展
- 对照学习 RAG 的工程层结构与安全问题

## 4. owasp-security

来源：`hoodini/ai-agents-skills@owasp-security`

安装命令：

```bash
npx skills add hoodini/ai-agents-skills@owasp-security -g -y
```

用途：

- 用 OWASP 风险视角复盘练习项目
- 补充常见风险分类

## 使用原则

这些 skill 是增强器，不是前置依赖。

也就是说：

- 没有这些 skill，仓库里的学习路线和练习项目也可以继续进行
- 有这些 skill，可以让某些分析、建模和工程实现更系统

## 推荐使用时机

### 学习总览阶段

优先用：

- `security-best-practices`
- `security-threat-model`

### 做 RAG 项目阶段

优先用：

- `langchain-rag`
- `security-best-practices`

### 做项目复盘阶段

优先用：

- `security-threat-model`
- `owasp-security`

## 说明

本仓库建议记录：

- skill 名称
- 安装命令
- 使用目的

不强制把 skill 本体文件一起纳入版本控制。
