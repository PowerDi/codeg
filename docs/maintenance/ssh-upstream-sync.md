# SSH 定制功能与上游更新维护指南

本指南用于维护 `PowerDi/codeg` Fork 中的 SSH 远端工作区功能。
SSH 已是 Fork 源码的一部分，不是每次升级后向安装包临时“注入”的插件。
正常更新应合并上游、保留并适配定制改动，再验证和构建。

**交付终点是提供构建产物地址：不替用户下载、解压、启动或安装桌面产物。**

相关说明：[SSH 使用与限制](../ssh-workspaces.md)、
[Windows 测试构建](../releasing/windows-test-build.md)、
[仓库开发约束](../../AGENTS.md)。

## 1. 保留上游更新提醒

桌面更新配置继续指向上游，不改成自己的 Fork，也不关闭更新检查或提醒：

```text
https://github.com/xintaofei/codeg/releases/latest/download/latest.json
```

配置位置是 `src-tauri/tauri.conf.json` 的 `plugins.updater.endpoints`。
保留上游签名验证；上游必要的公钥更新应正常审查和同步，不能通过关闭验签来更新。
版本号应跟随所合并的上游版本，不要为了区分测试包而随意抬高版本号，影响新版本提示；
定制构建用提交 SHA 和产物名称区分。

必须区分以下操作：

| 操作                          | 含义                                                                                 |
| ----------------------------- | ------------------------------------------------------------------------------------ |
| 检查上游新版本、查看更新提醒  | 保留，用于知道上游发布了新版本。                                                     |
| 在应用内确认安装上游更新      | 会使用上游安装包；该包若不包含 Fork 的定制代码，就不会保留这套 SSH 功能。            |
| 合并上游源码后构建自己的 Fork | 保留并适配 SSH 定制改动，生成新的测试产物，完成后只提供地址。                        |
| 更新远端 `codeg-server`       | 与替换本地桌面包不同；远端仍可使用上游预编译服务，但需验证升级后的协议兼容性和重连。 |

`src-tauri/tauri.windows-test.conf.json` 中的
`bundle.createUpdaterArtifacts: false` 只是不生成测试包自己的更新产物，
**不是禁用桌面更新，也不是已经实现了“只提醒、不允许安装”的保护开关**。
本指南不会修改现有更新行为；收到上游提示后，保留定制功能的维护流程见下文。

## 2. 更新前确认状态并留恢复点

1. 检查工作区、分支和远端。存在未提交修改时，先确认其归属和保存方式，不覆盖用户工作。
2. 确认 `origin` 是自己的 Fork，`upstream` 是 `xintaofei/codeg`。
   保留已有的 upstream 禁止推送设置，不向上游推送个人构建改动。
3. 同步 Fork 的 `main` 后创建备份和维护分支，再获取并合并上游。

以下命令供执行更新任务时参考，本指南本身不触发更新。
将 `YYYYMMDD` 替换为实际日期；分支已存在时换用新的名称，不强制覆盖：

```sh
git status --short --branch
git remote -v
git switch main
git pull --ff-only origin main
git branch backup/ssh-before-upstream-YYYYMMDD
git switch -c maintenance/upstream-YYYYMMDD
git fetch upstream
git log --oneline --left-right HEAD...upstream/main
git merge --no-ff upstream/main
```

只有确认工作区干净后才继续切换、拉取和合并。
如果 Fork 的 `main` 不能快进，先检查分叉原因，不改用强制重置。
也可合并已核对的上游发布标签，而不是追踪开发中的 `upstream/main`。
记录更新前的 Fork SHA、目标上游 SHA／版本及合并后的 SHA。

## 3. 解决冲突时保留完整接入链路

不要用覆盖式同步、`reset --hard upstream/main` 或整批选择上游版本来消除冲突。
也不要盲目重新 cherry-pick 已经合入的 SSH 提交，造成重复迁移或重复入口。

重点检查以下改动，而不是只保留 `src-tauri/src/ssh/` 目录：

| 范围       | 重点文件／目录                                                                                                                                                                                      | 必须保留的能力                                                             |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| SSH 核心   | `src-tauri/src/ssh/`                                                                                                                                                                                | 参数校验、安装引导、主机校验、密码助手、凭据隔离、隧道生命周期和错误脱敏。 |
| 命令与入口 | `src-tauri/src/commands/remote_workspace.rs`、`src-tauri/src/main.rs`、`src-tauri/src/lib.rs`                                                                                                       | SSH 命令注册、窗口归属、密码助手在启动完整桌面前处理请求。                 |
| 远端代理   | `src-tauri/src/commands/remote_proxy.rs`、`src-tauri/src/commands/acp.rs`、`src-tauri/src/browser/remote.rs`                                                                                        | HTTP、WebSocket、远端会话及浏览器相关路径仍指向正确的远端服务。            |
| 数据模型   | `src-tauri/src/models/remote_workspace_connection.rs`、`src-tauri/src/db/`、`src/lib/types.ts`                                                                                                      | SSH 连接字段、迁移注册及前后端类型一致，已有连接数据可继续读取。           |
| 前端接入   | `src/app/layout.tsx`、`src/components/layout/remote-workspace-manage-dialog.tsx`、`src/components/layout/ssh-auth-dialog.tsx`                                                                       | 管理入口、认证表单、主机指纹确认和取消操作仍可用。                         |
| 状态与展示 | `src/components/conversations/sidebar-conversation-list.tsx`、`src/contexts/remote-connection-context.tsx`、`src/lib/remote-workspace.ts`、`src/lib/remote-workspace-form.ts`、`src/i18n/messages/` | 连接定位、状态恢复、表单校验及所有语言的文案不丢失。                       |
| 构建与测试 | `.github/workflows/ssh-workspace.yml`、`.github/workflows/windows-test-build.yml`、`scripts/ssh-workspace-ci.sh`、`scripts/ssh-password-windows-smoke.py`                                           | SSH 回归检查、Windows 测试包及真实密码助手验证继续运行。                   |
| 打包与依赖 | `src-tauri/Cargo.toml`、`src-tauri/Cargo.lock`、`src-tauri/src/bin/codeg_mcp.rs`、`src-tauri/tauri.windows-test.conf.json`、`.gitattributes`                                                        | 依赖和 feature 一致，伴生程序有效，Linux 执行的脚本保持 LF。               |

涉及重构时按职责检查新位置，不能只以旧文件名仍然存在作为通过标准。

- 密码和私钥口令不能进入日志、命令行或明文连接配置。保留现有会话缓存策略；
  “记住密码”使用系统凭据库，检查目标变更时的凭据隔离和删除清理。
- 不为解决连接失败而自动接受未知／变更的主机密钥，或放开不受限制的转发。
- 保留远端升级、重启后的失效隧道清理和端点重新探测，验证兼容性而非盲信旧端口。
- 关闭本地窗口不能误杀远端智能体、终端或服务；不能用删除远端数据库作为升级修复。
- 若上游后来加入自己的 SSH 实现，先比较功能、安全和数据兼容性，再决定迁移方案，
  不直接删除 Fork 的实现或同时保留两套互相冲突的入口。

## 4. 验证与构建

完成冲突处理和提交前，至少检查：

```sh
git diff --name-only --diff-filter=U
git diff --check
git status --short
```

未解决的冲突必须清零，审查实际差异后再提交。涉及代码的检查项见
[AGENTS.md](../../AGENTS.md)；优先使用已有 GitHub Actions，不要求在用户电脑上安装完整构建环境。

在已获授权的更新任务中，把维护分支推到自己的 `origin`，选择同一待交付提交运行：

| 工作流                   | 必查项目                                                                                                               |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| **SSH Workspace Checks** | 前端 lint、测试、静态导出；桌面 Rust 测试及 clippy；隔离 SSH 安装、密码／主机信任、隧道和重连；服务器及 MCP 模式检查。 |
| **Windows Test Build**   | 有效的 `codeg-mcp` 伴生程序、桌面构建、Windows 原生 OpenSSH 密码验证及产物上传。                                       |

目前 SSH 工作流只在 `main`、`feat/ssh-remote-workspaces` 的 push 上自动运行，
同时支持 `workflow_dispatch`。其他维护分支需要手动运行；Windows 构建也需要手动运行。
没有出现失败状态不等于这些检查已经执行。

核对两次运行的 `head_sha` 与预期提交一致。修复后重新验证对应提交，
不要拿旧提交的通过结果或旧产物充当新构建。
保留隔离 SSH 脚本对临时账户和密码助手的保护：桌面构建可能把 Tauri 的空占位文件
覆盖到 Cargo 输出目录，测试助手必须使用经过确认的独立可执行文件。
不要在用户真实服务器上运行 CI 的隔离账户脚本。

需要合回 `origin/main` 时，按自己的 Fork 评审流程执行；
若合并或修正产生了新的待交付提交，应核对并重跑必要检查。
不因这份指南自动向上游提交、创建 Release 或发布更新清单。

## 5. 构建后只提供地址

确认工作流成功且产物存在、未过期后，交付以下信息：

- 产物地址及其 GitHub Actions 运行地址。
- 构建分支、完整或短提交 SHA、对应上游版本。
- SSH 检查和 Windows 原生验证的实际结果；未执行的验证如实注明。
- 产物有效期和访问条件。当前工作流默认保留 14 天，以本次产物实际到期时间为准；
  GitHub Artifacts 访问可能需要登录。

使用稳定的 GitHub 页面地址，不把短期签名跳转链接当成永久地址：

```text
运行：https://github.com/PowerDi/codeg/actions/runs/{runId}
产物：https://github.com/PowerDi/codeg/actions/runs/{runId}/artifacts/{artifactId}
```

**提供地址后即完成本次构建交付，不下载桌面产物到本机，不解压、启动或安装，
也不替用户点击应用内更新。** 后续使用由用户自行决定；需要额外操作时另行确认。
自动化测试在 CI 环境内执行，不等于已经在用户桌面完成手工验收。

失败时提供失败阶段和运行地址，不提供旧包冒充本次成功产物。
产物过期时说明需重新构建，不承诺永久可用，也不擅自改成 Release 发布。

## 6. 功能丢失时的处理

- 先分清是源码合并丢失定制改动，还是用户运行了不包含定制代码的上游桌面包。
- 对比更新前的备份分支和当前代码，在恢复分支修复接入链路并重新验证。
  如需中止尚未完成的合并，在确认工作区状态后使用 Git 的合并中止流程，不能强制覆盖用户工作。
- 修复后仍只提供对应构建地址，不自动重装或回退用户桌面。
  不删除连接配置、系统凭据库或远端数据；涉及数据回退时先确认备份和版本兼容性。
