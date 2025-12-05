# minish linenoise 补全实现计划

## 概述
以 `linenoise` 提供的行编辑能力替换现有 `fgets()`，实现命令历史、自动补全，以及符合规格的信号与控制字符行为，解决改造 shell 忽略 `SIGINT` 导致的交互问题。

## Scope & Specs
- 目标文件：`src/minish.c` 及必要的辅助源码/头文件。
- 参考规格：`specs/2025-12-05-minish-linenoise-completion.md`。
- 不触及其他 CodeBlocks 示例工程或上层 shell。

## 假设与不在范围
- `linenoise.c/.h` 已随工程提供且可直接编译。
- 不实现持久化历史、不改动 `Makefile` 以外的构建流程。
- 不引入高级 shell 语法解析、作业控制、别名系统。

## 分阶段计划
1. **行编辑主循环改造**
   - 将读取逻辑改为 `linenoise(prompt)`，处理 `NULL` 返回的 Ctrl-C/Ctrl-D 分支。
   - 抽取 `trim` 工具函数，保证空命令不进入执行路径。
   - 维护会话级历史容量（默认 128），Ctrl-C 触发不记录历史，Ctrl-D 空缓冲退出。
   - 验证父进程信号仍设置为 `SIG_IGN`，子进程恢复 `SIG_DFL`。

2. **自动补全设施**
   - 定义补全回调并注册；解析当前 token 判定命令或路径模式。
   - 内建命令列表放入静态数组，匹配前缀追加候选。
   - PATH 命令补全：实现缓存结构（目录快照 + 时间戳），提供刷新函数，使用 `access(X_OK)` 过滤可执行；缓存超时 1s 或检测 PATH 变动时重建。
   - 路径补全：检测 token 中 `/`，拆分目录与前缀，使用 `opendir/readdir` 列举，忽略 `.`、`..`；目录候选末尾追加 `/`。

3. **命令执行与历史钩子**
   - 统一处理内建命令（`exit/quit`）与外部命令路径，维持当前 fork/exec 流程。
   - 成功执行的非空命令追加到内存历史并 `linenoiseHistoryAdd()`；无需写磁盘。
   - 对 PATH/文件扫描失败、补全 I/O 错误等打印 warning 但不中断 shell。

4. **验证与清理**
   - 运行 `make`，确保无新告警。
   - 手动测试：
     1. 空闲时 `Ctrl-C` 刷行且不退出；执行 `sleep 5` 后 `Ctrl-C` 能中断。
     2. Tab 补全内建命令与 `/bin/ls` 等 PATH 可执行；输入 `/usr/bi` Tab 展示路径候选。
     3. `Ctrl-D` 退出打印 `bye.`；重启后历史为空。
   - 代码自检，确认无内存泄漏（`linenoise` 结果逐次 `free`）。

## 依赖与影响
- 依赖 POSIX API (`opendir`, `readdir`, `stat`, `fork`, `execve`, `waitpid`)；在 Linux/Unix shell 环境中可用。
- 可能引入头文件 `<dirent.h>`, `<sys/stat.h>`, `<errno.h>`, `<time.h>` 等。

## 风险与缓解
- **PATH 目录较大导致补全卡顿**：通过缓存与最小化刷新窗口（1s）降低重复扫描。
- **linenoise 行为差异**：集中在交互层测试，必要时阅读库文档调整配置。
- **信号处理回归**：在验证阶段重点测试 Ctrl-C，确保父子进程逻辑未破坏原目的。

## 验证策略
- 构建：`make -C src`（或 `make` 默认目标）。
- 手测：逐项执行上文验证场景。
- 可选：运行 `valgrind ./minish` 确认无未释放内存（如环境允许）。

## Rollout / Backout
- 部署：直接替换 `minish` 可执行。
- 回退：保留原 `src/minish.c` 版本，可通过 `git checkout -- src/minish.c` 恢复。

## 审批状态
- 计划提交，等待 `/plan` 阶段批准后方可进入 `/do`。
