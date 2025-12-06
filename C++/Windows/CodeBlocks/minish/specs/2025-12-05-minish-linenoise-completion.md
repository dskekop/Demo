# minish 交互式输入与补全规格

## 背景与问题
- 被改造的上层 shell 默认忽略 `SIGINT`，导致在其内部启动的程序无法通过 `Ctrl-C` 中断。`minish` 通过父进程忽略信号、子进程恢复默认处理方式来规避该问题，但当前交互体验仍停留在 `fgets()`。
- 现状无法提供行编辑、历史命令或补全功能，Tab 触发不会产生任何反馈，影响调试效率。

## 目标
1. 引入 `linenoise` 库，提供跨平台的行编辑能力。
2. 实现可扩展的命令补全，至少覆盖 minish 内建命令与 `$PATH` 中的可执行程序名。
3. 保持现有的信号行为：父进程忽略 `SIGINT/SIGQUIT`（空闲态 `Ctrl-C` 不应导致 minish 退出，只刷新行），子进程恢复默认处理。

## 非目标
- 复杂脚本语法解析（如管道、重定向）不在本轮改造范围。
- 不实现多作业控制（前后台切换、`Ctrl-Z`）。

## 功能性需求
1. **行编辑与历史**
   - 使用 `linenoise` 的 `linenoise()` 获取用户输入，替代 `fgets()`。
   - 支持左右移动、删除、`Ctrl-C`/`Ctrl-D` 等基础编辑快捷键（由库提供，需验证行为符合预期）。
   - 同一会话内维护命令历史，用户可通过 `↑/↓` 调阅；历史容量默认 128 条，可通过常量配置。
   - 历史仅在内存中维持，不再写入磁盘；minish 退出后历史丢弃，重新启动时不加载旧记录。

2. **自动补全**
   - 通过 `linenoiseSetCompletionCallback()` 注册补全回调。
   - 补全触发：用户按下 Tab，linenoise 回调得到当前缓冲区；根据指令行最后一个 token 生成候选。
   - 候选来源：
     1. minish 内建命令（目前为 `exit`、`quit`，保留扩展接口）。
     2. `$PATH` 中可执行文件名：按顺序扫描各目录，缓存 1 秒；若 `PATH` 发生变化（通过环境变量版本号或简单时间戳），下次补全重新构建缓存。
     3. 若 token 含有 `/`，视为文件路径补全：使用 `opendir()` 与 `readdir()` 基于给定前缀列出目录项，过滤 `.` 和 `..`；命中目录在候选末尾追加 `/` 以提示可继续深入。

3. **信号及控制字符处理**
   - 主循环仍在进入 `linenoise()` 前忽略 `SIGINT/SIGQUIT`。
   - 当用户在 `linenoise()` 中按 `Ctrl-C`，库返回 `NULL`；需检测并打印新行后继续循环，而不是退出程序，保持 idle 状态安全。
   - 当用户按 `Ctrl-D` 且缓冲为空，视为 EOF，退出循环并打印 `bye.`。

4. **命令执行流程**
   - 去除尾部空白（`linenoise` 已移除换行，但仍需 `strtrim`）。
   - 空字符串直接继续，不入历史。
   - 正常命令在成功执行后写入会话内历史（仅内存）。

## 非功能性要求
- **可移植性**：保留纯 C 实现；仅依赖 POSIX 基础接口与 `linenoise`（已包含在 `src/`）。
- **性能**：补全扫描应避免重复 I/O；PATH 可执行列表应缓存并控制更新频率。
- **可靠性**：路径遍历、文件加载失败需记录到 `stderr` 但不终止主循环。

## 接口与数据结构
- 新增 `struct completion_cache`：保存 PATH 版本（字符串哈希或 `mtime`）与候选列表（动态数组）。
- 新增 `static void completion_cb(const char *buf, linenoiseCompletions *lc)`。
- 新增 `static void load_history(void)` / `save_history(const char *cmd)`。
- 命令缓冲区使用 `char *line`，由 `linenoise()` 返回，记得在循环尾部 `free()`。

## 流程概述
```mermaid
description
flowchart TD
    A[启动] --> B[读 HOME、PATH 并建缓存]
    B --> C[linenoise(prompt)]
    C -->|NULL + errno=EAGAIN| C
    C -->|NULL (Ctrl-D)| H[退出]
    C -->|NULL (Ctrl-C)| C
    C --> D[trim + 判空]
    D -->|空| C
    D --> E[内建命令?]
    E -->|是| F[执行内建]
    E -->|否| G[fork/exec /bin/sh -c]
    F --> C
    G --> I[waitpid]
    I --> J[保存历史]
    J --> C
    H --> K[打印 bye]
    K --> L[结束]
```

## 验收标准
1. 在终端运行 `./minish`，按 Tab 可出现补全候选（至少内建命令与 `/bin/ls` 等 PATH 程序)。
2. 输入历史可通过上下方向键遍历，但会话结束后历史不被保留。
3. 用户在提示符处按 `Ctrl-C` 只会刷新行，不退出程序；执行外部命令时 `Ctrl-C` 可中断子进程。
4. 输入 `Ctrl-D` 退出时打印 `bye.`。
5. 代码通过 `make` 构建，无新增编译告警。

## 开放问题
- PATH 缓存是否需要实时监控环境变量变更？当前方案通过定时刷新，后续可考虑 `inotify`（Linux）或 `kqueue`（BSD）。
- 历史文件权限需不需要强制 `0600`？暂定使用系统默认 `umask`，如有安全需求再加限制。
