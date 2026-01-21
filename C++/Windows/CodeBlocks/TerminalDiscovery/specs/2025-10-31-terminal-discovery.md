# 终端发现代理规范

## 问题陈述与背景
- 交付一个可复用的 C 终端发现代理，能够运行在异构交换机操作系统上（首期锁定 Realtek SDK，后续覆盖 Netforward/Linux 等变体）。
- 通过过路的二层报文识别终端、维护存活状态，并以最小的特定平台代码将终端状态暴露给交换设备的上层模块。
- 现有 Realtek 平台已完成 ACL 适配，可持续上送 ARP 报文，不再需要终端发现模块额外确保 copy-to-CPU 能力。

## 目标
- 通过检查二层控制报文发现终端（当前聚焦 ARP，可扩展至 DHCP 等协议）。
- 通过主动探测与定时淘汰维护每个终端的生命周期，兼顾访问/聚合口与虚接口的联动。
- 引入可插拔的适配层，隔离 Realtek 等平台的硬件/内核差异，便于后续拓展至 Netforward、通用 Linux Raw Socket 模式。
- 提供可编程查询接口和实时增量通知，满足网络管理系统的消费需求。
- 在 ARM64、MIPS、x86 等不同 CPU 体系和报文收发架构间保持可移植性，并在 Realtek 平台率先完成 300 终端 Demo 验证。
- 提供可嵌入外部守护进程的初始化入口，满足多平台统一集成和生命周期托管。

## 交付与运行模式
- 公共逻辑（`common/`、`include/`）以 `libtd_common.a` 交付，平台主进程仅链接该跨平台静态库；Realtek/Netforward 主进程彼此独立运行。sidecar 仅在 Netforward 平台存在，位于 `stub/`，为独立进程且不依赖该静态库；其他平台（含 Realtek/Linux raw socket 等）不引入 sidecar。
- 平台适配器（Realtek、Netforward、Linux raw socket 等）在各自工程内单独编译成对象文件并与宿主进程/固件链接发布，运行时仅携带本平台适配器，不做动态切换或并行装载。
- 构建隔离：各平台保持独立编译入口/目标（含 sidecar），只依赖 `libtd_common.a` 与公共头；构建任一平台不检查其他平台的工具链或适配器对象，禁止单二进制条件编译多适配器。
- 运行时配置仅覆盖当前已编译进进程的适配器参数（接口名、发包节流、VLAN 过滤等），无法通过配置启用其他平台适配器。
- `src/` 目录物理分离平台无关/有关代码：公共代码编译成静态库，平台代码在各自工程内编译并与静态库解耦，便于增量集成新平台。
- Realtek 先行落地：优先打通静态库与 Realtek 适配层的编译链，保持现有编译选项与桥接依赖可用，再渐进推广到其他平台，避免一次性拆分阻断现网集成。
 - 构建与测试布局：
   - 顶层 Makefile 仅作分发器，提供 `make realtek`、`make netforward`、`make linux` 等对等命名的入口跳转至对应子目录，不再用单一 Makefile 携带全部平台规则；各平台目标命名需对等、对齐，避免出现默认/主平台的特殊命名（如 `all` 只代表某一平台）。
    - 每个平台拥有独立的 makefile 入口，负责本平台主进程与（仅 Netforward）sidecar 的编译、静态库的生成/清理（不单独暴露“仅编库”目标），并将对象文件与产物存放在平台私有输出目录（如 `out/<platform>/`），避免同名目标冲突。
    - 公共静态库仍为 `libtd_common.a`，由各平台 makefile 复用并在各自流程内生成/清理；平台适配器/sidecar 源文件以“白名单”方式写入各自 makefile，禁止跨平台引用。
    - Realtek 专属实现（除适配器外）仅在 Realtek 平台构建：`stub/td_switch_mac_stub.c`（覆盖 Realtek MAC 桥接弱符号）、`demo/td_switch_mac_demo.c`（桥接示例）、`src/ref/realtek/*`（仅作参考）与其他依赖 Realtek SDK/桥接头文件的源文件不得在 Netforward/Linux raw socket 等平台的构建入口中被包含，避免因缺失 SDK 依赖导致编译失败；非 Realtek 平台仅链接 `libtd_common.a` 与各自的适配器/sidecar 对象。
    - Netforward 平台在 makefile 中提供 sidecar 专用目标（如 `sidecar`、`sidecar-stub`），主进程与 sidecar 分别产出独立二进制，允许通过变量切换真实 IPC 对象或 stub。
    - 测试程序按平台无关性划分：平台无关测试需在所有平台 makefile 中构建；平台相关测试仅在对应平台 makefile 中构建与执行。
      - 各平台 makefile 需支持 `CROSS_PREFIX`/`cross-generic` 目标，使用通用交叉工具链（如 `mips-linux-gnu-`、`aarch64-linux-gnu-` 前缀）完成编译，以验证嵌入式环境的可行性并保持与现网平台一致；`cross` 目标仅供厂商特定工具链（如 `mips-rtl83xx-linux-`）存在时选择性使用，默认交叉验证依赖 `cross-generic`，不得将厂商专有工具链设为必备。

## 非目标
- 本阶段不实现完整的 DHCP/ND 嗅探能力。
- 不管理三层路由逻辑，也不直接操控 FIB/ARP 表，除非与终端跟踪相关。
- 不提供 UI/CLI 集成，仅关注后端接口。

## 功能性需求
1. **终端发现**：仅处理接收到的 ARP 广播、免费 ARP、单播回复等（本机发送的 ARP 已在适配层过滤），按 VLAN/接口识别终端；后续需可扩展至 DHCP 报文。
2. **保活机制**：每个终端每 120 秒发送一次单播 ARP request；连续三次无响应则删除终端。终端与其首次或最近一次有效报文对应的三层虚接口/VLAN 建立绑定，保活报文必须从该虚接口发出，确保与发现路径保持一致；若该接口缺失可用 IPv4（如接口 down、IP 被删除或迁移至不同网段导致无法拼装 ARP），则视为保活通道失效并进入接口无效流程。
3. **接口感知**：仅依赖 IPv4 地址增删和 `if_nametoindex` 可解析性来判断三层 VLAN 接口是否可用，无需额外监听 VLAN 接口的创建/删除事件；接口无效时暂停保活。
4. **Access/Trunk 逻辑**：当前平台 ACL 已保证送达内核的报文携带真实 VLAN tag，且该 VLAN 必然已在本机存在；因此无需额外查询 Access/Trunk 配置数据，仅依据报文内 VLAN 决定终端归属。仍需在缺失对应 VLANIF 时按三层 Down 逻辑处理。
5. **拓扑边界场景**：当关联的三层接口暂不可用（无法解析 `if_nametoindex`、缺少可匹配 IPv4、出现跨网段 ARP）时保留 30 分钟，期间不发送保活；恢复后转入探测态。
6. **平台适配**：为不同平台提供独立适配器实现；公共库被各平台工程复用，平台专有适配器在各自工程内单独编译并随宿主固件发布，运行期不支持动态选择或并行装载其他平台的适配器，避免交叉依赖导致的编译/链接失败。
7. **事件上报**：
   - 提供实时增量变更通知，注册回调后立即推送发现的终端变化。
   - 支持查询当前终端表的全量快照，并确保增量上报状态与查询快照一致。
   - 当终端因端口变更触发 `MOD` 事件时，增量载荷需同时携带新旧 ifindex；此处指的是面向北向的逻辑接口标识（即 `terminal_metadata.ifindex`，与 `TerminalInfo::ifindex` 对齐），而非内部用于发送保活的 `tx_kernel_ifindex`。其余事件类型旧端口值填 0 作为占位，便于北向通用处理。
8. **可配置项**：
   - 可配置终端保活周期、最大终端数量（200、300、500、1000 等档位）。
   - 仅针对当前已编译进进程的唯一平台适配器提供运行时参数（接口名、发包节流、VLAN 过滤等）；适配器类型在构建期确定，运行期不可切换。
   - 允许通过运行配置或 CLI 指定 `ignored_vlans` 列表，在收包路径上忽略特定 VLAN 的 ARP 报文，默认列表为空。
9. **守护进程集成**：
   - 在 `src/main/terminal_main.c` 提供一个默认不被自动调用的初始化函数，供外部守护进程在自身生命周期内显式触发启动；模块自进程启动后常驻，除非宿主进程退出不会主动关闭。
   - 初始化函数通过显式参数接收宿主进程提供的运行时配置（结构体或等效封装）；在调用 `td_config_to_manager_config` 之前按字段级安全覆盖 `td_runtime_config`，确保不同平台的动态输入被正确合并，并对非法/缺失值返回可诊断的错误。
   - 不在初始化函数内注册信号处理、命令行参数或帮助信息解析，也不默认开启周期性日志输出，由外部守护进程统一调度。
   - 初始化完成后默认将事件管线绑定至内置日志回调，保证在未注册北向回调时也能通过日志观察终端变化；外部若需启用增量上报，可调用 `setIncrementReport` 注册唯一的 C++ 回调，内部再由桥接层负责触发 `terminal_manager_set_event_sink` 完成切换。
   - 初始化成功后需提供只读访问接口直接返回内部 `terminal_manager` 句柄，供嵌入方调用 `terminal_manager_get_stats` 等观测函数；同时额外提供访问接口返回 `app_context` 只读引用，作为后续扩展挂载点。两类接口均禁止外部替换或销毁内部资源。
10. **调试可视化**：向外暴露一组只读调试函数，用于打印或导出核心数据结构快照（终端哈希桶、接口前缀表、接口绑定表、MAC 查表任务队列、`mac_need_refresh_`/`mac_pending_verify_*` 计数器以及 `mac_locator_version`），支持在不修改运行态状态机的前提下进行调试排障与结果验收。

- **性能**：
   - 1k 终端负载时单核占用 <10%，并确保在现有硬件 ARP 限速机制基础上仍不丢包。
   - 清晰量化 200、300、500、1000 终端档位的 CPU/内存曲线，作为不同设备能力的基准值。
- **能力验证**：在 Realtek 平台先行完成 300 终端规模的 Demo 验证，确认收发链路、保活节奏与上报机制满足指标。
- **可靠性**：确保无终端泄漏；并发访问需线程安全，接口状态波动时保证状态机一致性。
- **可移植性**：核心逻辑仅依赖 POSIX 类原语与适配器回调，平台特性封装在适配层。
- **可观测性**：输出结构化日志（级别-标签-消息），提供探测、响应、过期、队列丢弃、接口波动等计数器。所有保活定时、超时检查必须统一基于单调时钟，确保系统时间回拨或跳变不会影响状态推进。
      - 默认日志落地应包含标准可读的系统时间戳（wall clock，精确到秒），格式建议为 `YYYY-MM-DD HH:MM:SS`，以便与外部日志对齐；时间戳获取不需要依赖单调时钟，允许受 NTP 校时影响。
- **可测试性**：提供平台无关的状态机单测，以及基于适配器 mock 的发现/保活/事件上报集成测试。

## 调试与验证接口扩展
- **输出形态**：新增 `td_debug_writer_t`（`void (*td_debug_writer_t)(void *ctx, const char *line)`）回调类型，并在 C 北向 API 层公开 `td_debug_dump_*` 系列函数；默认提供写入 `FILE*` 的适配器，便于快速将结果重定向至日志或标准输出。
- **终端哈希快照**：`int td_debug_dump_terminal_table(const td_debug_dump_opts_t *opts, td_debug_writer_t writer, void *ctx);`
   - 在持有 `terminal_manager->lock` 的读区间内遍历 256 个哈希桶，输出桶索引、元素数量、最大链深、冲突次数。
   - 每个终端条目打印 MAC、IP、状态、所属 VLAN/ifindex、最近一次收包与探测时间（UTC 秒）、探测失败计数、事件队列挂起标记、绑定前缀 ID。
   - `opts` 支持按状态、VLAN、ifindex、MAC 前缀过滤，并可开启 `verbose_metrics` 选项附带探测计数与事件统计。
- **接口前缀表快照**：`int td_debug_dump_iface_prefix_table(td_debug_writer_t writer, void *ctx);`
   - 输出每个 `iface_prefix_entry` 的 ifindex、IPv4 前缀（CIDR 记法）、掩码长度、引用计数、最近一次写操作时间戳。
   - 若同一接口存在多个前缀，保持插入顺序并标注主前缀。
- **接口绑定索引快照**：`int td_debug_dump_iface_binding_table(td_debug_writer_t writer, void *ctx);`
   - 对 `iface_binding_entry` 打印 ifindex、关联终端数量、链表中首个终端的 MAC、是否包含 `IFACE_INVALID` 条目。
   - 提供 `expand_terminals` 可选参数，用于展开完整终端列表并指明其所属哈希桶编号。
- **MAC 查表任务队列**：`int td_debug_dump_mac_lookup_queue(td_debug_writer_t writer, void *ctx);`
   - 输出当前待执行/执行中的 MAC 查表任务，包括 MAC、目标 VLAN/ifindex、创建时间、重试计数、状态标记。
   - 同时打印 `mac_need_refresh_` 队列长度、`mac_pending_verify_success`/`mac_pending_verify_failure`/`mac_pending_verify_retry` 等计数器、最长排队时长。
- **Pending VLAN 队列快照**：`int td_debug_dump_pending_vlan_table(const td_debug_dump_opts_t *opts, td_debug_writer_t writer, void *ctx);`
   - 遍历 `pending_vlans[4096]` 桶数组，统计已占用桶数与挂起终端总数，便于快速判断异常规模。
   - 每个非空 VLAN 桶输出 `vlan=<vid> entries=<count>` 概要；若 `opts->expand_pending_vlans` 为真，则逐项展开终端详情（MAC、IP、当前状态、`pending_vlan_id`）。
   - 保持与其他 dump 函数一致的错误处理：`writer` 报错立即中止并返回负值；内部持有 `terminal_manager.lock` 期间不允许阻塞 IO。
- **MAC 定位版本号**：`int td_debug_dump_mac_locator_state(td_debug_writer_t writer, void *ctx);`
   - 输出 `mac_locator_version` 当前值、最近一次递增的触发原因（新增终端、查表成功、验证失败等）、关联终端数量。
   - 若无待处理任务仍需输出 baseline，便于比对上下游版本。
- **线程安全**：所有 `td_debug_dump_*` 函数仅在内部短时间持有读锁或复用管理器互斥，严禁在锁持有期间执行阻塞 IO；若调用方 `writer` 报错（通过上下文标记或 errno），需立即释放锁并返回负值。
- **跨语言桥接**：C++ 北向层提供轻量包装，可将调试输出收集为 `std::string` 或写入 `std::ostream`，同时暴露 `TerminalDebugSnapshot` 帮助上层工具复用；保证新增 API 通过 `extern "C"` 导出并保持稳定 ABI。
- **文档示例**：在 `doc/` 目录补充调试接口指南，给出典型调用示例、样例输出格式与排障建议；测试中覆盖最小/过滤/错误路径。

## 架构概览
- **核心服务层**：处理终端表、定时器、状态转换和报表生成的跨平台模块。
- **平台适配接口（PAI）**：抽象报文收发、接口事件等平台差异。
   - 必备回调：`adapter_init`、`register_packet_rx`、`send_arp`、`query_iface`、`log_write`；构建或启动期间确定单个适配器实例并贯穿运行期。
   - 若后续平台报文携带 CPU tag，则可从中直接解析整机 ifindex；Realtek 平台事件统一上报 ifindex（仍使用 32 位无符号整数），不再使用 port/lport 表述。
   - 参考实现：`realtek_adapter`（原生 Raw Socket + BPF）、`netforward_adapter`、`linux_rawsock_adapter`。
   - Realtek 适配器在初始化时直接监听物理口（如 `eth0`）收包，依赖平台已有 ACL 规则保障 ARP 上送；上行报文通过 VLAN 虚接口（如 `vlan1`）发出。
- **事件总线**：内部队列负责聚合终端变更并立即投递给上报子系统。
- **API 接口**：提供 `terminal_query_all`、`terminal_subscribe`、`terminal_config_set` 等 C API；内部实现需兼容外部团队计划提供的 C++ API。

## 参考实现提示
- **Realtek 参考代码约束**：
   - 可参考 `src/ref/realtek/loop_protect.c` 的线程、互斥量等 OSA 抽象，但实现可自行选择 POSIX 线程/锁等通用原语，无需强绑 OSA 框架。
   - 复用 Raw Socket + BPF 过滤模型，确保适配器初始化时设置专用过滤器以截获目标广播报文。
   - 事件循环可按功能设计（如 epoll、poll 或自定义调度），不强制依赖 `loop_protect_epoll_loop` 实现。
   - 报文发送推荐直接在物理口（例如 `eth0`）的 Raw Socket 上封装 802.1Q 头部完成 VLAN tag 后下发，无需为不同 VLAN 反复绑定对应的虚接口；若目标平台不允许用户态插入 VLAN tag，再回退到绑定虚接口（例如 `vlan1`）的模式。
   - 报文接收侧需监听物理网卡 `eth0`，结合 BPF 过滤筛选关心的报文。
   - 在 Realtek 平台使用 Raw Socket 绑定 `eth0` 收包时，`recvmsg` 返回的 `ifindex` 恒为 `eth0` 的索引；该值仅用于日志或入向定位，不能直接用于选择后续 ARP 发送接口，保活发包仍需依据终端绑定的 VLAN 信息。
   - Realtek 平台无法依赖 CPU tag 直接获得整机 ifindex，需要借助外部团队提供的 C++ 封装拉取整机二层转发表，按终端 MAC 查找逻辑口，再结合接口类型换算出 ifindex 用于事件上报与北向 `TerminalInfo`。
   - 底层 `libswitchapp.so` 的调用（例如 `createSwitch`、`getDevUcMacAddress`）统一由外部团队提供的桥接模块完成，现已交付并在 `src/demo/td_switch_mac_demo.c` 中完成联调验证。模块在装载阶段自行完成一次性 `createSwitch` 初始化并缓存返回的 `SwitchDev*`；对外至少导出两个 C 接口：`int td_switch_mac_snapshot(SwUcMacEntry *buf, uint32_t *out_count)`（命名可调整）与 `int td_switch_mac_get_capacity(uint32_t *out_capacity)`。后者仅调用缓存的 `SwitchDev*` 上的 `getDevMacMaxSize` 获取设备可容纳的最大 MAC 表项数；前者基于同一 `SwitchDev*` 调用 `getDevUcMacAddress` 获取当前快照，其中 `out_count` 仅作为**纯输出参数**携带实际条目数量，调用前无需填充任何容量提示，也不会被 SDK 视作“请求条目数”。实现可参考 `src/ref/realtek/mgmt_switch_mac.c` 中 `getDevMacMaxSize`/`getDevUcMacAddress` 的使用方式，同时确保外部模块内部负责引用计数与线程安全；需注意 Realtek SDK 的 `getDevUcMacAddress` 不会校验缓冲区长度，因此桥接模块本身不得在 `td_switch_mac_snapshot` 内部分配临时内存，而是依赖调用方先通过 `td_switch_mac_get_capacity` 获得容量后预先准备（并可静态复用）`SwUcMacEntry` 缓冲区；桥接模块仅在该缓冲区内填充数据，并保证返回的条目数量不超过调用方提供的容量。终端发现进程直接复用 SDK 定义的 `SwUcMacEntry` 结构，不再为兼容而进行结构转换，仅对 `attr` 等字段值进行解释。开发容器中由于无法引入 Realtek SDK 对应的 `libswitchapp.so` 及依赖环境，默认提供打桩实现覆盖上述两个接口：
       - 打桩实现位于工程源码中，以弱符号（`__attribute__((weak))`）形式导出 `td_switch_mac_get_capacity`/`td_switch_mac_snapshot`，返回固定容量（默认 1024）与可预测的若干示例条目；真实桥接模块参与链接时可自动覆盖弱符号，无需修改调用方。
       - 打桩逻辑将所有日志写入标准输出，并允许通过环境变量（例如 `TD_SWITCH_MAC_STUB_COUNT`）调整返回条目的数量；调用方传入的缓冲区不足或参数非法时会返回负错误码并打印提示，便于本地调试。
       - 当 SDK 真正接入生产环境时，需在构建脚本中确保真实桥接对象或静态库排在链接顺序前端（或直接禁用打桩文件编译），以便覆盖弱符号并恢复与外部模块一致的行为。
   - `td_switch_mac_demo_dump` 已通过上述桥接接口完成端到端验证，后续 ifindex 获取策略与同步流程应以该 demo 的数据流为基准：终端发现模块通过 demo 辅助逻辑解析 MAC→ifindex 映射，并在核心实现中复用相同的缓冲区及容量缓存策略，确保与外部桥接模块的调用约定一致。
      - 桥接模块由外部团队以 C++ 源文件形式交付，与终端发现项目一同编译；为降低额外拷贝与内存占用，`td_switch_mac_snapshot` 直接返回 SDK 定义的 `SwUcMacEntry` 缓冲区，由调用方按照 `td_switch_mac_get_capacity` 预留的条目上限复用该结构；终端发现进程直接依赖 `SwUcMacEntry` 布局，在编译期包含必要的对齐定义，并通过文档约定补充字段语义。
         - 外部团队新增导出的 C 接口 `int td_switch_mac_get_ifindex_by_vid(SwUcMacEntry *entry)`，由与 `td_switch_mac_snapshot`/`td_switch_mac_get_capacity` 相同的桥接模块负责封装 SDK 调用。调用方在入参 `entry` 中填充目标 `mac` 与 `vid`，成功时原地覆写命中的完整表项（携带 ifindex 等字段），未命中返回负错误码。
            - `td_switch_mac_get_ifindex_by_vid` 的查找域仅限“指定 VLAN 内的特定 MAC”，能够在命中时返回单条表项的 ifindex；若目标 MAC 当前被学习在其他 VLAN 或尚未被学习，该接口会直接失败。因此需要与“全表快照 + 版本号”组合使用：
               1. 周期性 `getDevUcMacAddress`/`mac_locator_version` 仍作为基线，用于覆盖整机范围、处理终端迁出/老化、维持缓存完整性。
               2. 点查接口只在我们“确信 VLAN 正确”且“需要快速确认端口”的场景触发，避免对未知 VLAN 的终端反复失败查询。
            - 推荐流程：
               1. `terminal_manager_on_packet`：报文先刷新 `entry->meta.vlan_id`，若探测到 VLAN 变更或 `meta.ifindex==0`，先依据报文指示的 VLAN 调用点查；成功后将点查返回的 ifindex 写回并同步 `meta.mac_view_version` 为当前 `mac_locator_version`，同时入队 `MOD` 事件；失败时仅记录日志并保持 `terminal_metadata.ifindex` 及关联元数据的旧值，禁止写 0 清空，等待后续全表刷新覆盖。
               2. `terminal_manager_on_timer`：保持现有逻辑，仅依据 `mac_locator_version` 变更驱动 `mac_need_refresh`/`mac_pending_verify` 队列，不额外调用点查接口。
               3. `mac_locator_on_refresh`：保持原有版本驱动流程，通过全表快照结果更新 `meta.ifindex` 与 `mac_view_version`，不在回调内追加新的点查；当本次快照查询失败或未命中终端时同样保留旧的 `ifindex` 值，不再强制写 0，待下一轮有效数据再行更新。
            - 点查接口本身不返回版本号；调用方需要在 `TD_ADAPTER_OK` 或 `TD_ADAPTER_ERR_NOT_FOUND` 两个分支中主动写入最新 `mac_locator_version`，以避免随后的版本刷新立即再次排队同一终端。
            - 无论是全表刷新还是点查，一旦拿到明确结论（命中或确认未命中），都应更新 `entry->meta.mac_view_version` 为最新值（点查路径取当前 `mac_locator_version`），避免后续 `mac_locator_on_refresh` 或计时线程重复排队；只有在点查返回 `TD_ADAPTER_ERR_NOT_READY` 等错误时才保留旧版本等待重试。
            - 考虑到点查接口本身开销极低，允许在后续报文驱动下重复尝试，无需显式记录或限制调用频率。
            - 通过“基线全表 + 有针对性的点查”组合，可兼顾跨 VLAN 的覆盖范围与 VLAN 内的毫秒级感知，同时避免对桥接模块施加过多重复请求。
         - `src/stub/td_switch_mac_stub.c` 需提供弱符号打桩实现，支持根据环境变量或内建样例数据返回确定性结果；未命中时返回 `-ENOENT`，命中时写回入口参数并返回 0，日志沿用 `[switch-mac-stub]` 前缀。
         - `src/demo/td_switch_mac_demo.c` 需补充示例代码展示该接口的调用流程：构造查询、打印命中结果、处理未命中路径，并与现有 `td_switch_mac_snapshot`/`td_switch_mac_get_capacity` 示例保持一致的输出格式。
   - 交叉编译建议使用 `mips-rtl83xx-linux-` 工具链前缀（如 `mips-rtl83xx-linux-gcc`），保持与现网 Realtek 平台环境一致；若该工具链暂不可用，可使用通用 MIPS 交叉工具链验证代码可编译性。
   - Realtek 适配器的 MAC 定位接口必须严格区分“缓存尚未就绪/刷新失败”与“未在 MAC 表中命中”两类场景：
      - 缓存正在刷新、强制刷新失败或尚未初始化时返回 `TD_ADAPTER_ERR_NOT_READY`，终端管理器据此保持队列等待下一轮版本更新；
      - 缓存可用但未命中目标 MAC/VLAN 时返回 `TD_ADAPTER_ERR_NOT_FOUND`，同时输出 `ifindex=0` 并保留当前版本号，禁止使用 `NOT_READY` 触发重复刷新；
      - 相关语义需在 `realtek_mac_locator_lookup` 与后续桥接实现中保持一致，确保 `mac_need_refresh` 队列不会因错误码混用而无限膨胀。
- **Netforward 参考约束与流程**：
   - sidecar 由来：与 hsl 进程间通信收包需要引入平台特定的进程框架，为避免污染/耦合集成本项目的主进程，采用 cloud-native sidecar 模式：sidecar 引入平台框架并完成与 hsl 的通信，再将报文透传给主进程。
   - 现阶段 sidecar 可不接入 hsl，默认以 stub/自发模拟报文完成终端发现链路验收；但需保持与 hsl 对接的兼容性（沿用相同 IPC 头部与收包流程），便于后续无缝切换为真实 hsl 数据源。
   - 收包链路：参考 `src/ref/netforward`，通过与用户态核心转发进程 hsl 的 IPC 收包，不再使用 Raw Socket。sidecar 负责接入平台框架并与 hsl 通信，将报文透传给主进程；主进程在适配器内解析后喂给已注册的 `register_packet_rx` 回调。提供 sidecar 打桩以便无 hsl 环境下验收。
   - 元数据解析：报文自带 CPU tag，`port` 字段即整机 ifindex（物理口），无需 `td_adapter_mac_locator_ops`。VLAN 取自 `vlanid` 字段；整机 ifindex 与 VLANIF 的 `kernel_ifindex` 语义独立，不混用。
   - 发包路径：主进程直接在对应 VLAN 虚接口（前缀 `Vlan`，如 `Vlan1`）发送，不经过 IPC/sidecar，也不使用“全局” `eth0`。平台不依赖且不提供 `libswitchapp.so`。
   - IPC 报文格式（sidecar↔hsl）：地址头为 `struct sockaddr_vlan`，后随完整以太网帧。

```
struct sockaddr_vlan {
   unsigned char dest_mac[HSL_ETHER_ALEN];
   unsigned char src_mac[HSL_ETHER_ALEN];
   unsigned int port;        /* Outgoing/Incoming interface index */
   unsigned short vlanid;    /* Vlan id */
   unsigned short svlanid;   /* SVlan id */
   unsigned int length;      /* Length of the Packet */
   unsigned short eth_type;  /* Ethernet type */
};

#define HSL_ETHER_ALEN 6
```

    sidecar 仅做透传，不修改报文；适配器负责将 `port`/`vlanid` 整理为平台无关层可用的 VLAN 和整机 ifindex。
   - 参考收包链路（便于 sidecar 模拟）：参考代码中通过 `message_client` 异步连接 HSL（Unix 域 `HSL_ASYNC_PATH` 或 TCP `HSL_ASYNC_PORT`），epoll 激活后进入“先 peek 头、再按长度读全帧”的流程：先用 `MSG_PEEK` 读取 `struct sockaddr_vlan` 拿到 `length`，再按该长度读完完整报文，拷贝头部后将余下以太帧交给平台解析。sidecar stub 需保持同一封装（头部 + 完整二层帧）以复用解析逻辑。
   - sidecar 与主进程（netforward 适配器）间的报文透传统一使用 Unix 域可靠流式 IPC，保证头部与帧数据的字节序、完整性与有序性，并与参考代码的 epoll/peek 读法天然对齐；本地同机场景无需退化到 UDP 或无序报文模式。
   - sidecar模拟补充：参考代码的收包回调按报文粒度触发，每次 epoll 可读只消费一个完整报文（`struct sockaddr_vlan` 头 + 长度为 `length` 的以太帧），不会合并多帧或拆分半帧；`length` 表示纯以太网帧长度（不含 `struct sockaddr_vlan`），sidecar/hsl 应保证 `length` 与后续帧字节数一致。stub 发送时需先写完整头，再紧跟帧内容，避免出现短读或多帧黏连导致解析偏移。
   - 运行步骤：sidecar stub 模拟 hsl IPC→适配器解析 VLAN/CPU tag→`register_packet_rx` 驱动终端发现；上行发包沿 VLANIF 直出。
   - 构建提示：直接使用通用 ARM64 交叉工具链（如 `aarch64-linux-gnu-`），无需依赖 `aarch64-none-linux-gnu-`。
- **北向 API 约束**：
   - 本项目提供 `getAllTerminalInfo` 与 `setIncrementReport` 的 C 导出实现，对外暴露为稳定 ABI；外部团队实现 `IncReportCb` 并承诺在被调用时不阻塞。
    - 需兼容外部团队既定的 C++ 类型定义：
   - `struct TerminalInfo { std::string mac; std::string ip; uint32_t ifindex; uint32_t prev_ifindex; ModifyTag tag; };`
   - `typedef std::vector<TerminalInfo> MAC_IP_INFO;`
   - `typedef void IncReportCb(const MAC_IP_INFO &info);`
    - 导出函数接口保持如下签名：
   - `int getAllTerminalInfo(MAC_IP_INFO &allTerIpInfo);`
       - `int setIncrementReport(IncReportCb cb);`
   - 增量回调载荷包含 MAC、IP、ifindex、prev_ifindex 与变更标签，对应内部 `terminal_event_record_t` 的 `ADD/DEL/MOD` 标签；当标签为 `MOD` 时必须提供非 0 的 `prev_ifindex` 指出端口原值，其余标签下该字段填 0；调用侧需按标签填充 `MAC_IP_INFO` 中元素的 `tag` 字段。
   - C 入口层通过 `extern "C"` 封装桥接至 C++ 实现，禁止跨 ABI 抛出异常，所有异常在桥接层内部捕获并写日志。
   - `MAC_IP_INFO` 中元素的扩展字段若需新增，必须保持向后兼容并在接口文档中声明。
   - `setIncrementReport` 只允许在初始化阶段调用一次，再次调用时必须返回错误码提醒调用方重复注册。
   - 北向桥接提供 `terminal_northbound_attach_default_sink`，在未注册业务回调时为管理器挂接默认日志 sink；调用方若后续调用 `setIncrementReport`，桥接层会替换事件管线并开始推送增量数据。
   - 模块无需维护用于重置上报状态的单例指针；回调注册成功后保持实时推送行为即可。
   - 若回调异常或违反非阻塞约定，模块需记录结构化日志，并在必要时触发一次空 `MAC_IP_INFO` 的告警回调提醒上层处理。

## 详细行为
- **初始化与嵌入**：
   1. 在 `src/main/terminal_main.c` 定义守护进程可调用的初始化函数（命名遵循 `terminal_discovery_*` 约定），函数默认不会被 `main` 入口主动调用，需由宿主进程在自身启动阶段显式触发。
   2. 初始化函数读取 `td_runtime_config` 默认值后，读取传入的显式参数结构体，对其中合法字段应用覆写，再调用 `td_config_to_manager_config` 生成最终运行配置；每个字段的合并需具备边界检查和缺省回退。
   3. 初始化函数内仅负责构建 `terminal_manager`、选择适配器并启动核心线程，不注册信号处理器、不解析命令行参数，也不设置周期性日志输出；宿主进程如需这些能力需自行实现。
   4. 初始化完成后由北向桥接调用 `terminal_northbound_attach_default_sink` 绑定默认日志回调，保证外部未注册增量上报时仍能通过日志观察终端事件；当北向调用 `setIncrementReport(cb)` 时，桥接层负责替换事件 sink 并将批次推送给该回调。
   5. 默认日志回调实现位于 C++ 桥接层，内置格式保持 `event=<TAG> mac=<MAC> ip=<IP> ifindex=<IDX>` 输出，支持 `setIncrementReport` 运行期在“仅日志”与“业务上报”模式之间切换；若外部未再次注册，事件管线维持最新一次回调配置。
   6. 模块在守护进程生命周期内保持运行；停机与资源回收由宿主进程负责，通常与进程退出同生共死。
- **接口管理**：
   1. 仅依赖可解析的三层虚接口名称与 IPv4 地址表判断可用性；二层 access/trunk 口的物理 up/down 不触发状态变更。
   2. 收到 Access 口报文、且当前无法解析对应 VLANIF 时终端保持发现状态但不保活；Trunk 口报文无需再次校验 permit 集合（ACL 已确保 VLAN 合法），仅在缺失对应 VLANIF 或 IPv4 时按无虚接口逻辑处理。
   3. 虚接口的实际影响归结为“是否存在可用 IPv4”：只有当 `if_nametoindex` 能解析出 VLANIF，且该接口至少绑定一个与终端 IP 同网段的 IPv4 地址时，终端才被视为具备可用邻居并可进入 `ACTIVE/PROBING`。任一条件不满足都视作 `IFACE_INVALID`，即便上游持续推送事件也不会放宽判定。收到 ARP 报文时若发现对应 VLANIF 尚未满足上述条件，仍需记录/刷新终端条目，但立即将其状态切换为 `IFACE_INVALID` 并停止保活，等待后续接口恢复；该行为确保“已发现但暂不可达”的终端不会误报为活跃。
   4. 需监听 `RTM_NEWADDR/DELADDR` 并维护“可用接口地址表”（`kernel_ifindex -> {prefix}`，以下简称地址表中的 ifindex 均指内核接口索引 `kernel_ifindex`）。该表实现为哈希表或动态数组，元素保存接口索引、前缀长度、网络地址（CIDR 表示）。进程启动阶段必须先获取一次当前完整 IPv4 地址表并写入该结构（优先使用 Netlink `RTM_GETADDR` dump，无法获取时回退至 `getifaddrs` 等通用接口），保证在第一批终端报文到来前即可判断接口有效性；若初始化抓取失败需写入告警日志并维持重试钩子，同时保持终端按现有逻辑处于 `IFACE_INVALID`，以便覆盖确实未配置 IPv4 的设备。一旦监听到某 VLANIF 新增 IPv4，即刻重新解析该接口下所有待恢复终端：若新地址与终端同网段，则恢复 `tx_source_ip/tx_kernel_ifindex`，将状态推进到 `PROBING` 并在下一轮保活或报文驱动下返回 `ACTIVE`；若仍不匹配则继续保持 `IFACE_INVALID`。
   5. 为避免地址事件触发全量扫描，维护两类索引：
         - `iface_binding_index`：按 `kernel_ifindex` 记录已完成 `resolve_tx_interface` 的终端列表（链表头数组或哈希表均可）。当地址事件移除最后一个可匹配的 IPv4 前缀或后续解析发现该接口已不可用时，仅遍历该列表即可批量将终端转入 `IFACE_INVALID`，同时清除其绑定信息并迁移到待恢复结构。
         - `pending_vlan_index`：按 VLAN ID 记录因缺失 VLANIF、VLANIF DOWN 或无匹配 IPv4 而无法完成 `resolve_tx_interface` 的终端，可实现为 4096 个桶位的直接索引数组或基于 VLAN ID 的开放寻址哈希表（支持在大规模 VLAN 场景下按需扩容），元素内至少保存 VLAN ID、最近一次解析失败的时间戳与 `terminal_entry` 链表头指针。条目写入规则为：
            * 若 `resolve_tx_interface` 成功（VLANIF 存在且命中 IPv4 前缀），从 `pending_vlan_index` 移除并登记到 `iface_binding_index`；
            * 若 VLANIF 存在但暂时无匹配 IPv4，可保留 `kernel_ifindex` 元信息便于日志，同时只保留在 `pending_vlan_index` 中等待地址事件恢复；
            * 若 VLANIF 当前无法通过 `if_nametoindex` 解析或仍无匹配 IPv4，则记录当前 VLAN 及必要的元数据，等待后续地址事件或新一轮报文驱动时重试；若持续无事件触发，条目会在 `iface_invalid_holdoff_sec`（默认 30 分钟）到期后被自动老化清理。
         - 监听到某 VLANIF 新增/恢复 IPv4 或因终端迁移进入新 VLAN 时，仅遍历对应 VLAN 的待恢复列表重新尝试绑定，成功后进入 `PROBING/ACTIVE`，失败则继续保留在 `pending_vlan_index`。
         - 终端因 MAC 漂移或端口调整进入新 VLAN 时，需先在持有 `terminal_manager.lock` 的前提下从旧 VLAN 的 `iface_binding_index` 或 `pending_vlan_index` 中摘除链表节点，随即按照新 VLAN 的解析结果写入对应索引：若新 VLAN 已具备可用 VLANIF，则登记至 `iface_binding_index` 并触发携带新旧逻辑 ifindex（`terminal_metadata.ifindex`）的 `MOD` 事件；若仍缺少有效前缀，则落入新 VLAN 的 `pending_vlan_index`，并更新失败时间戳以便后续超时/告警分析。
   6. 地址表与反向索引的读写均在持有 `terminal_manager.lock` 时进行；外部事件处理（Netlink 回调）进入核心引擎后需先获取此锁，保证与 `resolve_tx_interface`、终端状态机操作不存在竞态。为降低更新阻塞，可在锁内完成结构更新后再脱锁触发终端状态变更/事件队列。
- **报文路径**：
    1. 适配器仅上报入方向的 ARP 帧及其元数据（MAC、VLAN、入接口、时间戳）给发现引擎；若内核因 RX VLAN offload 剥离 802.1Q 头，必须启用 `PACKET_AUXDATA` 并从 `tpacket_auxdata` 读取原始 VLAN ID；本机发送的 ARP 在适配层即被忽略。
   2. 引擎归一化 VLAN/接口上下文，更新或创建 `terminal_entry` 状态，并入队变更事件；Realtek 平台默认收包不携带 CPU tag。处理免费 ARP（sender IP 为 0.0.0.0 或缺省）的场景时，以报文中的 target IP 作为终端 IPv4 地址来源，禁止继续记录 0.0.0.0 作为终端地址；sender/target 同时为 0.0.0.0 的异常报文应直接丢弃并写日志。若检测到源 MAC 非单播（例如刻意构造的组播或广播源 MAC），同样视为异常报文，直接丢弃且记录 WARN，不创建终端条目、事件或统计；原因是以太网规范要求源 MAC 必须为单播，设备通常不会学习组播/广播源地址，继续处理会导致终端表污染、端口漂移误判或被伪造 MAC 消耗容量。
   3. 若收包 VLAN 命中 `ignored_vlans` 列表，则记录 DEBUG 级日志后立即返回，不创建或更新终端条目、统计或 MAC 查表任务。
   4. 若收包 VLAN 在当前地址表中找不到对应 VLANIF（例如尚未创建该 VLAN 的虚接口），仍需保留该终端条目以便后续查询与事件溯源，但状态必须立即标记为 `IFACE_INVALID`，并跳过保活/探测；此时默认没有可用的 `kernel_ifindex` 与 `tx_source_ip`，需保持终端处于待恢复状态。同时输出结构化日志提示“VLAN 无可用虚接口”。当后续创建或恢复该 VLANIF 并补齐 IPv4 后，终端应按照接口管理章节定义的恢复流程自动转入 `PROBING/ACTIVE`，无需重新收包。若之后运维将终端从原 VLAN 端口拔除并接入另一 VLAN 的二层口，引擎需在下一次收到该 MAC 的报文时立即刷新条目的 VLAN/端口元数据：
      - 若新 VLAN 已存在可用 VLANIF，则重新绑定 `tx_source_ip/kernel_ifindex`，将状态推进为 `PROBING` 并触发一次携带新旧 ifindex 的 `MOD` 事件；
      - 若新 VLAN 仍缺少 VLANIF 或 IPv4，则沿用新的 VLAN 上下文继续保持 `IFACE_INVALID`，等待对应虚接口恢复，同时记录迁移后的待恢复状态。
   5. 如平台提供 CPU tag，终端条目的 `terminal_metadata` 需记录 ifindex（无论来自 CPU tag 还是外部查询），并据此完成事件变更检测；保活发包仍基于内核接口信息。
   6. 发送路径依据终端最近一次有效报文关联的三层上下文构造 ARP request，在用户态封装 `ethhdr + vlan_header + ether_arp` 后直接通过物理接口（如 `eth0`）发送；无需为每个 VLAN 重新绑定虚接口，只要写入正确的 VLAN ID 即可保持与发现路径一致。
      - 若目标平台拒绝用户态插入 VLAN tag，则回退到绑定虚接口（如 `vlan1`）的发送方式。Stage0 Raw Socket demo 已验证 Realtek 平台支持物理口带 VLAN tag 的直出策略，需在 demo 与适配器实现中默认采用该模式并保留回退逻辑。
   7. `resolve_tx_interface` 的校验顺序：先尝试通过 `if_nametoindex`（或外部回调）解析出 `ifindex > 0`，再查可用地址表验证终端 IP 是否命中该接口任一前缀；只有同时满足才视为保活路径可用。任何一步失败都会清空现有绑定、将终端置为 `IFACE_INVALID`，并保持在 `pending_vlan_index` 中等待后续地址事件或新报文重试。地址事件清空最后一个前缀时需要同步移除反向索引节点，避免残留终端继续使用失效接口。
- **终端状态机**：
   - `(收到报文且对应 VLANIF 已提供可用 IPv4) → ACTIVE → (120s 无流量) → PROBING → (3 次失败) → 删除`；否则终端保持或转入 `IFACE_INVALID`，等待接口恢复后再通过定时或新报文进入 `PROBING/ACTIVE`。
   - `ACTIVE → IFACE_INVALID`：接口 down、出现跨网段 ARP（sender IP 与收包虚接口 IP 不在同一网段）或 VLAN 无虚接口；`IFACE_INVALID` 保留 30 分钟后删除。
   - `IFACE_INVALID → PROBING`：接口 up、IP 改为同网段或新增虚接口时复活。
   - `PROBING → ACTIVE`：收到回应即恢复活跃。
- **保活循环**：
   - 独立定时线程负责保活与过期扫描；Realtek 适配器需按 100ms 间隔分散发包，防止突发。
   - 发送保活前必须确认终端仍绑定可用的三层虚接口/VLAN，并沿着发现报文的接口发送 ARP（若接口失效则转入 `IFACE_INVALID` 处理流程）。
   - 探测失败计数递增；第三次失败后移除条目并发出删除事件。
- **事件上报**：
   - 增量事件在内部队列中形成批次后立即分发；终端新增、删除、属性变更（仅 ifindex 发生变化时产生 `MOD`）分别入队。
   - 事件载荷使用 `terminal_event_record_t`（MAC/IP/ifindex/prev_ifindex + ModifyTag），其中 `prev_ifindex` 记录端口变更前的值，仅在 `MOD` 事件有效，其余事件填 0 以维持结构一致，供外层转换为 `MAC_IP_INFO`。
   - 全量查询返回当前快照，原始顺序由内部遍历决定；需要排序的上层可自行处理。
- **并发模型**：
   - 终端核心数据使用读写锁保护；定时线程与报文线程的写操作通过串行化任务队列执行。
   - 上报线程消费事件队列并即时批量下发通知；查询与配置接口需串行化访问，避免竞态。

## 数据结构模型
- `terminal_manager_t`：持有终端链表/堆、互斥锁、定时线程、运行标志等；负责调度保活与对外接口。
- `terminal_entry_t`：记录 MAC、IP、状态、上次收到报文时间、上次探测时间、探测失败计数、平台元数据（含 VLAN、ifindex 等）、链表指针。
- `metadata_t`：封装平台相关字段（如 ifindex、vlan 等），便于不同适配器扩展。
- `iface_address_table`：哈希表 `ifindex -> prefix_list`，每个元素包含 IPv4 网络地址与掩码长度；所有修改在 `terminal_manager.lock` 下完成。
- `iface_binding_index`：反向索引 `ifindex -> terminal_entry*` 链表，用于在接口前缀变更时快速定位受影响终端。
- 支持单链表遍历与时间轮/堆双实现，依据目标平台性能选择。
- `td_debug_dump_context_t`：封装调试导出会话上下文（过滤条件、时间戳缓存、累计输出行数等），供各 `td_debug_dump_*` 函数复用，确保输出格式与生命周期一致。

## 任务拆解
0. **Realtek Demo 验证**
   - 使用网络测试仪构造至少 300 个虚拟终端，验证现有 Raw Socket 收发链路、保活探测与实时上报流程满足性能与稳定性要求。
   - 记录测试方法、日志与瓶颈观察结论，作为后续方案设计与编码的输入。
1. **平台适配框架**
   - 定义 `adapter_api.h` 接口及默认 POSIX 工具。
   - 实现 Realtek 适配器骨架：使用可移植的线程/锁与事件循环抽象（POSIX 或平台特有实现均可），结合 Raw Socket+BPF 过滤；发送路径在 VLAN 虚接口（如 `vlan1`）上通过 Raw Socket 构造并下发 ARP 请求，无需使用 SDK 报文发送库。
2. **终端核心引擎**
   - 编写终端数据结构、生命周期状态机与锁策略。
   - 集成时间轮或小根堆调度器，驱动探测与过期。
3. **报文解码模块**
   - 解析 ARP 帧，提取 VLAN/接口上下文，做输入校验并通知发现引擎。
   - 预留扩展挂钩，以支持未来的 DHCP。
4. **上报与 API 层**
   - 实现实时的变更通知队列。
   - 提供同步查询接口，返回的快照保持遍历顺序。
   - 定义输出载荷契约：内部 `terminal_event_record_t`（MAC/IP/ifindex + ModifyTag）转换为携带 `tag` 字段的 `MAC_IP_INFO` 单向量，并撰写桥接文档。
5. **配置与 CLI 钩子**
   - 提供配置结构体/环境加载器，用于适配器选择、探测间隔、终端阈值。
   - CLI 新增 `--ignore-vlan <vid>`，可重复传入；`td_config` 负责去重、上限校验，并在解析失败时给出可诊断错误。
6. **日志与遥测**
   - 集成分级日志宏；暴露探测、响应、过期等计数器。
7. **测试体系**
   - 编写状态机单测（ACTIVE↔PROBING↔IFACE_INVALID）。
   - 构建适配器 mock 测试覆盖发现、探测成功/失败、接口波动等场景。
   - 搭建性能基准，使用合成事件验证 1000 终端的时间行为。
   - 新增覆盖 `ignored_vlans` 的单元与集成测试，确保被忽略 VLAN 不产生终端或事件，并正确记录日志。
8. **文档**
   - 输出开发者指南，涵盖适配器契约、构建说明与测试执行方式。
9. **调试接口实现**
   - 实现 `td_debug_writer_t` 与默认 `FILE*` 包装函数。
   - 编写 `td_debug_dump_terminal_table`、`td_debug_dump_iface_prefix_table`、`td_debug_dump_iface_binding_table`、`td_debug_dump_mac_lookup_queue`、`td_debug_dump_mac_locator_state` 及其过滤器逻辑，确保在 `terminal_manager` 锁保护下输出一致快照。
   - 在单测与集成测试中覆盖正常路径、过滤参数、错误回调路径；补充 `doc/` 调试指南示例代码。

## 验收准则
- 发现状态机与定时驱动逻辑的单测全部通过，并覆盖 `ACTIVE ↔ PROBING ↔ IFACE_INVALID`、终端保留 30 分钟、接口恢复场景。
- 基于 mock 的集成测试覆盖发现、保活成功/失败、接口上下线恢复、实时批量、Trunk/Access VLAN 判定等场景。
- 实验环境验证 Realtek 适配器的 ARP 收发链路，确认 VLAN tag 解析、Raw Socket 发送与 100ms 发包分散策略有效。
- 在参考硬件上进行 1000 终端的 CPU 剖析，满足性能目标，并形成 200/300/500/1000 档位的资源报告。
- 提供 Realtek 平台 300 终端 Demo 验证报告，包含测试步骤、网络测试仪配置、日志与瓶颈分析结论。
- 日志为结构化格式，计数器可通过调试接口或日志输出查看。
- 在 C/C++ 混合编译环境下完成 `getAllTerminalInfo` 与 `setIncrementReport` 接口的联调验收，验证全量查询完整性、增量回调实时性与异常保护行为，并确认回调输出仅包含 `mac`、`ip`、`ifindex` 字段。
- 调试导出函数在运行态可输出终端哈希桶、接口前缀表、接口绑定索引、MAC 查表队列、`mac_need_refresh_`/`mac_pending_verify_*` 计数及 `mac_locator_version` 的一致快照；单测覆盖过滤与错误路径，文档示例与实际输出一致。

## 替代方案评估
- 为每个终端创建线程执行保活（因扩展性差而否决）。
- 利用内核态 eBPF 实现 ARP 嗅探（因可移植性成本高而暂缓）。

## 未决问题
- Realtek 平台上，当 trunk 口混合存在未建虚接口的 VLAN 时的报文行为需在实验室确认。
- 无 VLANIF 时广播/单播 ARP copy-to-CPU 行为已由平台 ACL 保障，终端发现模块无需额外确认。
- Netforward、通用 Linux 平台的接口事件获取机制尚未确定，需要在适配器设计时补齐。
- 若未来 `TerminalInfo` 需要扩展字段，需与系统集成团队确认版本策略并保持 `MAC_IP_INFO` 兼容性。

## 发布与回退策略
- 通过运行时配置开关控制特性，禁用适配器初始化即可回退。
- 回退时停止服务并移除钩子，运行态缓存之外无持久状态。
- 遥测：监控探测计数与上报队列长度，以捕捉潜在回归。
