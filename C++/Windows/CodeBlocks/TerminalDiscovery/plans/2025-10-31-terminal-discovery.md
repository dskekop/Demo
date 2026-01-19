# 终端发现代理实施计划

## 范围与关联规范
- **目标**：依据 `specs/2025-10-31-terminal-discovery.md` 中的最新需求与约束，构建可跨平台移植的终端发现代理，首期聚焦 Realtek 平台，并确保与外部 C++ 北向接口的 ABI 兼容，同时提供面向调试与验收的只读导出接口，能实时输出终端哈希桶、接口前缀/绑定表、MAC 查表队列及相关计数器。
- **交付/构建模式**：遵循规范新增要求，`common/`、`include/` 等平台无关代码编译为静态库供各平台复用；平台相关适配器（如 Realtek、Netforward、Linux raw socket）由各平台工程单独编译、链接，运行期不做动态选择。分拆时优先确保 Realtek 现网编译链畅通，控制迁移成本。
- **关联规范**：`specs/2025-10-31-terminal-discovery.md`

## 假设与非目标
- Realtek 平台具备 Raw Socket 能力并允许在物理口（如 `eth0`）直接封装 802.1Q VLAN tag 发包；若目标环境禁止用户态插入 VLAN tag，再回退到绑定 VLAN 虚接口（如 `vlan1`）。推荐交叉编译前缀为 `mips-rtl83xx-linux-`（如 `mips-rtl83xx-linux-gcc`）；若该工具链暂不可用，可使用通用 MIPS 交叉工具链验证代码可编译性。
- Netforward 平台报文自带 CPU tag，可直接提供整机 ifindex；无需 MAC 查表，也不依赖 `libswitchapp.so`；收发由 sidecar 进程与平台 hsl 通信后透传给主进程。需在本项目内提供 sidecar 打桩实现以便无 hsl 环境的集成验证。
- Realtek 平台进程、Netforward 平台进程与 sidecar 进程相互独立运行；跨平台可复用部分仅限静态库形式的公共代码（`libtd_common.a`），各平台适配器以对象方式链接到各自进程，运行期不做动态切换。
- 终端发现逻辑仅依赖入方向 ARP 报文；适配器需在收包侧过滤掉本机发送的 ARP，避免无意义事件，并在内核剥离 VLAN tag 时通过 `PACKET_AUXDATA` 取回原始 VLAN。
- 设备启动阶段已默认为所有二层口启用 ARP Copy-to-CPU ACL，适配器无需额外校验或感知该配置。
- 设备上存在网络测试仪或等效工具，可模拟 ≥300 个终端。
- 暂不考虑软件层面的 ARP 限速策略；若后续平台启用，需要重新评估。
- 外部团队提供的 C++ API（`MAC_IP_INFO` 及相关回调）按约定稳定，且允许我们在构建链中启用 C/C++ 混合编译。
- Realtek 二层表访问将依赖外部团队交付的 C++ 桥接模块（提供 C 接口，如 `td_switch_mac_snapshot`），桥接负责封装 `SwitchDev*` 创建与 SDK 函数入口，但不会主动调用 `getDevMacMaxSize` 或 `getDevUcMacAddress`；容量查询与快照均由本项目（含 demo）发起，并向桥接传递调用侧准备的 `SwUcMacEntry` 缓冲区。本项目不会直接 `dlopen` 或操作 `SwitchDev`。
- 项目默认采用 C 语言实现；仅在对接外部 C++ ABI 时引入必要的桥接代码。
- 当前回调/查询要求输出 `mac`、`ip`、`ifindex` 与变更标签四个字段，并以字符串/整型形式携带；未来扩展将另行评估，回调在初始化阶段注册后保持实时推送。
- 开发环境为 x86，而目标 Realtek 平台为 MIPS；与硬件相关的测试需在目标平台上手动运行与验证。
- 不在本轮实现 CLI/UI、DHCP/ND 嗅探或与 FIB 的深度集成。
- 平台适配仅在构建期选择单一适配器；运行期不切换。公共静态库与平台专有适配器需保持编译解耦，拆分过程中 Realtek 平台的编译/链接路径必须优先验证，避免现网被阻断。

## 分阶段计划

### 阶段 0：Realtek Demo 验证（已完成）
1. ✅ 搭建测试环境：网络测试仪直连交换机，确认 `eth0` 具备 Raw Socket 收发能力，并在用户态封装 802.1Q VLAN tag 后可直接发包成功。
2. ✅ 开发 `src/demo/stage0_raw_socket_demo.c`：
   - 接收端固定监听 `eth0`，加载 BPF 过滤器并启用 `PACKET_AUXDATA` 恢复 VLAN；收到 ARP 时打印 opcode/VLAN/源目标信息，可选择十六进制转储。
   - 发送端允许指定 `--tx-iface`、`--tx-vlan`、源/目的 MAC/IP、间隔、次数；默认使用物理接口 `eth0` 并在用户态插入 VLAN tag，必要时可显式切换到虚接口。
3. ✅ 实机验证（基础）：确认 RX 能恢复 VLAN、忽略本机发送帧；TX 在物理接口 `eth0` 上封装 VLAN tag 后保持 100ms 间隔发出 ARP，并在目标终端被正确识别。
4. ✅ Demo 校验：使用 stage0 demo 记录 `recvmsg` 返回的 ifindex/接口名，确认物理口 `eth0` 收到报文后解析出的接口名恒为 `eth0`，不能直接用于选择后续 ARP 发包接口，仍需依据终端绑定的 VLAN 元数据决定报文内容。
5. ✅ VLAN tag 直出验证：扩展 stage0 demo 支持 `--tx-iface` + `--tx-vlan` 在用户态封装 802.1Q header 并直接从物理口发包，记录成功/失败条件及平台差异；该模式现已作为主线发包策略输入，虚接口绑定作为回退选项。
6. ✅ 终端规模验证：已在 Realtek 目标环境完成 1000 终端并发保活演练（阶段内仅记录通过情况，CPU/内存等指标后续按需补测），确认整体链路在高并发下保持稳定。
7. ✅ 新增 MAC 表桥接验证 demo：外部团队已交付 C++ 桥接源文件及其 C 接口，并与 `src/demo/td_switch_mac_demo.c` 联调通过。demo 在入口阶段调用 `td_switch_mac_get_capacity` 估算最大条目并缓存容量，后续复用同一 `SwUcMacEntry` 缓冲区驱动 `td_switch_mac_snapshot`；桥接模块在装载期间完成一次性 `createSwitch` 与 `SwitchDev*` 缓存，调用路径严格遵守 SDK 缓冲区约定。快照接口的第二个参数 `out_count` 完全作为出参使用，不支持“请求条数”语义；调用方需事先按容量准备缓存并在返回后读取实际条目。该 demo 现作为 ifindex 获取/同步方案的基线实现，后续生产逻辑需复用相同的容量缓存与缓冲区复用模式，确保与桥接模块的数据流一致。

### 阶段 1：适配层设计与实现（已完成）
1. ✅ ABI 设计：`src/include/adapter_api.h` 定义错误码、日志级别、报文视图、接口事件、ARP 请求结构；`src/include/td_adapter_registry.h` + `src/adapter/adapter_registry.c` 注册并解析唯一 Realtek 适配器描述符。
2. ✅ Realtek 适配器：
   - RX：`realtek_start` 时创建 `AF_PACKET` 套接字，附加 BPF、`PACKET_AUXDATA`，在 `rx_thread_main` 中恢复 VLAN、ingress ifindex（Realtek 平台固定为物理口 `eth0`）与 MAC，并预留解析 CPU tag 所携带的 ifindex 线索；该 ifindex 仅用于日志或调试，不参与后续发包接口决策。
   - TX：`realtek_send_arp` 使用 `send_lock` 节流；默认在物理接口 `eth0` 的原始套接字中封装 802.1Q 头直接发包，优先采用请求内的 VLAN/接口信息生成帧；若驱动拒绝用户态 VLAN tag，则回退到绑定虚接口（如 `vlan1`），发送前仍会查询接口 IPv4/MAC，若接口无 IP 则跳过并记录日志。
   - MAC 表拉取：在 demo 验证通过的基础上集成外部桥接模块提供的 C 接口（如 `td_switch_mac_snapshot`），由适配层显式触发容量查询与快照，周期性/按需复用调用侧维护的 `SwUcMacEntry` 数组，拉取并解析为内部 `ifindex/vlan` 映射供终端管理器检索；需要在适配层自行管理缓冲区容量、重试回退与错误日志，并确保桥接模块初始化失败时不会阻塞主线程。`realtek_mac_locator_lookup` 必须严格按照规范区分错误码：缓存未完成或刷新失败时返回 `TD_ADAPTER_ERR_NOT_READY`，未在 MAC 表命中时返回 `TD_ADAPTER_ERR_NOT_FOUND` 并附带 `ifindex=0`，避免终端管理器重复排队。
   - 接口管理：通过 `terminal_netlink` 订阅 IPv4 地址新增/删除事件（`RTM_NEWADDR/DELADDR`），并在需要时调用 `if_nametoindex` 判断 VLANIF 是否已经可解析；接口创建/删除不再单独监听，保活节奏仍在终端引擎线程内统一调度。
   - 生命周期：实现 `init/start/stop/shutdown`，确保线程安全关闭；未实现的接口事件/定时器将返回 `UNSUPPORTED` 并记录告警。
3. ✅ 公共组件：
   - `td_config_load_defaults` 提供统一的默认运行配置（适配器名称 `realtek`、`eth0`/`vlan1`、100ms 发送间隔、INFO 日志级别）。
   - `td_log_writef` 提供结构化日志输出与外部注入能力。

### 阶段 2：核心终端引擎（已完成）
1. ✅ 终端表与状态机：
   - `terminal_entry` 记录 MAC/IP、Ingress/VLAN 元数据（CPU tag 或外部桥接获取的 ifindex 共用同一字段存储，ifindex 已编码底层 port 与接口类型，便于区分聚合/子接口等场景）、探测节奏（`last_seen/last_probe/failed_probes`）与发包绑定（`tx_iface/tx_kernel_ifindex`）。
   - 状态流转：`ACTIVE ↔ PROBING` 基于报文与保活结果切换；若运行时检测到绑定接口缺失可用 IPv4（接口 down、IP 被移除或迁移至其他网段导致无法构造 ARP），即判定为不可保活并进入 `IFACE_INVALID`，按 `iface_invalid_holdoff_sec` 保留 30 分钟。
2. ✅ 调度策略：
   - 专用 `terminal_manager_worker` 线程按 `scan_interval_ms` 周期驱动 `terminal_manager_on_timer`，统一处理过期、保活、删除流程。
   - 所有超时判断与定时节奏统一依赖 Linux 单调时钟相关 API（如 `clock_gettime(CLOCK_MONOTONIC, ...)`），避免系统时间跳变导致误判。
   - 后续若需要提高规模弹性，再评估时间轮/小根堆方案，目前观测以 1s 节拍满足需求。
3. ✅ 保活执行：
   - `terminal_manager_on_timer` 聚合需要探测的终端，生成 `terminal_probe_request_t` 队列，脱离主锁逐个回调 `probe_cb`。
   - 超过 `keepalive_miss_threshold` 后清理终端并记录日志，避免 livelock。
4. ✅ 接口感知：
   - 报文回调刷新 ingress/VLAN 元数据，并通过 `resolve_tx_interface` 应用选择器、格式模板或入口接口回退；VLAN ID 始终从 `PACKET_AUXDATA` 恢复，若底层暂未解析出逻辑 ifindex，则回落到配置/选择器给出的发包接口，同时触发异步调用桥接 API 尝试补全逻辑 ifindex。
   - 仅依赖可解析的 VLANIF 名称与 IPv4 地址新增/删除（Netlink `RTM_NEWADDR/DELADDR` 或平台等效回调）判断接口可用性，在 `terminal_manager` 内维护：
     * `iface_address_table`：`kernel_ifindex -> prefix_list`；
     * `iface_binding_index`：`kernel_ifindex -> terminal_entry*` 列表，用于已完成 `resolve_tx_interface` 的终端；
     * `pending_vlan_index`：按 VLAN ID 聚合仍缺失可用 VLANIF/IPv4 的终端，首选 4096 桶数组或可扩容的开放寻址表，元素记录 VLAN ID、最近一次解析失败时间戳、链表头及可选 `kernel_ifindex` 备注。
   - `resolve_tx_interface` 先确认 `if_nametoindex`（或 selector）能返回 `kernel_ifindex > 0`，再校验终端 IP 是否命中地址表任一前缀；任一环节失败都会清空绑定、将终端置为 `IFACE_INVALID`，并把条目保留在 `pending_vlan_index`，等待后续地址事件或新报文触发重试；若持续无事件，条目会在 `iface_invalid_holdoff_sec`（默认 30 分钟）到期后自动老化。
   - 地址事件或新的报文驱动仅遍历对应 `kernel_ifindex`/VLAN 的索引：若删除最后一个匹配前缀或后续解析仍无法绑定，则将 `iface_binding_index` 中的终端批量迁移到 `pending_vlan_index` 并标记 `IFACE_INVALID`；若新增 IPv4 使同网段前缀恢复，则仅重试该 VLAN 的待恢复列表，将命中的终端移回 `iface_binding_index` 并推进至 `PROBING`。
   - 终端因 MAC 漂移或端口调整进入新 VLAN 时，在持有 `terminal_manager.lock` 的前提下先从旧 VLAN 的索引中摘除，再根据新 VLAN 解析结果写入 `iface_binding_index` 或 `pending_vlan_index`。若成功绑定逻辑接口，则更新 `terminal_metadata.ifindex` 并触发携带新旧逻辑 ifindex 的 `MOD` 事件；否则刷新失败时间戳等待后续恢复。
   - 保活发送上下文仍依据终端绑定的 VLAN 元数据与物理接口配置组合，而非直接复用收包返回的逻辑 ifindex。
   - 监听到绑定 VLANIF 删除最后一个有效 IPv4 时，立即清空终端的 `tx_kernel_ifindex/tx_source_ip`，输出结构化日志并将终端置为 `IFACE_INVALID` 保留；当同一接口重新添加与终端同网段的 IPv4 后，在地址表/索引更新钩子中触发恢复流程，将其推进到 `PROBING` 并安排下一轮保活。
5. ✅ 并发与锁：
   - 哈希桶访问由主互斥保护，探测回调在 worker 锁外执行，杜绝回调 re-entry 死锁。
6. ✅ 文档：`doc/design/stage2_terminal_manager.md` 描述线程模型、接口解析策略与配置参数取值。

### 阶段 3：报文解码与事件上报（已完成）
1. ✅ 报文解析：
   - `terminal_manager_on_packet` 在持锁前采集快照，刷新 VLAN/接口元数据并据此触发状态切换；若暂未解析到 ifindex 时回退到 VLAN 模板或选择器结果，保证事件仍能携带有效上下文。针对免费 ARP（sender IP 为空或 0.0.0.0）的情况，明确改用报文 `target IP` 更新终端 IPv4 地址，禁止继续记录无意义的 0.0.0.0；sender/target 同为 0.0.0.0 的报文视为异常并直接丢弃。检测到源 MAC 非单播（组播/广播源）时同样判定为异常并丢弃、输出 WARN；理由是以太网规范要求源地址为单播，设备通常不学习这类源 MAC，继续处理会导致终端表污染、端口漂移误判或容量被恶意 MAC 消耗。
   - Realtek 平台结合 MAC 表缓存刷新 `terminal_metadata.ifindex`，若缓存命中失败则触发桥接 API 重拉，确保事件与北向查询对齐整机 ifindex。
   - 依赖 ACL 提供的 VLAN tag 判定终端归属；若地址表查不到对应前缀或无法再构造有效 ARP（例如 VLANIF 被移除 IPv4 或迁移网段），即转入 `IFACE_INVALID`，后续在地址恢复或报文再次到达时重新探测。
   - 当 VLANIF 重新获得有效 IPv4 时，事件队列需及时触发一次 `IFACE_INVALID → PROBING` 的状态变更（或 `MOD`/`ADD` 视上下文而定），并补充相应结构化日志，保证北向能够感知恢复并在下一轮保活重新探测。
2. ✅ 事件队列：
   - 使用单一 FIFO 链表收集 `terminal_event_record_t`（MAC/IP/ifindex/prev_ifindex + ModifyTag），在 `terminal_manager_maybe_dispatch_events` 内实时批量分发。
   - 分发阶段在脱锁状态下将节点拷贝为连续数组并释放，内存分配失败时记录告警并丢弃该批次，避免回调阻塞核心逻辑。
3. ✅ 北向接口：
   - 新增 `terminal_manager_set_event_sink`、`terminal_manager_query_all`、`terminal_manager_flush_events`，由本项目导出 `getAllTerminalInfo`/`setIncrementReport`，外部团队提供非阻塞的 `IncReportCb`。
   - 查询阶段生成 `terminal_event_record_t` 数组后脱锁回调；订阅阶段在初始化时注册后即刻推送首批事件，并在桥接层将记录映射为携带逻辑 ifindex（`terminal_metadata.ifindex`/`TerminalInfo::ifindex`）与 `prev_ifindex`、`tag` 字段的 `MAC_IP_INFO` 单向量，确保 `MOD` 事件提供新旧逻辑 ifindex，其他事件旧值置 0。
4. ✅ 文档：
   - `doc/design/stage3_event_pipeline.md` 说明事件链路设计、实时上报策略、关键数据结构与并发模型，便于后续维护与扩展。
5. ✅ 事件字段升级：
   - 在 `terminal_manager` 内部记录端口切换时的 `prev_ifindex`，并在 `queue_event`/`terminal_manager_query_all` 输出结构中暴露该字段。
   - 扩展 `terminal_event_record_t` 及相关结构以携带 `prev_ifindex`，在 `MOD` 事件时提供旧端口信息；更新 `MAC_IP_INFO`/`TerminalInfo` 桥接层映射与增量回调打桩，确保非 `MOD` 事件旧端口置 0。
   - 调整 `getAllTerminalInfo` 快照与查询路径，保证历史端口字段在全量输出中同步可见，并与事件载荷保持一致。
   - 扩展 `terminal_manager_tests`、`terminal_integration_tests` 覆盖端口切换场景，验证增量回调与全量查询同时携带新旧 ifindex。
   - 更新设计/接口文档与示例，通知北向团队完成回调消费方兼容性验证。
6. ✅ VLAN 忽略过滤：已在 `td_config`/`terminal_manager` 中引入 `ignored_vlans` 判定逻辑，命中时记录 DEBUG 日志后直接返回，并同步更新设计文档。

### 阶段 4：配置、日志与文档（已完成）
1. ✅ 配置体系：扩展 `td_config` 支持终端保活间隔、失败阈值、最大终端数量等参数；引擎统一从配置体系读取，暂不依赖环境变量。
2. ✅ 日志与指标：引入核心模块结构化日志标签（如 `terminal_manager`, `event_queue`），暴露探测计数、失败数、接口波动等指标，预留对接外部采集的入口，并确保全部基于单调时钟；主程序新增 `--stats-interval`（默认 0，即禁用周期性输出，可指定秒数开启），并支持 `SIGUSR1` 触发即时 `terminal_stats` 快照。
   - ✅ `td_log_writef` 默认格式追加 `YYYY-MM-DD HH:MM:SS` 级别的系统时间戳（wall clock），同时保留自定义 sink 兼容性并新增相应单测。
3. ✅ 文档：补充阶段 2+ 核心引擎设计说明、API 参考与构建部署指南，同步最新 `MAC_IP_INFO`/`TerminalInfo` 字段约束。
4. ✅ 配置扩展：在 `td_config`/CLI 中新增 `ignored_vlans`（支持 `--ignore-vlan <vid>` 多次传入、内部去重与上限校验），并在管理器配置结构体与运行期命令中落地，可选开关默认关闭。

### 阶段 5：测试与验收（进行中）
1. ✅ 单元测试：新增 `terminal_discovery_tests` 覆盖状态机（探测失败淘汰、接口失效保留期、ifindex 变更上报）与事件分发，命令 `make test` 可在 x86 环境快速执行。
   - ✅ 已实现日志时间戳断言（`test_default_log_timestamp`），通过重定向标准错误验证默认 sink 输出格式。
2. ✅ 集成测试：新增 `terminal_integration_tests`，基于打桩 netlink/ARP 流程验证 `ADD/DEL` 事件、统计数据和重复注册保护。
3. ✅ 北向测试：
   - 通过 `terminal_integration_tests` 驱动 `setIncrementReport`/`getAllTerminalInfo`，验证异常保护、字段完整性（含 `ifindex/prev_ifindex` 数值）与重复注册告警。
   - 后续若需并发访问覆盖，可在现有桩环境扩展多线程情景。
   - ✅ 忽略 VLAN 覆盖：单元/集成测试已注入被忽略的 VLAN 报文，验证不会生成终端/事件并输出过滤日志。
   - ✅ 跨 VLAN 迁移覆盖：已在 `terminal_integration_tests` 中新增跨 VLAN 迁移流程，用例验证终端在 `pending_vlan_index`/`iface_binding_index` 间的切换、`MOD` 事件携带新旧 ifindex 以及重新绑定后的保活态。
   - ✅ IPv4 恢复覆盖：新增集成测试模拟 VLANIF IPv4 删除与恢复，确认条目回迁、`tx_kernel_ifindex/tx_source_ip` 重建、状态推进与事件/日志输出均符合规范。
5. ⏳ 实机/压力验证：
   - 300 终端 Realtek Demo 回归；1k 终端压力测试记录 CPU/内存/丢包。
   - 新增“异常源 MAC”桩/集成用例：构造组播/广播源 MAC 的 ARP，验证管理器记录 WARN、丢弃报文、不创建终端/事件/统计。
6. ⏳ 验收输出：整理测试报告、回滚策略、性能曲线。

### 阶段 6：守护进程初始化入口（已完成）
1. ✅ 重构初始化契约：`terminal_discovery_initialize` 仅接收运行时配置覆写，内置默认日志回调并在重复调用时返回 `-EALREADY`，与规范保持一致。
2. ✅ 在 `src/main/terminal_main.c` 提取 `terminal_discovery_bootstrap` helper，共享 CLI 与嵌入启动流程，包括配置合并、管理器创建、Netlink 启动与适配器订阅。
3. ✅ 暴露只读 accessor `terminal_discovery_get_manager`/`terminal_discovery_get_app_context`，并在 `terminal_discovery_api.hpp` 汇总北向 API，`terminal_northbound_attach_default_sink` 作为默认日志 sink 的唯一声明。
4. ✅ 扩充 `tests/terminal_embedded_init_tests.c` 覆盖成功路径、重复初始化保护、事件 sink 切换与回滚流程，`make test` 已纳入执行。
5. ✅ 更新 `doc/design/stage6_embedded_init.md` 与 `doc/design/src_overview.md`，描述嵌入式初始化、默认日志模式与回滚策略；README 无需新增条目。
6. ✅ `make test`（包含嵌入初始化用例）和现有集成测试全部通过，确保代码与文档交付一致。

### 阶段 7：调试导出接口（已完成）
1. ✅ 设计 `td_debug_writer_t` 及 `td_debug_dump_opts_t/td_debug_dump_context_t` 数据结构，确保在核心锁范围内的调用不会引入阻塞 IO，并定义默认的 `FILE*` 写入包装。
2. ✅ 在 `terminal_manager` 内实现 `td_debug_dump_terminal_table`、`td_debug_dump_iface_prefix_table`、`td_debug_dump_iface_binding_table`、`td_debug_dump_mac_lookup_queue`、`td_debug_dump_mac_locator_state`，支持按状态/VLAN/ifindex/MAC 前缀过滤以及输出行数统计，并确保在 `writer` 返回错误时及时释放锁并上报错误码。
3. ✅ 更新北向 C++ 桥接，提供面向 `std::string`/`std::ostream` 的轻量封装及 `TerminalDebugSnapshot` 工具类，便于外部守护进程在不中断主流程情况下获取快照；同时新增示例代码演示如何注册回调与调用调试接口。
4. ✅ 扩展单元与集成测试：补齐 `td_debug_dump_pending_vlan_table` 实现，串联 CLI `dump pending vlan` 与 C++ `TerminalDebugSnapshot::dumpPendingVlanTable`，并在单元/集成测试及调试文档中覆盖 pending VLAN 场景与展开输出示例。

### 阶段 8：启动阶段地址表同步（已完成）
1. ✅ 审核 `terminal_netlink`、`terminal_manager` 现有初始化流程及 `iface_address_table`/`iface_binding_index` 结构，明确首批接口地址注入位置与锁保护策略。
2. ✅ 实现 `terminal_netlink_sync_address_table()`：优先使用 Netlink `RTM_GETADDR` dump 获取当前 IPv4 地址表，失败时回退 `getifaddrs`，并复用增量更新解析代码，确保写入时持有管理器锁；
3. ✅ 在管理器/适配器启动序列中调用初次同步；若抓取失败，记录结构化告警并立即维持终端处于既有 `IFACE_INVALID` 判定路径，同时注册基于 `terminal_manager_worker` 的周期重试钩子，待重试成功后补齐地址表并触发一次接口检查。
4. ✅ 扩展单元/集成测试，覆盖初次同步成功、抓取失败保持 `IFACE_INVALID`、重试成功后恢复保活等场景，确保日志与状态转移符合规范。

### 阶段 9：VLAN 点查接口整合（已完成）
1. ✅ 打桩扩展：在 `src/stub/td_switch_mac_stub.c` 增加 `td_switch_mac_get_ifindex_by_vid` 弱符号实现，支持入参填充 VLAN/MAC 后返回固定示例 ifindex/错误码，并沿用 `[switch-mac-stub]` 日志；通过环境变量配置命中/未命中行为。点查失败及全表查询失败场景均需打印“stub”标识，且不得主动将 `entry->ifindex` 清零，以免误导上层诊断。
2. ✅ Demo 演示：在 `src/demo/td_switch_mac_demo.c` 补充调用样例，展示点查成功与未命中输出，并保持与快照示例一致的格式；确保 demo 在无真实 SDK 环境下与打桩配合。
3. ✅ 适配器桥接：已在 `td_adapter_mac_locator_ops` 中加入 `lookup_by_vid` 指针，并完成 Realtek 适配器对 `td_switch_mac_get_ifindex_by_vid` 的封装，区分 `TD_ADAPTER_ERR_NOT_FOUND`/`TD_ADAPTER_ERR_NOT_READY` 等错误码，同时保持全表快照路径不变。
4. ✅ 管理器逻辑：`terminal_manager_on_packet` 已集成 VLAN 点查流程，在 `ifindex==0` 或 VLAN 变更时触发 `lookup_by_vid`，成功后写回 `meta.ifindex` 与当前 `mac_locator_version`，未命中仅记录日志并保留旧的 `meta.ifindex` 等元数据等待后续覆盖；`on_timer`/`on_refresh` 依旧沿用版本驱动策略，查询失败时同样维持旧 ifindex，不再强制写 0。
5. ✅ 测试补充：已扩展单元测试覆盖点查命中/未命中与 VLAN 切换 `MOD` 事件，并通过 `make test` 验证通过；后续若需 demo/stub 断言可在回归阶段追加。
6. ✅ 文档同步：已更新规范与设计文档引用（demo 指南、适配器说明、调试手册），标注点查接口调用顺序与回退路径，并说明点查不返回版本号时由管理器写回当前版本的处理方式。

### 阶段 10：构建与目录拆分（进行中）
1. ✅ 顶层分发器 + 子目录 Makefile：当前仅拆分 Realtek、Netforward 两个平台入口（对等命名的 `make realtek`、`make netforward`），跳转到对应子目录的独立 makefile；各平台 makefile 负责主进程（以及仅 Netforward 的 sidecar）与 `libtd_common.a` 的生成/清理，不暴露“仅编库”目标，并将对象/产物输出到私有目录（如 `out/<platform>/`）避免冲突。
2. ✅ 平台白名单与 sidecar 目标：Realtek/Netforward 各自 makefile 采用白名单列出自身源文件，禁止跨平台引用；Realtek-only 源（`stub/td_switch_mac_stub.c`、`demo/td_switch_mac_demo.c`、`src/ref/realtek/*` 及依赖 Realtek SDK 头的文件）仅在 Realtek 构建入口参与，Netforward 排除。Netforward makefile 提供独立 `sidecar`/`sidecar-stub` 目标，sidecar 产出独立二进制，支持变量切换真实 IPC 对象或 stub。
3. ✅ 测试矩阵梳理：平台无关测试标记为各平台必编必跑；平台相关测试仅在对应平台 makefile 中构建/执行，并保持输出目录隔离以便流水线并行（已在 x86 下通过 `make realtek-test`、`make netforward-test` 回归）。
4. ✅ cross-generic 支撑：各平台 makefile 增设 `CROSS_PREFIX`/`cross-generic` 目标，使用通用交叉工具链完成一次编译验证并记录结果；默认通用前缀为 Realtek/MIPS `mips-linux-gnu-`，Netforward/ARM64 `aarch64-linux-gnu-`。厂商专有前缀（如 `mips-rtl83xx-linux-`/`aarch64-none-linux-gnu-`）仅在可用时供 `cross` 目标选择性使用，不作为默认或必备。
5. ✅ 公共代码静态库化：`libtd_common.a` 汇总 `common/` 与北向 C++ 代码，默认随平台构建产生并在各平台 makefile 内负责清理。
6. ✅ 平台适配编译边界：各平台适配器/桥接/stub（sidecar 除外）以对象文件复用并与应用链接，不再打包静态库，运行期不做动态选择。
7. ✅ 构建脚本回归：在拆分后回归 x86 `make realtek-test`、`make netforward-test`，并在各平台流水线新增“平台无关测试”与“平台特定测试”两个步骤，完成一次 `cross-generic` 编译验证入口（`realtek-cross-generic`、`netforward-cross-generic`）。

## 依赖与风险
- 依赖网络测试仪能稳定模拟大规模 ARP 终端。
- Raw Socket 权限或平台安全策略可能禁止用户态插入 VLAN tag 或绑定虚接口，需要在部署前确认可行的发送策略。
- Trunk 口在部分 VLAN 未建虚接口的报文行为仍待实验确认，可能影响终端保活策略。
- 若后续需要在 `TerminalInfo` 增加字段或调整序列化格式，需提前与系统集成团队确认版本策略并保持 `MAC_IP_INFO` 兼容性。
- 接口事件源（netlink/SDK）若行为差异大，需追加适配层开发。
- Realtek MAC 表桥接模块由外部团队维护，需确保源码及时交付并与主仓构建系统兼容，否则相关功能与测试将滞后。
- 调试导出接口在持锁遍历哈希桶时需要上层 `writer` 保持无阻塞特性，否则可能拉长核心锁持有时间；上线前需验证默认 `FILE*` 包装及外部适配器的行为。

## 验证策略
- 单元测试：状态机、定时器、实时上报链路。
- 集成测试：使用 mock 适配器模拟报文与接口事件。
- 实机测试：Realtek 平台 300 终端 demo；若资源允许扩展到 1000。
- 性能监测：CPU、内存、报文速率、探测成功率，覆盖 200/300/500/1000 终端档位。
- 由于平台差异，所有实机验证步骤需在 MIPS 目标环境手动执行，并记录操作过程与结果。
- 调试导出接口：在单测中通过打桩 `writer` 验证过滤条件、错误回调与空数据集处理，在集成测试中生成真实哈希桶/队列快照并校验关键字段。

## 审批与下一步
- 当前状态：阶段 0 Realtek Demo 验证、阶段 4 配置/日志、阶段 6 嵌入式入口以及阶段 9 VLAN 点查整合均已交付，相关设计更新可见 `doc/design/stage4_observability.md`、`doc/design/stage6_embedded_init.md`、`doc/design/src_overview.md`。
- 下一步：聚焦剩余待办——(1) 整理阶段 0 1000 终端演练记录与资源占用摘要（若验收需要可追加指标采集）；(2) 在阶段 5 推进实机/压力测试与北向鲁棒性验证；(3) 汇总验收报告与回滚策略文档，为最终项目评审做准备。
