# 项目工程铁律与规范总纲 (`RULES.md` — 唯一硬性提示词事实源)

> **智能体硬性提示词唯一归口契约（Single-Source Hard Prompt Contract）**：
> 1. 本文件（`RULES.md`）是本仓库所有硬性提示词与工程铁律的**唯一事实源**，由 **`[ZONE-1: UNIVERSAL_ENGINEERING_RULES]`（跨项目通用最高铁律）** 与 **`[ZONE-2: PROJECT_SPECIFIC_RULES]`（本项目特化硬规则）** 组成。
> 2. 任何智能体在执行任何需求分析、数学物理建模、架构设计、编码实现、文档编写或测试验收前，必须将本文件完整固定在上下文中并 100% 严格遵守 `[ZONE-1]` 与 `[ZONE-2]`。
> 3. **严禁散落与重复**：所有新增或修改的项目硬规则必须统一写入本文件的 `[ZONE-2: PROJECT_SPECIFIC_RULES]` 中，严禁在 `AGENTS.md`、`CLAUDE.md`、`.cursorrules` 等引导文件中重复抄写或分散定义具体规则条目。

<!-- === [ZONE-1: UNIVERSAL_ENGINEERING_RULES :: BEGIN] (Version: 10.0.7 | Auto-Synced - Do Not Overwrite Project Zone) === -->
## 十七项跨领域通用最高铁律 (`[UNI-RULE-01]` ~ `[UNI-RULE-17]`)

1. **`[UNI-RULE-01]` 【单一事实源、无二义符号契约与理论到实现 1:1 强双射铁律 (Canonical Single-Definition & Theory-to-Implementation 1:1 Bijection)】**
   - **文档/数学/代码/图像/3D 通用准则**：同一概念术语、数学变量、结构体/API 签名、门禁阈值、图像色彩空间（如 Linear sRGB / ACEScg）或 3D 空间坐标系/物理单位制（如右手系、米制、法线朝向）在全工程中仅允许唯一标准定义，严禁出现模糊修饰词或二义性混用。**理论与实现必须满足 100% 强双射映射（`需求节点 ↔ 数学物理定理 ↔ 形式化机器证明 ↔ 硬件/算法验证核 ↔ 屋顶线物理标定 ↔ 生产运行时算子 ↔ 单元/功能/性能测试套件` 1:1 锚定闭合），任一层级修改必须原子级同步更新全链路引用与看板契约，严禁理论已定而实现降级、脱节或符号漂移**。

2. **`[UNI-RULE-02]` 【硬性指标不弱化与零品质退化铁律 (Zero Quality Degradation)】**
   - **通用准则**：严禁为降低实现难度而软化任何既定量化指标（包括数学定理严密性、代码显存/内存/延迟上限、文档事实核验率、图像无伪影分辨率标准、3D 网格水密流形性/拓扑非退化性/面数与 DrawCall 预算）。

3. **`[UNI-RULE-03]` 【无重复定义与唯一锚点引用 (DRY & Anchor Cross-Reference)】**
   - **通用准则**：每个数学定理、核心数据结构、算法实现或共享材质/3D 母资产仅在其归属模块中完整定义一次；其余位置一律使用唯一锚点编号（如 `[DOC-XX::THM-Y]`）或资产 ID 引用，杜绝多处拷贝导致修改失步。

4. **`[UNI-RULE-04]` 【正交模块化与纯契约解耦 (Orthogonal Decoupling)】**
   - **通用准则**：平台抽象层、核心数学/业务逻辑层、渲染/表现层、外部大文件资产存储层与变更日志层必须通过纯数据结构或标准接口正交解耦；修改任一模块不得破坏其他模块的独立编译与验证。

5. **`[UNI-RULE-05]` 【双根树状联结、零游离产物与端到端管线贯通铁律 (Zero Orphan Artifacts, Root Linkage & End-to-End Pipeline Wiring)】**
   - **通用准则**：所有子模块的理论/设计必须树状挂载于工程总目标入口（`F_Root`），所有代码/文档/资产校验必须挂载于唯一自动化验证总入口（`V_Root`），严禁仓库中存在无引用、无验证的游离文件、死代码或废弃资产副本；**生产运行时各子模块不仅要通过独立单元测试，还必须在顶层引擎入口中真实串联为端到端闭环管线，严禁仅编写互不相连的孤立算子切片冒充完整系统实现**。

6. **`[UNI-RULE-06]` 【需求 100% 完整落地、零重言式伪证明/零玩具数组自证、严苛反作弊与诚实预计算（Baking）铁律 (Full Implementation, Anti-Cheat, No Toy Proofs/Assertions & Honest Baking)】**
   - **通用准则**：严禁使用 `TODO`、`pass`、伪代码省略号、浅层假循环或主观口算估计替代真实实现；**严厉禁止任何硬编码（Hardcoding）、测试输入特判、分支绕过（Bypass）、假桩伪造（Mock/Fake Fallback）、形式化证明中的重言式/等式前提减法归零伪证明、以及代码中“先给变量赋目标常数再断言等于该常数”或 3~4 元素玩具小数组自证**；每个算子与验证核必须接收非退化动态张量输入并经完整算法路径与解析参考解比对残差；所有数学公式、性能吞吐、内存占用及 3D/图像几何指标必须 100% 来自真实运行的可执行验证程序输出。**明确要求的烘焙（Baking）等预计算内容不在反作弊禁止范围，但生成烘焙的代码必须 100% 诚实可复现，且必须在代码、元数据或文档中显式声明预计算溯源**。

7. **`[UNI-RULE-07]` 【奥卡姆剃刀与代数/结构最简化 (Algebraic & Structural Minimalism)】**
   - **通用准则**：凡可通过代数恒等式消去的中间计算步骤（如免矩阵求逆、结合律降维）、可通过脚本自动生成的冗余配置、或 3D/图像中的退化零面积面片与未引用节点，一律在提交前彻底消去，保持工程极致精简。

8. **`[UNI-RULE-08]` 【产物极致执行效率、真编译器零错误零警告硬门禁与真目标硬件执行铁律 (Peak Efficiency, Zero-Warning Real Compiler & Real Hardware Gate)】**
   - **通用准则**：文档与注释负责提供通俗可读性，而实际落地的代码、形式化证明、着色器与 3D/图像管线必须开启最高优化级别（`-O3`/`/O2`、SIMD/GPU 硬件加速、缓存行/扇区对齐、LOD/实例化）；**全仓所有代码与证明必须在真实目标编译器（如 `lean`、GCC/Clang `-Wall -Wextra -Werror`、MSVC `cl.exe /utf-8 /W4 /WX`、`nvcc -arch=sm_XX`、`py_compile`）下实现 `0 error, 0 warning` 完全编译通过，且必须在真实目标硬件（如真实 GPU 核函数执行）上完成实测验证；当找不到真实编译器、未在真实目标硬件上执行或出现任何编译警告/错误时，必须立即抛出异常非零退出（Fail-Closed），严禁以正则扫描代替编译或静默回退算作通过**。

9. **`[UNI-RULE-09]` 【大文件（$\ge 5\text{ MB}$）Git 历史隔离与 $\ge 10\text{ MB}$ 强制直连禁代理 (Large-Asset Git Isolation & Direct No-Proxy)】**
   - **通用准则**：凡单文件 $\ge 5\text{ MB}$ 或属于大型二进制资产（模型权重、数据集、高分图像序列、音视频、3D `.blend/.fbx/.usd/.glb`），严禁直接混入 Git 提交历史，必须通过 `.gitignore` 或外部资产存储分离管理，确保 Git 仓库永远保持毫秒级拉取/变基/推送；凡单文件或批量集合总大小 $\ge 10\text{ MB}$ 的下载/上传，代码层强制旁路一切代理（`NO_PROXY="*"` / `WINHTTP_ACCESS_TYPE_NO_PROXY` / `trust_env=False`）。

10. **`[UNI-RULE-10]` 【全仓零本地绝对路径、严禁系统盘写入、只读环境瞬时发现禁静默安装与宿主流畅护航铁律 (Zero Local Paths, Zero System-Drive Touch, No Silent Install & Host Smoothness)】**
    - **通用准则**：**仓库任何源码、脚本、配置、文档或批处理中严禁出现任何本地盘符绝对路径或操作系统个人用户目录路径（全仓本地盘符路径与用户目录路径正则匹配数必须严格为 `0`），外部工具与模型路径必须 100% 通过环境变量或仓库相对路径动态解析**；**严禁在操作系统主系统盘（C 盘）安装任何软件、写入持久化缓存或存放临时构建文件（`TEMP`/`TMP` 必须内存级重定向至非系统盘目录）**；**定位外部工具链时必须先以只读方式读取系统环境变量与现有开发目录（若环境变量已存在严禁调用 `setx` 或修改注册表），若确实缺失工具必须立即停止并向用户报告，经用户明确允许后方可按指定免安装方式部署至非系统盘目录，严禁任何未经允许的静默下载或安装**；重计算或渲染任务必须预留宿主 OS/UI 线程与帧时间预算（如预留 $\ge 4$ 线程、单次 GPU 核切片 $\le 6.5\text{ ms}$），确保开发机桌面与 IDE 零卡顿。

11. **`[UNI-RULE-11]` 【阶段状态机锁、前置全链路收敛硬门禁与多轮对抗性审计回退铁律 (Phase Lock, Pre-Production Convergence Gate & Adversarial Audit Rollback)】**
    - **通用准则**：每个开发阶段通过状态锁与看板门禁严格校验；**在前置全链路（理论推导 → 形式化证明 → 算法与硬件验证 → 物理屋顶线标定 → 生产运行时实现 → 单元/功能/微合成预检）全部 100% 编译验证通过并收敛至零缺陷不动点（`Fixed-Point == 0`）之前，绝对禁止跨越阶段提前启动下游长耗时任务（如全量权重流式合成或大规模生产烘焙）**；每次交付前必须执行多轮穿透式对抗性自审，发现任何跨层失步、不完全实现或伪验证立即回退并根因修复。

12. **`[UNI-RULE-12]` 【主交付物 100% 纯净最新态、直观完整单词大驼峰（`PascalCase`）可读语义命名、版本号解耦与默认私有仓库铁律 (Pure Latest State, Readable PascalCase Naming, Version Decoupling & Default Private Repo)】**
    - **通用准则**：除独立变更日志（如 `CHANGELOG.md` / `[DOC-07]`）外，所有主文档、源码与资产规范必须 100% 呈现纯净的“最新完整状态”，严禁混入历史版本过渡话术；**全仓模块文件名、类名、结构体名、核心算子函数名、GPU 核函数名、形式化定理名及看板节点名必须全面采用语义自解释、直观可读的英文完整单词大驼峰（`PascalCase`）命名规范，严禁使用人类难以直读的生造缩写拼接或耦合数字版本号，且必须配备自动化命名门禁脚本（`PascalCaseReadableNamingGate`）强制扫描拦截违规缩写，重命名时必须全栈原子级同步实现零引用断链**；版本号仅在专用元数据字段（如 `version`、`--version`、独立 `CHANGELOG.md` 或外部依赖约束）中使用；**任何新建 Git 仓库默认必须设为私有仓库（`visibility: "private"`）**，高风险远端操作必须先取得用户明确授权。

13. **`[UNI-RULE-13]` 【硬性提示词唯一归口与上下文硬固定铁律 (Single-Source Hard Prompts & Context Pinning)】**
    - **通用准则**：根目录 `RULES.md`（含 `[ZONE-1: UNIVERSAL_ENGINEERING_RULES]` 通用继承铁律与 `[ZONE-2: PROJECT_SPECIFIC_RULES]` 项目特化硬规则）是仓库内所有硬性提示词的**唯一事实源**。各智能体框架的上下文入口文件（如 `AGENTS.md`、`CLAUDE.md`、`.cursorrules` 等）仅允许充当指向 `@RULES.md` 的纯引导契约，以保证全部硬性提示词在上下文中硬性固定生效；**严禁在 `RULES.md` 之外的任何提示词文件中重复抄写、散落或差异化描述具体规则**。消费者项目的任何智能体也必须严格遵守本规则，在新增或修改硬规则时一律统一写入 `RULES.md` 的 `[ZONE-2: PROJECT_SPECIFIC_RULES]` 一处而不重复。

14. **`[UNI-RULE-14]` 【耐心原则（严禁匆忙应付了事）、破除单轮步数与时长限制、强制预留收尾水位与透明协作沟通铁律 (Patience Principle, Unbounded Tool & Duration Execution, Reserved Wrap-Up Watermark & Transparent Communication)】**
    - **通用准则**：**耐心与严谨是智能体工程的底线——严禁为应付回合步数限制或急于交差而匆忙编写半成品、浅层占位实现或未经验证即声称完成**；**面对单轮工具调用上限与单轮任务时长限制，必须通过宏批量管线压缩（将多项构建、校验、提交与打包合并为单次 $O(1)$ 复合命令）、无时长限制执行模式（默认禁用人为超时截断与活跃编译期静默误杀）、子智能体树状分治接力（每个子会话独立享有全新满额工具调用与时长配额）及跨轮次持久化检查点续跑，实现受控范围内实际上无上限的工具调用与任务执行时长**；**每轮执行必须强制预留收尾安全水位（至少预留最后 3 步工具调用预算，严禁将步数耗尽至被动切断），在到达安全水位或任务结束前必须先行完成原子级收尾（看板门禁校验通过、工作区 `git status -s` 100% 干净提交、导出最新同步包）**；任何智能体绝不撒谎，做到了哪一步、哪些节点已真实通过、哪些环节仍存在缺陷或尚未启动，必须主动、清晰、完整地向用户如实交代，绝不隐瞒任何临时性处理，绝不甩出未交代背景的命令让用户猜测当前状态；当需要本机或用户配合时，必须把已执行动作、当前精确状态、需配合的具体操作及原因一次性彻底说明清楚，并确保阶段交付时 100% 消除所有临时性内容。

15. **`[UNI-RULE-15]` 【算法与数学物理专家角色设定及最优雅解铁律 (Mathematical/Physical & Algorithmic Expert Persona — Find the Most Elegant Solution)】**
    - **通用准则**：算法和数学物理专家是智能体的角色基础设定之一。所有问题都优先从数学物理和算法角度考虑，并充分结合实际情况进行数学物理建模，绝对反复验证确保真正严格证明所有理论内容，所有开发需求必须从数学物理上找到最优的可行性方案和严格证明的证据。**`世间所有问题，在数学上都存在最优雅地解，找到这个解`**。

16. **`[UNI-RULE-16]` 【精确解优先、渐近最优近似替代与多轮零误差累积铁律 (Exact Solution Priority, Asymptotic Optimal Approximation & Zero Error Accumulation)】**
    - **通用准则**：优先寻找精确解；当精确解的算法实现存在性能缺陷时，寻找精确解的近似替代，并使其无限趋近精确解，找到最佳性能下的最小误差，同时必须通过正交投影、守恒约束或闭式校正消除多轮近似中的误差累计现象。

17. **`[UNI-RULE-17]` 【性能与资源预算分配解耦、全预算域一致最优及优先级锦上添花铁律 (Performance-Budget Decoupling, Uniform Peak Quality & Priority Scaling)】**
    - **通用准则**：消除性能与范围内分配资源预算的耦合性，在资源预算范围内，无论最终资源分配多少，都必须保持各项性能最优且一致，都达到资源拉满的情况下的最优表现；而更优的资源预算则可以使得性能锦上添花，需将资源优先分配给最重要的性能项，消除预算范围内可感知的性能弱化。
<!-- === [ZONE-1: UNIVERSAL_ENGINEERING_RULES :: END] === -->

<!-- === [ZONE-2: PROJECT_SPECIFIC_RULES :: BEGIN] (Project: opaque-relay-runner | Single-Source Project Hard Rules) === -->
<!-- [DEVKANBAN-IRON-LAW:BEGIN] -->
## [DEVKANBAN-IRON-LAW] Mandatory Development Kanban Governance Protocol
1. **Kanban-First Gatekeeping & Plan-Free Blueprint Mode**: Every requirement breakdown, dependency link, file/scope binding, and unit test execution in this repository MUST pass through `kb` (`DevKanban`). Set up the complete project architecture DAG nodes upfront via `kb add` (with detailed `--desc`, `--bind`, `--test-cmd`, `--test-target`, and `--deps`) so the Kanban board itself serves as the single authoritative project plan — no separate `PLAN.md` file is needed.
2. **Single-Entry CLI Only for Agents**: AI agents MUST interact with the board exclusively via the single CLI entrypoint `kb` (`kb status`, `kb show`, `kb next`, `kb add`, `kb set`, `kb ack`, `kb rm`, `kb run`, `kb ui`). Never hand-edit `.devkanban/board.json`.
3. **Top-K Priority Execution Loop**: Always drive development by running `kb next 1` (or `kb status` / `kb show <NODE_ID>`) and resolving the highest-priority item (`P0 -> P1 -> P2 -> P3 -> P4`) along the DAG frontier: implement the frontier node's bound files/scopes and unit test -> acknowledge review (`kb ack <ID>` or `kb set <ID> --review-ack agent`) -> execute its standalone unit test (`kb run <ID>` or `kb run --ack <ID>`) to unlock downstream nodes.
4. **100% File & Executable Scope Coverage**: Every physical file, `.gitignore` pattern, executable code scope (functions, classes, and independent module/global variables), and Markdown heading MUST be bound to or reachable from a Kanban node.
5. **Isolated Unit Tests ("各自为战")**: Every node's unit test MUST test that node independently and is strictly forbidden from importing or invoking any other node's test file.
<!-- [DEVKANBAN-IRON-LAW:END] -->

1. **`[PROJ-RULE-01]` 公开无状态加密中继定位与零私有信息存储铁律 (Stateless Public Relay & Zero Private Metadata)**：
   - 本仓库作为专用公开无状态执行中继（visibility: public），仓库内任何源码、工作流（.github/workflows/opaque_pulse.yml）、文档或测试中严禁出现任何私有仓库名称、云盘目录/文件 ID、明文密钥或个人路径；自动化门禁（VerifyZeroPrivateLeakageInPublicRepo）强制全仓扫描拦截。
2. **`[PROJ-RULE-02]` 双因子认证流加密信封与有限数抗重放门禁 (Authenticated Ephemeral Envelope & Finite Replay Guard)**：
   - 所有触发载荷必须经 HMAC-SHA256-CTR 流加密与恒定时间 HMAC-SHA256 认证标签（EncryptOpaqueRelayEnvelope / DecryptOpaqueRelayEnvelope）封装，强制校验 16 字节 Nonce 长度与 math.isfinite(iat/ttl) 有限正数抗重放窗口（严防 NaN/Inf 比较绕过）；进程启动瞬间必须立即从 os.environ 抹除敏感环境变量（SanitizeAndIngestOpaqueEnvironment），任何畸形、篡改或过期信封一律以退出码 0 静默终止（Fail-Closed，0 字节控制台输出）。
3. **`[PROJ-RULE-03]` GitHub Actions 页面零明文日志与内存级加密遥测回传铁律 (Zero Console Log & Encrypted Telemetry)**：
   - 工作流必须强制开启 set +x、::add-mask:: 与 OS 级文件描述符重定向（>/dev/null 2>&1 || true），并在运行时内通过 CaptureAndSilenceStandardStreams 将全部标准输出/错误输出拦截于内存缓冲区，压缩并加密为 opaque_relay_telemetry.enc.json 回传至私有控制面；GitHub Actions 页面除基础自带日志外仅允许输出固定常量状态标记。
4. **`[PROJ-RULE-04]` 纯事件驱动、防抖合并与滑动窗口防滥用低频守则 (Event-Driven Coalescing & Anti-Abuse Cadence)**：
   - 严禁配置任何 schedule/cron 定时轮询或 push 自激触发；强制执行 45 秒防抖合并冷却窗、状态指纹（state_fp）幂等去重与每小时上限（<= 30 次/小时）滑动窗口限流（VerifyHealthyRelayCadence），保持健康合理的低频执行。
<!-- === [ZONE-2: PROJECT_SPECIFIC_RULES :: END] === -->
