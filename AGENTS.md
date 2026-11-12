## 项目概述

**伴随设备身份校验**（`@ohos/companion_device_auth`）是 OpenHarmony 的用户身份校验执行器，通过伴随设备（手表、耳机、PC）对用户进行身份校验。它作为 `SystemAbility` 注册在 `useriam` 子系统中，与统一用户身份校验框架（`user_auth_framework`）集成。

两种角色运行同一套代码：
- **主机（Host）**：被校验的设备（手机通过手表近距离解锁）
- **伴随（Companion）**：执行校验的设备（手表确认佩戴者身份）

行为按设备持有主机绑定还是伴随注册区分。

## 知识索引（改动前按场景先读）

| 场景 | 先读 |
| --- | --- |
| 新增/修改对外 API | `interface/` → `frameworks/native/client/` → `frameworks/native/ipc/idl/` → `services/service_entry/`（四层贯通） |
| 改请求生命周期/超时/取消 | 下方「请求与订阅生命周期」 |
| 跨线程调用/阻塞操作 | 下方「线程模型」 |
| 定位跨设备交互 | `services/cross_device_interaction/<type>/` + `services/cross_device_comm/` |
| 改跨设备消息格式 | 下方「跨设备消息兼容」 |
| 改算法/协议/能力协商 | 下方「协商」 |
| 安全/加密/存储 | `services/security_agent/`（C++）→ `services/external_adapters/security_command_adapter/`（Rust） |

## 构建与测试

GN/Ninja 组件，用 `oh-build` 构建、`oh-test` 跑测试。

| 目标 | GN 路径 |
| --- | --- |
| 服务 | `//base/useriam/companion_device_auth/services:companion_device_auth_service_group` |
| 客户端库 | `//base/useriam/companion_device_auth/frameworks/native/client:companion_device_auth_client` |
| JS/NAPI | `//base/useriam/companion_device_auth/frameworks/js/napi:companiondeviceauth` |
| ETS/ANI | `//base/useriam/companion_device_auth/frameworks/ets/ani:companion_device_auth_ani` |
| C++ 单测 | `//base/useriam/companion_device_auth/test/unittest:companion_device_auth_unittest` |
| Rust 单测 | `rust_companion_device_auth_services_test` |
| 模糊测试 | `//base/useriam/companion_device_auth/test/fuzztest:companion_device_auth_fuzztest` |

`companion_device_auth.gni` 的特性标志控制条件编译：`companion_device_auth_has_soft_bus_channel`（SoftBus 跨设备通道）、`companion_device_auth_has_account_os_account`（用 OS 账户管理器而非常量用户 ID）、`companion_device_auth_has_ext`（ext 部件存在时由它提供服务共享库）、`companion_device_auth_enable_coverage`（测试覆盖率插桩）。

测试基础设施：`test/unittest/services/cpp/common/inc/` 放 mock 头；`test/fake/` 替换定时器、SoftBus、系统参数依赖；测试以 `-Dprivate=public -Dprotected=public` 编译。

### 验证取证（必做）

- 能执行：实际跑最小编译/测试，把 `status`/`command`/`message` 写入 `build_result.json` / `test_result.json`。
- 环境不可用：写 `status: skipped` + 具体原因；**禁止** `not_run`，**禁止**谎报 `passed: true`。
- 理解/定位类：答案里给出「最小验证方式 + 通过判据」。

## 架构

```
interface/           → 公共 API 头文件（inner_api）
frameworks/
  native/client/     → C++ 客户端库（IPC 代理）
  native/ipc/        → IDL 生成的代理/存根
  js/napi/           → JS/NAPI 绑定
  ets/ani/           → ArkUI Native Interface 绑定
services/            → 核心服务实现
  service_entry/     → CompanionDeviceAuthService（SystemAbility 入口）
  singleton/         → 单例管理器（所有 manager 的统一获取入口）
  cross_device_comm/ → 跨设备通信基础设施（通道、路由、设备状态）
  cross_device_interaction/ → 业务请求处理器（按交互类型划分）
  companion/         → 伴随设备注册管理
  host_binding/      → 主机设备绑定管理
  fwk_comm/          → UserIAM 框架集成（执行器注册）
  security_agent/    → 安全层（与 Rust 通过 cxx 桥接）
  request/           → 请求生命周期管理
  external_adapters/ → 平台适配层（SoftBus、账户、身份校验器等）
  utils/             → 工具类（定时器、任务运行器等）
  misc/              → 杂项属性/参数
```

### 关键模式

**IPC**：`frameworks/native/ipc/idl/` 中的 IDL 文件生成代理/存根类。服务端继承 `CompanionDeviceAuthStub`；客户端使用 `CompanionDeviceAuthProxy`。

**单例管理器**（`services/singleton/`）：所有管理器通过集中的 `SingletonManager` 访问，提供类型化的 getter。这避免了直接使用全局状态并支持测试模拟。

**请求模式**（`services/cross_device_interaction/`）：每种交互类型（add_companion、token_auth、delegate_auth 等）都有各自的子目录，包含：
- `*Message` 类 — 序列化/反序列化
- `Host*Request` / `Companion*Request` — 各角色的请求处理器
- `*Handler` 类 — 入站消息处理器（同步/异步）

**消息路由**：`cross_device_comm/` 提供通道抽象。`MessageRouter` 将入站消息分发到已注册的处理器。`ConnectionManager` 和 `DeviceStatusManager` 处理传输层生命周期。

**线程模型**：常驻线程上的单线程事件循环。所有 adapter/singleton 访问必须在常驻线程上进行。IPC 回调使用 `PostTask` 委派到常驻线程。阻塞操作在临时线程上运行，然后通过 `PostTask` 返回。

**安全代理**：通过 cxx 桥接到 C++ 的 Rust 实现。处理加密操作和安全命令处理。位于 `services/security_agent/`，Rust 源码在 `services/external_adapters/security_command_adapter/`。

**执行器集成**：`fwk_comm/` 使用 `AllInOneExecutor` 模式将伴随设备认证注册为 UserIAM 框架的执行器，支持注册/认证/删除操作。

**链路汇聚点（跨设备链路还原时勿漏）**
- `services/singleton/inc/singleton_manager.h` — `SingletonManager`，所有 manager 的统一获取入口。
- `services/singleton/inc/cross_device_interaction/incoming_message_handler_registry.h` — `IncomingMessageHandlerRegistry`，所有入站 handler 的集中注册表。

**专家经验（改动前必读）**：线程边界（adapter/singleton 仅常驻线程访问，跨线程用 `PostTask`）与请求/订阅生命周期（`Destroy()` 先释放 `Subscription`，cleanup 只做本地 erase）是本仓最易踩坑的两处，详见下方「线程模型」「请求与订阅生命周期」。

## 代码风格

### 内存与指针安全

- **所有分配必须进行空指针检查**：`std::make_shared`/`std::make_unique`/`new (std::nothrow)` 的结果必须创建后立即用 `ENSURE_OR_RETURN_VAL` 检查
- **成员变量和参数不用裸指针**：成员变量用 `std::shared_ptr`，函数参数用 `const std::shared_ptr<T>&`
- **异步回调用 `weak_from_this()`**：生命周期超出当前作用域的 lambda 禁止捕获 `this` 或 `shared_from_this()`，改用 `weak_from_this()` 再 `lock()` 并检查空
- **例外**：`ScopeGuard` 一类栈绑定对象可裸 `this`，与所在函数同生命周期
- **防御性空指针检查**：每个函数入口检查自己的指针参数（不依赖调用者）；成员变量在每个方法开头检查一次即可，同一方法内不重复

### 线程模型（仅 services/）

所有 `adapter` 和 `singleton` 访问必须在**常驻线程**上运行。IPC/框架线程和临时线程通过 `PostTask` 委派。

```cpp
// 同步：IPC 线程需要返回值
ResultCode code = GENERAL_ERROR;
std::promise<void> done;
auto future = done.get_future();
if (!TaskRunnerManager::GetInstance().PostTask([&]() {
    code = GetManager().DoWork();
    done.set_value();
})) { return GENERAL_ERROR; }
auto status = future.wait_for(std::chrono::milliseconds(500));

// 异步：即发即弃，回调在常驻线程执行
TaskRunnerManager::GetInstance().PostTask([cb = std::move(callback)]() mutable {
    auto result = GetManager().DoWork();
    cb(result);
});

// 阻塞操作：临时线程跑完回常驻线程（REPORT = 外部依赖挂起只上报不杀进程）
TaskRunnerManager::GetInstance().PostOneShotTask("name", "ownerBundleName", TaskBlockPolicy::REPORT,
    [...]() {
        int result = BlockingCall();
        TaskRunnerManager::GetInstance().PostTaskOnResident([result]() {
            GetManager().HandleResult(result);
        });
    });
```

- `TaskRunnerManager::GetInstance().RunningOnDefaultTaskRunner()` 在当前处于常驻线程时返回 true。
- `PostTaskOnResident` 就是给非常驻线程用的，从 IPC/临时线程调它是正确用法。
- **服务单线程模型**：服务方法在常驻线程串行执行，成员变量无需互斥锁。单方法内的 TOCTOU（检查后使用）是安全的，不要标记为竞态。

### 请求与订阅生命周期

`RequestManagerImpl::Remove` 由 `BaseRequest::Destroy` 经 `PostTaskOnResident` 延迟触发；常驻线程 `deque::erase` 时若该 `shared_ptr<IRequest>` 是最后一个引用，析构函数**同步在 erase 现场执行**。此时若析构链上的 `Subscription` cleanup 同步干了复杂活（典型：`UnsubscribeDeviceStatus → RefreshDeviceList` 改 `deviceStatusMap_`），就会破坏正被 erase 的堆，表现为 jemalloc `may double free`。为此两条硬规则：

1. **每个 Request 在自己的 `Destroy()` 里释放所有 Subscription 成员**——调基类 `Destroy()` 前 `xxxSubscription_.reset()`。`Destroy()` 必先于析构执行（`Remove` 从 `Destroy` 内 PostTask），从而把 cleanup 移出 erase 现场。各层各管各的：`OutboundRequest`/`InboundRequest::Destroy` 释放本层 subscription，派生类释放自己的，`BaseRequest::Destroy` 已由 `StopTimeout` 释放 `timeoutSubscription_`。`Destroy()` 非虚，派生类靠 name-hiding 不要加 `override`；`Complete*` 里的非限定 `Destroy()` 会解析到最派生版本。
2. **Subscription 的 cleanup lambda 只做本地 erase**（从所属 manager 容器移除/取消定时器后结束）。周边副作用（`RefreshDeviceList`、`NotifySubscribers`、observer 增删、外部 sysparam 解注册等）必须用 `PostTaskOnResident` 延迟，并捕获**所属 manager** 的 `weak_from_this()`（不是 Request 的），manager 比单个 Request 长命故 late-safe。合规模板：`SystemSettingsManagerImpl::SubscribeSettingsChange`、`AuthenticatorManager::SubscribeAuthenticatorStatus`。

## 跨设备消息兼容

跨设备消息就是各 `*Message` 的 Encode/Decode，内容装在 `Attributes` KV 里。这些消息一旦上线，对端可能还是旧版本 SA，所以新主机×新伴随、新×旧、旧×新、旧×旧四种组合都要能跑通。

1. **新字段一律可选**：Decode 用 `HasAttribute` 判断，字段缺了不能 decode 失败；Encode 只能新增 key，不能改已有 key 的含义（这条只限同一条消息——`AttributeKey` 按消息隔离，别的消息里用同一个 key 表达同样的意思没问题）。
2. **新字段缺省时走旧行为**：旧对端不发这个字段，本端要按旧逻辑跑完，不能报错退出。例外是明确不考虑旧端的字段（比如 enroll 回包的 capability），缺了就当失败。
3. **`ATTR_CDA_SA_PROTOCOL_ID` 缺省就是 `VERSION_1`**，不能改。新版本主机一定会带这个字段，缺省值代表"还没带协商字段的老对端能用的协议"。线上如果显式收到 INVALID(0)，按"协商了本端不支持的协议"报错。
4. **本地 DB 不做兼容**：只有一种记录格式，新字段无条件读写，不写版本判断、不做旧格式回退、不做迁移。blob 头的 `CURRENT_VERSION` 恒为 0，只用来标格式和查损坏。格式变了就让旧数据作废——清掉重新绑定，不为旧数据写代码。
5. **Rust 安全 blob 的编解码也按第 1、2 条审**：`security_command_adapter` 里的编解码结构解不出来，链路就断了。
6. **支持列表只能加值不能删值**：上线过的取值不能从支持列表里删。录入时保存的参数必须与后续交互保持一致；删值会导致存量绑定无法同步，也无法重新绑定。确实要删时，必须同时提供数据迁移或强制重新绑定。
7. **同步回包的两层列表必须来自同一份数据**：加密内层列表和明文外层列表必须由发送方用同一份数据构造，不能"内层照抄对端的 offer"。
8. **同步出错不能伪装成没绑定**：伴随有绑定但生成 proof 失败，要通过 `result` 返回错误，不能降成 `SUCCESS + 空 proof`；安全层返回成功也不行，服务层必须检查 proof 非空。只有真的没有绑定，才能返回成功加空 proof。旧对端的 `SUCCESS + 空 proof` 有歧义，主机要保留凭证、允许发现、记告警，不能拿它作废凭证。
9. **作废凭证只有一个来源**：已定位绑定的复验轮里，`HostEndCompanionCheck` 返回任何非 SUCCESS（proof 不过、secureProtocolId 非法、参数对不上）都 `SetTemplateInvalid`，参数分歧的 20011/20014 用专属 reason，其余用通用 reason。作废只影响凭证，不影响本轮——`EndCompanionCheck` 返回 void，作废后本轮 sync 照样算成功。
10. **发现和绑定复验分开**：同步请求发布本端完整的支持列表；收到回包后按当前主机用户和回包里的伴随用户找到绑定，再校验绑定时保存的参数。不能用缓存用户去裁剪发现请求。发现里的 secureProtocolId 表示新绑定将用的值，已有绑定的安全封装读 DB 里的持久化值。接受轮学到的用户编号只用于发现展示和重绑路由，不给任何信任；作废判定跟发现缓存热不热没关系。
11. **一个设备可以有多个 processor、多个 SK**：这是设计要求。一个对端设备可含多个 processor，enroll 时每个 processor 独立做 KA、写独立的 SK 行。安全消息按 processor 分节，一条消息可以载多节。host 侧 enroll/delegate/issue/obtain/sync 都要遍历 `read_device_capability_info` 逐节 decode，每一节都得解开，空表报错；不要用 device 行保存的参数把设备当成单个 processor，从而跳过这个循环。
12. **改消息的 UT 必须有一条"不带新字段的旧格式 decode"用例**，模板见 `add_companion_message_test.cpp` 的空 attribute case。

## 协商

算法、协议、能力三件事做法相同：两端在加密通道里互传支持列表，各自跟本端支持集求交集。有优先序的按顺序取第一个命中的，没有优先序的只要交集非空。对端列表里本端不认识的值被交集自然滤掉，**不要对整个列表做成员校验**——那会挡住对端扩容后的逐步对齐。

校验分两档：录入（enroll）时对双方列表求交集、按优先顺序选值，并核对两端回显；已有绑定在同步（sync）时复验绑定时保存的参数。对端加密内层必须包含这些参数；能力列表必须完整包含保存的所有能力。缺少任何一项都按参数分歧失败，不允许只取交集后继续。

集合来源决定怎么分组：协议和能力来自 C++ FFI（两端各持一份列表），算法来自 TA 自己（一份常量）。

### 优先序

顺序只在三处有意义，其余一律按集合比较（`IntersectList` 只保证去重，不保证顺序）：

- `LocalDeviceProfile.protocols` —— 协议优先序
- 本端能力列表 —— 能力优先序
- `SUPPORTED_KA/KDF/AEAD/MAC_ALGORITHMS` —— 算法各角色的优先序（两端共用一张表：成员是支持集，顺序是优先序）

**已上线成员的相对顺序不能改**，改了正常升级就会互通失败；新成员按优先序插入，位置由它的优先级决定。宣告出去的列表本身只包含能接受的值——防"被逼选弱值"靠的是列表内容，重新比对防的是实现或偏好表跑偏。

### 算法

host 用明文的 `SecKeyNegoRequest` 发全部支持的算法；companion 按 `SUPPORTED_*` 顺序逐角色选第一个交集值，任一角色没有交集就返回 20015。

之后有三处比对，缺一不可：companion 在加密的 `SecBindingRequest` 里核对 host 回显的算法集合与明文收到的一致；host 收到选中值后核对它等于自己在本端优先序 ∩ 对端宣告集上重算的期望值，也等于本分节明文里的选中值。最后这条不能删——MAC 在 enroll 期不参与加解密，也不参与密钥派生，它是明文 MAC 被中途改掉的唯一防线。对端不宣告支持集（旧对端）时跳过重算这条，其余两条仍生效。

算法只在录入时协商一次并保存，同步阶段不再协商。`secure_protocol_id` 只管消息格式、分节和同步复验，不含算法含义。不设打包的 crypto suite 版本号，算法演进靠逐参数机制。算法协商的线格式不兼容未支持四角色协商的旧对端，旧端初次绑定需双方同版本；存量绑定不受影响（算法在录入时定，之后读 SK 保存值）。

### 协议

host 的 C++ `NegotiateProtocol` 按本端 `protocols` 顺序选择双方都支持的第一个协议，明文宣告，并将本端完整优先顺序列表放进 `SecBindingRequest` 加密内层下发。两端都要重新计算并比对：companion 根据收到的 host 优先顺序和本端支持列表重算，结果必须等于本端已选中的协议；host 根据 companion 宣告的支持列表和本端优先顺序重算，结果必须等于绑定时保存的协议。任一端结果不一致都返回 20011。回包仍带一个单值回显。

### 能力

host 本地持本端能力列表参与求交，不在 `SecBindingRequest` 加密内层下发；companion 在 `SecBindingReply` 回本端能力列表。host 按本端列表顺序求交后落库（`intersect_lists_in_reference_order`），超出本端列表的值直接裁掉不报错，空交集也合法（落空列表）。host 还要求各 processor 分节算出的结果一致，不一致 → 20014。companion 不落库（`HostBinding` 没有 capability 列）。

- **录入时固定能力列表**：落库的列表同时通过 `HostEndAddCompanionOutput.capabilityList` 返回给 C++ 建 Companion 内存镜像，镜像从创建起就和 DB 一致。
- **保存后不再更新**：能力列表在录入时确定，之后不更新；**同步始终不写能力 DB**，要增加能力只能重新绑定（再次经过用户同意）。同步时，对端加密内层必须完整包含绑定时保存的能力；多宣告的能力不生效，实际仍使用保存的列表。缺少任何已保存能力都返回 20014 并作废凭证；已保存列表非空而对端宣告为空，也属于缺项。已保存列表为空时，空宣告合法。
- **两端用同一份数据判断**：Rust `check_device_capability` 读 DB 里的持久化列表，必须明确包含所查能力，列表为空就拒绝；C++ `IsCapabilitySupported` 读内存镜像，同样要求明确包含，列表为空返回 false。设备状态更新始终保留内存中保存的列表，不采信同步通告，也不重读 DB。`HasCapability` 中"空集表示全支持"只用于 localProfile 配置来源，不能用来判断设备能力。
- "该设备当前没有可用的伴随校验能力"用空的能力列表表示，是否可用由界面/框架层决定，本层不拦截。

### sync 校验

- **外层只检查结构，结论以加密内层为准**：`ValidateReplyParameters` 要求协议表非空、且与本端 offer 有交集，不满足就是本轮 `PROTOCOL_NEGOTIATION_FAILED`，**不作废凭证**。这条在所有路径上都生效，并排在安全层之前。这是有意为之：外层不做身份校验，被篡改也只会让本轮失败（isSynced=false、停止重试），不会作废凭证。
- 协议：绑定时保存的 `protocolId` 必须出现在加密内层列表里，否则返回 20011 并作废凭证。
- 能力：加密内层必须完整包含绑定时保存的能力列表，否则返回 20014 并作废凭证；校验通过时，实际生效的仍是保存的列表，host 当前 profile 不参与同步。
- 各 processor 分节解出的协议、能力列表必须集合相等，不一致按 20011 / 20014 报，Rust 侧作废。
- 外层协议协商没交集只会让同步停下，和已校验过的绑定参数有分歧是两回事，不作废凭证。

### 边界校验

Rust 按 TA 模块对待，FFI 是信任边界：SA 传进来的 protocol/capability/algorithm 列表、selected、enrolled_protocol_id，以及既有绑定流程的 secure_protocol_id，都必须在边界按 TA 自己声明的支持集校验，不能因为 C++ 交集层已经过滤过就免检。DB 读取侧同理——`get_binding_secure_protocol_id` / `get_device_secure_protocol_id` 返回的持久化协议值就是要生效的值，返回前先过 `validate_secure_protocol_id`。

校验只检查**值是否在本端支持列表中**，不在就拒绝，**不要求它等于绑定时保存的协议值**——按相等检查会在协议扩容后拒绝仍在正常交互的存量绑定。异常 DB 行（保存值是 0 或超出枚举范围）统一返回 20013。`device_id_type` 在 FFI 边界过 `is_valid_device_id_type`，必须是 `UNIFIED_DEVICE_ID(1)` 或不小于 `VENDOR_BEGIN(10000)` 的值，与 C++ `common_defines.h` 保持一致。本端执行器 ACL 用 `LOCAL_EXECUTOR_MAX_ACL`，别在流程里散写 `Acl3`。

扩协议时 C++ `profile.protocols` 和 Rust `SUPPORTED_PROTOCOL_VERSIONS` 一起扩；扩能力时 C++ 列表和 Rust 枚举一起扩。

### 实现约束

- **密码操作必须走 `message_crypto` 的分发函数**，不要在流程代码里直调原语或 engine 的具体算法方法：KA 走 `generate_key_pair`/`key_agreement`，对称走 `derive_session_key`/`encrypt_sec_message`/`decrypt_sec_message`/`compute_mac`，非法 id 在碰到 engine 之前就 fail-closed。分发层按意图命名（算法 id 是参数），实现层按算法命名（`encrypt_sec_message_aes256_gcm` 等，私有）。
- **算法相关的都放 `common/algorithm.rs`**：`CryptoAlgorithms`/`SelectedAlgorithms` 以及选择、校验函数都在这里，别散到 db_manager 或 constants。
- **SK 行整捆存 `SelectedAlgorithms`**（ka/kdf/aead/mac 四个 u16 放一个 struct），不要拆成平铺参数按位置传——四个同类型数值裸传一旦错位就是静默的密码学错误。ka 只用来自描述和审计（分发不读），kdf/aead/mac 供分发。
- **FFI 头是手工镜像的**：`companion_device_auth_ffi.h` 和 Rust 的 `#[repr(C)]` 结构必须同步改。

### 扩展算法或协议的检查项

- 新增算法必须同时补齐角色枚举、引擎实现和分发分支，只加枚举不算支持。密钥交换算法还要实现对应的密钥对生成函数；密钥派生长度等算法差异在分发分支处理。
- 共享秘密超过 32B 时，在 `key_agreement` 分支压到 32B（不用迁移），或者升级 DB 格式并作废重新绑定；实现时必须明确选择。
- **扩展协议支持列表并发布前，确认现网已没有协议能力低于新基线的对端，或者明确接受这些旧绑定作废**（旧对端会被 Rust 的子集校验拒绝，表现为 SUCCESS + 空 proof）。
- 新增协议的回归测试必须覆盖：支持列表包含旧对端不认识的 ID 时，双方仍能用原有的共同参数成功复验。不要把误作废凭证写成预期行为。
- 多 processor 改动注意三点：per-processor 的 AttributeKey 映射、delegate 的 `auth_token` blob 分节、protocol 与 processor 不再一一对应。
