# E2E 模块测试设计文档

为伴随设备认证服务（`@ohos/companion_device_auth`）的 C++ 核心逻辑提供高覆盖率、高稳定性的**端到端（E2E）功能测试**。

## 1. 测试目标与范围

- **测试重点**：核心业务状态机（设备绑定、状态同步、令牌申请与认证）的流转正确性，以及关键异常分支（超时、鉴权失败、对端拒绝）的容错处理。
- **隔离策略**：完全脱离真实硬件（SoftBus）和真实的跨语言底层运行环境（Rust FFI），通过依赖注入在进程内构建可控的沙盒。
- **核心目标**：以最少的测试替身，覆盖最长的生产代码路径。测试应从服务层公开 API 开始，经过完整业务管道，在 FakeChannel 边界处进行消息注入/捕获验证。

### 判断是否为 E2E 测试的标准

- 入口是服务层 API 或执行器入口（非内部组件直接调用）
- 所有中间件（请求管理器、消息路由、连接管理器等）都是真实的生产代码
- 只在系统边界（通道、适配器、单例）处替换为 Fake/Mock
- 消息以 raw bytes 形式在 FakeChannel 边界流转，而非在内部方法边界 mock

## 2. 测试边界架构

```
       [ GTest 测试驱动脚本 ]
               │
   ╔═══════════▼══════════════════════════════════════════╗
   ║               【 被测系统 (SUT) 】                   ║
   ║                                                      ║
   ║  执行器工厂 → AllInOneExecutor                        ║
   ║    (框架调度入口，注册/认证/删除)                      ║
   ║                                                      ║
   ║  请求管理器 → 请求状态机                              ║
   ║  伴随设备管理器 / 主机绑定管理器 (真实数据)            ║
   ║  跨设备通信管理器 / 消息路由                          ║
   ║  入站消息处理器注册表                                 ║
   ╚═══════════════╦══════════════════════════════════════╝
                   │
   ┌───────────────▼──────────────────────────────────────┐
   │                  【 替身隔离层 】                     │
   │                                                      ║
   │  ┌── Fake（有状态 + 有回调订阅） ──────────────────┐  │
   │  │ FakeChannel     捕获发送 + 模拟接收 + 设备状态   │  │
   │  │ FakeTimeKeeper  可控时间推进                     │  │
   │  │ FakeUserIdManager 用户状态 + 切换回调            │  │
   │  │ FakeSystemParamManager 参数 Get/Set/Watch 联动   │  │
   │  │ FakeMiscManager  ID生成 + 设备选择回调           │  │
   │  │ FakeIdmAdapter   模板状态 + 变更回调             │  │
   │  │ FakeSaManagerAdapter SA订阅 + 状态变化回调       │  │
   │  │ FakeDriverManagerAdapter 框架注册模拟            │  │
   │  └──────────────────────────────────────────────────┘  │
   │                                                      ║
   │  ┌── Mock（精确控制返回值） ──────────────────────┐   │
   │  │ MockSecurityAgent   绕过 Rust FFI              │   │
   │  │ MockUserAuthAdapter 精确控制认证结果            │   │
   │  │ MockEventManagerAdapter 空实现                  │   │
   │  └───────────────────────────────────────────────┘   │
   │                                                      ║
   │  不注入: SecurityCommandAdapter (被 SecurityAgent 绕过) │
   └───────────────────────────────────────────────────────┘
```

## 3. 测试替身选择原则

| 模式 | 策略 | 适用场景 |
|------|------|---------|
| **Real** | 不替换 | 核心业务逻辑，绝不替换 |
| **Fake** | 有状态替身 | 需要维护内部状态 + 支持回调订阅 + 提供测试后门触发事件 |
| **Mock** | gmock | 需要精确控制返回值、验证调用参数 |

**核心规律：有状态 + 有回调订阅 → 一律用 Fake**

### Fake vs Mock 决策树

```
该组件是否需要内部状态？
  否 → Mock（控制返回值即可）
  是 → 该组件是否需要向被测系统回调？
    否 → Fake（简单状态容器）
    是 → Fake + Test* 后门方法（状态 + 回调 + 触发器）
```

## 4. 完整组件隔离清单

### 4.1 单例层（单例管理器注入，不替换）

| 组件 | 理由 |
|------|------|
| ICompanionManager | 核心被测系统，伴随设备管理 |
| IHostBindingManager | 核心被测系统，绑定关系管理 |
| IRequestManager | 核心被测系统，请求生命周期管理 |
| IRequestFactory | 核心被测系统，请求创建 |
| IncomingMessageHandlerRegistry | 核心被测系统，消息处理器注册 |
| ICrossDeviceCommManager | 核心被测系统，注入 FakeChannel 控制输入输出 |
| IExecutorFactory | 框架调度入口。`AllInOneExecutor::Enroll()` → `RequestFactory::CreateHostAddCompanionRequest()` → `RequestManager::Start()`。空 mock 会跳过整个请求管道 |

### 4.2 单例层（需替换）

| 组件 | 策略 | 理由 |
|------|------|------|
| ISecurityAgent | **Mock** | Rust FFI 桥接，需精确控制返回值（成功/失败），绕过底层加密运算 |
| IMiscManager | **Fake** | `GetNextGlobalId()` 原子计数器 + `GetLocalUdid()` 系统调用 + 设备选择回调。Fake 提供 `TestSimulateDeviceSelectResult()` 后门 |

### 4.3 适配器层（适配器管理器注入）

| 组件 | 策略 | 理由 |
|------|------|------|
| ITimeKeeper | **Fake** | `GetSystemTimeMs()` / `GetSteadyTimeMs()` 需可控时间。提供 `TestAdvanceSystemTime(ms)` |
| IUserIdManager | **Fake** | `GetActiveUserId()` + `SubscribeActiveUserId(callback)`。Fake 提供 `TestSetActiveUser()` 自动更新状态并通告订阅者 |
| ISystemParamManager | **Fake** | `Get/Set/WatchParam` 有状态联动。Set 自动触发 Watcher |
| IIdmAdapter | **Fake** | `GetUserTemplates()` 有状态查询 + `SubscribeUserTemplateChange()` 回调订阅。Fake 提供 `TestSimulateTemplateChange()` |
| ISaManagerAdapter | **Fake** | `SubscribeSystemAbility()` 捕获 listener stub。Fake 提供 `TestSimulateSaOnline/Offline()` |
| IDriverManagerAdapter | **Fake** | `Start(driver)` 内部框架调 `GetExecutorList()` → `GetExecutorInfo()` → `OnRegisterFinish()`。Fake 模拟框架注册流程并缓存执行器供测试使用 |
| IUserAuthAdapter | **Mock** | `BeginDelegateAuth` + `CancelAuthentication`，ON_CALL 即可 |
| IEventManagerAdapter | **Mock** | 纯观测性上报，空实现即可 |
| ISecurityCommandAdapter | **不注入** | 被 SecurityAgent Mock 绕过 |

### 4.4 非 DI 组件

| 组件 | 策略 | 理由 |
|------|------|------|
| ICrossDeviceChannel | **Fake** | 完整实现 16 个接口方法。捕获 4 个关键回调 + SendMessage 队列 + OpenConnection 自动触发 CONNECTED |

### 4.5 编译期硬编码单例（无需额外 Fake）

以下组件通过 `::GetInstance()` 全局访问，不经过单例管理器/适配器管理器注入，已有编译期测试替身：

| 组件 | 替身位置 | 策略 | 理由 |
|------|---------|------|------|
| TaskRunnerManager | `test/fake/self/task_runner_manager.cpp` | **编译期 Fake** | `PostTask*` 队列收集 + `ExecuteAll()`/`EnsureAllTaskExecuted()` 同步排空。`RunningOnDefaultTaskRunner()` 永远返回 true |
| RelativeTimer | `test/fake/self/relative_timer.cpp` | **编译期 Fake** | `Register`/`PostTask` 队列收集，每个定时器存储绝对截止时间（注册时刻 `timeProvider()` + ms）。时间源通过 `SetTimeProvider()` 链接到 MockTimeKeeper 的 `GetSteadyTimeMs()`。`EnsureAllTaskExecuted()` 仅触发已过期定时器（`当前时间 >= 截止时间`） |

**关键说明**：RelativeTimer Fake 的时间源由 ModuleTestGuard 在初始化时通过 `SetTimeProvider()` 链接到 MockTimeKeeper。定时器在 `EnsureAllTaskExecuted()` 时仅当 MockTimeKeeper 的 steady time 超过其截止时间才触发。测试需在调用 `DrainAllTasks()` 前通过 `guard.GetTimeKeeper().AdvanceSteadyTime()` 推进足够时间来触发超时定时器。

### 4.6 统计

| 策略 | 数量 | 占比 |
|------|------|------|
| Real (被测系统) | 7 | 37% |
| Fake | 8 | 42% |
| Mock | 3 | 16% |
| 不注入 | 1 | 5% |

## 5. 测试脚手架 ModuleTestGuard

ModuleTestGuard 是所有 E2E 测试的脚手架，封装了完整的服务初始化流程。

### 5.1 初始化流程

```
ModuleTestGuard()
  → 单例管理器::Reset() + 适配器管理器::Reset()
  → TestServiceInitializer::Create()        // 继承 BaseServiceInitializer，override 注入点
    → 19-step 初始化管线（与生产完全一致）
      → InitializeTimeKeeper()              → MockTimeKeeper
      → InitializeEventManagerAdapter()     → MockEventManagerAdapter
      → InitializeSaManagerAdapter()        → FakeSaManagerAdapter
      → InitializeChannels()                → FakeChannel（替代 SoftBus）
      → InitializeSystemParamManager()      → FakeSystemParamManager
      → InitializeUserIdManager()           → FakeUserIdManager
      → InitializeUserAuthFramework()       → MockUserAuthAdapter + FakeIdmAdapter + FakeDriverManagerAdapter
      → InitializeMiscManager()             → FakeMiscManager
      → InitializeSecurityAgent()           → MockSecurityAgent（绕过 Rust FFI）
      → 请求管理器 / 请求工厂 / 处理器注册表 / 跨设备通信管理器 → Real
  → RelativeTimer::SetTimeProvider()        // 链接 RelativeTimer 到 MockTimeKeeper
  → BaseServiceCore::Create()
  → DrainAllTasks()
  → SetupDefaultValues()（设置活跃用户、初始时间、Mock 默认行为）
```

### 5.2 关键设计决策

**为什么用 TestServiceInitializer 而不是手动创建所有组件？**

因为 `BaseServiceInitializer` 内部的初始化顺序（19-step 管线）和依赖关系是生产代码的一部分。Override 虚函数而不是手动组装，确保：
- 初始化顺序始终与生产一致
- 新增初始化步骤时，测试自动同步
- 减少维护成本

**为什么不调用 SetWeakPtr()？**

`CompanionDeviceAuthService::OnStart()` 内部通过 `weakSelf_.promote()` 检查服务是否存活。不调用 `SetWeakPtr()` 会导致 `promote()` 返回 nullptr，从而跳过 `Publish()` 步骤。这是有意为之的——Publish 需要 SA 框架支持，在模块测试中不可用。跳过它不影响核心业务逻辑。

### 5.3 析构流程

```
~ModuleTestGuard()
  → DrainAllTasks()
  → Mock::VerifyAndClearExpectations()（所有 Mock）
  → service_ = nullptr
  → 单例管理器::Reset()
  → 适配器管理器::Reset()
```

## 6. 测试两阶段原则

E2E 模块测试分为两个明确的阶段：

### 6.1 设置阶段

**目的**：构造测试所需的前置内部状态

**允许的操作**：
- 直接调用 `CompanionManager::BeginAddCompanion/EndAddCompanion` 注册伴随设备
- 直接调用 `HostBindingManager::BeginAddHostBinding` 创建绑定关系
- 直接调用 `RequestManager::Start` 启动请求（仅用于状态构造，非被测流程）
- 使用 Fake 的测试后门（如 `TestSetActiveUser`、`TestSetUserTemplates`）

**原因**：设置阶段的目的是快速构造测试前置条件，无需走完整的消息流。这是**测试辅助操作**，不是被测业务逻辑。

### 6.2 运行阶段

**目的**：测试被测业务逻辑的 E2E 行为

**必须遵守**：
- **入口**：服务层 API、通道边界（消息注入）、执行器入口（`Enroll/Authenticate`）
- **路径**：完整生产代码路径，不得跳过任何中间层
- **边界**：仅在系统边界（FakeChannel）进行消息注入和捕获
- **禁止**：直接调用管理器/请求内部方法来驱动被测流程

**原因**：运行阶段是真正的 E2E 测试，必须验证完整的生产消息流路径。

### 6.3 阶段划分判定表

| 场景 | 阶段 | 是否允许直接调用内部 API | 原因 |
|------|------|--------------------------|------|
| 注册伴随设备（前置状态） | 设置 | 允许 | 快速构造测试前置条件 |
| 注册主机绑定（前置状态） | 设置 | 允许 | 快速构造测试前置条件 |
| 设置用户模板 | 设置 | 允许 | 使用 Fake 后门 |
| 订阅设备状态 | 运行 | 禁止 | 必须走完整服务 API |
| 同步设备状态 | 运行 | 禁止 | 必须走完整消息流 |
| 添加伴随设备 | 运行 | 禁止 | 必须走注册 → 消息流 |
| 令牌认证 | 运行 | 禁止 | 必须走认证 → 消息流 |

### 6.4 设置辅助方法选择指南

ModuleTestGuard 提供三个设置辅助方法，选择原则如下：

| 辅助方法 | 适用场景 | 说明 |
|---------|---------|------|
| RegisterCompanionDirect | 主机侧测试前置注册（推荐） | 直接调用 EndAddCompanion，快速构造伴随设备状态。适用于同步、认证等测试的前置条件 |
| RegisterHostBindingDirect | 伴随侧测试前置注册 | 直接调用 BeginAddHostBinding，快速构造主机绑定状态 |
| RegisterCompanionViaMessageFlow | 需要验证注册流程本身时使用 | 走完整注册 → 3 轮消息注入流程。仅在需要测试注册路径的 E2E 行为时使用，**不应用于纯设置目的** |

**原则**：设置阶段应优先使用 Direct 系列方法快速构造状态。ViaMessageFlow 系列方法仅在需要测试对应消息流路径时使用，因为它们执行完整 E2E 流程，增加了设置的复杂性和脆弱性。

### 6.5 注释规范

为明确区分两个阶段，测试代码应使用清晰的注释标记：

```cpp
// 设置阶段: [描述设置目的]
// 允许直接调用内部 API

// 运行阶段: [描述被测场景]
// 必须走完整 E2E 路径
```

## 7. 消息级测试模式

E2E 测试中，主机和伴随在同一进程内运行。消息通过 FakeChannel 进行"物理"隔离。

### 7.1 Raw Message 格式

消息路由使用 `Attributes` 编码 raw message。Header 和 payload 共存于同一个 Attributes 对象：

| Attributes Key | 类型 | 含义 |
|----------------|------|------|
| `ATTR_CDA_SA_CONNECTION_NAME` | string | 连接标识 |
| `ATTR_CDA_SA_MSG_SEQ_NUM` | uint32 | 消息序号 |
| `ATTR_CDA_SA_MSG_ACK` | bool | 是否为回复 |
| `ATTR_CDA_SA_MSG_TYPE` | uint16 | 消息类型（MessageType 枚举） |

### 7.2 消息编解码工具函数

每个测试文件中定义通用的编解码辅助函数：

```cpp
// 解码 raw message
std::optional<RawMsgInfo> DecodeRawMsg(const std::vector<uint8_t> &rawMsg)
{
    Attributes attr(rawMsg);
    RawMsgInfo info;
    // 提取 ATTR_CDA_SA_CONNECTION_NAME, ATTR_CDA_SA_MSG_SEQ_NUM,
    //        ATTR_CDA_SA_MSG_ACK, ATTR_CDA_SA_MSG_TYPE
    info.payload = attr; // payload = 整个 Attributes
    return info;
}

// 编码请求 raw message
std::vector<uint8_t> BuildRequestRawMsg(const std::string &connName, uint32_t seq,
    MessageType msgType, const Attributes &payload)
{
    Attributes msg(payload.Serialize()); // 先序列化 payload，再追加 header
    msg.SetStringValue(ATTR_CDA_SA_CONNECTION_NAME, connName);
    msg.SetUint32Value(ATTR_CDA_SA_MSG_SEQ_NUM, seq);
    msg.SetBoolValue(ATTR_CDA_SA_MSG_ACK, false);
    msg.SetUint16Value(ATTR_CDA_SA_MSG_TYPE, static_cast<uint16_t>(msgType));
    return msg.Serialize();
}

// 编码回复 raw message（isReply = true）
std::vector<uint8_t> BuildReplyRawMsg(...) { /* 同上，ATTR_CDA_SA_MSG_ACK = true */ }
```

**重要细节**：`Build*RawMsg` 必须先 `Serialize` payload 再设置 header 字段。反序操作会导致 payload 的 header 字段被覆盖。

### 7.3 消息往返模式

```
主机测试:
  1. 服务 API 触发 → 生产路径 → FakeChannel 捕获请求 raw msg
  2. DecodeRawMsg → 提取 seq + connectionName
  3. 构造回复（用业务层 Encode/Decode 函数）
  4. BuildReplyRawMsg → TestSimulateIncomingMessage 注入
  5. 生产路径处理回复 → 验证回调/状态

伴随测试:
  1. TestSimulateIncomingConnection（模拟主机连接）
  2. BuildRequestRawMsg → TestSimulateIncomingMessage 注入
  3. 生产路径处理请求 → FakeChannel 捕获回复
  4. DecodeRawMsg → DecodeSyncDeviceStatusReply → 验证字段
```

## 8. 异步任务排空

### 8.1 DrainAllTasks()

所有 E2E 测试中，每次触发异步操作后都必须调用：

```cpp
void DrainAllTasks()
{
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    RelativeTimer::GetInstance().EnsureAllTaskExecuted();
}
```

### 8.2 何时调用

- `ModuleTestGuard` 构造完成后（OnStart 会投递定时任务）
- 每次调用 FakeChannel 的 `Test*` 方法后
- 每次调用服务 API 后
- 验证最终结果前

### 8.3 DrainPendingTasks vs DrainAllTasks

在伴随侧测试中，使用 `DrainPendingTasks()` 替代 `DrainAllTasks()`：

```cpp
void DrainPendingTasks()
{
    // 仅排空任务队列，不触发 RelativeTimer（避免触发请求超时定时器）
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
}
```

**何时使用 DrainPendingTasks**：
- 伴随侧消息往返期间（避免触发请求超时定时器）
- 设置阶段（构造前置条件时不需要触发定时器）

**何时使用 DrainAllTasks**：
- 验证最终结果前
- 主机侧完整流程结束后

## 9. FakeChannel 关键 API

| API | 用途 |
|-----|------|
| `TestSimulateDeviceOnline(key)` | 触发设备上线事件 |
| `TestSimulateIncomingMessage(connName, rawMsg)` | 注入 raw message |
| `TestSimulateIncomingConnection(connName, physKey)` | 模拟远端连接 |
| `TestSimulateRemoteDisconnect(connName, reason)` | 模拟断开 |
| `GetSentMessages(connName)` | 获取指定连接的已发送消息列表 |
| `GetAllConnectionNames()` | 获取所有有发送记录的连接名 |
| `ClearSentMessages()` | 清空发送队列（在注入前清理，避免误读旧消息） |

### 连接名获取

在主机测试中，连接名由生产代码内部生成（基于 deviceId 的哈希）。测试不应硬编码连接名，而应使用：

```cpp
auto allConnNames = guard.GetChannel().GetAllConnectionNames();
ASSERT_FALSE(allConnNames.empty());
const auto &connName = allConnNames[0];
```

## 10. E2E 流程示例：同步设备状态

### 步骤 1：初始化 + 设备上线

```
ModuleTestGuard 构造
  → 真实组件创建（跨设备通信管理器注入 FakeChannel）
  → FakeChannel 回调被捕获

guard.SimulateDeviceOnline(companionPhysicalKey)
  → FakeChannel.TestSimulateDeviceOnline()
  → 设备状态管理器::HandleChannelDeviceStatusChange
  → deviceStatusMap_ 填充
```

### 步骤 2：主机发起请求

```
guard.GetRequestManager().Start(request)
  → PostTaskOnResident { request->Start() }
  → EnsureAllTaskExecuted()
    → 出站请求::Start()
      → OpenConnection()
        → FakeChannel 自动触发 CONNECTED
      → BeginCompanionCheck()
        → MockSecurityAgent::HostBeginCompanionCheck() ← 返回 salt+challenge
      → SendSyncDeviceStatusRequest()
        → 消息路由::SendMessage()
          → FakeChannel::SendMessage() → 捕获到 sentMessages_
```

### 步骤 3：伴随处理请求

```
auto sent = guard.GetChannel().GetSentMessages(connName).back();
guard.InjectRawMessage(connName, sent)
  → FakeChannel.TestSimulateIncomingMessage()
  → 消息路由::HandleRawMessage()
    → 伴随同步处理器::HandleIncomingMessage
      → FakeUserIdManager::GetActiveUserId() 返回预设值
      → EncodeSyncDeviceStatusReply
    → onReply → 消息路由::SendReply
      → FakeChannel::SendMessage() → 捕获伴随的回复
```

### 步骤 4：主机接收回复

```
auto reply = guard.GetChannel().GetSentMessages(connName).back();
guard.InjectRawMessage(connName, reply)
  → 消息路由::HandleRawMessage() → isReply=true
    → 主机同步请求::HandleSyncDeviceStatusReply
      → MockSecurityAgent::HostEndCompanionCheck()
      → CompleteWithSuccess → InvokeCallback

验证：callbackResult == SUCCESS
```

## 11. 常见陷阱与解决方案

### 11.1 编译错误

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| `ErrCode::SUCCESS` 编译失败 | `ErrCode` 是 `int` 的别名，不是类/命名空间 | 直接返回 `0` |
| `ProtocolId::DEFAULT` 不存在 | 枚举只有 `INVALID=0` 和 `VERSION_1=1` | 使用 `ProtocolId::VERSION_1` |
| `SubscribeAvailableDeviceStatus` 参数不匹配 | 实际有 3 个参数 | 添加 `int32_t subscribeResult = 0` 输出参数 |

### 11.2 Mock 设置

- `MockSecurityAgent` 的默认行为通过 `ON_CALL` 设置在 `SetupSecurityAgentDefaults()` 中
- 测试特定场景时用 `EXPECT_CALL` 覆盖默认行为
- 析构时调用 `Mock::VerifyAndClearExpectations()` 避免跨测试泄漏

### 11.3 IPC 回调 Mock

对于需要 `sptr<>` 引用的 IPC 回调（如 `IIpcAvailableDeviceStatusCallback`），创建 Mock 类：

```cpp
class MockAvailableDeviceStatusCallback : public IIpcAvailableDeviceStatusCallback {
public:
    MOCK_METHOD(ErrCode, OnAvailableDeviceStatusChange,
        (const std::vector<IpcDeviceStatus> &), (override));
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
};

// 使用 sptr::MakeSptr 创建
sptr<MockAvailableDeviceStatusCallback> callback =
    sptr<MockAvailableDeviceStatusCallback>::MakeSptr();
```

### 11.4 消息路由额外属性

伴随侧处理请求时，消息路由会自动从连接信息中提取远端设备 key，注入到 payload 中（`ATTR_CDA_SA_SRC_IDENTIFIER`）。但某些处理器（如伴随同步处理器）还需要 `ATTR_CDA_SA_HOST_DEVICE_KEY`，这需要在构造请求 raw message 时手动编码：

```cpp
EncodeHostDeviceKey(request.hostDeviceKey, requestPayload);
```

## 12. 校验充分性要求

E2E 测试的价值取决于校验的深度。以下规则是所有 E2E 测试必须遵守的最低标准。

### 12.1 API 返回值必须校验

每个服务层 API 调用的返回值 / 输出参数都必须被检查：

```cpp
// 错误: 返回值未检查，后续断言可能基于错误的前提
service->SubscribeAvailableDeviceStatus(userId, callback, subscribeResult);

// 正确: 显式校验 API 成功
int32_t subscribeResult = -1;  // 用非零初始值，确保被赋值
service->SubscribeAvailableDeviceStatus(userId, callback, subscribeResult);
EXPECT_EQ(subscribeResult, 0) << "SubscribeAvailableDeviceStatus should succeed";
```

**规则**：输出参数用非零/非默认值初始化，断言其被正确赋值。

### 12.2 回调参数必须深入校验

Mock 回调捕获的参数不应只检查"是否存在"，必须逐字段验证：

```cpp
// 正确: 捕获参数，逐字段验证
bool callbackFired = false;
std::vector<IpcDeviceStatus> capturedList;
EXPECT_CALL(*callback, OnAvailableDeviceStatusChange(_))
    .WillOnce(Invoke([&](const std::vector<IpcDeviceStatus> &list) {
        callbackFired = true;
        capturedList = list;
        return 0;
    }));
// ...
EXPECT_TRUE(callbackFired);
ASSERT_EQ(capturedList.size(), 1u);
EXPECT_EQ(capturedList[0].deviceKey.deviceId, "companion-001");
EXPECT_EQ(capturedList[0].deviceKey.deviceUserId, HOST_USER);
```

**规则**：回调内用 `ASSERT_*` 验证数量，用 `EXPECT_*` 验证每个字段的值。不要在 gmock `Invoke` 内做断言（gtest 不保证 Invoke 内 ASSERT 的行为），应在 Invoke 外捕获、在测试主体中验证。

### 12.3 查询接口必须全字段校验

通过生产查询接口获取的结果应验证所有相关字段。

### 12.4 Mock 交互必须显式校验

对流程中的关键 Mock 方法（如 SecurityAgent），不仅要设 `ON_CALL` 默认行为，还要用 `EXPECT_CALL` 验证被调用。

**规则**：对流程中的关键步骤（开始/结束检查、开始/结束添加伴随设备等），用 `EXPECT_CALL` 确认调用，不用 `ON_CALL` 默认行为覆盖。

### 12.5 回复字段必须逐个验证

对于从 FakeChannel 捕获的回复消息，解码后应验证所有关键字段。

### 12.6 校验清单模板

每个 E2E 测试评审时，检查以下清单：

| # | 检查项 | 说明 |
|---|--------|------|
| 1 | API 返回值 / 输出参数是否校验 | 确保入口操作成功 |
| 2 | 回调是否触发 | `EXPECT_TRUE(callbackFired)` |
| 3 | 回调参数数量是否校验 | `ASSERT_EQ(list.size(), N)` |
| 4 | 回调参数每个字段是否校验 | deviceId, deviceUserId, deviceUserName, isOnline... |
| 5 | 生产查询接口是否调用 | `GetDeviceStatus` / `GetCompanionStatus` 等 |
| 6 | 查询结果的每个字段是否校验 | 不只查一个字段就结束 |
| 7 | 关键 Mock 方法的调用是否用 EXPECT_CALL 验证 | 开始/结束检查, 开始/结束添加伴随设备 |
| 8 | 回复消息的具体字段值是否校验 | 不只检查非空 |
| 9 | raw message 的 header 是否校验 | msgType, isReply 是否正确 |
| 10 | 错误路径：如果测试的是错误场景，错误码是否正确 | |

## 13. 新增 E2E 测试的步骤

### 13.1 确定测试场景

1. 确定入口点（服务 API / 执行器 / 通道事件注入）
2. 确定主机还是伴随视角
3. 确定期望的最终状态/回调

### 13.2 编写测试

```
1. ModuleTestGuard guard;                          // 初始化完整服务
2. 配置 Fake 状态（TestSetActiveUser / TestSetUserTemplates 等）
   - 使用设置辅助方法构造前置状态：
     - RegisterCompanionDirect(hostUserId, companionDeviceKey, templateId) — 主机侧快速注册伴随设备
     - RegisterHostBindingDirect(companionUserId, hostDeviceKey) — 伴随侧快速注册主机绑定
3. 配置 Mock（EXPECT_CALL 覆盖默认行为）
4. 触发业务入口
5. DrainAllTasks();
6. 从 FakeChannel 捕获/注入消息（如需多轮交互则重复 5-6）
7. DrainAllTasks();
8. 验证最终结果（回调参数、查询接口返回值、Mock 调用次数）
```

### 13.3 典型模板

```cpp
HWTEST_F(XxxModuleTest, ScenarioE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    // 1. 配置 Mock
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginCompanionCheck(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(output), Return(ResultCode::SUCCESS)));

    // 2. 触发业务
    auto &service = guard.GetService();
    service->SomeApiCall(...);
    DrainAllTasks();

    // 3. 消息交互（如需要）
    auto connNames = guard.GetChannel().GetAllConnectionNames();
    // ... 解码 → 编码回复 → 注入 ...

    // 4. 验证
    EXPECT_TRUE(callbackFired);
}
```

## 14. 测试场景覆盖

### 14.1 已完成（47 个）

| 测试文件 | 测试名 | 覆盖范围 |
|---------|--------|---------|
| `service_init_module_test.cpp` | ServiceInitSucceedsE2E_001 | 19-step 初始化管线，所有单例可查询 |
| `service_init_module_test.cpp` | LoadPersistedDataAfterUserSwitchE2E_001 | 用户切换 → SecurityAgent Mock → 数据加载 |
| `sync_device_status_module_test.cpp` | HostSyncNoTemplateE2E_001 | 订阅 → 设备上线 → 同步 → 无模板 → 回调通知 |
| `sync_device_status_module_test.cpp` | HostSyncWithTemplateCheckSuccessE2E_001 | 有模板 → companion check 成功 |
| `sync_device_status_module_test.cpp` | HostSyncWithTemplateCheckFailureE2E_001 | 有模板 → companion check 失败 → 设备仍同步 |
| `sync_device_status_module_test.cpp` | CompanionResponseNoBindingE2E_001 | 收到同步请求 → 无绑定 → 返回回复 |
| `sync_device_status_module_test.cpp` | CompanionResponseWithBindingE2E_001 | 有绑定 → companion check response 包含在回复中 |
| `add_companion_module_test.cpp` | CompanionAddCompanionInitKeyNegotiationE2E_001 | 伴随侧密钥协商 |
| `add_companion_module_test.cpp` | CompanionAddCompanionFullE2E_001 | 伴随侧完整 3 轮绑定 |
| `add_companion_module_test.cpp` | CompanionDuplicateAddReplacedBindingE2E_001 | 重复绑定 → 旧绑定替换 |
| `add_companion_module_test.cpp` | CompanionAddCompanionInitKeyNegotiationErrorE2E_001 | 密钥协商 SA 错误 → 错误回复 |
| `add_companion_module_test.cpp` | HostAddCompanionFullE2E_001 | 主机侧完整 3 轮绑定 → 回调成功 |
| `add_companion_module_test.cpp` | HostAddCompanionBeginAddCompanionFailedE2E_006 | 绑定流程 SA 错误 — 主机侧 BeginAddCompanion 失败 → 回调 GENERAL_ERROR、CompanionManager 无新记录 |
| `add_companion_module_test.cpp` | HostAddCompanionEndAddCompanionFailedE2E_007 | 绑定流程 SA 错误 — 主机侧 EndAddCompanion 失败 → 回调 GENERAL_ERROR、CompanionManager 无新记录 |
| `auth_module_test.cpp` | RequestAbortedReceivedE2E_001 | 收到 REQUEST_ABORTED(CANCELED) → OutboundRequest 取消 |
| `auth_module_test.cpp` | RequestAbortedPreemptedE2E_002 | 收到 REQUEST_ABORTED(BUSY) → OutboundRequest 取消 |
| `auth_module_test.cpp` | RequestAbortedCommunicationErrorE2E_003 | 收到 REQUEST_ABORTED(COMMUNICATION_ERROR) → 错误传播 |
| `auth_module_test.cpp` | HostIssueTokenFullE2E_001 | 主机令牌颁发完整 3 轮 |
| `auth_module_test.cpp` | CompanionProcessIssueTokenFullE2E_002 | 伴随侧令牌颁发 2 轮 |
| `auth_module_test.cpp` | HostIssueTokenPreIssueFailedE2E_003 | 主机令牌颁发 PreIssue 失败 |
| `auth_module_test.cpp` | CompanionObtainTokenFullE2E_001 | 伴随侧获取令牌 2 轮 |
| `auth_module_test.cpp` | HostProcessObtainTokenE2E_002 | 主机处理获取令牌 2 轮 |
| `auth_module_test.cpp` | HostProcessPreObtainTokenFailedE2E_003 | 主机 PreObtainToken 失败 |
| `auth_module_test.cpp` | HostRemoveCompanionFullE2E_001 | 主机删除绑定完整流程 |
| `auth_module_test.cpp` | CompanionRemoveHostBindingE2E_002 | 伴随侧删除绑定成功 |
| `auth_module_test.cpp` | CompanionRemoveHostBindingFailedE2E_003 | 伴随侧删除绑定失败 |
| `auth_module_test.cpp` | HostTokenAuthSuccessE2E_001 | 主机令牌认证成功 |
| `auth_module_test.cpp` | HostTokenAuthNoTokenE2E_001 | 主机令牌认证失败（无令牌） |
| `auth_module_test.cpp` | CompanionProcessTokenAuthSuccessE2E_001 | 伴随侧令牌认证成功（含 MAC） |
| `auth_module_test.cpp` | CompanionProcessTokenAuthNoTokenE2E_001 | 伴随侧令牌认证失败（无令牌） |
| `auth_module_test.cpp` | HostDelegateAuthSuccessE2E_001 | 主机委托认证成功（两轮） |
| `auth_module_test.cpp` | CompanionDelegateAuthFullE2E_001 | 伴随侧委托认证 Begin |
| `auth_module_test.cpp` | HostDelegateAuthFailureE2E_001 | 主机委托认证失败 |
| `auth_module_test.cpp` | CompanionRevokeTokenE2E_001 | 伴随侧撤销令牌 |
| `auth_module_test.cpp` | HostDelegateAuthPreemptedE2E_001 | 请求抢占 — 新 DelegateAuth 取消旧请求 → 旧回调 CANCELED |
| `auth_module_test.cpp` | HostTokenAuthPreemptedE2E_001 | 请求抢占 — 新 TokenAuth 取消旧请求 → 旧回调 CANCELED |
| `auth_module_test.cpp` | CompanionDelegateAuthFullFlowE2E_001 | 伴随侧 DelegateAuth 完整流程 — Begin + End 两轮 + 回调验证 |
| `auth_module_test.cpp` | UserSwitchCancelsRequestE2E_001 | 用户切换 → 不取消活跃请求（请求保持等待状态，最终由超时机制处理） |
| `auth_module_test.cpp` | HostTokenAuthCallbackExtraInfoVerifiedE2E_001 | 结果校验增强 — TokenAuth 回调 extraInfo 等于 HostEndTokenAuth 输出的 fwkMsg |
| `auth_module_test.cpp` | HostDelegateAuthCallbackExtraInfoVerifiedE2E_001 | 结果校验增强 — DelegateAuth 回调 extraInfo 等于 HostEndDelegateAuth 输出的 fwkMsg |
| `timeout_module_test.cpp` | SyncDeviceStatusTimeoutE2E_001 | OutboundRequest 超时 — SyncDeviceStatus 推进时间 >60s → 回调 TIMEOUT |
| `timeout_module_test.cpp` | TokenAuthTimeoutE2E_001 | OutboundRequest 超时 — TokenAuth 推进时间 >60s → 回调 TIMEOUT |
| `timeout_module_test.cpp` | DelegateAuthTimeoutE2E_001 | OutboundRequest 超时 — DelegateAuth 推进时间 >60s → 回调 TIMEOUT |
| `timeout_module_test.cpp` | IssueTokenTimeoutE2E_001 | OutboundRequest 超时 — IssueToken 推进时间 >60s → 内部完成错误路径 |
| `connection_module_test.cpp` | RemoteDisconnectCancelsRequestE2E_001 | 连接远端断开 → OutboundRequest 回调 COMMUNICATION_ERROR |
| `connection_module_test.cpp` | DisconnectMessageHandlingE2E_001 | DISCONNECT 消息 → 连接关闭 → OutboundRequest 回调 COMMUNICATION_ERROR |
| `connection_module_test.cpp` | KeepAliveAfterIdleE2E_001 | 连接空闲 >10s → KEEP_ALIVE 请求发送 → 注入回复 → 连接保持 |

### 14.2 待补充

（当前无待补充项，P0 和 P1 已全部实现。）

### 14.3 不属于 E2E 范畴

以下场景应通过**单元测试**覆盖，不适合 E2E 模块测试：

| 场景 | 原因 |
|------|------|
| 并发请求上限（如 IssueToken 最多 10 个） | 业务规格边界值测试，属于 RequestManagerImpl 单元测试 |
| 绑定规格上限（最多 10 个绑定/伴随设备） | 业务规格边界值测试，属于 CompanionManager/HostBindingManager 单元测试 |

## 15. 关键参考文件

| 用途 | 路径 |
|------|------|
| 测试脚手架 | `test/moduletest/services/cpp/common/inc/module_test_guard.h` |
| 脚手架实现 | `test/moduletest/services/cpp/common/src/module_test_guard.cpp` |
| FakeChannel | `test/moduletest/services/cpp/common/inc/fake_channel.h` |
| 主机同步请求 | `services/cross_device_interaction/sync_device_status/src/host_sync_device_status_request.cpp` |
| 伴随同步处理 | `services/cross_device_interaction/sync_device_status/src/companion_sync_device_status_handler.cpp` |
| 消息编解码 | `services/cross_device_interaction/sync_device_status/inc/sync_device_status_message.h` |
| 消息路由 | `services/cross_device_comm/src/message_router.cpp` |
| 设备状态管理器 | `services/cross_device_comm/src/device_status_manager.cpp` |
| 连接管理器 | `services/cross_device_comm/src/connection_manager.cpp` |
| 出站请求生命周期 | `services/cross_device_interaction/common/src/outbound_request.cpp` |
| 跨设备通信管理器实现 | `services/cross_device_comm/src/cross_device_comm_manager_impl.cpp` |
| AllInOneExecutor（框架入口） | `services/fwk_comm/src/companion_device_auth_all_in_one_executor.cpp` |
| 通道接口 | `services/singleton/inc/cross_device_comm/icross_device_channel.h` |
| TaskRunnerManager fake | `test/fake/self/task_runner_manager.cpp` |
| RelativeTimer fake | `test/fake/self/relative_timer.cpp` |
| 构建配置 | `test/moduletest/services/cpp/BUILD.gn` |
