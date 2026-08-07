## 项目概述

**伴随设备认证**（`@ohos/companion_device_auth`）是一个 OpenHarmony 用户认证执行器，通过伴随设备（手表、耳机、PC）对用户进行身份认证。它作为 `SystemAbility` 注册在 `useriam` 子系统中，并与统一用户认证框架（`user_auth_framework`）集成。

系统运行在两种角色下：
- **主机（Host）**：被认证的设备（例如手机通过手表近距离解锁）
- **伴随（Companion）**：对用户进行认证的设备（例如手表确认佩戴者身份）

两种角色运行同一套代码；行为根据设备持有的是主机绑定还是伴随注册而有所区别。

## 构建系统

本项目为基于 GN/Ninja 的 OpenHarmony 组件。使用 `oh-build` 技能进行构建：

```
/oh-build
```

构建目标（GN 路径）：
- **服务**：`//base/useriam/companion_device_auth/services:companion_device_auth_service_group`
- **客户端库**：`//base/useriam/companion_device_auth/frameworks/native/client:companion_device_auth_client`
- **JS/NAPI**：`//base/useriam/companion_device_auth/frameworks/js/napi:companiondeviceauth`
- **ETS/ANI**：`//base/useriam/companion_device_auth/frameworks/ets/ani:companion_device_auth_ani`

### 条件编译（`.gni`）

`companion_device_auth.gni` 中的特性标志控制条件编译：
- `companion_device_auth_has_soft_bus_channel` — 启用 SoftBus 跨设备通道（添加 `-DHAS_SOFT_BUS_CHANNEL`）
- `companion_device_auth_has_account_os_account` — 使用 OS 账户管理器而非常量用户 ID
- `companion_device_auth_has_ext` — 当 `companion_device_auth_ext` 部件存在时，跳过服务共享库（由 ext 提供）
- `companion_device_auth_enable_coverage` — 在测试中启用覆盖率插桩

## 测试

使用 `oh-test` 技能运行测试：

```
/oh-test
```

### 测试目标

- **C++ 单元测试**：`//base/useriam/companion_device_auth/test/unittest:companion_device_auth_unittest`
  - 服务测试：`companion_device_auth_services_cpp_test`
  - 客户端测试：`companion_device_auth_client_impl_test`
- **Rust 单元测试**：`companion_device_auth_services_rust_test`
- **模糊测试**：`//base/useriam/companion_device_auth/test/fuzztest:companion_device_auth_fuzztest`
  - 服务模糊器：`CompanionDeviceAuthServiceFuzzer`
  - 客户端模糊器：`CompanionDeviceAuthClientFuzzer`

### 测试基础设施

- 模拟头文件位于 `test/unittest/services/cpp/common/inc/`（mock_*.h）
- 模糊测试通用工具位于 `test/fuzztest/companion_device_auth_services_fuzzer/common/`
- `test/fake/` 中的测试替身替换了定时器、SoftBus 和系统参数依赖
- 测试使用 `-Dprivate=public -Dprotected=public` 编译以访问私有成员
- 使用 `oh-test` 技能指定具体测试名称运行单个测试

## 架构

### 层次结构

```
interface/           → 公共 API 头文件（inner_api）
frameworks/
  native/client/     → C++ 客户端库（使用 IPC 代理）
  native/ipc/        → IDL 生成的代理/存根（用于 IPC）
  js/napi/           → JS/NAPI 绑定
  ets/ani/           → ArkUI Native Interface 绑定
services/            → 核心服务实现
  service_entry/     → CompanionDeviceAuthService（SystemAbility 入口）
  singleton/         → 单例管理器（集中访问所有管理器）
  cross_device_comm/ → 跨设备通信基础设施
  cross_device_interaction/ → 业务请求处理器（按交互类型划分）
  companion/         → 伴随设备注册管理
  host_binding/      → 主机设备绑定管理
  fwk_comm/          → UserIAM 框架集成（执行器注册）
  security_agent/    → 安全层（Rust + C++ 桥接，通过 cxx）
  request/           → 请求生命周期管理
  external_adapters/ → 平台适配层（SoftBus、账户、认证等）
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

**线程模型**：常驻线程上的单线程事件循环。所有 adapter/singleton 访问必须在常驻线程上进行。IPC 回调使用 `PostTask` 委派到常驻线程。阻塞操作在临时线程上运行，然后通过 `PostTask` 返回。完整线程规则参见 `services/AGENTS.md`。

**安全代理**：通过 cxx 桥接到 C++ 的 Rust 实现。处理加密操作和安全命令处理。位于 `services/security_agent/`，Rust 源码在 `services/external_adapters/security_command_adapter/`。

**执行器集成**：`fwk_comm/` 使用 `AllInOneExecutor` 模式将伴随设备认证注册为 UserIAM 框架的执行器，支持注册/认证/删除操作。

## 代码风格规则（来自 AGENTS.md）

### 内存与指针安全（整个代码库）

- **所有分配必须进行空指针检查**：`std::make_shared`/`std::make_unique`/`new (std::nothrow)` 的结果必须在创建后立即使用 `ENSURE_OR_RETURN_VAL` 检查
- **成员变量和参数不使用裸指针**：成员变量使用 `std::shared_ptr`，函数参数使用 `const std::shared_ptr<T>&`
- **异步回调使用 `weak_from_this()`**：在生命周期超出当前作用域的 lambda 中，禁止捕获 `this` 或 `shared_from_this()`。使用 `weak_from_this()`，然后 `lock()` 并进行空指针检查后再使用
- **例外：栈作用域对象**：`ScopeGuard` 及类似的栈绑定对象可以使用裸 `this`，因为它们与所在函数具有相同的生命周期
- **防御性空指针检查**：每个函数必须在入口处检查自己的指针参数（不依赖调用者）。成员变量必须在每个方法开头进行空指针检查，但在同一方法内初始检查后无需重复检查

### 线程模型（仅 services/）

所有 `adapter` 和 `singleton` 访问必须在**常驻线程**上运行。IPC/框架线程和临时线程必须通过 `PostTask` 委派。

**同步跨模块调用** — IPC 线程需要返回值：
```cpp
ResultCode code = GENERAL_ERROR;
std::promise<void> done;
auto future = done.get_future();
if (!TaskRunnerManager::GetInstance().PostTask([&]() {
    code = GetManager().DoWork();
    done.set_value();
})) { return GENERAL_ERROR; }
auto status = future.wait_for(std::chrono::milliseconds(500));
```

**异步跨模块调用** — 即发即弃，回调在常驻线程上执行：
```cpp
TaskRunnerManager::GetInstance().PostTask([cb = std::move(callback)]() mutable {
    auto result = GetManager().DoWork();
    cb(result);
});
```

**阻塞操作** — 在临时线程上运行，然后 PostTask 回常驻线程：
```cpp
TaskRunnerManager::GetInstance().PostTaskOnTemporary("name", [...]() {
    int result = BlockingCall();
    TaskRunnerManager::GetInstance().PostTask([result]() {
        GetManager().HandleResult(result);
    });
});
```

**线程检查**：`TaskRunnerManager::GetInstance().RunningOnDefaultTaskRunner()` 在当前处于常驻线程时返回 true。

**服务单线程模型**：服务类方法在常驻线程上串行执行。成员变量无需互斥锁保护。TOCTOU 模式（检查后使用）在单个方法内是安全的——不应将其标记为竞态条件。

**`PostTaskOnResident` 设计**：它从非常驻线程调用，用于在常驻线程上调度工作。从 IPC/临时线程调用它是正确且预期的行为。

### 请求与订阅生命周期（Request / Subscription）

**析构期销毁陷阱**：`RequestManagerImpl::Remove` 由 `BaseRequest::Destroy` 经 `PostTaskOnResident` 延迟触发；常驻线程执行 `deque::erase` 时，若该 `shared_ptr<IRequest>` 是最后一个引用，Request 析构函数会**同步在 erase 现场执行**。此时若析构链上的 `Subscription` cleanup 同步执行复杂逻辑（典型：`DeviceStatusManager::UnsubscribeDeviceStatus → RefreshDeviceList` 改 `deviceStatusMap_`），会破坏正在被 erase 的堆，表现为 jemalloc 的 `may double free`。崩溃栈特征：`Timer::OnTimer → BaseRequest::Destroy lambda → RequestManagerImpl::Remove → ~Request → free → "may double free"`。

为此定两条硬规则：

1. **每个 Request 必须在自己的 `Destroy()` 里释放所有 Subscription 成员**——在调用基类 `Destroy()` 前 `xxxSubscription_.reset()`。`Destroy()` 必先于析构执行（`Remove` 是从 `Destroy` 内 PostTask 的），从而把 cleanup 移出 erase 现场。各层级各管各的：`OutboundRequest::Destroy`/`InboundRequest::Destroy` 释放本层 subscription（`connectionStatusSubscription_`、`requestAbortedSubscription_`），派生类释放自己的；`BaseRequest::Destroy` 已通过 `StopTimeout` 释放 `timeoutSubscription_`。`Destroy()` 非虚，派生类靠 name-hiding（不加 `override`），`Complete*` 中的非限定 `Destroy()` 会解析到最派生版本。
2. **Subscription 的 cleanup lambda 必须是纯本地 erase**（只从所属 manager 的容器移除/取消定时器，然后结束）。任何周边副作用（`RefreshDeviceList`、`NotifySubscribers`、`RefreshObserver`、observer register/unregister、外部 sysparam 解注册等）必须用 `PostTaskOnResident` 延迟，并捕获**所属 manager** 的 `weak_from_this()`（不是 Request 的）——manager 比单个 Request 长命，故 late-safe。合规模板：`SystemSettingsManagerImpl::SubscribeSettingsChange`、`AuthenticatorManager::SubscribeAuthenticatorStatus`。

### 工具

- 使用 `useriam-format-include` 技能进行头文件排序
- 使用 `oh-commit` 技能进行代码审查、格式化和提交工作流
