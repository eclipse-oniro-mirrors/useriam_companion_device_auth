/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdint>
#include <cstring>

#include "fuzzer/FuzzedDataProvider.h"

#include "adapter_initializer.h"
#include "fuzz_data_generator.h"
#include "service_fuzz_entry.h"
#include "singleton_initializer.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Define function pointer type
using FuzzFunction = void (*)(FuzzedDataProvider &);

// Array of all fuzz functions
static const FuzzFunction g_fuzzFunctions[] = {
    // Common Module
    FuzzServiceCommon,
    FuzzServiceConverter,

    // Companion Module
    FuzzCompanion,
    FuzzCompanionManagerImpl,

    // CrossDeviceComm Module
    FuzzChannelManager,
    FuzzConnectionManager,
    FuzzCrossDeviceCommManagerImpl,
    FuzzDeviceStatusEntry,
    FuzzDeviceStatusManager,
    FuzzLocalDeviceStatusManager,
    FuzzMessageRouter,

    // CrossDeviceInteraction Module
    FuzzCommonMessage,
    FuzzRequestAbortedMessage,
    FuzzKeepAliveHandler,
    FuzzRevokeTokenMessage,
    FuzzHostRevokeTokenHandler,
    FuzzAddCompanionMessage,
    FuzzCompanionInitKeyNegotiationHandler,
    FuzzSyncDeviceStatusMessage,
    FuzzCompanionSyncDeviceStatusHandler,
    FuzzHostSyncDeviceStatusRequest,
    FuzzIssueTokenMessage,
    FuzzCompanionPreIssueTokenHandler,
    FuzzHostIssueTokenRequest,
    FuzzHostPreObtainTokenHandler,
    FuzzTokenAuthMessage,
    FuzzCompanionTokenAuthHandler,
    FuzzHostTokenAuthRequest,
    FuzzDelegateAuthMessage,
    FuzzCompanionDelegateAuthRequest,
    FuzzCompanionDelegateAuthCallback,
    FuzzCompanionStartDelegateAuthHandler,
    FuzzHostDelegateAuthRequest,
    FuzzRemoveHostBindingMessage,
    FuzzCompanionRemoveHostBindingHandler,
    FuzzHostRemoveHostBindingRequest,
    FuzzObtainTokenMessage,
    FuzzCompanionIssueTokenRequest,
    FuzzCompanionObtainTokenRequest,
    FuzzHostObtainTokenRequest,
    FuzzAuthMaintainStateChangeMessage,
    FuzzHostAuthMaintainStateChangeHandler,
    FuzzCompanionAuthMaintainStateChangeRequest,
    FuzzHostMixAuthRequest,
    FuzzHostSingleMixAuthRequest,
    FuzzHostAddCompanionRequest,
    FuzzCompanionAddCompanionRequest,
    FuzzCompanionRevokeTokenRequest,

    // Incoming Message Handler
    FuzzAsyncIncomingMessageHandler,
    FuzzSyncIncomingMessageHandler,
    FuzzIncomingMessageHandlerRegistry,

    // FwkComm Module
    FuzzFwkCommManager,
    FuzzCompanionDeviceAuthAllInOneExecutor,
    FuzzCompanionDeviceAuthDriver,
    FuzzCompanionDeviceAuthExecutorCallback,
    FuzzCompanionAuthInterfaceAdapter,
    FuzzAllInOneExecutor,
    FuzzDriver,
    FuzzExecutorCallback,

    // ExternalAdapters Module
    FuzzDeviceManagerAdapter,
    FuzzSoftBusAdapter,
    FuzzUserAuthAdapter,
    FuzzPermissionAdapter,
    FuzzExecutorDriverManagerAdapter,
    FuzzSaManagerAdapter,

    // SoftBusCrossDeviceChannel Module
    FuzzSoftBusChannel,
    FuzzSoftBusConnectionManager,
    FuzzSoftBusDeviceStatusManager,
    FuzzSoftBusGlobalCallbacks,
    FuzzSoftBusSocket,

    // Host Binding Module
    FuzzHostBinding,
    FuzzHostBindingManager,
    FuzzHostBindingManagerImpl,

    // Misc Module
    FuzzAttributes,
    FuzzSystemParamManagerImpl,
    FuzzConstantUserIdManager,
    FuzzDefaultUserIdManager,
    FuzzMiscManagerImpl,

    // Request Module
    FuzzRequest,
    FuzzBaseRequest,
    FuzzRequestFactoryImpl,
    FuzzRequestManagerImpl,

    // SecurityAgent Module
    FuzzSecurityAgentImpl,
    FuzzCompanionDeviceAuthFFIUtil,
    FuzzCommandInvoker,
    FuzzFfiUtil,

    // Utils Module
    FuzzSubscription,
    FuzzSaStatusListener,
    FuzzErrorGuard,
    FuzzScopeGuard,

    // ServiceEntry Module
    FuzzSubscriptionManager,
    FuzzSubscriptionUtil,
    FuzzTemplateStatusSubscription,
    FuzzAvailableDeviceSubscription,
    FuzzContinuousAuthSubscription,
};

static constexpr size_t g_fuzzFunctionCount = sizeof(g_fuzzFunctions) / sizeof(g_fuzzFunctions[0]);
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }

    FuzzedDataProvider fuzzData(data, size);

    if (!InitializeAdapterManager(fuzzData)) {
        return 0;
    }

    if (!InitializeSingletonManager(fuzzData)) {
        return 0;
    }

    // Read function index from fuzz data
    uint32_t functionIndex = fuzzData.ConsumeIntegral<uint32_t>();
    // Call the selected fuzz function if index is valid
    if (functionIndex < g_fuzzFunctionCount) {
        g_fuzzFunctions[functionIndex](fuzzData);
    }

    EnsureAllTaskExecuted();
    CleanupSingletonManager();
    CleanupAdapterManager();
    return 0;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
