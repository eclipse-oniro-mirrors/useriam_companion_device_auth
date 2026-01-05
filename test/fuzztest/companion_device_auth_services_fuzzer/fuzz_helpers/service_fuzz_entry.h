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

#ifndef COMPANION_DEVICE_AUTH_SERVICE_FUZZ_ENTRY_H
#define COMPANION_DEVICE_AUTH_SERVICE_FUZZ_ENTRY_H

#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// ============ Common Module ============
void FuzzServiceCommon(FuzzedDataProvider &fuzzData);
void FuzzServiceConverter(FuzzedDataProvider &fuzzData);

// ============ Companion Module ============
void FuzzCompanion(FuzzedDataProvider &fuzzData);
void FuzzCompanionManagerImpl(FuzzedDataProvider &fuzzData);

// ============ CrossDeviceComm Module ============
void FuzzChannelManager(FuzzedDataProvider &fuzzData);
void FuzzConnectionManager(FuzzedDataProvider &fuzzData);
void FuzzCrossDeviceCommManagerImpl(FuzzedDataProvider &fuzzData);
void FuzzDeviceStatusEntry(FuzzedDataProvider &fuzzData);
void FuzzDeviceStatusManager(FuzzedDataProvider &fuzzData);
void FuzzLocalDeviceStatusManager(FuzzedDataProvider &fuzzData);
void FuzzMessageRouter(FuzzedDataProvider &fuzzData);

// ============ CrossDeviceInteraction Module ============
// Common Infrastructure
void FuzzCommonMessage(FuzzedDataProvider &fuzzData);

// Message Handlers
void FuzzAsyncIncomingMessageHandler(FuzzedDataProvider &fuzzData);
void FuzzSyncIncomingMessageHandler(FuzzedDataProvider &fuzzData);
void FuzzIncomingMessageHandlerRegistry(FuzzedDataProvider &fuzzData);

// Keep Alive
void FuzzKeepAliveHandler(FuzzedDataProvider &fuzzData);

// Revoke Token
void FuzzRevokeTokenMessage(FuzzedDataProvider &fuzzData);
void FuzzHostRevokeTokenHandler(FuzzedDataProvider &fuzzData);
void FuzzCompanionRevokeTokenRequest(FuzzedDataProvider &fuzzData);

// Add Companion
void FuzzAddCompanionMessage(FuzzedDataProvider &fuzzData);
void FuzzCompanionAddCompanionRequest(FuzzedDataProvider &fuzzData);
void FuzzHostAddCompanionRequest(FuzzedDataProvider &fuzzData);
void FuzzCompanionInitKeyNegotiationHandler(FuzzedDataProvider &fuzzData);

// Sync Device Status
void FuzzSyncDeviceStatusMessage(FuzzedDataProvider &fuzzData);
void FuzzCompanionSyncDeviceStatusHandler(FuzzedDataProvider &fuzzData);
void FuzzHostSyncDeviceStatusRequest(FuzzedDataProvider &fuzzData);

// Issue Token
void FuzzIssueTokenMessage(FuzzedDataProvider &fuzzData);
void FuzzCompanionIssueTokenRequest(FuzzedDataProvider &fuzzData);
void FuzzCompanionPreIssueTokenHandler(FuzzedDataProvider &fuzzData);
void FuzzHostIssueTokenRequest(FuzzedDataProvider &fuzzData);

// Token Auth
void FuzzTokenAuthMessage(FuzzedDataProvider &fuzzData);
void FuzzHostTokenAuthRequest(FuzzedDataProvider &fuzzData);
void FuzzCompanionTokenAuthHandler(FuzzedDataProvider &fuzzData);

// Delegate Auth
void FuzzDelegateAuthMessage(FuzzedDataProvider &fuzzData);
void FuzzCompanionDelegateAuthRequest(FuzzedDataProvider &fuzzData);
void FuzzCompanionDelegateAuthCallback(FuzzedDataProvider &fuzzData);
void FuzzHostDelegateAuthRequest(FuzzedDataProvider &fuzzData);
void FuzzCompanionStartDelegateAuthHandler(FuzzedDataProvider &fuzzData);

// Remove Host Binding
void FuzzRemoveHostBindingMessage(FuzzedDataProvider &fuzzData);
void FuzzCompanionRemoveHostBindingHandler(FuzzedDataProvider &fuzzData);
void FuzzHostRemoveHostBindingRequest(FuzzedDataProvider &fuzzData);

// Obtain Token
void FuzzObtainTokenMessage(FuzzedDataProvider &fuzzData);
void FuzzCompanionObtainTokenRequest(FuzzedDataProvider &fuzzData);
void FuzzHostObtainTokenRequest(FuzzedDataProvider &fuzzData);
void FuzzHostPreObtainTokenHandler(FuzzedDataProvider &fuzzData);

// Auth Maintain State Change
void FuzzAuthMaintainStateChangeMessage(FuzzedDataProvider &fuzzData);
void FuzzHostAuthMaintainStateChangeHandler(FuzzedDataProvider &fuzzData);
void FuzzCompanionAuthMaintainStateChangeRequest(FuzzedDataProvider &fuzzData);

// Request Aborted
void FuzzRequestAbortedMessage(FuzzedDataProvider &fuzzData);

// Mix Auth
void FuzzHostMixAuthRequest(FuzzedDataProvider &fuzzData);
void FuzzHostSingleMixAuthRequest(FuzzedDataProvider &fuzzData);

// ============ FwkComm Module ============
void FuzzFwkCommManager(FuzzedDataProvider &fuzzData);
void FuzzCompanionDeviceAuthAllInOneExecutor(FuzzedDataProvider &fuzzData);
void FuzzCompanionDeviceAuthDriver(FuzzedDataProvider &fuzzData);
void FuzzCompanionDeviceAuthExecutorCallback(FuzzedDataProvider &fuzzData);
void FuzzCompanionAuthInterfaceAdapter(FuzzedDataProvider &fuzzData);
void FuzzAllInOneExecutor(FuzzedDataProvider &fuzzData);
void FuzzDriver(FuzzedDataProvider &fuzzData);
void FuzzExecutorCallback(FuzzedDataProvider &fuzzData);

// ============ ExternalAdapters Module ============
void FuzzDeviceManagerAdapter(FuzzedDataProvider &fuzzData);
void FuzzSoftBusAdapter(FuzzedDataProvider &fuzzData);
void FuzzSaManagerAdapter(FuzzedDataProvider &fuzzData);
void FuzzUserAuthAdapter(FuzzedDataProvider &fuzzData);
void FuzzPermissionAdapter(FuzzedDataProvider &fuzzData);
void FuzzExecutorDriverManagerAdapter(FuzzedDataProvider &fuzzData);

// ============ Host Binding Module ============
void FuzzHostBinding(FuzzedDataProvider &fuzzData);
void FuzzHostBindingManager(FuzzedDataProvider &fuzzData);
void FuzzHostBindingManagerImpl(FuzzedDataProvider &fuzzData);

// ============ Misc Module ============
void FuzzAttributes(FuzzedDataProvider &fuzzData);
void FuzzSystemParamManagerImpl(FuzzedDataProvider &fuzzData);
void FuzzConstantUserIdManager(FuzzedDataProvider &fuzzData);
void FuzzDefaultUserIdManager(FuzzedDataProvider &fuzzData);
void FuzzMiscManagerImpl(FuzzedDataProvider &fuzzData);

// ============ Request Module ============
void FuzzRequest(FuzzedDataProvider &fuzzData);
void FuzzBaseRequest(FuzzedDataProvider &fuzzData);
void FuzzRequestFactoryImpl(FuzzedDataProvider &fuzzData);
void FuzzRequestManagerImpl(FuzzedDataProvider &fuzzData);

// ============ SecurityAgent Module ============
void FuzzSecurityAgentImpl(FuzzedDataProvider &fuzzData);
void FuzzCompanionDeviceAuthFFIUtil(FuzzedDataProvider &fuzzData);
void FuzzCommandInvoker(FuzzedDataProvider &fuzzData);
void FuzzFfiUtil(FuzzedDataProvider &fuzzData);

// ============ SoftBus Cross Device Channel Module ============
void FuzzSoftBusChannel(FuzzedDataProvider &fuzzData);
void FuzzSoftBusConnectionManager(FuzzedDataProvider &fuzzData);
void FuzzSoftBusDeviceStatusManager(FuzzedDataProvider &fuzzData);
void FuzzSoftBusGlobalCallbacks(FuzzedDataProvider &fuzzData);
void FuzzSoftBusSocket(FuzzedDataProvider &fuzzData);

// ============ ServiceEntry Module ============
void FuzzSubscriptionManager(FuzzedDataProvider &fuzzData);
void FuzzAvailableDeviceSubscription(FuzzedDataProvider &fuzzData);
void FuzzContinuousAuthSubscription(FuzzedDataProvider &fuzzData);
void FuzzTemplateStatusSubscription(FuzzedDataProvider &fuzzData);
void FuzzSubscriptionUtil(FuzzedDataProvider &fuzzData);

// ============ Utils Module ============
void FuzzSubscription(FuzzedDataProvider &fuzzData);
void FuzzSaStatusListener(FuzzedDataProvider &fuzzData);
void FuzzErrorGuard(FuzzedDataProvider &fuzzData);
void FuzzScopeGuard(FuzzedDataProvider &fuzzData);

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SERVICE_FUZZ_ENTRY_H
