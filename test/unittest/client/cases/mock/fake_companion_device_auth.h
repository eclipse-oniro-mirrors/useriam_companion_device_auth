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

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_CLIENT_MOCK_FAKE_COMPANION_DEVICE_AUTH_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_CLIENT_MOCK_FAKE_COMPANION_DEVICE_AUTH_H

#include <gmock/gmock.h>

#include "companion_device_auth_types.h"
#include "icompanion_device_auth.h"
#include "iipc_available_device_status_callback.h"
#include "iipc_continuous_auth_status_callback.h"
#include "iipc_device_select_callback.h"
#include "iipc_template_status_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

/**
 * @brief Fake/Mock implementation of ICompanionDeviceAuth for unit testing.
 *        Uses GMock to allow flexible behavior configuration in tests.
 */
class FakeCompanionDeviceAuth : public ICompanionDeviceAuth {
public:
    FakeCompanionDeviceAuth() = default;
    ~FakeCompanionDeviceAuth() override = default;

    // Implement all ICompanionDeviceAuth interface methods with GMock
    MOCK_METHOD(ErrCode, SubscribeAvailableDeviceStatus,
        (int32_t localUserId, const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback, int32_t &resultCode),
        (override));
    MOCK_METHOD(ErrCode, UnsubscribeAvailableDeviceStatus,
        (const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback, int32_t &resultCode), (override));
    MOCK_METHOD(ErrCode, SubscribeTemplateStatusChange,
        (int32_t localUserId, const sptr<IIpcTemplateStatusCallback> &templateStatusCallback, int32_t &resultCode),
        (override));
    MOCK_METHOD(ErrCode, UnsubscribeTemplateStatusChange,
        (const sptr<IIpcTemplateStatusCallback> &templateStatusCallback, int32_t &resultCode), (override));
    MOCK_METHOD(ErrCode, SubscribeContinuousAuthStatusChange,
        (const IpcSubscribeContinuousAuthStatusParam &param,
            const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback, int32_t &resultCode),
        (override));
    MOCK_METHOD(ErrCode, UnsubscribeContinuousAuthStatusChange,
        (const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback, int32_t &resultCode), (override));
    MOCK_METHOD(ErrCode, GetTemplateStatus,
        (int32_t localUserId, std::vector<IpcTemplateStatus> &templateStatusList, int32_t &resultCode), (override));
    MOCK_METHOD(ErrCode, RegisterDeviceSelectCallback,
        (const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback, int32_t &resultCode), (override));
    MOCK_METHOD(ErrCode, UnregisterDeviceSelectCallback, (int32_t & resultCode), (override));
    MOCK_METHOD(ErrCode, UpdateTemplateEnabledBusinessIds,
        (uint64_t templateId, const std::vector<int32_t> &enabledBusinessIds, int32_t &resultCode), (override));
    MOCK_METHOD(ErrCode, CheckLocalUserIdValid, (int32_t localUserId, bool &isUserIdValid, int32_t &resultCode),
        (override));

    // IRemoteBroker interface - stub implementation
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_CLIENT_MOCK_FAKE_COMPANION_DEVICE_AUTH_H
