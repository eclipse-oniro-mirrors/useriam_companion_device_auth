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

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_CLIENT_MOCK_MOCK_COMPANION_DEVICE_AUTH_PROXY_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_CLIENT_MOCK_MOCK_COMPANION_DEVICE_AUTH_PROXY_H

#include <vector>

#include "iremote_broker.h"
#include "iremote_object.h"
#include <gmock/gmock.h>

#include "mock_remote_object.h"

// Forward declarations for IPC types used in the interface
namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

struct IpcTemplateStatus;
struct IpcSubscribeContinuousAuthStatusParam;

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

/**
 * @brief Mock implementation of ICompanionDeviceAuth interface for unit testing.
 *        This mock allows tests to simulate service responses without actual IPC communication.
 */
class MockCompanionDeviceAuthProxy : public IRemoteBroker {
public:
    MockCompanionDeviceAuthProxy() = default;

    // Constructor for BrokerCreator (required for iface_cast support)
    explicit MockCompanionDeviceAuthProxy(const sptr<IRemoteObject> &object)
    {
        (void)object; // Ignore the object in mock
    }

    ~MockCompanionDeviceAuthProxy() override = default;

    // Mock all service interface methods
    MOCK_METHOD(int32_t, RegisterDeviceSelectCallback, (const sptr<IRemoteObject> &callback, int32_t &result));
    MOCK_METHOD(int32_t, UnregisterDeviceSelectCallback, (int32_t & result));
    MOCK_METHOD(int32_t, UpdateTemplateEnabledBusinessIds,
        (uint64_t templateId, const std::vector<int32_t> &enabledBusinessIds, int32_t &result));
    MOCK_METHOD(int32_t, GetTemplateStatus,
        (int32_t localUserId, std::vector<IpcTemplateStatus> &templateStatusList, int32_t &result));
    MOCK_METHOD(int32_t, SubscribeTemplateStatusChange,
        (int32_t localUserId, const sptr<IRemoteObject> &callback, int32_t &result));
    MOCK_METHOD(int32_t, UnsubscribeTemplateStatusChange, (const sptr<IRemoteObject> &callback, int32_t &result));
    MOCK_METHOD(int32_t, SubscribeAvailableDeviceStatus,
        (int32_t localUserId, const sptr<IRemoteObject> &callback, int32_t &result));
    MOCK_METHOD(int32_t, UnsubscribeAvailableDeviceStatus, (const sptr<IRemoteObject> &callback, int32_t &result));
    MOCK_METHOD(int32_t, SubscribeContinuousAuthStatusChange,
        (const IpcSubscribeContinuousAuthStatusParam &param, const sptr<IRemoteObject> &callback, int32_t &result));
    MOCK_METHOD(int32_t, UnsubscribeContinuousAuthStatusChange, (const sptr<IRemoteObject> &callback, int32_t &result));
    MOCK_METHOD(int32_t, CheckLocalUserIdValid, (int32_t localUserId, bool &isUserIdValid, int32_t &result));

    // IRemoteObject methods (needed for proxy conversion)
    sptr<IRemoteObject> AsObject()
    {
        // Return the mock remote object for testing
        return remoteObj_;
    }

    // Declare interface descriptor for iface_cast support
    static constexpr const char16_t *metaDescriptor_ = u"OHOS.UserIam.CompanionDeviceAuth.ICompanionDeviceAuth";
    static inline const std::u16string GetDescriptor()
    {
        return metaDescriptor_;
    }

private:
    sptr<MockRemoteObject> remoteObj_ = new (std::nothrow) MockRemoteObject();

    // Broker delegator for automatic registration with BrokerRegistration
    // This enables iface_cast to find and instantiate this mock
    static inline BrokerDelegator<MockCompanionDeviceAuthProxy> delegator_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_CLIENT_MOCK_MOCK_COMPANION_DEVICE_AUTH_PROXY_H
