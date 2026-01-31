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
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "iremote_broker.h"
#include "iremote_object.h"
#include "message_option.h"
#include "message_parcel.h"

#include "common_defines.h"
#include "companion_device_auth_client_impl.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Fuzz test constants
constexpr int32_t INT32_NEG10 = -10;
constexpr int32_t INT32_10 = 10;
constexpr int32_t INT32_100000 = 100000;
constexpr uint32_t UINT32_1 = 1;
constexpr uint32_t UINT32_10 = 10;
constexpr size_t SIZE_5 = 5;
constexpr size_t SIZE_10 = 10;

// Forward declarations for IPC types (from IDL)
struct IpcTemplateStatus;
struct IpcSubscribeContinuousAuthStatusParam;

// Mock IRemoteObject for fuzzing
class FuzzMockRemoteObject : public IRemoteObject {
public:
    FuzzMockRemoteObject() = default;
    ~FuzzMockRemoteObject() override = default;

    // Override required IRemoteObject methods
    bool IsProxyObject() const override
    {
        return true;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        (void)recipient;
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        (void)recipient;
        return true;
    }

    int32_t SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        (void)code;
        (void)data;
        (void)reply;
        (void)option;
        return 0;
    }

    // Prevent actual IPC calls
    sptr<IRemoteBroker> AsInterface() override
    {
        return nullptr;
    }

    int32_t GetObjectRefCount() override
    {
        return 1;
    }

    int32_t Dump(int fd, const std::vector<std::u16string> &args) override
    {
        (void)fd;
        (void)args;
        return 0;
    }
};

// Mock ICompanionDeviceAuth for fuzzing
class FuzzMockCompanionDeviceAuth : public ICompanionDeviceAuth {
public:
    FuzzMockCompanionDeviceAuth()
    {
    }
    ~FuzzMockCompanionDeviceAuth() override = default;

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }

    void SetMockResults(int32_t ipcResult, int32_t serviceResult)
    {
        mockIpcResult_ = ipcResult;
        mockResult_ = serviceResult;
    }

    int32_t mockIpcResult_ = SUCCESS;
    int32_t mockResult_ = SUCCESS;

    // Implement all ICompanionDeviceAuth methods to return mock results
    int32_t RegisterDeviceSelectCallback(const sptr<IIpcDeviceSelectCallback> &callback, int32_t &result) override
    {
        (void)callback;
        result = mockResult_;
        return mockIpcResult_;
    }

    int32_t UnregisterDeviceSelectCallback(int32_t &result) override
    {
        result = mockResult_;
        return mockIpcResult_;
    }

    int32_t UpdateTemplateEnabledBusinessIds(uint64_t templateId, const std::vector<int32_t> &enabledBusinessIds,
        int32_t &result) override
    {
        (void)templateId;
        (void)enabledBusinessIds;
        result = mockResult_;
        return mockIpcResult_;
    }

    int32_t GetTemplateStatus(int32_t localUserId, std::vector<IpcTemplateStatus> &templateStatusList,
        int32_t &result) override
    {
        (void)localUserId;
        templateStatusList.clear();
        result = mockResult_;
        return mockIpcResult_;
    }

    int32_t SubscribeTemplateStatusChange(int32_t localUserId, const sptr<IIpcTemplateStatusCallback> &callback,
        int32_t &result) override
    {
        (void)localUserId;
        (void)callback;
        result = mockResult_;
        return mockIpcResult_;
    }

    int32_t UnsubscribeTemplateStatusChange(const sptr<IIpcTemplateStatusCallback> &callback, int32_t &result) override
    {
        (void)callback;
        result = mockResult_;
        return mockIpcResult_;
    }

    int32_t SubscribeContinuousAuthStatusChange(const IpcSubscribeContinuousAuthStatusParam &param,
        const sptr<IIpcContinuousAuthStatusCallback> &callback, int32_t &result) override
    {
        (void)param;
        (void)callback;
        result = mockResult_;
        return mockIpcResult_;
    }

    int32_t UnsubscribeContinuousAuthStatusChange(const sptr<IIpcContinuousAuthStatusCallback> &callback,
        int32_t &result) override
    {
        (void)callback;
        result = mockResult_;
        return mockIpcResult_;
    }

    int32_t SubscribeAvailableDeviceStatus(int32_t localUserId, const sptr<IIpcAvailableDeviceStatusCallback> &callback,
        int32_t &result) override
    {
        (void)localUserId;
        (void)callback;
        result = mockResult_;
        return mockIpcResult_;
    }

    int32_t UnsubscribeAvailableDeviceStatus(const sptr<IIpcAvailableDeviceStatusCallback> &callback,
        int32_t &result) override
    {
        (void)callback;
        result = mockResult_;
        return mockIpcResult_;
    }

    int32_t CheckLocalUserIdValid(int32_t localUserId, bool &isUserIdValid, int32_t &result) override
    {
        (void)localUserId;
        isUserIdValid = true;
        result = mockResult_;
        return mockIpcResult_;
    }
};

// Fuzz test callbacks
class FuzzMockDeviceSelectCallback : public IDeviceSelectCallback {
public:
    ~FuzzMockDeviceSelectCallback() override = default;
    void OnDeviceSelect(int32_t selectPurpose, const std::shared_ptr<SetDeviceSelectResultCallback> &callback) override
    {
        (void)selectPurpose;
        (void)callback;
    }
};

class FuzzMockTemplateStatusCallback : public ITemplateStatusCallback {
public:
    explicit FuzzMockTemplateStatusCallback(int32_t userId) : userId_(userId)
    {
    }
    ~FuzzMockTemplateStatusCallback() override = default;
    int32_t GetUserId() override
    {
        return userId_;
    }
    void OnTemplateStatusChange(const std::vector<ClientTemplateStatus> templateStatusList) override
    {
        (void)templateStatusList;
    }

private:
    int32_t userId_;
};

class FuzzMockAvailableDeviceStatusCallback : public IAvailableDeviceStatusCallback {
public:
    explicit FuzzMockAvailableDeviceStatusCallback(int32_t userId) : userId_(userId)
    {
    }
    ~FuzzMockAvailableDeviceStatusCallback() override = default;
    int32_t GetUserId() override
    {
        return userId_;
    }
    void OnAvailableDeviceStatusChange(const std::vector<ClientDeviceStatus> deviceStatusList) override
    {
        (void)deviceStatusList;
    }

private:
    int32_t userId_;
};

class FuzzMockContinuousAuthStatusCallback : public IContinuousAuthStatusCallback {
public:
    FuzzMockContinuousAuthStatusCallback(int32_t userId, std::optional<uint64_t> templateId)
        : userId_(userId),
          templateId_(templateId)
    {
    }
    ~FuzzMockContinuousAuthStatusCallback() override = default;
    int32_t GetUserId() override
    {
        return userId_;
    }
    std::optional<uint64_t> GetTemplateId() override
    {
        return templateId_;
    }
    void OnContinuousAuthStatusChange(const bool isAuthPassed,
        const std::optional<int32_t> authTrustLevel = std::nullopt) override
    {
        (void)isAuthPassed;
        (void)authTrustLevel;
    }

private:
    int32_t userId_;
    std::optional<uint64_t> templateId_;
};

// Fuzz operations for CompanionDeviceAuthClientImpl

// Operation 0: RegisterDeviceSelectCallback
static void FuzzOp0(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    // Set mock results from fuzz data
    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    // Create client and set mock proxy
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    // Create callback (or nullptr based on fuzz data)
    bool useNullCallback = fuzzData.ConsumeBool();
    std::shared_ptr<IDeviceSelectCallback> callback = nullptr;
    if (!useNullCallback) {
        callback = std::make_shared<FuzzMockDeviceSelectCallback>();
    }

    // Call the API
    client.RegisterDeviceSelectCallback(callback);
}

// Operation 1: UnregisterDeviceSelectCallback
static void FuzzOp1(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);
    client.UnregisterDeviceSelectCallback();
}

// Operation 2: UpdateTemplateEnabledBusinessIds
static void FuzzOp2(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    // Generate fuzz data for templateId and businessIds
    uint64_t templateId = fuzzData.ConsumeIntegral<uint64_t>();
    std::vector<int32_t> businessIds;
    size_t vectorSize = fuzzData.ConsumeIntegralInRange<size_t>(0, SIZE_10);
    for (size_t i = 0; i < vectorSize; ++i) {
        businessIds.push_back(fuzzData.ConsumeIntegral<int32_t>());
    }

    client.UpdateTemplateEnabledBusinessIds(templateId, businessIds);
}

// Operation 3: GetTemplateStatus
static void FuzzOp3(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    std::vector<ClientTemplateStatus> statusList;
    client.GetTemplateStatus(userId, statusList);
}

// Operation 4: SubscribeTemplateStatusChange
static void FuzzOp4(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    bool useNullCallback = fuzzData.ConsumeBool();
    std::shared_ptr<ITemplateStatusCallback> callback = nullptr;
    if (!useNullCallback) {
        callback = std::make_shared<FuzzMockTemplateStatusCallback>(userId);
    }

    client.SubscribeTemplateStatusChange(userId, callback);
}

// Operation 5: UnsubscribeTemplateStatusChange
static void FuzzOp5(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    bool useNullCallback = fuzzData.ConsumeBool();
    std::shared_ptr<ITemplateStatusCallback> callback = nullptr;
    if (!useNullCallback) {
        callback = std::make_shared<FuzzMockTemplateStatusCallback>(userId);
    }

    client.UnsubscribeTemplateStatusChange(callback);
}

// Operation 6: SubscribeAvailableDeviceStatus
static void FuzzOp6(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    bool useNullCallback = fuzzData.ConsumeBool();
    std::shared_ptr<IAvailableDeviceStatusCallback> callback = nullptr;
    if (!useNullCallback) {
        callback = std::make_shared<FuzzMockAvailableDeviceStatusCallback>(userId);
    }

    client.SubscribeAvailableDeviceStatus(userId, callback);
}

// Operation 7: UnsubscribeAvailableDeviceStatus
static void FuzzOp7(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    bool useNullCallback = fuzzData.ConsumeBool();
    std::shared_ptr<IAvailableDeviceStatusCallback> callback = nullptr;
    if (!useNullCallback) {
        callback = std::make_shared<FuzzMockAvailableDeviceStatusCallback>(userId);
    }

    client.UnsubscribeAvailableDeviceStatus(callback);
}

// Operation 8: SubscribeContinuousAuthStatusChange
static void FuzzOp8(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    bool useNullCallback = fuzzData.ConsumeBool();
    bool hasTemplateId = fuzzData.ConsumeBool();

    std::shared_ptr<IContinuousAuthStatusCallback> callback = nullptr;
    std::optional<uint64_t> templateId = std::nullopt;

    if (!useNullCallback) {
        std::optional<uint64_t> callbackTemplateId = std::nullopt;
        if (hasTemplateId) {
            callbackTemplateId = fuzzData.ConsumeIntegral<uint64_t>();
        }
        callback = std::make_shared<FuzzMockContinuousAuthStatusCallback>(userId, callbackTemplateId);
    }

    if (hasTemplateId) {
        templateId = fuzzData.ConsumeIntegral<uint64_t>();
    }

    client.SubscribeContinuousAuthStatusChange(userId, callback, templateId);
}

// Operation 9: UnsubscribeContinuousAuthStatusChange
static void FuzzOp9(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    bool useNullCallback = fuzzData.ConsumeBool();
    bool hasTemplateId = fuzzData.ConsumeBool();

    std::shared_ptr<IContinuousAuthStatusCallback> callback = nullptr;
    if (!useNullCallback) {
        std::optional<uint64_t> templateId = std::nullopt;
        if (hasTemplateId) {
            templateId = fuzzData.ConsumeIntegral<uint64_t>();
        }
        callback = std::make_shared<FuzzMockContinuousAuthStatusCallback>(userId, templateId);
    }

    client.UnsubscribeContinuousAuthStatusChange(callback);
}

// Operation 10: CheckLocalUserIdValid
static void FuzzOp10(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    bool isUserIdValid = false;
    client.CheckLocalUserIdValid(userId, isUserIdValid);
}

// Operation 11: Test with null fetcher
static void FuzzOp11(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test with null proxy
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(nullptr);

    auto callback = std::make_shared<FuzzMockDeviceSelectCallback>();
    client.RegisterDeviceSelectCallback(callback);
}

// Operation 12: Test with fetcher that returns null proxy
static void FuzzOp12(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test with fetcher that returns null proxy
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(nullptr);

    auto callback = std::make_shared<FuzzMockDeviceSelectCallback>();
    client.RegisterDeviceSelectCallback(callback);
}

// Operation 13: Test proxy caching (GetProxy returns cached proxy)
static void FuzzOp13(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    // First call - creates and caches proxy
    auto callback = std::make_shared<FuzzMockDeviceSelectCallback>();
    client.RegisterDeviceSelectCallback(callback);

    // Second call - uses cached proxy (tests GetProxy line 475)
    client.UnregisterDeviceSelectCallback();

    // Third call - still uses cached proxy
    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    std::vector<ClientTemplateStatus> statusList;
    client.GetTemplateStatus(userId, statusList);
}

// Operation 14: Test callback not found in unsubscribe
static void FuzzOp14(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();

    // Subscribe with callback A
    auto callbackA = std::make_shared<FuzzMockTemplateStatusCallback>(userId);
    client.SubscribeTemplateStatusChange(userId, callbackA);

    // Try to unsubscribe with different callback B (tests callback not found path)
    auto callbackB = std::make_shared<FuzzMockTemplateStatusCallback>(userId + 1);
    client.UnsubscribeTemplateStatusChange(callbackB);
}

// Operation 15: Test multiple operations on same client instance
static void FuzzOp15(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    // Register multiple callbacks to test list management
    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();

    auto callback1 = std::make_shared<FuzzMockTemplateStatusCallback>(userId);
    client.SubscribeTemplateStatusChange(userId, callback1);

    auto callback2 = std::make_shared<FuzzMockTemplateStatusCallback>(userId);
    client.SubscribeTemplateStatusChange(userId, callback2);

    auto callback3 = std::make_shared<FuzzMockAvailableDeviceStatusCallback>(userId);
    client.SubscribeAvailableDeviceStatus(userId, callback3);

    // Unsubscribe in different order to test std::find_if
    client.UnsubscribeTemplateStatusChange(callback2);
    client.UnsubscribeAvailableDeviceStatus(callback3);
    client.UnsubscribeTemplateStatusChange(callback1);
}

// Operation 16: Test repeated subscribe with same callback
static void FuzzOp16(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    auto callback = std::make_shared<FuzzMockTemplateStatusCallback>(userId);

    // Subscribe with same callback twice
    client.SubscribeTemplateStatusChange(userId, callback);
    client.SubscribeTemplateStatusChange(userId, callback);

    // Both subscriptions should be in the list
    // Unsubscribe once - should still have one in list
    client.UnsubscribeTemplateStatusChange(callback);

    // Try to unsubscribe again - should fail (not found)
    int32_t result = client.UnsubscribeTemplateStatusChange(callback);
    (void)result; // Use result to avoid unused variable warning
}

// Operation 17: Test subscribe-unsubscribe-subscribe pattern
static void FuzzOp17(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    int32_t ipcResult = fuzzData.ConsumeIntegral<int32_t>();
    int32_t serviceResult = fuzzData.ConsumeIntegral<int32_t>();
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    auto callback = std::make_shared<FuzzMockAvailableDeviceStatusCallback>(userId);

    // Subscribe -> Unsubscribe -> Subscribe pattern
    client.SubscribeAvailableDeviceStatus(userId, callback);
    client.UnsubscribeAvailableDeviceStatus(callback);
    client.SubscribeAvailableDeviceStatus(userId, callback);

    // Final unsubscribe to clean up
    client.UnsubscribeAvailableDeviceStatus(callback);
}

// Operation 18: Test error code variations
static void FuzzOp18(FuzzedDataProvider &fuzzData)
{
    sptr<FuzzMockCompanionDeviceAuth> mockProxy = new FuzzMockCompanionDeviceAuth();

    // Use various error codes from fuzz data
    int32_t ipcResult = fuzzData.ConsumeIntegralInRange<int32_t>(INT32_NEG10, INT32_10);
    int32_t serviceResult = fuzzData.ConsumeIntegralInRange<int32_t>(INT32_NEG10, INT32_10);
    mockProxy->SetMockResults(ipcResult, serviceResult);

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(mockProxy);

    // Test with various error conditions
    int32_t userId = fuzzData.ConsumeIntegralInRange<int32_t>(0, INT32_100000);
    uint64_t templateId = fuzzData.ConsumeIntegral<uint64_t>();

    // Try UpdateTemplateEnabledBusinessIds with error codes
    std::vector<int32_t> businessIds;
    size_t vectorSize = fuzzData.ConsumeIntegralInRange<size_t>(0, SIZE_5);
    for (size_t i = 0; i < vectorSize; ++i) {
        businessIds.push_back(fuzzData.ConsumeIntegralInRange<int32_t>(1, INT32_10));
    }
    client.UpdateTemplateEnabledBusinessIds(templateId, businessIds);

    // Try GetTemplateStatus with error codes
    std::vector<ClientTemplateStatus> statusList;
    client.GetTemplateStatus(userId, statusList);
}

// Main fuzz function
void FuzzCompanionDeviceAuthClientImpl(FuzzedDataProvider &fuzzData)
{
    using FuzzOp = void (*)(FuzzedDataProvider &);
    static const FuzzOp fuzzOps[] = {
        FuzzOp0,  // RegisterDeviceSelectCallback
        FuzzOp1,  // UnregisterDeviceSelectCallback
        FuzzOp2,  // UpdateTemplateEnabledBusinessIds
        FuzzOp3,  // GetTemplateStatus
        FuzzOp4,  // SubscribeTemplateStatusChange
        FuzzOp5,  // UnsubscribeTemplateStatusChange
        FuzzOp6,  // SubscribeAvailableDeviceStatus
        FuzzOp7,  // UnsubscribeAvailableDeviceStatus
        FuzzOp8,  // SubscribeContinuousAuthStatusChange
        FuzzOp9,  // UnsubscribeContinuousAuthStatusChange
        FuzzOp10, // CheckLocalUserIdValid
        FuzzOp11, // Null fetcher
        FuzzOp12, // Null remote object
        FuzzOp13, // Proxy caching test
        FuzzOp14, // Callback not found test
        FuzzOp15, // Multiple operations test
        FuzzOp16, // Repeated subscribe test
        FuzzOp17, // Subscribe-unsubscribe-subscribe pattern
        FuzzOp18, // Error code variations
    };
    constexpr size_t numOps = sizeof(fuzzOps) / sizeof(FuzzOp);

    // Select operation based on fuzz data
    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(UINT32_1, UINT32_10);
    for (uint32_t i = 0; i < loopCount && fuzzData.remaining_bytes() > 0; ++i) {
        size_t opIndex = fuzzData.ConsumeIntegralInRange<size_t>(0, numOps - 1);
        fuzzOps[opIndex](fuzzData);
    }
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(CompanionDeviceAuthClientImpl)

} // namespace UserIam
} // namespace OHOS
