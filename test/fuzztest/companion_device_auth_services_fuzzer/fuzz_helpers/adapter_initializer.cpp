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

#include "adapter_initializer.h"

#include <memory>
#include <string>

#include "fuzzer/FuzzedDataProvider.h"

#include "device_manager_adapter.h"
#include "ipc_object_stub.h"
#include "system_ability_status_change_stub.h"

#include "access_token_kit_adapter.h"
#include "adapter_manager.h"
#include "driver_manager_adapter.h"
#include "event_manager_adapter.h"
#include "fuzz_data_generator.h"
#include "idm_adapter.h"
#include "sa_manager_adapter.h"
#include "security_command_adapter.h"
#include "service_common.h"
#include "soft_bus_adapter.h"
#include "soft_bus_adapter_manager.h"
#include "subscription.h"
#include "system_param_manager.h"
#include "time_keeper.h"
#include "user_auth_adapter.h"
#include "user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Mock Adapter classes for dependency injection during fuzzing

class MockDriverManagerAdapter : public IDriverManagerAdapter {
public:
    explicit MockDriverManagerAdapter(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    bool Start(std::shared_ptr<CompanionDeviceAuthDriver> driver) override
    {
        (void)driver;
        return fuzzData_.ConsumeBool();
    }

private:
    FuzzedDataProvider &fuzzData_ [[maybe_unused]];
};

class MockSoftBusAdapter : public ISoftBusAdapter {
public:
    explicit MockSoftBusAdapter(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    void RegisterCallback(const std::shared_ptr<ISoftBusSocketCallback> &callback) override
    {
        (void)callback;
    }

    std::optional<SocketId> CreateServerSocket() override
    {
        if (fuzzData_.ConsumeBool()) {
            return fuzzData_.ConsumeIntegral<SocketId>();
        }
        return std::optional<SocketId>();
    }

    std::optional<SocketId> CreateClientSocket(const std::string &connectionName, const std::string &networkId) override
    {
        (void)connectionName;
        (void)networkId;
        if (fuzzData_.ConsumeBool()) {
            return fuzzData_.ConsumeIntegral<SocketId>();
        }
        return std::optional<SocketId>();
    }

    bool SendBytes(int32_t socketId, const std::vector<uint8_t> &data) override
    {
        (void)socketId;
        (void)data;
        return fuzzData_.ConsumeBool();
    }

    void ShutdownSocket(int32_t socketId) override
    {
        (void)socketId;
    }

private:
    FuzzedDataProvider &fuzzData_ [[maybe_unused]];
};

class MockAccessTokenKitAdapter : public IAccessTokenKitAdapter {
public:
    explicit MockAccessTokenKitAdapter(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    bool CheckPermission(IPCObjectStub &stub, const std::string &permissionName) override
    {
        (void)stub;
        (void)permissionName;
        return fuzzData_.ConsumeBool();
    }

    bool CheckSystemPermission(IPCObjectStub &stub) override
    {
        (void)stub;
        return fuzzData_.ConsumeBool();
    }

    uint32_t GetAccessTokenId(IPCObjectStub &stub) override
    {
        (void)stub;
        return fuzzData_.ConsumeIntegral<uint32_t>();
    }

private:
    FuzzedDataProvider &fuzzData_ [[maybe_unused]];
};

class MockUserAuthAdapter : public IUserAuthAdapter {
public:
    explicit MockUserAuthAdapter(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    uint64_t BeginDelegateAuth(uint32_t userId, const std::vector<uint8_t> &challenge, uint32_t authTrustLevel,
        AuthResultCallback callback) override
    {
        (void)userId;
        (void)challenge;
        (void)authTrustLevel;
        (void)callback;
        return fuzzData_.ConsumeIntegral<uint64_t>();
    }

    int32_t CancelAuthentication(uint64_t contextId) override
    {
        (void)contextId;
        return fuzzData_.ConsumeIntegral<int32_t>();
    }

private:
    FuzzedDataProvider &fuzzData_ [[maybe_unused]];
};

class MockIdmAdapter : public IIdmAdapter {
public:
    explicit MockIdmAdapter(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    std::vector<uint64_t> GetUserTemplates(int32_t userId) override
    {
        (void)userId;
        std::vector<uint64_t> templateIds;
        if (fuzzData_.ConsumeBool()) {
            size_t count = fuzzData_.ConsumeIntegralInRange<size_t>(0, 10);
            for (size_t i = 0; i < count; ++i) {
                templateIds.push_back(fuzzData_.ConsumeIntegral<uint64_t>());
            }
        }
        return templateIds;
    }

    std::unique_ptr<Subscription> SubscribeUserTemplateChange(int32_t userId, TemplateChangeCallback callback) override
    {
        (void)userId;
        (void)callback;
        return std::make_unique<Subscription>([]() {});
    }

private:
    FuzzedDataProvider &fuzzData_ [[maybe_unused]];
};

class MockSaManagerAdapter : public ISaManagerAdapter {
public:
    explicit MockSaManagerAdapter(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    bool SubscribeSystemAbility(int32_t systemAbilityId, const sptr<SystemAbilityStatusChangeStub> &listener) override
    {
        (void)systemAbilityId;
        (void)listener;
        return fuzzData_.ConsumeBool();
    }

    bool UnSubscribeSystemAbility(int32_t systemAbilityId, const sptr<SystemAbilityStatusChangeStub> &listener) override
    {
        (void)systemAbilityId;
        (void)listener;
        return fuzzData_.ConsumeBool();
    }

private:
    FuzzedDataProvider &fuzzData_ [[maybe_unused]];
};

class MockEventManagerAdapter : public IEventManagerAdapter {
public:
    explicit MockEventManagerAdapter(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    void ReportSystemFault(const char *fileName, uint32_t lineNum, FaultType faultType, std::string &faultInfo) override
    {
        (void)fileName;
        (void)lineNum;
        (void)faultType;
        (void)faultInfo;
    }

private:
    FuzzedDataProvider &fuzzData_ [[maybe_unused]];
};

class MockDeviceManagerAdapter : public IDeviceManagerAdapter {
public:
    explicit MockDeviceManagerAdapter(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    bool InitDeviceManager() override
    {
        return fuzzData_.ConsumeBool();
    }

    void UnInitDeviceManager() override
    {
    }

    std::optional<std::string> GetUdidByNetworkId(const std::string &networkId) override
    {
        (void)networkId;
        if (fuzzData_.ConsumeBool()) {
            return GenerateRandomString(fuzzData_);
        }
        return std::optional<std::string>();
    }

    bool QueryTrustedDevices(std::vector<DmDeviceInfo> &deviceList) override
    {
        (void)deviceList;
        return fuzzData_.ConsumeBool();
    }

    bool RegisterDevStatusCallback(const std::shared_ptr<DmDeviceStatusCallback> &callback) override
    {
        (void)callback;
        return fuzzData_.ConsumeBool();
    }

    void UnRegisterDevStatusCallback(const std::shared_ptr<DmDeviceStatusCallback> &callback) override
    {
        (void)callback;
    }

private:
    FuzzedDataProvider &fuzzData_ [[maybe_unused]];
};

class MockSystemParamManager : public ISystemParamManager {
public:
    explicit MockSystemParamManager(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    std::string GetParam(const std::string &key, const std::string &defaultValue) override
    {
        (void)key;
        return defaultValue;
    }

    void SetParam(const std::string &key, const std::string &value) override
    {
        (void)key;
        (void)value;
    }

    void SetParamTwice(const std::string &key, const std::string &value1, const std::string &value2) override
    {
        (void)key;
        (void)value1;
        (void)value2;
    }

    std::unique_ptr<Subscription> WatchParam(const std::string &key, SystemParamCallback &&callback) override
    {
        (void)key;
        (void)callback;
        return std::make_unique<Subscription>([] {});
    }

    void OnParamChange(const std::string &key, const std::string &value) override
    {
        (void)key;
        (void)value;
    }

private:
    FuzzedDataProvider &fuzzData_ [[maybe_unused]];
};

class MockUserIdManager : public IUserIdManager {
public:
    explicit MockUserIdManager(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    bool Initialize()
    {
        return true;
    }

    UserId GetActiveUserId() const override
    {
        return 0;
    }

    std::string GetActiveUserName() const override
    {
        return "";
    }

    std::unique_ptr<Subscription> SubscribeActiveUserId(ActiveUserIdCallback &&callback) override
    {
        (void)callback;
        return std::make_unique<Subscription>([] {});
    }

    bool IsUserIdValid(int32_t userId) override
    {
        (void)userId;
        return fuzzData_.ConsumeBool();
    }

private:
    FuzzedDataProvider &fuzzData_ [[maybe_unused]];
};

class MockTimeKeeper : public ITimeKeeper {
public:
    MockTimeKeeper() : systemTimeMs_(0), steadyTimeMs_(0)
    {
    }

    std::optional<SystemTimeMs> GetSystemTimeMs() override
    {
        return systemTimeMs_;
    }

    std::optional<SteadyTimeMs> GetSteadyTimeMs() override
    {
        return steadyTimeMs_;
    }

private:
    SystemTimeMs systemTimeMs_;
    SteadyTimeMs steadyTimeMs_;
};

class MockSecurityCommandAdapter : public ISecurityCommandAdapter {
public:
    MockSecurityCommandAdapter() = default;

    ResultCode Initialize()
    {
        return ResultCode::SUCCESS;
    }

    ResultCode InvokeCommand(int32_t commandId, const uint8_t *inputData, uint32_t inputDataLen, uint8_t *outputData,
        uint32_t outputDataLen) override
    {
        (void)commandId;
        (void)inputData;
        (void)inputDataLen;
        (void)outputData;
        (void)outputDataLen;
        return ResultCode::SUCCESS;
    }
};

bool InitializeAdapterManager(FuzzedDataProvider &fuzzData)
{
    AdapterManager &adapterMgr = AdapterManager::GetInstance();

    auto driverMgr = std::make_shared<MockDriverManagerAdapter>(fuzzData);
    adapterMgr.SetDriverManagerAdapter(driverMgr);

    // Note: DeviceManagerAdapter and SoftBusAdapter are managed by SoftBusChannelAdapterManager
    auto softBusAdapter = std::make_shared<MockSoftBusAdapter>(fuzzData);
    SoftBusChannelAdapterManager::GetInstance().SetSoftBusAdapter(softBusAdapter);

    auto deviceMgrAdapter = std::make_shared<MockDeviceManagerAdapter>(fuzzData);
    SoftBusChannelAdapterManager::GetInstance().SetDeviceManagerAdapter(deviceMgrAdapter);

    auto accessTokenAdapter = std::make_shared<MockAccessTokenKitAdapter>(fuzzData);
    adapterMgr.SetAccessTokenKitAdapter(accessTokenAdapter);

    auto userAuthAdapter = std::make_shared<MockUserAuthAdapter>(fuzzData);
    adapterMgr.SetUserAuthAdapter(userAuthAdapter);

    auto idmAdapter = std::make_shared<MockIdmAdapter>(fuzzData);
    adapterMgr.SetIdmAdapter(idmAdapter);

    auto saMgrAdapter = std::make_shared<MockSaManagerAdapter>(fuzzData);
    adapterMgr.SetSaManagerAdapter(saMgrAdapter);

    auto eventMgrAdapter = std::make_shared<MockEventManagerAdapter>(fuzzData);
    adapterMgr.SetEventManagerAdapter(eventMgrAdapter);

    auto timeKeeper = std::make_shared<MockTimeKeeper>();
    adapterMgr.SetTimeKeeper(timeKeeper);

    auto securityCmdAdapter = std::make_shared<MockSecurityCommandAdapter>();
    adapterMgr.SetSecurityCommandAdapter(securityCmdAdapter);

    auto systemParamMgr = std::make_shared<MockSystemParamManager>(fuzzData);
    adapterMgr.SetSystemParamManager(systemParamMgr);

    auto userIdMgr = std::make_shared<MockUserIdManager>(fuzzData);
    adapterMgr.SetUserIdManager(userIdMgr);

    return true;
}

void CleanupAdapterManager()
{
    AdapterManager::GetInstance().Reset();
    SoftBusChannelAdapterManager::GetInstance().Reset();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
