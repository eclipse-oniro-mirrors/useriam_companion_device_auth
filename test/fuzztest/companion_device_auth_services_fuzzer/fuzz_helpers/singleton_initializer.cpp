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

#include "singleton_initializer.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "adapter_initializer.h"
#include "channel_adapter_initializer.h"
#include "companion_manager.h"
#include "cross_device_comm_manager.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "host_binding_manager.h"
#include "incoming_message_handler_registry.h"
#include "misc_manager.h"
#include "request_factory.h"
#include "request_manager.h"
#include "security_agent.h"
#include "singleton_manager.h"
#include "system_param_manager.h"
#include "task_runner_manager.h"
#include "user_auth_client_callback.h"
#include "user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
const size_t SIZE_100 = 100;
}

class MockCompanionManager : public ICompanionManager {
public:
    explicit MockCompanionManager(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    std::optional<CompanionStatus> GetCompanionStatus(TemplateId templateId) override
    {
        (void)templateId;
        if (fuzzData_.ConsumeBool()) {
            CompanionStatus status;
            // Fuzz the CompanionStatus structure
            status.templateId = fuzzData_.ConsumeIntegral<TemplateId>();
            status.hostUserId = fuzzData_.ConsumeIntegral<UserId>();
            status.companionDeviceStatus.deviceKey.deviceId = GenerateRandomString(fuzzData_);
            return std::optional<CompanionStatus>(status);
        }
        return std::optional<CompanionStatus>();
    }

    std::optional<CompanionStatus> GetCompanionStatus(UserId hostUserId, const DeviceKey &companionDeviceKey) override
    {
        (void)hostUserId;
        (void)companionDeviceKey;
        if (fuzzData_.ConsumeBool()) {
            CompanionStatus status;
            status.templateId = fuzzData_.ConsumeIntegral<TemplateId>();
            status.hostUserId = fuzzData_.ConsumeIntegral<UserId>();
            status.companionDeviceStatus.deviceKey.deviceId = GenerateRandomString(fuzzData_);
            return std::optional<CompanionStatus>(status);
        }
        return std::optional<CompanionStatus>();
    }

    std::vector<CompanionStatus> GetAllCompanionStatus() override
    {
        std::vector<CompanionStatus> statuses;
        size_t count = fuzzData_.ConsumeIntegralInRange<size_t>(0, 10);
        for (size_t i = 0; i < count; ++i) {
            CompanionStatus status;
            status.templateId = fuzzData_.ConsumeIntegral<TemplateId>();
            status.hostUserId = fuzzData_.ConsumeIntegral<UserId>();
            status.companionDeviceStatus.deviceKey.deviceId = GenerateRandomString(fuzzData_);
            statuses.push_back(status);
        }
        return statuses;
    }

    std::unique_ptr<Subscription> SubscribeCompanionDeviceStatusChange(
        OnCompanionDeviceStatusChange &&callback) override
    {
        (void)callback;
        return nullptr;
    }

    void UnsubscribeCompanionDeviceStatusChange(SubscribeId subscriptionId) override
    {
        (void)subscriptionId;
    }

    ResultCode BeginAddCompanion(const BeginAddCompanionParams &params,
        std::vector<uint8_t> &outAddHostBindingRequest) override
    {
        (void)params;
        outAddHostBindingRequest = fuzzData_.ConsumeBytes<uint8_t>(FUZZ_MAX_MESSAGE_LENGTH);
        return ResultCode::SUCCESS;
    }

    ResultCode EndAddCompanion(const EndAddCompanionInput &input, EndAddCompanionOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS) {
            size_t fwkMsgSize = fuzzData_.ConsumeIntegralInRange<size_t>(64, FUZZ_MAX_FWK_MESSAGE_LENGTH);
            output.fwkMsg = fuzzData_.ConsumeBytes<uint8_t>(fwkMsgSize);
            size_t tokenSize = fuzzData_.ConsumeIntegralInRange<size_t>(32, FUZZ_MAX_TOKEN_LENGTH);
            output.tokenData = fuzzData_.ConsumeBytes<uint8_t>(tokenSize);
            output.atl = fuzzData_.ConsumeIntegral<Atl>();
        }
        return result;
    }

    ResultCode RemoveCompanion(TemplateId templateId) override
    {
        (void)templateId;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode UpdateCompanionStatus(TemplateId templateId, const std::string &deviceName,
        const std::string &deviceUserName) override
    {
        (void)templateId;
        (void)deviceName;
        (void)deviceUserName;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode UpdateCompanionEnabledBusinessIds(TemplateId templateId,
        const std::vector<BusinessId> &enabledBusinessIds) override
    {
        (void)templateId;
        (void)enabledBusinessIds;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    bool SetCompanionTokenAtl(TemplateId templateId, std::optional<Atl> atl) override
    {
        (void)templateId;
        (void)atl;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0;
    }

    ResultCode UpdateToken(TemplateId templateId, const std::vector<uint8_t> &fwkMsg, bool &needRedistribute) override
    {
        (void)templateId;
        (void)fwkMsg;
        needRedistribute = fuzzData_.ConsumeBool();
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode HandleCompanionCheckFail(TemplateId templateId) override
    {
        (void)templateId;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    void StartIssueTokenRequests(const std::vector<TemplateId> &templateIds,
        const std::vector<uint8_t> &fwkUnlockMsg) override
    {
        (void)templateIds;
        (void)fwkUnlockMsg;
    }

    void NotifyCompanionStatusChange() override
    {
    }

    void HandleRemoveHostBindingComplete(TemplateId templateId) override
    {
        (void)templateId;
    }

private:
    bool Initialize() override
    {
        return true;
    }

    FuzzedDataProvider &fuzzData_;
};

class MockHostBindingManager : public IHostBindingManager {
public:
    explicit MockHostBindingManager(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    std::optional<HostBindingStatus> GetHostBindingStatus(BindingId bindingId) override
    {
        (void)bindingId;
        if (fuzzData_.ConsumeBool()) {
            HostBindingStatus status;
            status.bindingId = fuzzData_.ConsumeIntegral<BindingId>();
            status.companionUserId = fuzzData_.ConsumeIntegral<UserId>();
            status.hostDeviceStatus.deviceKey.deviceId = GenerateRandomString(fuzzData_);
            return std::optional<HostBindingStatus>(status);
        }
        return std::optional<HostBindingStatus>();
    }

    std::optional<HostBindingStatus> GetHostBindingStatus(UserId companionUserId,
        const DeviceKey &hostDeviceKey) override
    {
        (void)companionUserId;
        (void)hostDeviceKey;
        if (fuzzData_.ConsumeBool()) {
            HostBindingStatus status;
            status.bindingId = fuzzData_.ConsumeIntegral<BindingId>();
            status.companionUserId = fuzzData_.ConsumeIntegral<UserId>();
            status.hostDeviceStatus.deviceKey.deviceId = GenerateRandomString(fuzzData_);
            return std::optional<HostBindingStatus>(status);
        }
        return std::optional<HostBindingStatus>();
    }

    ResultCode BeginAddHostBinding(RequestId requestId, UserId companionUserId, SecureProtocolId secureProtocolId,
        const std::vector<uint8_t> &addHostBindingRequest, std::vector<uint8_t> &outAddHostBindingReply) override
    {
        (void)requestId;
        (void)companionUserId;
        (void)secureProtocolId;
        (void)addHostBindingRequest;
        outAddHostBindingReply = fuzzData_.ConsumeBytes<uint8_t>(FUZZ_MAX_MESSAGE_LENGTH);
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode EndAddHostBinding(RequestId requestId, ResultCode resultCode,
        const std::vector<uint8_t> &tokenData = {}) override
    {
        (void)requestId;
        (void)resultCode;
        (void)tokenData;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode RemoveHostBinding(UserId companionUserId, const DeviceKey &hostDeviceKey) override
    {
        (void)companionUserId;
        (void)hostDeviceKey;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    bool SetHostBindingTokenValid(BindingId bindingId, bool isTokenValid) override
    {
        (void)bindingId;
        (void)isTokenValid;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0;
    }

    void StartObtainTokenRequests(UserId userId, const std::vector<uint8_t> &fwkUnlockMsg) override
    {
        (void)userId;
        (void)fwkUnlockMsg;
    }

    void RevokeTokens(UserId userId) override
    {
        (void)userId;
    }

private:
    bool Initialize() override
    {
        return true;
    }

    FuzzedDataProvider &fuzzData_;
};

class MockMiscManager : public IMiscManager {
public:
    explicit MockMiscManager(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    uint64_t GetNextGlobalId() override
    {
        return fuzzData_.ConsumeIntegral<uint64_t>();
    }

    bool SetDeviceSelectCallback(uint32_t tokenId, const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback) override
    {
        (void)tokenId;
        (void)deviceSelectCallback;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0;
    }

    bool GetDeviceDeviceSelectResult(uint32_t tokenId, SelectPurpose selectPurpose,
        DeviceSelectResultHandler &&resultHandler) override
    {
        (void)tokenId;
        (void)selectPurpose;
        if (resultHandler) {
            std::vector<DeviceKey> results;
            FillDeviceKeyVector(fuzzData_, results, SIZE_100);
            resultHandler(results);
        }
        return GenerateFuzzBool(fuzzData_);
    }

    void ClearDeviceSelectCallback(uint32_t tokenId) override
    {
        (void)tokenId;
    }

    std::optional<std::string> GetLocalUdid() override
    {
        return std::optional<std::string>();
    }

    bool CheckBusinessIds(const std::vector<BusinessId> &) override
    {
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0;
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
        if (callback && fuzzData_.ConsumeBool()) {
            std::string fuzzedValue = GenerateRandomString(fuzzData_);
            callback(fuzzedValue);
        }
        // Always return valid subscription to ensure initialization succeeds
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

    bool Initialize() override
    {
        // Always return true for stability
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
        if (callback) {
            UserId userId = fuzzData_.ConsumeIntegral<UserId>();
            TaskRunnerManager::GetInstance().PostTaskOnResident(
                [callback = std::move(callback), userId]() { callback(userId); });
        }
        // Always return valid subscription to ensure HostBindingManagerImpl::Initialize() succeeds
        return std::make_unique<Subscription>([] {});
    }

    bool IsUserIdValid(int32_t userId) override
    {
        (void)userId;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0;
    }

private:
    FuzzedDataProvider &fuzzData_ [[maybe_unused]];
};

class MockSecurityAgent : public ISecurityAgent {
public:
    explicit MockSecurityAgent(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    ResultCode Init() override
    {
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode SetActiveUser(const SetActiveUserInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode HostGetExecutorInfo([[maybe_unused]] HostGetExecutorInfoOutput &output) override
    {
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            output.executorInfo.esl = fuzzData_.ConsumeIntegral<int32_t>();
            output.executorInfo.maxTemplateAcl = fuzzData_.ConsumeIntegral<uint32_t>();
            size_t keySize = fuzzData_.ConsumeIntegralInRange<size_t>(32, 256);
            output.executorInfo.publicKey = fuzzData_.ConsumeBytes<uint8_t>(keySize);
        }
        return result;
    }

    ResultCode HostOnRegisterFinish(const RegisterFinishInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode HostGetPersistedCompanionStatus(const HostGetPersistedCompanionStatusInput &input,
        [[maybe_unused]] HostGetPersistedCompanionStatusOutput &output) override
    {
        (void)input;
        size_t companionCount = fuzzData_.ConsumeIntegralInRange<size_t>(0, 10);
        for (size_t i = 0; i < companionCount; ++i) {
            PersistedCompanionStatus status;
            status.templateId = fuzzData_.ConsumeIntegral<TemplateId>();
            status.hostUserId = fuzzData_.ConsumeIntegral<UserId>();
            status.companionDeviceKey.deviceId = GenerateRandomString(fuzzData_);
            output.companionStatusList.push_back(status);
        }
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode CompanionGetPersistedHostBindingStatus(const CompanionGetPersistedHostBindingStatusInput &input,
        [[maybe_unused]] CompanionGetPersistedHostBindingStatusOutput &output) override
    {
        (void)input;
        size_t bindingCount = fuzzData_.ConsumeIntegralInRange<size_t>(0, 10);
        for (size_t i = 0; i < bindingCount; ++i) {
            output.hostBindingStatusList.push_back(GenerateFuzzPersistedHostBindingStatus(fuzzData_));
        }
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode HostBeginCompanionCheck(const HostBeginCompanionCheckInput &input,
        HostBeginCompanionCheckOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS) {
            size_t saltSize = fuzzData_.ConsumeIntegralInRange<size_t>(8, FUZZ_MAX_SALT_LENGTH);
            output.salt = fuzzData_.ConsumeBytes<uint8_t>(saltSize);
            output.challenge = fuzzData_.ConsumeIntegral<uint64_t>();
        }
        return result;
    }

    ResultCode HostEndCompanionCheck(const HostEndCompanionCheckInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode HostCancelCompanionCheck(const HostCancelCompanionCheckInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode CompanionProcessCheck(const CompanionProcessCheckInput &input,
        CompanionProcessCheckOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t respSize = fuzzData_.ConsumeIntegralInRange<size_t>(16, FUZZ_MAX_RESPONSE_LENGTH);
            output.companionCheckResponse = fuzzData_.ConsumeBytes<uint8_t>(respSize);
        }
        return result;
    }

    ResultCode HostGetInitKeyNegotiationRequest(const HostGetInitKeyNegotiationRequestInput &input,
        HostGetInitKeyNegotiationRequestOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t msgSize = fuzzData_.ConsumeIntegralInRange<size_t>(256, FUZZ_MAX_LARGE_MESSAGE_LENGTH);
            output.initKeyNegotiationRequest = fuzzData_.ConsumeBytes<uint8_t>(msgSize);
        }
        return result;
    }

    ResultCode HostBeginAddCompanion(const HostBeginAddCompanionInput &input,
        HostBeginAddCompanionOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t msgSize = fuzzData_.ConsumeIntegralInRange<size_t>(64, FUZZ_MAX_MESSAGE_LENGTH);
            output.addHostBindingRequest = fuzzData_.ConsumeBytes<uint8_t>(msgSize);
        }
        return result;
    }

    ResultCode HostEndAddCompanion(const HostEndAddCompanionInput &input, HostEndAddCompanionOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS) {
            size_t fwkMsgSize = fuzzData_.ConsumeIntegralInRange<size_t>(64, FUZZ_MAX_FWK_MESSAGE_LENGTH);
            output.fwkMsg = fuzzData_.ConsumeBytes<uint8_t>(fwkMsgSize);
            output.templateId = fuzzData_.ConsumeIntegral<TemplateId>();
            size_t tokenSize = fuzzData_.ConsumeIntegralInRange<size_t>(32, FUZZ_MAX_TOKEN_LENGTH);
            output.tokenData = fuzzData_.ConsumeBytes<uint8_t>(tokenSize);
        }
        return result;
    }

    ResultCode HostCancelAddCompanion(const HostCancelAddCompanionInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode CompanionInitKeyNegotiation(const CompanionInitKeyNegotiationInput &input,
        CompanionInitKeyNegotiationOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            output.requestId = fuzzData_.ConsumeIntegral<RequestId>();
            size_t msgSize = fuzzData_.ConsumeIntegralInRange<size_t>(256, FUZZ_MAX_LARGE_MESSAGE_LENGTH);
            output.initKeyNegotiationReply = fuzzData_.ConsumeBytes<uint8_t>(msgSize);
        }
        return result;
    }

    ResultCode CompanionBeginAddHostBinding(const CompanionBeginAddHostBindingInput &input,
        CompanionBeginAddHostBindingOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS) {
            size_t msgSize = fuzzData_.ConsumeIntegralInRange<size_t>(64, FUZZ_MAX_MESSAGE_LENGTH);
            output.addHostBindingReply = fuzzData_.ConsumeBytes<uint8_t>(msgSize);
            if (fuzzData_.ConsumeBool()) {
                output.replacedBindingId = fuzzData_.ConsumeIntegral<BindingId>();
            }
            // hostBindingStatus is PersistedHostBindingStatus, fill its fields directly
            output.hostBindingStatus.bindingId = fuzzData_.ConsumeIntegral<BindingId>();
            output.hostBindingStatus.companionUserId = fuzzData_.ConsumeIntegral<UserId>();
            output.hostBindingStatus.hostDeviceKey.deviceId = GenerateRandomString(fuzzData_);
            output.hostBindingStatus.isTokenValid = fuzzData_.ConsumeBool();
        }
        return result;
    }

    ResultCode CompanionEndAddHostBinding(const CompanionEndAddHostBindingInput &input,
        CompanionEndAddHostBindingOutput &output) override
    {
        (void)input;
        output.bindingId = fuzzData_.ConsumeIntegral<BindingId>();
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode HostRemoveCompanion(const HostRemoveCompanionInput &input, HostRemoveCompanionOutput &output) override
    {
        (void)input;
        output.userId = fuzzData_.ConsumeIntegral<UserId>();
        output.companionDeviceKey.deviceId = GenerateRandomString(fuzzData_);
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode CompanionRemoveHostBinding(const CompanionRemoveHostBindingInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode HostBeginDelegateAuth(const HostBeginDelegateAuthInput &input,
        HostBeginDelegateAuthOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t msgSize = fuzzData_.ConsumeIntegralInRange<size_t>(64, FUZZ_MAX_MESSAGE_LENGTH);
            output.startDelegateAuthRequest = fuzzData_.ConsumeBytes<uint8_t>(msgSize);
        }
        return result;
    }

    ResultCode HostEndDelegateAuth(const HostEndDelegateAuthInput &input, HostEndDelegateAuthOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t msgSize = fuzzData_.ConsumeIntegralInRange<size_t>(64, FUZZ_MAX_MESSAGE_LENGTH);
            output.fwkMsg = fuzzData_.ConsumeBytes<uint8_t>(msgSize);
            output.authType = static_cast<AuthType>(fuzzData_.ConsumeIntegral<uint32_t>());
            // Note: Atl is a complex type, minimal initialization for fuzz testing
        }
        return result;
    }

    ResultCode HostCancelDelegateAuth(const HostCancelDelegateAuthInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode CompanionBeginDelegateAuth(const CompanionDelegateAuthBeginInput &input,
        CompanionDelegateAuthBeginOutput &output) override
    {
        (void)input;
        output.challenge = fuzzData_.ConsumeIntegral<uint64_t>();
        // Note: Atl is a complex type, minimal initialization for fuzz testing
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode CompanionEndDelegateAuth(const CompanionDelegateAuthEndInput &input,
        CompanionDelegateAuthEndOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t respSize = fuzzData_.ConsumeIntegralInRange<size_t>(16, FUZZ_MAX_RESPONSE_LENGTH);
            output.delegateAuthResult = fuzzData_.ConsumeBytes<uint8_t>(respSize);
        }
        return result;
    }

    ResultCode HostPreIssueToken(const HostPreIssueTokenInput &input, HostPreIssueTokenOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t tokenSize = fuzzData_.ConsumeIntegralInRange<size_t>(32, FUZZ_MAX_TOKEN_LENGTH);
            output.preIssueTokenRequest = fuzzData_.ConsumeBytes<uint8_t>(tokenSize);
        }
        return result;
    }

    ResultCode HostBeginIssueToken(const HostBeginIssueTokenInput &input, HostBeginIssueTokenOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t tokenSize = fuzzData_.ConsumeIntegralInRange<size_t>(32, FUZZ_MAX_TOKEN_LENGTH);
            output.issueTokenRequest = fuzzData_.ConsumeBytes<uint8_t>(tokenSize);
        }
        return result;
    }

    ResultCode HostEndIssueToken(const HostEndIssueTokenInput &input, HostEndIssueTokenOutput &output) override
    {
        (void)input;
        (void)output;
        // Note: Atl is a complex type, minimal initialization for fuzz testing
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode HostCancelIssueToken(const HostCancelIssueTokenInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode CompanionPreIssueToken(const CompanionPreIssueTokenInput &input,
        CompanionPreIssueTokenOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t tokenSize = fuzzData_.ConsumeIntegralInRange<size_t>(32, FUZZ_MAX_TOKEN_LENGTH);
            output.preIssueTokenReply = fuzzData_.ConsumeBytes<uint8_t>(tokenSize);
        }
        return result;
    }

    ResultCode CompanionProcessIssueToken(const CompanionProcessIssueTokenInput &input,
        CompanionProcessIssueTokenOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t tokenSize = fuzzData_.ConsumeIntegralInRange<size_t>(32, FUZZ_MAX_TOKEN_LENGTH);
            output.issueTokenReply = fuzzData_.ConsumeBytes<uint8_t>(tokenSize);
        }
        return result;
    }

    ResultCode CompanionCancelIssueToken(const CompanionCancelIssueTokenInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode HostProcessPreObtainToken(const HostProcessPreObtainTokenInput &input,
        HostProcessPreObtainTokenOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t tokenSize = fuzzData_.ConsumeIntegralInRange<size_t>(32, FUZZ_MAX_TOKEN_LENGTH);
            output.preObtainTokenReply = fuzzData_.ConsumeBytes<uint8_t>(tokenSize);
        }
        return result;
    }

    ResultCode HostProcessObtainToken(const HostProcessObtainTokenInput &input,
        HostProcessObtainTokenOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t tokenSize = fuzzData_.ConsumeIntegralInRange<size_t>(32, FUZZ_MAX_TOKEN_LENGTH);
            output.obtainTokenReply = fuzzData_.ConsumeBytes<uint8_t>(tokenSize);
        }
        return result;
    }

    ResultCode HostCancelObtainToken(const HostCancelObtainTokenInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode CompanionBeginObtainToken(const CompanionBeginObtainTokenInput &input,
        CompanionBeginObtainTokenOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t tokenSize = fuzzData_.ConsumeIntegralInRange<size_t>(32, FUZZ_MAX_TOKEN_LENGTH);
            output.obtainTokenRequest = fuzzData_.ConsumeBytes<uint8_t>(tokenSize);
        }
        return result;
    }

    ResultCode CompanionEndObtainToken(const CompanionEndObtainTokenInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode CompanionCancelObtainToken(const CompanionCancelObtainTokenInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode HostBeginTokenAuth(const HostBeginTokenAuthInput &input, HostBeginTokenAuthOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t respSize = fuzzData_.ConsumeIntegralInRange<size_t>(16, FUZZ_MAX_RESPONSE_LENGTH);
            output.tokenAuthRequest = fuzzData_.ConsumeBytes<uint8_t>(respSize);
        }
        return result;
    }

    ResultCode HostEndTokenAuth(const HostEndTokenAuthInput &input, HostEndTokenAuthOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t fwkMsgSize = fuzzData_.ConsumeIntegralInRange<size_t>(64, FUZZ_MAX_FWK_MESSAGE_LENGTH);
            output.fwkMsg = fuzzData_.ConsumeBytes<uint8_t>(fwkMsgSize);
        }
        return result;
    }

    ResultCode HostUpdateToken(const HostUpdateTokenInput &input, HostUpdateTokenOutput &output) override
    {
        (void)input;
        (void)output;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode CompanionProcessTokenAuth(const CompanionProcessTokenAuthInput &input,
        CompanionProcessTokenAuthOutput &output) override
    {
        (void)input;
        ResultCode result = static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
        if (result == ResultCode::SUCCESS && fuzzData_.ConsumeBool()) {
            size_t respSize = fuzzData_.ConsumeIntegralInRange<size_t>(16, FUZZ_MAX_RESPONSE_LENGTH);
            output.tokenAuthReply = fuzzData_.ConsumeBytes<uint8_t>(respSize);
        }
        return result;
    }

    ResultCode HostUpdateCompanionStatus(const HostUpdateCompanionStatusInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode HostUpdateCompanionEnabledBusinessIds(const HostUpdateCompanionEnabledBusinessIdsInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode HostCheckTemplateEnrolled(const HostCheckTemplateEnrolledInput &input,
        HostCheckTemplateEnrolledOutput &output) override
    {
        (void)input;
        (void)output;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode HostRevokeToken(const HostRevokeTokenInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

    ResultCode CompanionRevokeToken(const CompanionRevokeTokenInput &input) override
    {
        (void)input;
        return static_cast<ResultCode>(fuzzData_.ConsumeIntegral<uint32_t>());
    }

private:
    bool Initialize() override
    {
        return true;
    }

    FuzzedDataProvider &fuzzData_;
};

class MockCrossDeviceCommManager : public ICrossDeviceCommManager {
public:
    explicit MockCrossDeviceCommManager(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    bool Start() override
    {
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0;
    }

    std::unique_ptr<Subscription> SubscribeIsAuthMaintainActive(std::function<void(bool)> &&callback) override
    {
        if (callback && fuzzData_.ConsumeBool()) {
            bool isActive = fuzzData_.ConsumeBool();
            callback(isActive);
        }
        // Always return valid subscription to ensure initialization succeeds
        return std::make_unique<Subscription>([] {});
    }

    bool IsAuthMaintainActive() override
    {
        return fuzzData_.ConsumeBool();
    }

    LocalDeviceProfile GetLocalDeviceProfile() override
    {
        return LocalDeviceProfile();
    }

    std::optional<DeviceStatus> GetDeviceStatus(const DeviceKey &deviceKey) override
    {
        (void)deviceKey;
        return std::optional<DeviceStatus>();
    }

    std::vector<DeviceStatus> GetAllDeviceStatus() override
    {
        return std::vector<DeviceStatus>();
    }

    std::unique_ptr<Subscription> SubscribeAllDeviceStatus(OnDeviceStatusChange &&onDeviceStatusChange) override
    {
        if (onDeviceStatusChange && fuzzData_.ConsumeBool()) {
            std::vector<DeviceStatus> deviceStatuses;
            FillDeviceStatusVector(fuzzData_, deviceStatuses, SIZE_100);
            onDeviceStatusChange(deviceStatuses);
        }
        // Always return valid subscription to ensure initialization succeeds
        return std::make_unique<Subscription>([] {});
    }

    void SetSubscribeMode(SubscribeMode subscribeMode) override
    {
        (void)subscribeMode;
    }

    std::optional<SteadyTimeMs> GetManageSubscribeTime() const override
    {
        return std::optional<SteadyTimeMs>();
    }

    std::unique_ptr<Subscription> SubscribeDeviceStatus(const DeviceKey &deviceKey,
        OnDeviceStatusChange &&onDeviceStatusChange) override
    {
        (void)deviceKey;
        if (onDeviceStatusChange && fuzzData_.ConsumeBool()) {
            std::vector<DeviceStatus> deviceStatuses;
            FillDeviceStatusVector(fuzzData_, deviceStatuses, SIZE_100);
            onDeviceStatusChange(deviceStatuses);
        }
        // Always return valid subscription to ensure initialization succeeds
        return std::make_unique<Subscription>([] {});
    }

    bool OpenConnection(const DeviceKey &deviceKey, std::string &outConnectionName) override
    {
        (void)deviceKey;
        // Generate fuzzed connection name
        outConnectionName = "connection_" + GenerateRandomString(fuzzData_);
        return GenerateFuzzBool(fuzzData_);
    }

    void CloseConnection(const std::string &connectionName) override
    {
        (void)connectionName;
    }

    bool IsConnectionOpen(const std::string &connectionName) override
    {
        (void)connectionName;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0;
    }

    ConnectionStatus GetConnectionStatus(const std::string &connectionName) override
    {
        (void)connectionName;
        return ConnectionStatus::DISCONNECTED;
    }

    std::optional<DeviceKey> GetLocalDeviceKeyByConnectionName(const std::string &connectionName) override
    {
        (void)connectionName;
        return std::optional<DeviceKey>();
    }

    std::unique_ptr<Subscription> SubscribeConnectionStatus(const std::string &connectionName,
        OnConnectionStatusChange &&onConnectionStatusChange) override
    {
        if (onConnectionStatusChange && fuzzData_.ConsumeBool()) {
            ConnectionStatus status = static_cast<ConnectionStatus>(fuzzData_.ConsumeIntegral<uint32_t>());
            std::string reason = GenerateRandomString(fuzzData_);
            TaskRunnerManager::GetInstance().PostTaskOnResident(
                [onConnectionStatusChange = std::move(onConnectionStatusChange), connectionName, status, reason]() {
                    onConnectionStatusChange(connectionName, status, reason);
                });
        }
        // Always return valid subscription to ensure initialization succeeds
        return std::make_unique<Subscription>([] {});
    }

    std::unique_ptr<Subscription> SubscribeIncomingConnection(MessageType msgType, OnMessage &&onMessage) override
    {
        (void)msgType;
        if (onMessage && fuzzData_.ConsumeBool()) {
            Attributes message = GenerateFuzzAttributes(fuzzData_);
            OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
            onMessage(message, onMessageReply);
        }
        // Always return valid subscription to ensure initialization succeeds
        return std::make_unique<Subscription>([] {});
    }

    bool SendMessage(const std::string &connectionName, MessageType msgType, Attributes &request,
        OnMessageReply &&onMessageReply) override
    {
        (void)connectionName;
        (void)msgType;
        (void)request;
        // Call the reply callback with fuzzed data
        if (onMessageReply) {
            Attributes reply = GenerateFuzzAttributes(fuzzData_);
            onMessageReply(reply);
        }
        return GenerateFuzzBool(fuzzData_);
    }

    std::unique_ptr<Subscription> SubscribeMessage(const std::string &connectionName, MessageType msgType,
        OnMessage &&onMessage) override
    {
        (void)connectionName;
        (void)msgType;
        if (onMessage && fuzzData_.ConsumeBool()) {
            Attributes message = GenerateFuzzAttributes(fuzzData_);
            OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
            onMessage(message, onMessageReply);
        }
        // Always return valid subscription to ensure initialization succeeds
        return std::make_unique<Subscription>([] {});
    }

    bool CheckOperationIntent(const DeviceKey &deviceKey, uint32_t tokenId,
        OnCheckOperationIntentResult &&resultCallback) override
    {
        (void)deviceKey;
        (void)tokenId;
        // Call the result callback with fuzzed data
        if (resultCallback) {
            bool result = GenerateFuzzBool(fuzzData_);
            resultCallback(result);
        }
        return GenerateFuzzBool(fuzzData_);
    }

    std::optional<SecureProtocolId> HostGetSecureProtocolId(const DeviceKey &companionDeviceKey) override
    {
        (void)companionDeviceKey;
        return std::optional<SecureProtocolId>();
    }

    SecureProtocolId CompanionGetSecureProtocolId() override
    {
        return GenerateFuzzSecureProtocolId(fuzzData_);
    }

private:
    FuzzedDataProvider &fuzzData_ [[maybe_unused]];
};

class MockFuzzIRequest : public IRequest {
public:
    explicit MockFuzzIRequest(FuzzedDataProvider &fuzzData, RequestId requestId, ScheduleId scheduleId)
        : fuzzData_(fuzzData),
          requestId_(requestId),
          scheduleId_(scheduleId)
    {
    }

    void Start() override
    {
    }

    bool Cancel(ResultCode resultCode) override
    {
        (void)resultCode;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0;
    }

    RequestType GetRequestType() const override
    {
        uint32_t leftRange = 0;
        uint32_t rightRange = 100;
        return static_cast<RequestType>(fuzzData_.ConsumeIntegralInRange<uint32_t>(leftRange, rightRange));
    }

    const char *GetDescription() const override
    {
        return "MockFuzzRequest";
    }

    RequestId GetRequestId() const override
    {
        return requestId_;
    }

    ScheduleId GetScheduleId() const override
    {
        return scheduleId_;
    }

    std::optional<DeviceKey> GetPeerDeviceKey() const override
    {
        return std::optional<DeviceKey>();
    }

    uint32_t GetMaxConcurrency() const override
    {
        uint32_t leftRange = 1;
        uint32_t rightRange = 10;
        return fuzzData_.ConsumeIntegralInRange<uint32_t>(leftRange, rightRange);
    }

    bool ShouldCancelOnNewRequest(RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice,
        uint32_t subsequentSameTypeCount) const override
    {
        (void)newRequestType;
        (void)newPeerDevice;
        (void)subsequentSameTypeCount;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0;
    }

private:
    FuzzedDataProvider &fuzzData_;
    RequestId requestId_;
    ScheduleId scheduleId_;
};

class MockRequestManager : public IRequestManager {
public:
    explicit MockRequestManager(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    bool Start(const std::shared_ptr<IRequest> &request) override
    {
        if (!request) {
            return false;
        }
        if (fuzzData_.ConsumeIntegral<uint32_t>() > 0) {
            requestStorage_[request->GetRequestId()] = request;
            return true;
        }
        return false;
    }

    bool Cancel(RequestId requestId) override
    {
        if (fuzzData_.ConsumeIntegral<uint32_t>() > 0) {
            auto it = requestStorage_.find(requestId);
            if (it != requestStorage_.end()) {
                return it->second->Cancel(ResultCode::SUCCESS);
            }
            return true;
        }
        return false;
    }

    bool CancelRequestByScheduleId(ScheduleId scheduleId) override
    {
        (void)scheduleId;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0;
    }

    void CancelAll() override
    {
        requestStorage_.clear();
    }

    void Remove(RequestId requestId) override
    {
        requestStorage_.erase(requestId);
    }

    std::shared_ptr<IRequest> Get(RequestId requestId) const override
    {
        // Only return stored requests, don't modify state
        auto it = requestStorage_.find(requestId);
        return (it != requestStorage_.end()) ? it->second : nullptr;
    }

private:
    FuzzedDataProvider &fuzzData_;
    std::map<RequestId, std::shared_ptr<IRequest>> requestStorage_;
};

class MockRequestFactory : public IRequestFactory {
public:
    explicit MockRequestFactory(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData), requestCounter_(0)
    {
    }

    std::shared_ptr<IRequest> CreateHostAddCompanionRequest(ScheduleId scheduleId, const std::vector<uint8_t> &fwkMsg,
        uint32_t tokenId, FwkResultCallback &&requestCallback) override
    {
        (void)fwkMsg;
        (void)tokenId;
        (void)requestCallback;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0
            ? std::make_shared<MockFuzzIRequest>(fuzzData_, requestCounter_++, scheduleId)
            : nullptr;
    }

    std::shared_ptr<IRequest> CreateHostTokenAuthRequest(ScheduleId scheduleId, const std::vector<uint8_t> &fwkMsg,
        UserId hostUserId, TemplateId templateId, FwkResultCallback &&requestCallback) override
    {
        (void)fwkMsg;
        (void)hostUserId;
        (void)templateId;
        (void)requestCallback;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0
            ? std::make_shared<MockFuzzIRequest>(fuzzData_, requestCounter_++, scheduleId)
            : nullptr;
    }

    std::shared_ptr<IRequest> CreateHostRemoveHostBindingRequest(UserId hostUserId, TemplateId templateId,
        const DeviceKey &companionDeviceKey) override
    {
        (void)hostUserId;
        (void)templateId;
        (void)companionDeviceKey;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0
            ? std::make_shared<MockFuzzIRequest>(fuzzData_, requestCounter_++, 0)
            : nullptr;
    }

    std::shared_ptr<IRequest> CreateHostSyncDeviceStatusRequest(UserId hostUserId, const DeviceKey &companionDeviceKey,
        const std::string &companionDeviceName, SyncDeviceStatusCallback &&callback) override
    {
        (void)hostUserId;
        (void)companionDeviceKey;
        (void)companionDeviceName;
        (void)callback;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0
            ? std::make_shared<MockFuzzIRequest>(fuzzData_, requestCounter_++, 0)
            : nullptr;
    }

    std::shared_ptr<IRequest> CreateHostIssueTokenRequest(UserId hostUserId, TemplateId templateId,
        const std::vector<uint8_t> &fwkUnlockMsg) override
    {
        (void)hostUserId;
        (void)templateId;
        (void)fwkUnlockMsg;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0
            ? std::make_shared<MockFuzzIRequest>(fuzzData_, requestCounter_++, 0)
            : nullptr;
    }

    std::shared_ptr<IRequest> CreateHostDelegateAuthRequest(ScheduleId scheduleId, const std::vector<uint8_t> &fwkMsg,
        UserId hostUserId, TemplateId templateId, FwkResultCallback &&requestCallback) override
    {
        (void)fwkMsg;
        (void)hostUserId;
        (void)templateId;
        (void)requestCallback;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0
            ? std::make_shared<MockFuzzIRequest>(fuzzData_, requestCounter_++, scheduleId)
            : nullptr;
    }

    std::shared_ptr<IRequest> CreateCompanionAddCompanionRequest(const std::string &connectionName,
        const Attributes &request, OnMessageReply replyCallback, const DeviceKey &hostDeviceKey) override
    {
        (void)connectionName;
        (void)request;
        (void)replyCallback;
        (void)hostDeviceKey;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0
            ? std::make_shared<MockFuzzIRequest>(fuzzData_, requestCounter_++, 0)
            : nullptr;
    }

    std::shared_ptr<IRequest> CreateCompanionIssueTokenRequest(const std::string &connectionName,
        const Attributes &request, OnMessageReply replyCallback, const DeviceKey &hostDeviceKey) override
    {
        (void)connectionName;
        (void)request;
        (void)replyCallback;
        (void)hostDeviceKey;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0
            ? std::make_shared<MockFuzzIRequest>(fuzzData_, requestCounter_++, 0)
            : nullptr;
    }

    std::shared_ptr<IRequest> CreateHostObtainTokenRequest(const std::string &connectionName, const Attributes &request,
        OnMessageReply replyCallback, const DeviceKey &companionDeviceKey) override
    {
        (void)connectionName;
        (void)request;
        (void)replyCallback;
        (void)companionDeviceKey;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0
            ? std::make_shared<MockFuzzIRequest>(fuzzData_, requestCounter_++, 0)
            : nullptr;
    }

    std::shared_ptr<IRequest> CreateCompanionObtainTokenRequest(const DeviceKey &hostDeviceKey,
        const std::vector<uint8_t> &fwkUnlockMsg) override
    {
        (void)hostDeviceKey;
        (void)fwkUnlockMsg;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0
            ? std::make_shared<MockFuzzIRequest>(fuzzData_, requestCounter_++, 0)
            : nullptr;
    }

    std::shared_ptr<IRequest> CreateCompanionDelegateAuthRequest(const std::string &connectionName,
        UserId companionUserId, const DeviceKey &hostDeviceKey,
        const std::vector<uint8_t> &startDelegateAuthRequest) override
    {
        (void)connectionName;
        (void)companionUserId;
        (void)hostDeviceKey;
        (void)startDelegateAuthRequest;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0
            ? std::make_shared<MockFuzzIRequest>(fuzzData_, requestCounter_++, 0)
            : nullptr;
    }

    std::shared_ptr<IRequest> CreateCompanionRevokeTokenRequest(UserId companionUserId,
        const DeviceKey &hostDeviceKey) override
    {
        (void)companionUserId;
        (void)hostDeviceKey;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0
            ? std::make_shared<MockFuzzIRequest>(fuzzData_, requestCounter_++, 0)
            : nullptr;
    }

    std::shared_ptr<IRequest> CreateHostMixAuthRequest(ScheduleId scheduleId, std::vector<uint8_t> fwkMsg,
        UserId hostUserId, std::vector<TemplateId> templateIdList, FwkResultCallback &&requestCallback) override
    {
        (void)fwkMsg;
        (void)hostUserId;
        (void)templateIdList;
        (void)requestCallback;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0
            ? std::make_shared<MockFuzzIRequest>(fuzzData_, requestCounter_++, scheduleId)
            : nullptr;
    }

    std::shared_ptr<IRequest> CreateHostSingleMixAuthRequest(ScheduleId scheduleId, std::vector<uint8_t> fwkMsg,
        UserId hostUserId, TemplateId templateId, FwkResultCallback &&requestCallback) override
    {
        (void)fwkMsg;
        (void)hostUserId;
        (void)templateId;
        (void)requestCallback;
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0
            ? std::make_shared<MockFuzzIRequest>(fuzzData_, requestCounter_++, scheduleId)
            : nullptr;
    }

private:
    FuzzedDataProvider &fuzzData_;
    uint32_t requestCounter_;
};

class MockIncomingMessageHandlerRegistry : public IncomingMessageHandlerRegistry {
public:
    explicit MockIncomingMessageHandlerRegistry(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    bool Initialize()
    {
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0;
    }

    void AddHandler(std::shared_ptr<IncomingMessageHandler> handler)
    {
        (void)handler;
    }

    bool RegisterHandlers()
    {
        return fuzzData_.ConsumeIntegral<uint32_t>() > 0;
    }

private:
    FuzzedDataProvider &fuzzData_ [[maybe_unused]];
};

// Singleton initializer functions
static bool InitCompanionManager(FuzzedDataProvider &fuzzData)
{
    auto companionMgr = std::make_shared<MockCompanionManager>(fuzzData);
    SingletonManager::GetInstance().SetCompanionManager(companionMgr);
    return true;
}

static bool InitHostBindingManager(FuzzedDataProvider &fuzzData)
{
    auto hostBindingMgr = std::make_shared<MockHostBindingManager>(fuzzData);
    SingletonManager::GetInstance().SetHostBindingManager(hostBindingMgr);
    return true;
}

static bool InitMiscManager(FuzzedDataProvider &fuzzData)
{
    auto miscMgr = std::make_shared<MockMiscManager>(fuzzData);
    SingletonManager::GetInstance().SetMiscManager(miscMgr);
    return true;
}

static bool InitSystemParamManager(FuzzedDataProvider &fuzzData)
{
    auto systemParamMgr = std::make_shared<MockSystemParamManager>(fuzzData);
    SingletonManager::GetInstance().SetSystemParamManager(systemParamMgr);
    return true;
}

static bool InitUserIdManager(FuzzedDataProvider &fuzzData)
{
    auto activeUserIdMgr = std::make_shared<MockUserIdManager>(fuzzData);
    SingletonManager::GetInstance().SetUserIdManager(activeUserIdMgr);
    return true;
}

static bool InitSecurityAgent(FuzzedDataProvider &fuzzData)
{
    auto securityAgent = std::make_shared<MockSecurityAgent>(fuzzData);
    SingletonManager::GetInstance().SetSecurityAgent(securityAgent);
    return true;
}

static bool InitCrossDeviceCommManager(FuzzedDataProvider &fuzzData)
{
    auto crossDeviceCommMgr = std::make_shared<MockCrossDeviceCommManager>(fuzzData);
    SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);
    return true;
}

static bool InitRequestManager(FuzzedDataProvider &fuzzData)
{
    auto requestMgr = std::make_shared<MockRequestManager>(fuzzData);
    SingletonManager::GetInstance().SetRequestManager(requestMgr);
    return true;
}

static bool InitRequestFactory(FuzzedDataProvider &fuzzData)
{
    auto requestFactory = std::make_shared<MockRequestFactory>(fuzzData);
    SingletonManager::GetInstance().SetRequestFactory(requestFactory);
    return true;
}

static bool InitIncomingMessageHandlerRegistry(FuzzedDataProvider &fuzzData)
{
    auto messageHandlerRegistry = std::make_shared<MockIncomingMessageHandlerRegistry>(fuzzData);
    SingletonManager::GetInstance().SetIncomingMessageHandlerRegistry(messageHandlerRegistry);
    return true;
}

// Singleton cleanup functions
static void ResetSingletonManagerRegistry()
{
    SingletonManager::GetInstance().Reset();
}

bool InitializeSingletonManager(FuzzedDataProvider &fuzzData)
{
    // Use registry to initialize all singletons
    return SingletonInitRegistry::InitializeAll(fuzzData);
}

void CleanupSingletonManager()
{
    // Use registry to cleanup all singletons (in reverse order)
    SingletonCleanupRegistry::CleanupAll();
}

// Auto-register all singleton initializers and cleanup functions
namespace {
static const bool g_singletonInitializersRegistered = []() {
    // Register initializers in order
    REGISTER_SINGLETON_INIT(CompanionManager);
    REGISTER_SINGLETON_INIT(HostBindingManager);
    REGISTER_SINGLETON_INIT(MiscManager);
    REGISTER_SINGLETON_INIT(SystemParamManager);
    REGISTER_SINGLETON_INIT(UserIdManager);
    REGISTER_SINGLETON_INIT(SecurityAgent);
    REGISTER_SINGLETON_INIT(CrossDeviceCommManager);
    REGISTER_SINGLETON_INIT(RequestManager);
    REGISTER_SINGLETON_INIT(RequestFactory);
    REGISTER_SINGLETON_INIT(IncomingMessageHandlerRegistry);

    SingletonCleanupRegistry::Register(ResetSingletonManagerRegistry);

    return true;
}();
} // namespace

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
