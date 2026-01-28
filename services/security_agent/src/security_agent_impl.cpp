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
#include <cinttypes>
#include <cstdint>
#include <memory>
#include <utility>

#include "securec.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "common_defines.h"
#include "companion_device_auth_ffi.h"
#include "companion_device_auth_ffi_util.h"
#include "security_agent_imp.h"
#include "singleton_manager.h"

#include "adapter_manager.h"

#undef LOG_TAG
#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
SecurityAgentImpl::SecurityAgentImpl()
{
}

std::shared_ptr<ISecurityAgent> SecurityAgentImpl::Create()
{
    auto impl = std::shared_ptr<SecurityAgentImpl>(new (std::nothrow) SecurityAgentImpl());
    ENSURE_OR_RETURN_VAL(impl != nullptr, nullptr);
    impl->Initialize();
    impl->Init();
    return impl;
}

bool SecurityAgentImpl::Initialize()
{
    auto &userIdManager = GetUserIdManager();
    auto activeUserSubscription_ = userIdManager.SubscribeActiveUserId([this](UserId userId) {
        auto result = SetActiveUser(SetActiveUserInput { userId });
        if (result != SUCCESS) {
            IAM_LOGE("failed to update active user %{public}d", result);
        }
    });
    ENSURE_OR_RETURN_VAL(activeUserSubscription_ != nullptr, false);

    auto result = SetActiveUser(SetActiveUserInput { userIdManager.GetActiveUserId() });
    ENSURE_OR_RETURN_VAL(result == SUCCESS, false);

    return true;
}

ResultCode SecurityAgentImpl::Init()
{
    auto ffiInput = std::make_unique<InitInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);

    auto ffiOutput = std::make_unique<InitOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult =
        GetSecurityCommandAdapter().InvokeCommand(CommandId::INIT, reinterpret_cast<uint8_t *>(ffiInput.get()),
            sizeof(InitInputFfi), reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(InitOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::SetActiveUser(const SetActiveUserInput &input)
{
    IAM_LOGI("SetActiveUser invoked, userId %{public}d", input.userId);

    auto ffiInput = std::make_unique<SetActiveUserInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->userId = input.userId;

    auto ffiOutput = std::make_unique<SetActiveUserOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::SET_ACTIVE_USER_ID,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(SetActiveUserInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(SetActiveUserOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostGetExecutorInfo(HostGetExecutorInfoOutput &output)
{
    auto ffiInput = std::make_unique<GetExecutorInfoInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);

    auto ffiOutput = std::make_unique<GetExecutorInfoOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::GET_EXECUTOR_INFO,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(GetExecutorInfoInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(GetExecutorInfoOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeExecutorInfo(*ffiOutput, output.executorInfo);
    ENSURE_OR_RETURN_VAL(decodeRet, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostOnRegisterFinish(const RegisterFinishInput &input)
{
    auto ffiInput = std::make_unique<HostRegisterFinishInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostRegisterFinishInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostRegisterFinishOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_REGISTER_FINISH,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostRegisterFinishInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostRegisterFinishOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostGetPersistedCompanionStatus(const HostGetPersistedCompanionStatusInput &input,
    HostGetPersistedCompanionStatusOutput &output)
{
    auto ffiInput = std::make_unique<HostGetPersistedStatusInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->userId = input.userId;

    auto ffiOutput = std::make_unique<HostGetPersistedStatusOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_GET_PERSISTED_STATUS,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostGetPersistedStatusInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostGetPersistedStatusOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodePersistedCompanionStatusList(ffiOutput->companionStatusList, output.companionStatusList);
    ENSURE_OR_RETURN_VAL(decodeRet, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionGetPersistedHostBindingStatus(
    const CompanionGetPersistedHostBindingStatusInput &input, CompanionGetPersistedHostBindingStatusOutput &output)
{
    auto ffiInput = std::make_unique<CompanionGetPersistedStatusInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->userId = input.userId;

    auto ffiOutput = std::make_unique<CompanionGetPersistedStatusOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_GET_PERSISTED_STATUS,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionGetPersistedStatusInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionGetPersistedStatusOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodePersistedHostBindingStatusList(ffiOutput->bindingStatusList, output.hostBindingStatusList);
    ENSURE_OR_RETURN_VAL(decodeRet, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostBeginCompanionCheck(const HostBeginCompanionCheckInput &input,
    HostBeginCompanionCheckOutput &output)
{
    auto ffiInput = std::make_unique<HostBeginCompanionCheckInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->requestId = input.requestId;

    auto ffiOutput = std::make_unique<HostBeginCompanionCheckOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_BEGIN_COMPANION_CHECK,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostBeginCompanionCheckInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostBeginCompanionCheckOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    output.salt.assign(ffiOutput->salt.data, ffiOutput->salt.data + ffiOutput->salt.len);
    output.challenge = ffiOutput->challenge;
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostEndCompanionCheck(const HostEndCompanionCheckInput &input)
{
    auto ffiInput = std::make_unique<HostEndCompanionCheckInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostEndCompanionCheckInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostEndCompanionCheckOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_END_COMPANION_CHECK,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostEndCompanionCheckInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostEndCompanionCheckOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostCancelCompanionCheck(const HostCancelCompanionCheckInput &input)
{
    auto ffiInput = std::make_unique<HostCancelCompanionCheckInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->requestId = input.requestId;

    auto ffiOutput = std::make_unique<HostCancelCompanionCheckOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_CANCEL_COMPANION_CHECK,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostCancelCompanionCheckInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostCancelCompanionCheckOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionProcessCheck(const CompanionProcessCheckInput &input,
    CompanionProcessCheckOutput &output)
{
    auto ffiInput = std::make_unique<CompanionProcessCheckInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeCompanionProcessCheckInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<CompanionProcessCheckOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_PROCESS_CHECK,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionProcessCheckInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionProcessCheckOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeCompanionProcessCheckOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostGetInitKeyNegotiationRequest(const HostGetInitKeyNegotiationRequestInput &input,
    HostGetInitKeyNegotiationRequestOutput &output)
{
    auto ffiInput = std::make_unique<HostGetInitKeyNegotiationInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostGetInitKeyNegotiationInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostGetInitKeyNegotiationOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_GET_INIT_KEY_NEGOTIATION,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostGetInitKeyNegotiationInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostGetInitKeyNegotiationOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeHostInitKeyNegotiationOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, GENERAL_ERROR);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostBeginAddCompanion(const HostBeginAddCompanionInput &input,
    HostBeginAddCompanionOutput &output)
{
    auto ffiInput = std::make_unique<HostBeginAddCompanionInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostBeginAddCompanionInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostBeginAddCompanionOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_BEGIN_ADD_COMPANION,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostBeginAddCompanionInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostBeginAddCompanionOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeHostBeginAddCompanionOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostEndAddCompanion(const HostEndAddCompanionInput &input,
    HostEndAddCompanionOutput &output)
{
    auto ffiInput = std::make_unique<HostEndAddCompanionInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostEndAddCompanionInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostEndAddCompanionOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_END_ADD_COMPANION,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostEndAddCompanionInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostEndAddCompanionOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeHostEndAddCompanionOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostCancelAddCompanion(const HostCancelAddCompanionInput &input)
{
    auto ffiInput = std::make_unique<HostCancelAddCompanionInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->requestId = input.requestId;

    auto ffiOutput = std::make_unique<HostCancelAddCompanionOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_CANCEL_ADD_COMPANION,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostCancelAddCompanionInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostCancelAddCompanionOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionInitKeyNegotiation(const CompanionInitKeyNegotiationInput &input,
    CompanionInitKeyNegotiationOutput &output)
{
    auto ffiInput = std::make_unique<CompanionInitKeyNegotiationInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeCompanionInitKeyNegotiationInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<CompanionInitKeyNegotiationOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_INIT_KEY_NEGOTIATION,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionInitKeyNegotiationInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionInitKeyNegotiationOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeCompanionInitKeyNegotiationOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionBeginAddHostBinding(const CompanionBeginAddHostBindingInput &input,
    CompanionBeginAddHostBindingOutput &output)
{
    auto ffiInput = std::make_unique<CompanionBeginAddHostBindingInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeCompanionBeginAddHostBindingInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<CompanionBeginAddHostBindingOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_BEGIN_ADD_HOST_BINDING,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionBeginAddHostBindingInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionBeginAddHostBindingOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeCompanionBeginAddHostBindingOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionEndAddHostBinding(const CompanionEndAddHostBindingInput &input,
    CompanionEndAddHostBindingOutput &output)
{
    auto ffiInput = std::make_unique<CompanionEndAddHostBindingInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeCompanionEndAddHostBindingInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<CompanionEndAddHostBindingOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_END_ADD_HOST_BINDING,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionEndAddHostBindingInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionEndAddHostBindingOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeCompanionEndAddHostBindingOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostRemoveCompanion(const HostRemoveCompanionInput &input,
    HostRemoveCompanionOutput &output)
{
    auto ffiInput = std::make_unique<HostRemoveCompanionInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->templateId = input.templateId;

    auto ffiOutput = std::make_unique<HostRemoveCompanionOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_REMOVE_COMPANION,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostRemoveCompanionInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostRemoveCompanionOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    output.userId = ffiOutput->userId;
    bool decodeRet = DecodeDeviceKey(ffiOutput->companionDeviceKey, output.companionDeviceKey);
    ENSURE_OR_RETURN_VAL(decodeRet, GENERAL_ERROR);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionRemoveHostBinding(const CompanionRemoveHostBindingInput &input)
{
    auto ffiInput = std::make_unique<CompanionRemoveHostBindingInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->bindingId = input.bindingId;

    auto ffiOutput = std::make_unique<CompanionRemoveHostBindingOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_REMOVE_HOST_BINDING,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionRemoveHostBindingInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionRemoveHostBindingOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostBeginDelegateAuth(const HostBeginDelegateAuthInput &input,
    HostBeginDelegateAuthOutput &output)
{
    auto ffiInput = std::make_unique<HostBeginDelegateAuthInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostBeginDelegateAuthInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostBeginDelegateAuthOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_BEGIN_DELEGATE_AUTH,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostBeginDelegateAuthInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostBeginDelegateAuthOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeHostBeginDelegateAuthOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostEndDelegateAuth(const HostEndDelegateAuthInput &input,
    HostEndDelegateAuthOutput &output)
{
    auto ffiInput = std::make_unique<HostEndDelegateAuthInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostEndDelegateAuthInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostEndDelegateAuthOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_END_DELEGATE_AUTH,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostEndDelegateAuthInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostEndDelegateAuthOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeHostEndDelegateAuthOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostCancelDelegateAuth(const HostCancelDelegateAuthInput &input)
{
    auto ffiInput = std::make_unique<HostCancelDelegateAuthInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->requestId = input.requestId;

    auto ffiOutput = std::make_unique<HostCancelDelegateAuthOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_CANCEL_DELEGATE_AUTH,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostCancelDelegateAuthInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostCancelDelegateAuthOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionBeginDelegateAuth(const CompanionDelegateAuthBeginInput &input,
    CompanionDelegateAuthBeginOutput &output)
{
    auto ffiInput = std::make_unique<CompanionBeginDelegateAuthInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeCompanionBeginDelegateAuthInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<CompanionBeginDelegateAuthOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_BEGIN_DELEGATE_AUTH,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionBeginDelegateAuthInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionBeginDelegateAuthOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeCompanionBeginDelegateAuthOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionEndDelegateAuth(const CompanionDelegateAuthEndInput &input,
    CompanionDelegateAuthEndOutput &output)
{
    auto ffiInput = std::make_unique<CompanionEndDelegateAuthInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeCompanionEndDelegateAuthInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<CompanionEndDelegateAuthOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_END_DELEGATE_AUTH,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionEndDelegateAuthInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionEndDelegateAuthOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeCompanionEndDelegateAuthOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostPreIssueToken(const HostPreIssueTokenInput &input, HostPreIssueTokenOutput &output)
{
    auto ffiInput = std::make_unique<HostPreIssueTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostPreIssueTokenInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostPreIssueTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_PRE_ISSUE_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostPreIssueTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostPreIssueTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeHostPreIssueTokenOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostBeginIssueToken(const HostBeginIssueTokenInput &input,
    HostBeginIssueTokenOutput &output)
{
    auto ffiInput = std::make_unique<HostBeginIssueTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostBeginIssueTokenInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostBeginIssueTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_BEGIN_ISSUE_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostBeginIssueTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostBeginIssueTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeHostBeginIssueTokenOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostEndIssueToken(const HostEndIssueTokenInput &input, HostEndIssueTokenOutput &output)
{
    auto ffiInput = std::make_unique<HostEndIssueTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostEndIssueTokenInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostEndIssueTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_END_ISSUE_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostEndIssueTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostEndIssueTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeHostEndIssueTokenOutput(*ffiOutput, output.atl);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostCancelIssueToken(const HostCancelIssueTokenInput &input)
{
    auto ffiInput = std::make_unique<HostCancelIssueTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->requestId = input.requestId;

    auto ffiOutput = std::make_unique<HostCancelIssueTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_CANCEL_ISSUE_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostCancelIssueTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostCancelIssueTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionPreIssueToken(const CompanionPreIssueTokenInput &input,
    CompanionPreIssueTokenOutput &output)
{
    auto ffiInput = std::make_unique<CompanionPreIssueTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeCompanionPreIssueTokenInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<CompanionPreIssueTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_PRE_ISSUE_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionPreIssueTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionPreIssueTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeCompanionPreIssueTokenOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionProcessIssueToken(const CompanionProcessIssueTokenInput &input,
    CompanionProcessIssueTokenOutput &output)
{
    auto ffiInput = std::make_unique<CompanionProcessIssueTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeCompanionProcessIssueTokenInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<CompanionProcessIssueTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_PROCESS_ISSUE_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionProcessIssueTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionProcessIssueTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeCompanionProcessIssueTokenOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionCancelIssueToken(const CompanionCancelIssueTokenInput &input)
{
    auto ffiInput = std::make_unique<CompanionCancelIssueTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->requestId = input.requestId;

    auto ffiOutput = std::make_unique<CompanionCancelIssueTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_PROCESS_ISSUE_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionCancelIssueTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionCancelIssueTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostProcessPreObtainToken(const HostProcessPreObtainTokenInput &input,
    HostProcessPreObtainTokenOutput &output)
{
    auto ffiInput = std::make_unique<HostProcessPreObtainTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostProcessPreObtainTokenInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostProcessPreObtainTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_PROCESS_PRE_OBTAIN_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostProcessPreObtainTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostProcessPreObtainTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeHostProcessPreObtainTokenOutput(*ffiOutput, output.preObtainTokenReply);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostProcessObtainToken(const HostProcessObtainTokenInput &input,
    HostProcessObtainTokenOutput &output)
{
    auto ffiInput = std::make_unique<HostProcessObtainTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostProcessObtainTokenInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostProcessObtainTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_PROCESS_OBTAIN_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostProcessObtainTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostProcessObtainTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeHostProcessObtainTokenOutput(*ffiOutput, output.obtainTokenReply, output.atl);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostCancelObtainToken(const HostCancelObtainTokenInput &input)
{
    auto ffiInput = std::make_unique<HostCancelObtainTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->requestId = input.requestId;

    auto ffiOutput = std::make_unique<HostCancelObtainTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_CANCEL_OBTAIN_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostCancelObtainTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostCancelObtainTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionBeginObtainToken(const CompanionBeginObtainTokenInput &input,
    CompanionBeginObtainTokenOutput &output)
{
    auto ffiInput = std::make_unique<CompanionBeginObtainTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeCompanionBeginObtainTokenInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<CompanionBeginObtainTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_BEGIN_OBTAIN_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionBeginObtainTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionBeginObtainTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeCompanionBeginObtainTokenOutput(*ffiOutput, output.obtainTokenRequest);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionEndObtainToken(const CompanionEndObtainTokenInput &input)
{
    auto ffiInput = std::make_unique<CompanionEndObtainTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeCompanionEndObtainTokenInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<CompanionEndObtainTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_END_OBTAIN_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionEndObtainTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionEndObtainTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionCancelObtainToken(const CompanionCancelObtainTokenInput &input)
{
    auto ffiInput = std::make_unique<CompanionCancelObtainTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->requestId = input.requestId;

    auto ffiOutput = std::make_unique<CompanionCancelObtainTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_CANCEL_OBTAIN_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionCancelObtainTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionCancelObtainTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostBeginTokenAuth(const HostBeginTokenAuthInput &input, HostBeginTokenAuthOutput &output)
{
    auto ffiInput = std::make_unique<HostBeginTokenAuthInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostBeginTokenAuthInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostBeginTokenAuthOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_BEGIN_TOKEN_AUTH,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostBeginTokenAuthInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostBeginTokenAuthOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeHostBeginTokenAuthOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostEndTokenAuth(const HostEndTokenAuthInput &input, HostEndTokenAuthOutput &output)
{
    auto ffiInput = std::make_unique<HostEndTokenAuthInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostEndTokenAuthInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostEndTokenAuthOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_END_TOKEN_AUTH,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostEndTokenAuthInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostEndTokenAuthOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeHostEndTokenAuthOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostUpdateToken(const HostUpdateTokenInput &input, HostUpdateTokenOutput &output)
{
    auto ffiInput = std::make_unique<HostUpdateTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostUpdateTokenInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostUpdateTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_UPDATE_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostUpdateTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostUpdateTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeHostUpdateTokenOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionProcessTokenAuth(const CompanionProcessTokenAuthInput &input,
    CompanionProcessTokenAuthOutput &output)
{
    auto ffiInput = std::make_unique<CompanionProcessTokenAuthInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeCompanionProcessTokenAuthInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<CompanionProcessTokenAuthOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_PROCESS_TOKEN_AUTH,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionProcessTokenAuthInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionProcessTokenAuthOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeCompanionProcessTokenAuthOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, INVALID_PARAMETERS);
    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostRevokeToken(const HostRevokeTokenInput &input)
{
    auto ffiInput = std::make_unique<HostRevokeTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->templateId = input.templateId;

    auto ffiOutput = std::make_unique<HostRevokeTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_REVOKE_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostRevokeTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostRevokeTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::CompanionRevokeToken(const CompanionRevokeTokenInput &input)
{
    auto ffiInput = std::make_unique<CompanionRevokeTokenInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    ffiInput->bindingId = input.bindingId;

    auto ffiOutput = std::make_unique<CompanionRevokeTokenOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::COMPANION_REVOKE_TOKEN,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(CompanionRevokeTokenInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(CompanionRevokeTokenOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostUpdateCompanionStatus(const HostUpdateCompanionStatusInput &input)
{
    auto ffiInput = std::make_unique<HostUpdateCompanionStatusInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostUpdateCompanionStatusInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostUpdateCompanionStatusOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_UPDATE_COMPANION_STATUS,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostUpdateCompanionStatusInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostUpdateCompanionStatusOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostUpdateCompanionEnabledBusinessIds(
    const HostUpdateCompanionEnabledBusinessIdsInput &input)
{
    auto ffiInput = std::make_unique<HostUpdateCompanionEnabledBusinessIdsInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostUpdateCompanionEnabledBusinessIdsInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostUpdateCompanionEnabledBusinessIdsOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult =
        GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_UPDATE_COMPANION_ENABLED_BUSINESS_IDS,
            reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostUpdateCompanionEnabledBusinessIdsInputFfi),
            reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostUpdateCompanionEnabledBusinessIdsOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return SUCCESS;
}

ResultCode SecurityAgentImpl::HostCheckTemplateEnrolled(const HostCheckTemplateEnrolledInput &input,
    HostCheckTemplateEnrolledOutput &output)
{
    auto ffiInput = std::make_unique<HostCheckTemplateEnrolledInputFfi>();
    ENSURE_OR_RETURN_VAL(ffiInput != nullptr, GENERAL_ERROR);
    bool encodeRet = EncodeHostCheckTemplateEnrolledInput(input, *ffiInput);
    ENSURE_OR_RETURN_VAL(encodeRet, INVALID_PARAMETERS);

    auto ffiOutput = std::make_unique<HostCheckTemplateEnrolledOutputFfi>();
    ENSURE_OR_RETURN_VAL(ffiOutput != nullptr, GENERAL_ERROR);

    int32_t invokeResult = GetSecurityCommandAdapter().InvokeCommand(CommandId::HOST_CHECK_TEMPLATE_ENROLLED,
        reinterpret_cast<uint8_t *>(ffiInput.get()), sizeof(HostCheckTemplateEnrolledInputFfi),
        reinterpret_cast<uint8_t *>(ffiOutput.get()), sizeof(HostCheckTemplateEnrolledOutputFfi));
    ENSURE_OR_RETURN_VAL(invokeResult == SUCCESS, GENERAL_ERROR);

    bool decodeRet = DecodeHostCheckTemplateEnrolledOutput(*ffiOutput, output);
    ENSURE_OR_RETURN_VAL(decodeRet, GENERAL_ERROR);

    IAM_LOGI("success, enrolled=%{public}d", output.enrolled);
    return SUCCESS;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
