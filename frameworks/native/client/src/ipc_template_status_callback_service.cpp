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

#include "ipc_template_status_callback_service.h"

#include <cinttypes>
#include <memory>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "common_defines.h"
#include "companion_device_auth_common_defines.h"

#define LOG_TAG "CDA_SDK"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
IpcTemplateStatusCallbackService::IpcTemplateStatusCallbackService(int32_t userId,
    const std::shared_ptr<ITemplateStatusCallback> &impl)
    : userId_(userId),
      callback_(impl)
{
}

int32_t IpcTemplateStatusCallbackService::OnTemplateStatusChange(
    const std::vector<IpcTemplateStatus> &templateStatusList)
{
    IAM_LOGI("start, templateStatusList size:%{public}zu", templateStatusList.size());
    ENSURE_OR_RETURN_VAL(callback_ != nullptr, GENERAL_ERROR);

    std::vector<ClientTemplateStatus> clientTemplateStatusList;
    for (const auto &templateStatus : templateStatusList) {
        IAM_LOGI("deviceIdType:%{public}d, deviceId:%{public}s, deviceUserId:%{public}d",
            templateStatus.deviceStatus.deviceKey.deviceIdType,
            GetMaskedString(templateStatus.deviceStatus.deviceKey.deviceId).c_str(),
            templateStatus.deviceStatus.deviceKey.deviceUserId);
        ClientDeviceKey clientDeviceKey;
        clientDeviceKey.deviceIdType = templateStatus.deviceStatus.deviceKey.deviceIdType;
        clientDeviceKey.deviceId = templateStatus.deviceStatus.deviceKey.deviceId;
        clientDeviceKey.deviceUserId = templateStatus.deviceStatus.deviceKey.deviceUserId;

        IAM_LOGI("deviceUserName:%{public}s, deviceModelInfo:%{public}s, deviceName:%{public}s, isOnline:%{public}d, "
                 "supportedBusinessIds size:%{public}zu",
            templateStatus.deviceStatus.deviceUserName.c_str(), templateStatus.deviceStatus.deviceModelInfo.c_str(),
            templateStatus.deviceStatus.deviceName.c_str(), templateStatus.deviceStatus.isOnline,
            templateStatus.deviceStatus.supportedBusinessIds.size());
        ClientDeviceStatus clientDeviceStatus;
        clientDeviceStatus.deviceKey = clientDeviceKey;
        clientDeviceStatus.deviceUserName = templateStatus.deviceStatus.deviceUserName;
        clientDeviceStatus.deviceModelInfo = templateStatus.deviceStatus.deviceModelInfo;
        clientDeviceStatus.deviceName = templateStatus.deviceStatus.deviceName;
        clientDeviceStatus.isOnline = templateStatus.deviceStatus.isOnline;
        clientDeviceStatus.supportedBusinessIds = templateStatus.deviceStatus.supportedBusinessIds;

        IAM_LOGI("templateId:%{public}s, isConfirmed:%{public}d, isValid:%{public}d, localUserId:%{public}d, "
                 "addedTime:%{public}" PRId64 ", enabledBusinessIds size:%{public}zu",
            GET_MASKED_NUM_CSTR(templateStatus.templateId), templateStatus.isConfirmed, templateStatus.isValid,
            templateStatus.localUserId, templateStatus.addedTime, templateStatus.enabledBusinessIds.size());
        ClientTemplateStatus clientTemplateStatus;
        clientTemplateStatus.templateId = templateStatus.templateId;
        clientTemplateStatus.isConfirmed = templateStatus.isConfirmed;
        clientTemplateStatus.isValid = templateStatus.isValid;
        clientTemplateStatus.localUserId = templateStatus.localUserId;
        clientTemplateStatus.addedTime = templateStatus.addedTime;
        clientTemplateStatus.enabledBusinessIds = templateStatus.enabledBusinessIds;
        clientTemplateStatus.deviceStatus = clientDeviceStatus;
        clientTemplateStatusList.push_back(clientTemplateStatus);
    }

    callback_->OnTemplateStatusChange(clientTemplateStatusList);
    return SUCCESS;
}

int32_t IpcTemplateStatusCallbackService::GetUserId()
{
    return userId_;
}

std::shared_ptr<ITemplateStatusCallback> IpcTemplateStatusCallbackService::GetCallback()
{
    return callback_;
}

int32_t IpcTemplateStatusCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t IpcTemplateStatusCallbackService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS