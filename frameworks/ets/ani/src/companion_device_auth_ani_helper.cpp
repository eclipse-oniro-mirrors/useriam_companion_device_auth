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

#include "companion_device_auth_ani_helper.h"

#include <cinttypes>
#include <map>
#include <string>

#include "nlohmann/json.hpp"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#include "taihe/runtime.hpp"

#define LOG_TAG "COMPANION_DEVICE_AUTH_ANI"

using namespace taihe;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
const size_t UINT64_BYTE_SIZE = 8;
const int32_t ATL1 = 10000;
const int32_t ATL2 = 20000;
const int32_t ATL3 = 30000;
const int32_t ATL4 = 40000;

const std::map<int32_t, std::string> g_result2Str = {
    { static_cast<int32_t>(ResultCode::GENERAL_ERROR),
        "The system service is not working properly. Please try again later." },
    { static_cast<int32_t>(ResultCode::NOT_ENROLLED), "The template is not found." },
    { static_cast<int32_t>(ResultCode::USER_ID_NOT_FOUND), "The local user is not found." },
    { static_cast<int32_t>(ResultCode::INVALID_BUSINESS_ID), "The business id is invalid." },
    { static_cast<int32_t>(ResultCode::CHECK_PERMISSION_FAILED), "Permission denied." },
    { static_cast<int32_t>(ResultCode::CHECK_SYSTEM_PERMISSION_FAILED), "Not system application." }
};
} // namespace

taihe::array<uint8_t> CompanionDeviceAuthAniHelper::ConvertTemplateId(uint64_t templateId)
{
    taihe::array<uint8_t> result(UINT64_BYTE_SIZE);

    for (size_t i = 0; i < UINT64_BYTE_SIZE; i++) {
        result[i] = static_cast<uint8_t>((templateId >> (i * UINT64_BYTE_SIZE)) & 0xFF);
    }

    return result;
}

uint64_t CompanionDeviceAuthAniHelper::ConvertAniTemplateId(taihe::array<uint8_t> templateId)
{
    uint64_t result = 0;
    if (templateId.size() < UINT64_BYTE_SIZE) {
        return 0;
    }

    for (size_t i = 0; i < UINT64_BYTE_SIZE; ++i) {
        result |= static_cast<uint64_t>(templateId[i]) << (i * UINT64_BYTE_SIZE);
    }

    return result;
}

companionDeviceAuth::DeviceStatus CompanionDeviceAuthAniHelper::ConvertDeviceStatus(
    ClientDeviceStatus clientDeviceStatus)
{
    companionDeviceAuth::DeviceKey deviceKey = ConvertDeviceKey(clientDeviceStatus.deviceKey);
    taihe::array<int32_t> supportedBusinessIds = ConvertInt32VectorToArray(clientDeviceStatus.supportedBusinessIds);
    companionDeviceAuth::DeviceStatus result { deviceKey, clientDeviceStatus.deviceUserName,
        clientDeviceStatus.deviceModelInfo, clientDeviceStatus.deviceName, clientDeviceStatus.isOnline,
        supportedBusinessIds };
    return result;
}

companionDeviceAuth::TemplateStatus CompanionDeviceAuthAniHelper::ConvertTemplateStatus(
    ClientTemplateStatus clientTemplateStatus, ani_env *env)
{
    taihe::array<uint8_t> templateId = ConvertTemplateId(clientTemplateStatus.templateId);
    uintptr_t addedTime = ConvertAddedTime(clientTemplateStatus.addedTime, env);
    taihe::array<int32_t> enabledBusinessIds = ConvertInt32VectorToArray(clientTemplateStatus.enabledBusinessIds);
    companionDeviceAuth::DeviceStatus deviceStatus = ConvertDeviceStatus(clientTemplateStatus.deviceStatus);
    companionDeviceAuth::TemplateStatus result { templateId, clientTemplateStatus.isConfirmed,
        clientTemplateStatus.isValid, clientTemplateStatus.localUserId, addedTime, enabledBusinessIds, deviceStatus };
    return result;
}

taihe::array<int32_t> CompanionDeviceAuthAniHelper::ConvertInt32VectorToArray(const std::vector<int32_t> &input)
{
    taihe::array<int32_t> result(input.size());
    for (size_t i = 0; i < input.size(); i++) {
        result[i] = input[i];
    }
    return result;
}

std::vector<int32_t> CompanionDeviceAuthAniHelper::ConvertArrayToInt32Vector(const taihe::array<int32_t> &input)
{
    return std::vector<int32_t>(input.begin(), input.end());
}

uintptr_t CompanionDeviceAuthAniHelper::ConvertAddedTime(int32_t addedTime, ani_env *env)
{
    uintptr_t result = {};
    ani_object dateObj;
    if (!WrapDate(addedTime, dateObj, env)) {
        return result;
    }
    result = reinterpret_cast<uintptr_t>(dateObj);
    return result;
}

companionDeviceAuth::DeviceKey CompanionDeviceAuthAniHelper::ConvertDeviceKey(ClientDeviceKey clientDeviceKey)
{
    companionDeviceAuth::DeviceKey result { clientDeviceKey.deviceIdType, clientDeviceKey.deviceId,
        clientDeviceKey.deviceUserId };
    return result;
}

ClientDeviceKey CompanionDeviceAuthAniHelper::ConvertAniDeviceKey(companionDeviceAuth::DeviceKey deviceKey)
{
    ClientDeviceKey result;
    result.deviceIdType = deviceKey.deviceIdType;
    result.deviceId = deviceKey.deviceId;
    result.deviceUserId = deviceKey.deviceUserId;
    return result;
}

bool CompanionDeviceAuthAniHelper::WrapDate(int64_t time, ani_object &outObj, ani_env *env)
{
    IAM_LOGI("start");
    if (env == nullptr || time < 0) {
        IAM_LOGE("env is nullptr or time is invalid value");
        return false;
    }
    ani_class cls;
    ani_status status;
    if (ANI_OK != (status = env->FindClass("escompat.Date", &cls))) {
        IAM_LOGE("fail to find class escompat.Date");
        return false;
    }
    ani_method ctor;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &ctor)) != ANI_OK) {
        IAM_LOGE("fail to find method <ctor>. :.");
        return false;
    }
    if ((status = env->Object_New(cls, ctor, &outObj)) != ANI_OK) {
        IAM_LOGE("Object_New fail");
        return false;
    }
    ani_double msObj = 0;
    if ((status = env->Object_CallMethodByName_Double(outObj, "setTime", "d:d", &msObj, static_cast<double>(time))) !=
        ANI_OK) {
        IAM_LOGE("Object_CallMethodByName_Double fail");
        return false;
    }
    return true;
}

::ohos::userIAM::userAuth::userAuth::AuthTrustLevel CompanionDeviceAuthAniHelper::ConvertAuthTrustLevel(
    int32_t authTrustLevel)
{
    switch (authTrustLevel) {
        case ATL1:
            return ::ohos::userIAM::userAuth::userAuth::AuthTrustLevel::key_t::ATL1;
        case ATL2:
            return ::ohos::userIAM::userAuth::userAuth::AuthTrustLevel::key_t::ATL2;
        case ATL3:
            return ::ohos::userIAM::userAuth::userAuth::AuthTrustLevel::key_t::ATL3;
        case ATL4:
            return ::ohos::userIAM::userAuth::userAuth::AuthTrustLevel::key_t::ATL4;
        default:
            IAM_LOGE("fail to convert atl");
            return ::ohos::userIAM::userAuth::userAuth::AuthTrustLevel::key_t::ATL1;
    }
}

bool CompanionDeviceAuthAniHelper::IsAuthTrustLevelValid(int32_t authTrustLevel)
{
    return (
        (authTrustLevel == ATL1) || (authTrustLevel == ATL2) || (authTrustLevel == ATL3) || (authTrustLevel == ATL4));
}

std::vector<uint8_t> CompanionDeviceAuthAniHelper::ConvertArrayToUint8Vector(const taihe::array<uint8_t> &input)
{
    return std::vector<uint8_t>(input.begin(), input.end());
}

void CompanionDeviceAuthAniHelper::ThrowBusinessError(int32_t error)
{
    std::string msgStr;
    if (error == INVALID_BUSINESS_ID) {
        msgStr = g_result2Str.at(error);
        error = FRAMEWORKS_INVALID_PARAMS;
    } else if ((error == USER_ID_NOT_FOUND) || (error == NOT_ENROLLED)) {
        msgStr = g_result2Str.at(error);
        error = FRAMEWORKS_NOT_FOUND;
    } else if (error == CHECK_PERMISSION_FAILED) {
        msgStr = g_result2Str.at(error);
        error = FRAMEWORKS_CHECK_PERMISSION_FAILED;
    } else if (error == CHECK_SYSTEM_PERMISSION_FAILED) {
        msgStr = g_result2Str.at(error);
        error = FRAMEWORKS_CHECK_SYSTEM_PERMISSION_FAILED;
    } else {
        msgStr = g_result2Str.at(GENERAL_ERROR);
        error = FRAMEWORKS_GENERAL_ERROR;
    }
    IAM_LOGI("ThrowBusinessError, errorCode: %{public}d, errmsg: %{public}s", error, msgStr.c_str());
    taihe::set_business_error(error, msgStr);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS