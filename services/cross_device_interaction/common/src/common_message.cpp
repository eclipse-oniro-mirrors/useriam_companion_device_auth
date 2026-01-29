/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common_message.h"

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
bool DecodeDeviceKey(const Attributes &attributes, Attributes::AttributeKey userIdKey, DeviceKey &deviceKey)
{
    if (!attributes.GetInt32Value(userIdKey, deviceKey.deviceUserId)) {
        IAM_LOGE("Get device user id failed");
        return false;
    }
    int32_t idType = 0;
    if (!attributes.GetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, idType)) {
        IAM_LOGE("Get id type failed");
        return false;
    }
    deviceKey.idType = static_cast<DeviceIdType>(idType);
    if (!attributes.GetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, deviceKey.deviceId)) {
        IAM_LOGE("Get device id failed");
        return false;
    }
    return true;
}
} // namespace

std::optional<DeviceKey> DecodeHostDeviceKey(const Attributes &attributes)
{
    DeviceKey deviceKey = {};
    if (!DecodeDeviceKey(attributes, Attributes::ATTR_CDA_SA_HOST_USER_ID, deviceKey)) {
        return std::nullopt;
    }
    return deviceKey;
}

std::optional<DeviceKey> DecodeCompanionDeviceKey(const Attributes &attributes)
{
    DeviceKey deviceKey = {};
    if (!DecodeDeviceKey(attributes, Attributes::ATTR_CDA_SA_COMPANION_USER_ID, deviceKey)) {
        return std::nullopt;
    }
    return deviceKey;
}

void EncodeHostDeviceKey(const DeviceKey &deviceKey, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(deviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, deviceKey.deviceId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, deviceKey.deviceUserId);
}

void EncodeCompanionDeviceKey(const DeviceKey &deviceKey, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(deviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, deviceKey.deviceId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, deviceKey.deviceUserId);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
