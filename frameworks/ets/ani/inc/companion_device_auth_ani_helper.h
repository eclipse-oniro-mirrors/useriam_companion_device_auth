/**
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

#ifndef COMPANION_DEVICE_AUTH_ANI_HELPER_H
#define COMPANION_DEVICE_AUTH_ANI_HELPER_H

#include <iostream>
#include <vector>

#include "nocopyable.h"

#include "ani.h"
#include "common_defines.h"
#include "companion_device_auth_common_defines.h"
#include "ohos.userIAM.companionDeviceAuth.proj.hpp"

namespace companionDeviceAuth = ohos::userIAM::companionDeviceAuth;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class CompanionDeviceAuthAniHelper {
public:
    static taihe::array<uint8_t> ConvertTemplateId(uint64_t templateId);
    static companionDeviceAuth::DeviceStatus ConvertDeviceStatus(ClientDeviceStatus clientDeviceStatus);
    static companionDeviceAuth::TemplateStatus ConvertTemplateStatus(ClientTemplateStatus clientTemplateStatus,
        ani_env *env);
    static uintptr_t ConvertAddedTime(int32_t addedTime, ani_env *env);
    static companionDeviceAuth::DeviceKey ConvertDeviceKey(ClientDeviceKey clientDeviceKey);
    static bool WrapDate(int64_t time, ani_object &outObj, ani_env *env);
    static taihe::array<int32_t> ConvertInt32VectorToArray(const std::vector<int32_t> &input);
    static uint64_t ConvertAniTemplateId(taihe::array<uint8_t> templateId);
    static std::vector<int32_t> ConvertArrayToInt32Vector(const taihe::array<int32_t> &input);
    static ClientDeviceKey ConvertAniDeviceKey(companionDeviceAuth::DeviceKey deviceKey);
    static ::ohos::userIAM::userAuth::userAuth::AuthTrustLevel ConvertAuthTrustLevel(int32_t authTrustLevel);
    static bool IsAuthTrustLevelValid(int32_t authTrustLevel);
    static std::vector<uint8_t> ConvertArrayToUint8Vector(const taihe::array<uint8_t> &input);
    static void ThrowBusinessError(int32_t error);

private:
    CompanionDeviceAuthAniHelper() = default;
    ~CompanionDeviceAuthAniHelper() = default;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // COMPANION_DEVICE_AUTH_ANI_HELPER_H