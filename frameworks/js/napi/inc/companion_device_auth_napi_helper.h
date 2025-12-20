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

#ifndef COMPANION_DEVICE_AUTH_NAPI_HELPER_H
#define COMPANION_DEVICE_AUTH_NAPI_HELPER_H

#include <string>
#include <vector>

#include "napi/native_api.h"

#include "nocopyable.h"

#include "companion_device_auth_client.h"
#include "companion_device_auth_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class CompanionDeviceAuthNapiHelper {
public:
    static napi_status GetUint8ArrayValue(napi_env env, napi_value value, std::vector<uint8_t> &array);
    static napi_status GetInt32Array(napi_env env, napi_value obj, std::vector<int32_t> &vec);
    static napi_value GetNamedProperty(napi_env env, napi_value value, const std::string &propertyName);
    static napi_status GetInt32Value(napi_env env, napi_value value, int32_t &out);
    static napi_status SetDateProperty(napi_env env, napi_value obj, const char *name, int64_t timeStamp);
    static napi_status SetBusinessIdsProperty(napi_env env, napi_value obj, const char *name,
        const std::vector<int32_t> &businessIds);
    static napi_status SetDeviceStatusProperty(napi_env env, napi_value obj, const char *name,
        const ClientDeviceStatus &deviceStatus);
    static napi_status SetDeviceKeyProperty(napi_env env, napi_value obj, const char *name,
        const ClientDeviceKey &deviceKey);
    static napi_status SetUint8ArrayProperty(napi_env env, napi_value obj, const char *name,
        const std::vector<uint8_t> &value);
    static napi_status SetInt32Property(napi_env env, napi_value obj, const char *name, int32_t value);
    static napi_status SetStringPropertyUtf8(napi_env env, napi_value obj, const std::string &name,
        const std::string &value);
    static napi_status SetBoolProperty(napi_env env, napi_value obj, const char *name, bool value);
    static napi_value ConVertDeviceStatusToNapiValue(napi_env env, const ClientDeviceStatus &deviceStatus);
    static napi_value ConvertTemplateStatusListToNapiValue(napi_env env,
        const std::vector<ClientTemplateStatus> &templateStatusList);
    static napi_value ConvertDeviceKeyToNapiValue(napi_env env, const ClientDeviceKey &deviceKey);
    static napi_status ConvertNapiValueToClientDeviceSelectResult(napi_env env, napi_value napiDeviceSelectResult,
        ClientDeviceSelectResult &result);
    static napi_status ConvertNapiValueToDeviceKeys(napi_env env, napi_value deviceKeyArray,
        std::vector<ClientDeviceKey> &deviceKeyList);
    static napi_status ConvertNapiValueToDeviceKey(napi_env env, napi_value deviceKey,
        ClientDeviceKey &clientDeviceKey);
    static napi_status ConvertNapiUint8ArrayToUint64(napi_env env, napi_value value, uint64_t &out);
    static napi_value ConvertTemplateStatusToNapiValue(napi_env env, const ClientTemplateStatus &status);
    static napi_value ConvertDeviceStatusListToNapiValue(napi_env env,
        const std::vector<ClientDeviceStatus> &deviceStatusList);
    static napi_status CheckNapiType(napi_env env, napi_value value, napi_valuetype type);
    static napi_status CallVoidNapiFunc(napi_env env, napi_ref funcRef, size_t argc, const napi_value *argv);
    static napi_status CallNapiFuncWithResult(napi_env env, napi_ref funcRef, size_t argc, const napi_value *argv,
        napi_value *result);
    static napi_value GenerateBusinessError(napi_env env, int32_t result);
    static napi_status GetFunctionRef(napi_env env, napi_value value, napi_ref &ref);
    static std::string GetStringFromValueUtf8(napi_env env, napi_value value);

private:
    CompanionDeviceAuthNapiHelper() = default;
    ~CompanionDeviceAuthNapiHelper() = default;
};

class JsRefHolder : public NoCopyable {
public:
    JsRefHolder(napi_env env, napi_value value);
    ~JsRefHolder() override;
    bool IsValid() const;
    napi_ref Get() const;
    bool Equals(const std::shared_ptr<JsRefHolder> &other) const;

private:
    napi_env env_ { nullptr };
    napi_ref ref_ { nullptr };
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // COMPANION_DEVICE_AUTH_NAPI_HELPER_H