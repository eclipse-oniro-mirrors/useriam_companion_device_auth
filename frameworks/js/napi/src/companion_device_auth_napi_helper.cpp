/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "companion_device_auth_napi_helper.h"

#include <cinttypes>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "securec.h"
#include <uv.h>

#include "iam_logger.h"
#include "iam_ptr.h"

#include "common_defines.h"

#define LOG_TAG "CDA_NAPI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
const size_t UINT64_BYTE_SIZE = 8;
const uint8_t UINT8_BYTE_MASK = 0xFF;
static constexpr const int MAX_STRING_LENGTH = 65536;
struct DeleteRefHolder {
    napi_env env { nullptr };
    napi_ref ref { nullptr };
};

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

JsRefHolder::JsRefHolder(napi_env env, napi_value value)
{
    if (env == nullptr || value == nullptr) {
        IAM_LOGE("get null ptr");
        return;
    }
    napi_status ret = CompanionDeviceAuthNapiHelper::GetFunctionRef(env, value, ref_);
    if (ret != napi_ok) {
        IAM_LOGE("GetFunctionRef fail %{public}d", ret);
        ref_ = nullptr;
        return;
    }
    env_ = env;
}

JsRefHolder::~JsRefHolder()
{
    if (!IsValid()) {
        IAM_LOGI("invalid");
        return;
    }
    IAM_LOGD("delete reference");
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    std::shared_ptr<DeleteRefHolder> deleteRefHolder = MakeShared<DeleteRefHolder>();
    if (deleteRefHolder == nullptr) {
        IAM_LOGE("deleteRefHolder is null");
        return;
    }
    deleteRefHolder->env = env_;
    deleteRefHolder->ref = ref_;
    auto task = [deleteRefHolder]() {
        IAM_LOGI("start");
        if (deleteRefHolder == nullptr) {
            IAM_LOGE("deleteRefHolder is invalid");
            return;
        }
        napi_status ret = napi_delete_reference(deleteRefHolder->env, deleteRefHolder->ref);
        if (ret != napi_ok) {
            IAM_LOGE("napi_delete_reference fail %{public}d", ret);
            return;
        }
    };
    if (napi_status::napi_ok != napi_send_event(env_, task, napi_eprio_immediate)) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}

bool JsRefHolder::IsValid() const
{
    return (env_ != nullptr && ref_ != nullptr);
}

napi_ref JsRefHolder::Get() const
{
    return ref_;
}

bool JsRefHolder::Equals(const std::shared_ptr<JsRefHolder> &other) const
{
    if (!other || !other->IsValid() || !this->IsValid()) {
        return false;
    }

    napi_value thisValue;
    napi_value otherValue;
    napi_status status = napi_get_reference_value(env_, this->Get(), &thisValue);
    if (status != napi_ok) {
        return false;
    }

    status = napi_get_reference_value(env_, other->Get(), &otherValue);
    if (status != napi_ok) {
        return false;
    }

    bool result = false;
    status = napi_strict_equals(env_, thisValue, otherValue, &result);
    return (status == napi_ok) && result;
}

napi_status CompanionDeviceAuthNapiHelper::GetUint8ArrayValue(napi_env env, napi_value value,
    std::vector<uint8_t> &array)
{
    bool isTypedarray;
    napi_status result = napi_is_typedarray(env, value, &isTypedarray);
    if (result != napi_ok) {
        IAM_LOGE("napi_is_typedarray fail");
        return result;
    }
    if (!isTypedarray) {
        IAM_LOGE("value is not typedarray");
        return napi_array_expected;
    }
    napi_typedarray_type type;
    size_t length;
    void *data;
    napi_value buffer;
    size_t offset;
    result = napi_get_typedarray_info(env, value, &type, &length, &data, &buffer, &offset);
    if (result != napi_ok) {
        IAM_LOGE("napi_get_typedarray_info fail");
        return result;
    }
    if (type != napi_uint8_array) {
        IAM_LOGE("value is not napi_uint8_array");
        return napi_invalid_arg;
    }
    array.resize(length);
    if (memcpy_s(array.data(), length, data, length) != EOK) {
        IAM_LOGE("memcpy_s fail");
        return napi_generic_failure;
    }
    return result;
}

napi_status CompanionDeviceAuthNapiHelper::GetInt32Array(napi_env env, napi_value obj, std::vector<int32_t> &vec)
{
    vec.clear();
    uint32_t len;
    napi_get_array_length(env, obj, &len);
    IAM_LOGI("GetInt32Array length: %{public}d", len);
    for (uint32_t index = 0; index < len; index++) {
        napi_value value;
        int32_t getValue;
        NAPI_CALL_BASE(env, napi_get_element(env, obj, index, &value), napi_generic_failure);
        NAPI_CALL_BASE(env, napi_get_value_int32(env, value, &getValue), napi_generic_failure);
        IAM_LOGI("vec[%{public}d]: %{public}d", index, len);
        vec.emplace_back(getValue);
    }
    return napi_ok;
}

napi_status CompanionDeviceAuthNapiHelper::CheckNapiType(napi_env env, napi_value value, napi_valuetype type)
{
    napi_valuetype valuetype;
    napi_status result = napi_typeof(env, value, &valuetype);
    if (result != napi_ok) {
        IAM_LOGE("napi_typeof fail");
        return result;
    }
    if (valuetype != type) {
        IAM_LOGE("check valuetype fail");
        return napi_generic_failure;
    }
    return napi_ok;
}

napi_status CompanionDeviceAuthNapiHelper::CallNapiFuncWithResult(napi_env env, napi_ref funcRef, size_t argc,
    const napi_value *argv, napi_value *result)
{
    napi_value funcVal;
    napi_status ret = napi_get_reference_value(env, funcRef, &funcVal);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_reference_value failed %{public}d", ret);
        return ret;
    }

    napi_value undefined;
    ret = napi_get_undefined(env, &undefined);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_undefined failed %{public}d", ret);
        return ret;
    }

    ret = napi_call_function(env, undefined, funcVal, argc, argv, result);
    if (ret != napi_ok) {
        IAM_LOGE("napi_call_function failed %{public}d", ret);
    }

    return ret;
}

napi_status CompanionDeviceAuthNapiHelper::SetDateProperty(napi_env env, napi_value obj, const char *name,
    int64_t timeStamp)
{
    napi_value addedTimeValue;
    double jsTimeStamp = static_cast<double>(timeStamp) * 1000.0;
    napi_status ret = napi_create_date(env, jsTimeStamp, &addedTimeValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_date failed %{public}d", ret);
        return ret;
    }

    ret = napi_set_named_property(env, obj, "addedTime", addedTimeValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property failed %{public}d", ret);
    }

    return ret;
}

napi_status CompanionDeviceAuthNapiHelper::SetDeviceStatusProperty(napi_env env, napi_value obj, const char *name,
    const ClientDeviceStatus &deviceStatus)
{
    napi_value deviceStatusValue = ConVertDeviceStatusToNapiValue(env, deviceStatus);
    napi_status ret = napi_set_named_property(env, obj, "deviceStatus", deviceStatusValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property failed %{public}d", ret);
    }
    return ret;
}

napi_value CompanionDeviceAuthNapiHelper::ConVertDeviceStatusToNapiValue(napi_env env,
    const ClientDeviceStatus &deviceStatus)
{
    napi_value deviceStatusValue;
    napi_status status = napi_create_object(env, &deviceStatusValue);
    if (status != napi_ok) {
        IAM_LOGE("napi_create_object fail ret:%{public}d", status);
        return nullptr;
    }

    status = SetDeviceKeyProperty(env, deviceStatusValue, "deviceKey", deviceStatus.deviceKey);
    if (status != napi_ok) {
        IAM_LOGE("SetDeviceKeyProperty fail ret:%{public}d", status);
        return nullptr;
    }

    status = SetStringPropertyUtf8(env, deviceStatusValue, "deviceUserName", deviceStatus.deviceUserName);
    if (status != napi_ok) {
        IAM_LOGE("SetStringPropertyUtf8 fail ret:%{public}d", status);
        return nullptr;
    }

    status = SetStringPropertyUtf8(env, deviceStatusValue, "deviceModelInfo", deviceStatus.deviceModelInfo);
    if (status != napi_ok) {
        IAM_LOGE("SetStringPropertyUtf8 fail ret:%{public}d", status);
        return nullptr;
    }

    status = SetStringPropertyUtf8(env, deviceStatusValue, "deviceName", deviceStatus.deviceName);
    if (status != napi_ok) {
        IAM_LOGE("SetStringPropertyUtf8 fail ret:%{public}d", status);
        return nullptr;
    }

    status = SetBoolProperty(env, deviceStatusValue, "isOnline", deviceStatus.isOnline);
    if (status != napi_ok) {
        IAM_LOGE("SetBoolProperty fail ret:%{public}d", status);
        return nullptr;
    }

    status = SetBoolProperty(env, deviceStatusValue, "isOnline", deviceStatus.isOnline);
    if (status != napi_ok) {
        IAM_LOGE("SetBoolProperty fail ret:%{public}d", status);
        return nullptr;
    }

    status = SetBusinessIdsProperty(env, deviceStatusValue, "supportedBusinessIds", deviceStatus.supportedBusinessIds);
    if (status != napi_ok) {
        IAM_LOGE("SetBusinessIdsProperty fail ret:%{public}d", status);
        return nullptr;
    }

    return deviceStatusValue;
}

napi_status CompanionDeviceAuthNapiHelper::SetDeviceKeyProperty(napi_env env, napi_value obj, const char *name,
    const ClientDeviceKey &deviceKey)
{
    napi_value deviceKeyValue = ConvertDeviceKeyToNapiValue(env, deviceKey);
    napi_status status = napi_set_named_property(env, obj, "deviceKey", deviceKeyValue);
    if (status != napi_ok) {
        IAM_LOGE("napi_set_named_property fail ret:%{public}d", status);
    }
    return status;
}

napi_value CompanionDeviceAuthNapiHelper::ConvertDeviceKeyToNapiValue(napi_env env, const ClientDeviceKey &deviceKey)
{
    napi_value deviceKeyValue;
    napi_status status = napi_create_object(env, &deviceKeyValue);
    if (status != napi_ok) {
        IAM_LOGE("napi_create_object fail ret:%{public}d", status);
        return nullptr;
    }

    status = SetInt32Property(env, deviceKeyValue, "deviceIdType", deviceKey.deviceIdType);
    if (status != napi_ok) {
        IAM_LOGE("SetInt32Property fail ret:%{public}d", status);
        return nullptr;
    }

    status = SetStringPropertyUtf8(env, deviceKeyValue, "deviceId", deviceKey.deviceId);
    if (status != napi_ok) {
        IAM_LOGE("SetStringPropertyUtf8 fail ret:%{public}d", status);
        return nullptr;
    }

    status = SetInt32Property(env, deviceKeyValue, "deviceUserId", deviceKey.deviceUserId);
    if (status != napi_ok) {
        IAM_LOGE("SetInt32Property fail ret:%{public}d", status);
        return nullptr;
    }

    return deviceKeyValue;
}

napi_status CompanionDeviceAuthNapiHelper::SetBoolProperty(napi_env env, napi_value obj, const char *name, bool value)
{
    napi_value napiValue = nullptr;
    napi_status ret = napi_get_boolean(env, value, &napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_boolean fail, ret:%{public}d", ret);
        return ret;
    }

    ret = napi_set_named_property(env, obj, name, napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property fail, ret:%{public}d", ret);
    }
    return ret;
}

napi_status CompanionDeviceAuthNapiHelper::SetStringPropertyUtf8(napi_env env, napi_value obj, const std::string &name,
    const std::string &value)
{
    napi_value jsValue = nullptr;
    if (napi_create_string_utf8(env, value.c_str(), strlen(value.c_str()), &jsValue) != napi_ok) {
        IAM_LOGE("get string error");
        return napi_generic_failure;
    }
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, jsValue, &valueType), napi_generic_failure);
    napi_set_named_property(env, obj, name.c_str(), jsValue);
    return napi_ok;
}

napi_value CompanionDeviceAuthNapiHelper::ConvertTemplateStatusListToNapiValue(napi_env env,
    const std::vector<ClientTemplateStatus> &templateStatusList)
{
    napi_value templateStatusListValue;
    napi_status status = napi_create_array_with_length(env, templateStatusList.size(), &templateStatusListValue);
    if (status != napi_ok) {
        IAM_LOGE("napi_create_array_with_length fail ret:%{public}d", status);
        return nullptr;
    }

    for (size_t i = 0; i < templateStatusList.size(); ++i) {
        napi_value element = ConvertTemplateStatusToNapiValue(env, templateStatusList[i]);
        status = napi_set_element(env, templateStatusListValue, i, element);
        if (status != napi_ok) {
            IAM_LOGE("napi_set_element fail at index %{public}zu, ret:%{public}d", i, status);
            continue;
        }
    }

    return templateStatusListValue;
}

napi_status CompanionDeviceAuthNapiHelper::ConvertNapiValueToClientDeviceSelectResult(napi_env env,
    napi_value napiDeviceSelectResult, ClientDeviceSelectResult &result)
{
    bool hasSelectionContext = false;
    napi_value selectionContext = nullptr;
    napi_status status = napi_has_named_property(env, napiDeviceSelectResult, "selectionContext", &hasSelectionContext);
    if (status != napi_ok) {
        IAM_LOGE("napi_has_named_property fail, ret:%{public}d", status);
        return status;
    }

    if (!hasSelectionContext) {
        IAM_LOGI("selectionContext not provided in DeviceSelectResult");
    } else {
        status = napi_get_named_property(env, napiDeviceSelectResult, "selectionContext", &selectionContext);
        if (status != napi_ok) {
            IAM_LOGE("napi_get_named_property fail, ret:%{public}d", status);
            return status;
        }
        std::vector<uint8_t> clientSelectionContext;
        status = CompanionDeviceAuthNapiHelper::GetUint8ArrayValue(env, selectionContext, clientSelectionContext);
        if (status != napi_ok) {
            IAM_LOGE("ConvertNapiUint8ArrayToUint64 fail, ret:%{public}d", status);
            return status;
        }
        result.selectionContext = clientSelectionContext;
    }

    napi_value deviceKeys = nullptr;
    status = napi_get_named_property(env, napiDeviceSelectResult, "deviceKeys", &deviceKeys);
    if (status != napi_ok) {
        IAM_LOGE("napi_get_named_property fail, ret:%{public}d", status);
        return status;
    }

    status = CompanionDeviceAuthNapiHelper::ConvertNapiValueToDeviceKeys(env, deviceKeys, result.deviceKeys);
    if (status != napi_ok) {
        IAM_LOGE("ConvertNapiValueToDeviceKeys fail, ret:%{public}d", status);
        return status;
    }

    return status;
}

napi_status CompanionDeviceAuthNapiHelper::ConvertNapiValueToDeviceKeys(napi_env env, napi_value deviceKeyArray,
    std::vector<ClientDeviceKey> &deviceKeyList)
{
    IAM_LOGI("start");
    bool isArray = false;
    napi_status status = napi_is_array(env, deviceKeyArray, &isArray);
    if (status != napi_ok || !isArray) {
        IAM_LOGE("invalid format");
        return status;
    }

    uint32_t arrayLength;
    status = napi_get_array_length(env, deviceKeyArray, &arrayLength);
    if (status != napi_ok) {
        IAM_LOGE("get array length fail");
        return status;
    }

    for (size_t i = 0; i < arrayLength; ++i) {
        napi_value deviceKey;
        status = napi_get_element(env, deviceKeyArray, i, &deviceKey);
        if (status != napi_ok) {
            IAM_LOGE("failed to get device key at index %{public}zu", i);
            continue;
        }

        ClientDeviceKey clientDeviceKey;
        status = ConvertNapiValueToDeviceKey(env, deviceKey, clientDeviceKey);
        if (status == napi_ok) {
            deviceKeyList.push_back(clientDeviceKey);
        } else {
            IAM_LOGE("fail to convert at index %{public}zu", i);
        }
    }
    return napi_ok;
}

napi_status CompanionDeviceAuthNapiHelper::ConvertNapiValueToDeviceKey(napi_env env, napi_value deviceKey,
    ClientDeviceKey &clientDeviceKey)
{
    napi_value deviceIdTypeValue = CompanionDeviceAuthNapiHelper::GetNamedProperty(env, deviceKey, "deviceIdType");
    napi_status ret =
        CompanionDeviceAuthNapiHelper::GetInt32Value(env, deviceIdTypeValue, clientDeviceKey.deviceIdType);
    if (ret != napi_ok) {
        IAM_LOGE("get deviceIdType fail ret:%{public}d", ret);
        return ret;
    }

    napi_value deviceIdValue = CompanionDeviceAuthNapiHelper::GetNamedProperty(env, deviceKey, "deviceId");
    std::string deviceId = CompanionDeviceAuthNapiHelper::GetStringFromValueUtf8(env, deviceIdValue);
    if (deviceId == "") {
        IAM_LOGE("get deviceId fail");
        return napi_generic_failure;
    }
    clientDeviceKey.deviceId = deviceId;

    napi_value deviceUserIdValue = CompanionDeviceAuthNapiHelper::GetNamedProperty(env, deviceKey, "deviceUserId");
    ret = CompanionDeviceAuthNapiHelper::GetInt32Value(env, deviceUserIdValue, clientDeviceKey.deviceUserId);
    if (ret != napi_ok) {
        IAM_LOGE("get deviceUserId fail ret:%{public}d", ret);
    }

    return ret;
}

std::string CompanionDeviceAuthNapiHelper::GetStringFromValueUtf8(napi_env env, napi_value value)
{
    if (CheckNapiType(env, value, napi_string) != napi_ok) {
        return "";
    }
    std::string result;
    std::vector<char> str(MAX_STRING_LENGTH + 1, '\0');
    size_t length = 0;
    NAPI_CALL(env, napi_get_value_string_utf8(env, value, &str[0], MAX_STRING_LENGTH, &length));
    if (length > 0) {
        return result.append(&str[0], length);
    }
    return result;
}

napi_value CompanionDeviceAuthNapiHelper::GetNamedProperty(napi_env env, napi_value object,
    const std::string &propertyName)
{
    napi_value value = nullptr;
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, propertyName.c_str(), &hasProperty));
    if (!hasProperty) {
        return value;
    }
    NAPI_CALL(env, napi_get_named_property(env, object, propertyName.c_str(), &value));
    return value;
}

napi_status CompanionDeviceAuthNapiHelper::GetInt32Value(napi_env env, napi_value value, int32_t &out)
{
    napi_status result = CheckNapiType(env, value, napi_number);
    if (result != napi_ok) {
        IAM_LOGE("CheckNapiType fail");
        return result;
    }
    result = napi_get_value_int32(env, value, &out);
    if (result != napi_ok) {
        IAM_LOGE("napi_get_value_int32 fail");
    }
    return result;
}

napi_value CompanionDeviceAuthNapiHelper::ConvertDeviceStatusListToNapiValue(napi_env env,
    const std::vector<ClientDeviceStatus> &deviceStatusList)
{
    napi_value deviceStatusListValue;
    napi_status status = napi_create_array_with_length(env, deviceStatusList.size(), &deviceStatusListValue);
    if (status != napi_ok) {
        IAM_LOGE("napi_create_array_with_length fail");
        return nullptr;
    }

    for (size_t i = 0; i < deviceStatusList.size(); ++i) {
        napi_value element = ConVertDeviceStatusToNapiValue(env, deviceStatusList[i]);
        status = napi_set_element(env, deviceStatusListValue, i, element);
        if (status != napi_ok) {
            IAM_LOGE("napi_create_array_with_length fail at index: %{public}zu", i);
            continue;
        }
    }

    return deviceStatusListValue;
}

napi_status CompanionDeviceAuthNapiHelper::SetUint8ArrayProperty(napi_env env, napi_value obj, const char *name,
    const std::vector<uint8_t> &value)
{
    size_t size = value.size();
    void *data;
    napi_value buffer;
    napi_status ret = napi_create_arraybuffer(env, size, &data, &buffer);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_arraybuffer failed %{public}d", ret);
        return ret;
    }
    if (size != 0) {
        if (memcpy_s(data, size, value.data(), value.size()) != EOK) {
            IAM_LOGE("memcpy_s failed");
            return napi_generic_failure;
        }
    }
    napi_value napiValue;
    ret = napi_create_typedarray(env, napi_uint8_array, size, buffer, 0, &napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_typedarray failed %{public}d", ret);
        return ret;
    }
    ret = napi_set_named_property(env, obj, name, napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property failed %{public}d", ret);
    }
    return ret;
}

napi_status CompanionDeviceAuthNapiHelper::SetInt32Property(napi_env env, napi_value obj, const char *name,
    int32_t value)
{
    napi_value napiValue = nullptr;
    napi_status ret = napi_create_int32(env, value, &napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_int32 failed %{public}d", ret);
        return ret;
    }
    ret = napi_set_named_property(env, obj, name, napiValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_set_named_property failed %{public}d", ret);
    }
    return ret;
}

napi_status CompanionDeviceAuthNapiHelper::CallVoidNapiFunc(napi_env env, napi_ref funcRef, size_t argc,
    const napi_value *argv)
{
    napi_value funcVal;
    napi_status ret = napi_get_reference_value(env, funcRef, &funcVal);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_reference_value failed %{public}d", ret);
        return ret;
    }
    napi_value undefined;
    ret = napi_get_undefined(env, &undefined);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_undefined failed %{public}d", ret);
        return ret;
    }
    napi_value callResult;
    ret = napi_call_function(env, undefined, funcVal, argc, argv, &callResult);
    if (ret != napi_ok) {
        IAM_LOGE("napi_call_function failed %{public}d", ret);
    }
    return ret;
}

napi_status CompanionDeviceAuthNapiHelper::ConvertNapiUint8ArrayToUint64(napi_env env, napi_value value, uint64_t &out)
{
    std::vector<uint8_t> outArray;
    napi_status status = GetUint8ArrayValue(env, value, outArray);
    if (status != napi_ok) {
        IAM_LOGE("GetUint8ArrayValue fail, ret:%{public}d", status);
        return status;
    }

    memcpy_s(&out, sizeof(out), outArray.data(), sizeof(uint64_t));
    return napi_ok;
}

napi_status CompanionDeviceAuthNapiHelper::SetBusinessIdsProperty(napi_env env, napi_value obj, const char *name,
    const std::vector<int32_t> &businessIds)
{
    napi_value businessIdsValue;
    napi_status status = napi_create_array_with_length(env, businessIds.size(), &businessIdsValue);
    if (status != napi_ok) {
        IAM_LOGE("napi_create_array_with_length fail, ret:%{public}d", status);
        return status;
    }

    for (size_t i = 0; i < businessIds.size(); ++i) {
        napi_value element;
        status = napi_create_int32(env, businessIds[i], &element);
        if (status != napi_ok) {
            IAM_LOGE("napi_create_int32 fail, ret:%{public}d", status);
            continue;
        }

        status = napi_set_element(env, businessIdsValue, i, element);
        if (status != napi_ok) {
            IAM_LOGE("napi_set_element fail, ret:%{public}d", status);
            continue;
        }
    }

    status = napi_set_named_property(env, obj, name, businessIdsValue);
    if (status != napi_ok) {
        IAM_LOGE("napi_set_named_property fail, ret:%{public}d", status);
    }
    return status;
}

napi_value CompanionDeviceAuthNapiHelper::ConvertTemplateStatusToNapiValue(napi_env env,
    const ClientTemplateStatus &status)
{
    napi_value templateStatusValue;
    napi_status ret = napi_create_object(env, &templateStatusValue);
    if (ret != napi_ok) {
        IAM_LOGE("napi_create_object fail ret:%{public}d", ret);
        return nullptr;
    }

    std::vector<uint8_t> result(UINT64_BYTE_SIZE);
    for (size_t i = 0; i < UINT64_BYTE_SIZE; ++i) {
        result[i] = static_cast<uint8_t>((status.templateId >> (i * UINT64_BYTE_SIZE)) & UINT8_BYTE_MASK);
    }

    ret = CompanionDeviceAuthNapiHelper::SetUint8ArrayProperty(env, templateStatusValue, "templateId", result);
    if (ret != napi_ok) {
        IAM_LOGE("SetUint8ArrayProperty fail ret:%{public}d", ret);
        return nullptr;
    }

    ret = CompanionDeviceAuthNapiHelper::SetBoolProperty(env, templateStatusValue, "isConfirmed", status.isConfirmed);
    if (ret != napi_ok) {
        IAM_LOGE("SetBoolProperty fail ret:%{public}d", ret);
        return nullptr;
    }

    ret = CompanionDeviceAuthNapiHelper::SetBoolProperty(env, templateStatusValue, "isValid", status.isValid);
    if (ret != napi_ok) {
        IAM_LOGE("SetBoolProperty fail ret:%{public}d", ret);
        return nullptr;
    }

    ret = CompanionDeviceAuthNapiHelper::SetInt32Property(env, templateStatusValue, "localUserId", status.localUserId);
    if (ret != napi_ok) {
        IAM_LOGE("SetInt32Property fail ret:%{public}d", ret);
        return nullptr;
    }

    ret = CompanionDeviceAuthNapiHelper::SetDateProperty(env, templateStatusValue, "addedTime", status.addedTime);
    if (ret != napi_ok) {
        IAM_LOGE("SetDateProperty fail ret:%{public}d", ret);
        return nullptr;
    }

    ret = CompanionDeviceAuthNapiHelper::SetBusinessIdsProperty(env, templateStatusValue, "enabledBusinessIds",
        status.enabledBusinessIds);
    if (ret != napi_ok) {
        IAM_LOGE("SetEnabledBusinessIdsProperty fail ret:%{public}d", ret);
        return nullptr;
    }

    ret = CompanionDeviceAuthNapiHelper::SetDeviceStatusProperty(env, templateStatusValue, "deviceStatus",
        status.deviceStatus);
    if (ret != napi_ok) {
        IAM_LOGE("SetEnabledBusinessIdsProperty fail ret:%{public}d", ret);
        return nullptr;
    }

    return templateStatusValue;
}

napi_value CompanionDeviceAuthNapiHelper::GenerateBusinessError(napi_env env, int32_t error)
{
    std::string msgStr;
    napi_value code;
    napi_value msg;
    napi_value businessError;
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
    NAPI_CALL(env, napi_create_int32(env, error, &code));
    NAPI_CALL(env, napi_create_string_utf8(env, msgStr.c_str(), NAPI_AUTO_LENGTH, &msg));
    NAPI_CALL(env, napi_create_error(env, nullptr, msg, &businessError));
    NAPI_CALL(env, napi_set_named_property(env, businessError, "code", code));
    return businessError;
}

napi_status CompanionDeviceAuthNapiHelper::GetFunctionRef(napi_env env, napi_value value, napi_ref &ref)
{
    napi_status result = CheckNapiType(env, value, napi_function);
    if (result != napi_ok) {
        IAM_LOGE("CheckNapiType fail");
        return result;
    }
    result = napi_create_reference(env, value, 1, &ref);
    if (result != napi_ok) {
        IAM_LOGE("napi_create_reference fail");
    }
    return result;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
