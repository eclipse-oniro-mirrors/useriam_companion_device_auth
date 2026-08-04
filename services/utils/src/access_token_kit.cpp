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

#include "access_token_kit.h"

#include "accesstoken_kit.h"
#include "ipc_object_stub.h"
#include "ipc_skeleton.h"

#include "iam_logger.h"

#include "service_common.h"
#include "tokenid_kit.h"
#include "xcollie_helper.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_ACCESS_TOKEN_KIT

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using namespace Security::AccessToken;

namespace {
CallerTokenType MapCallerTokenType(ATokenTypeEnum type)
{
    switch (type) {
        case TOKEN_HAP:
            return CallerTokenType::Hap;
        case TOKEN_NATIVE:
            return CallerTokenType::Native;
        case TOKEN_SHELL:
            return CallerTokenType::Shell;
        default:
            return CallerTokenType::Invalid;
    }
}
} // namespace

bool AccessTokenUtil::CheckPermission(IPCObjectStub &stub, const std::string &permissionName)
{
    if (permissionName.empty()) {
        IAM_LOGE("Permission name is empty");
        return false;
    }

    uint32_t callingTokenId = stub.GetCallingTokenID();

    XCollieHelper xcollie("AccessTokenUtil-CheckPermission", API_CALL_TIMEOUT, false);
    if (AccessTokenKit::VerifyAccessToken(callingTokenId, permissionName) != RET_SUCCESS) {
        return false;
    }
    return true;
}

bool AccessTokenUtil::CheckSystemPermission(IPCObjectStub &stub)
{
    uint32_t callingTokenId = stub.GetCallingTokenID();
    XCollieHelper xcollie("AccessTokenUtil-CheckSystemPermission", API_CALL_TIMEOUT, false);
    ATokenTypeEnum callingType = AccessTokenKit::GetTokenTypeFlag(callingTokenId);
    if (callingType == TOKEN_NATIVE) {
        IAM_LOGI("the caller is native system service");
        return true;
    }
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    bool checkRet = TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
    if (checkRet && callingType == TOKEN_HAP) {
        IAM_LOGI("the caller is system application");
        return true;
    }
    return false;
}

uint32_t AccessTokenUtil::GetAccessTokenId(IPCObjectStub &stub)
{
    uint32_t tokenId = stub.GetCallingTokenID();
    IAM_LOGD("get caller tokenId: %{public}u", tokenId);
    return tokenId;
}

CallerInfo AccessTokenUtil::GetCallerInfo(IPCObjectStub &stub)
{
    CallerInfo info;
    info.tokenId = stub.GetCallingTokenID();
    info.pid = IPCSkeleton::GetCallingPid();
    info.uid = IPCSkeleton::GetCallingUid();
    info.type = MapCallerTokenType(AccessTokenKit::GetTokenTypeFlag(info.tokenId));
    if (info.type == CallerTokenType::Hap) {
        HapTokenInfo hapTokenInfo;
        if (AccessTokenKit::GetHapTokenInfo(info.tokenId, hapTokenInfo) == RET_SUCCESS) {
            info.name = hapTokenInfo.bundleName;
        }
    } else if (info.type == CallerTokenType::Native) {
        NativeTokenInfo nativeTokenInfo;
        if (AccessTokenKit::GetNativeTokenInfo(info.tokenId, nativeTokenInfo) == RET_SUCCESS) {
            info.name = nativeTokenInfo.processName;
        }
    }
    IAM_LOGI("caller name:%{public}s type:%{public}d pid:%{public}d uid:%{public}d", info.name.c_str(),
        static_cast<int32_t>(info.type), info.pid, info.uid);
    return info;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
