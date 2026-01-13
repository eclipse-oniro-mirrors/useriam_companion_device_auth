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

#include "access_token_kit_adapter_impl.h"

#include "accesstoken_kit.h"
#include "ipc_object_stub.h"
#include "ipc_skeleton.h"

#include "iam_logger.h"

#include "tokenid_kit.h"
#include "xcollie_helper.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002510
#undef LOG_TAG
#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using Security::AccessToken::AccessTokenKit;
using Security::AccessToken::ATokenTypeEnum;
using Security::AccessToken::RET_SUCCESS;
using Security::AccessToken::TOKEN_HAP;
using Security::AccessToken::TokenIdKit;

bool AccessTokenKitAdapterImpl::CheckPermission(IPCObjectStub &stub, const std::string &permissionName)
{
    if (permissionName.empty()) {
        IAM_LOGE("Permission name is empty");
        return false;
    }

    uint32_t firstTokenId = stub.GetFirstTokenID();
    uint32_t callingTokenId = stub.GetCallingTokenID();

    using namespace Security::AccessToken;
    XCollieHelper xcollie("AccessTokenKitAdapterImpl-CheckPermission", API_CALL_TIMEOUT);
    if ((firstTokenId != 0 && AccessTokenKit::VerifyAccessToken(firstTokenId, permissionName) != RET_SUCCESS) ||
        AccessTokenKit::VerifyAccessToken(callingTokenId, permissionName) != RET_SUCCESS) {
        return false;
    }
    return true;
}

bool AccessTokenKitAdapterImpl::CheckSystemPermission(IPCObjectStub &stub)
{
    uint32_t callingTokenId = stub.GetCallingTokenID();
    using namespace Security::AccessToken;
    XCollieHelper xcollie("AccessTokenKitAdapterImpl-CheckSystemPermission", API_CALL_TIMEOUT);
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    bool checkRet = TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
    ATokenTypeEnum callingType = AccessTokenKit::GetTokenTypeFlag(callingTokenId);
    if (checkRet && callingType == TOKEN_HAP) {
        IAM_LOGI("the caller is system application");
        return true;
    }
    return false;
}

uint32_t AccessTokenKitAdapterImpl::GetAccessTokenId(IPCObjectStub &stub)
{
    uint32_t tokenId = stub.GetFirstTokenID();
    IAM_LOGD("get first caller tokenId: %{public}u", tokenId);
    if (tokenId == 0) {
        tokenId = stub.GetCallingTokenID();
        IAM_LOGD("no first caller, get direct caller tokenId: %{public}u", tokenId);
    }
    return tokenId;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
