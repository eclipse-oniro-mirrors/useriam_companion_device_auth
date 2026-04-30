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

bool AccessTokenUtil::CheckPermission(IPCObjectStub &stub, const std::string &permissionName)
{
    if (permissionName.empty()) {
        IAM_LOGE("Permission name is empty");
        return false;
    }

    uint32_t callingTokenId = stub.GetCallingTokenID();

    XCollieHelper xcollie("AccessTokenUtil-CheckPermission", API_CALL_TIMEOUT);
    if (AccessTokenKit::VerifyAccessToken(callingTokenId, permissionName) != RET_SUCCESS) {
        return false;
    }
    return true;
}

bool AccessTokenUtil::CheckSystemPermission(IPCObjectStub &stub)
{
    uint32_t callingTokenId = stub.GetCallingTokenID();
    XCollieHelper xcollie("AccessTokenUtil-CheckSystemPermission", API_CALL_TIMEOUT);
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

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
