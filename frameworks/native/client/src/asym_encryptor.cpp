/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "asym_encryptor.h"

#include "common_defines.h"
#include "iam_logger.h"
#include "rsa_oaep_encryptor.h"

#define LOG_TAG "CDA_SDK"
#define LOG_FILE_ID LOG_FILE_ASYM_ENCRYPTOR

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::unique_ptr<AsymEncryptor> CreateAsymEncryptor(AsymEncryptAlgorithm algorithm, std::vector<uint8_t> publicKey)
{
    switch (algorithm) {
        case AsymEncryptAlgorithm::RSA_4096_OAEP_SHA256:
            return RsaOaepEncryptor::Create(std::move(publicKey), RSA_4096_KEY_BITS);
        default:
            IAM_LOGE("unsupported asymmetric encrypt algorithm:%{public}d", static_cast<uint8_t>(algorithm));
            return nullptr;
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
