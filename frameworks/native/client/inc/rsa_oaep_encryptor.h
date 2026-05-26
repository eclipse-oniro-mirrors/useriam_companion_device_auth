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

#ifndef RSA_OAEP_ENCRYPTOR_H
#define RSA_OAEP_ENCRYPTOR_H

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "asym_encryptor.h"
#include "nocopyable.h"

typedef struct evp_pkey_st EVP_PKEY;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class RsaOaepEncryptor : public AsymEncryptor, public NoCopyable {
public:
    static std::unique_ptr<RsaOaepEncryptor> Create(std::vector<uint8_t> publicKey, int32_t expectedKeyBits);
    ~RsaOaepEncryptor() override;

    std::optional<std::vector<uint8_t>> Encrypt(const std::vector<uint8_t> &plaintext) override;
    bool HasPublicKey() const;

private:
    struct EvpPkeyDeleter {
        void operator()(EVP_PKEY *p) const;
    };
    explicit RsaOaepEncryptor(std::unique_ptr<EVP_PKEY, EvpPkeyDeleter> pkey);

    std::unique_ptr<EVP_PKEY, EvpPkeyDeleter> pkey_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // RSA_OAEP_ENCRYPTOR_H
