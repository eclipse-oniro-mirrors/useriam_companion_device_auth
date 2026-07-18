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

#include "rsa_oaep_encryptor.h"

#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "CDA_SDK"
#define LOG_FILE_ID LOG_FILE_RSA_OAEP_ENCRYPTOR

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
void RsaOaepEncryptor::EvpPkeyDeleter::operator()(EVP_PKEY *p) const
{
    if (p != nullptr) {
        EVP_PKEY_free(p);
    }
}

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX *c) const
    {
        if (c != nullptr) {
            EVP_PKEY_CTX_free(c);
        }
    }
};

std::unique_ptr<RsaOaepEncryptor> RsaOaepEncryptor::Create(std::vector<uint8_t> publicKey, int32_t expectedKeyBits)
{
    if (publicKey.empty()) {
        IAM_LOGE("public key is empty");
        return nullptr;
    }

    if (publicKey.size() > static_cast<size_t>(std::numeric_limits<long>::max())) {
        IAM_LOGE("public key too large, size:%{public}zu", publicKey.size());
        return nullptr;
    }

    const uint8_t *keyData = publicKey.data();
    EVP_PKEY *raw = d2i_PUBKEY(nullptr, &keyData, static_cast<long>(publicKey.size()));
    if (raw == nullptr) {
        IAM_LOGE("d2i_PUBKEY failed, public key len:%{public}zu", publicKey.size());
        return nullptr;
    }

    int32_t actualBits = EVP_PKEY_bits(raw);
    if (actualBits != expectedKeyBits) {
        IAM_LOGE("key size mismatch, expected:%{public}d, actual:%{public}d", expectedKeyBits, actualBits);
        EVP_PKEY_free(raw);
        return nullptr;
    }

    std::unique_ptr<RsaOaepEncryptor> encryptor(
        new (std::nothrow) RsaOaepEncryptor(std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>(raw)));
    ENSURE_OR_RETURN_VAL(encryptor != nullptr, nullptr);
    return encryptor;
}

RsaOaepEncryptor::RsaOaepEncryptor(std::unique_ptr<EVP_PKEY, EvpPkeyDeleter> pkey) : pkey_(std::move(pkey))
{
}

RsaOaepEncryptor::~RsaOaepEncryptor() = default;

bool RsaOaepEncryptor::HasPublicKey() const
{
    return pkey_ != nullptr;
}

std::optional<std::vector<uint8_t>> RsaOaepEncryptor::Encrypt(const std::vector<uint8_t> &plaintext)
{
    if (pkey_ == nullptr) {
        IAM_LOGE("no valid public key, cannot encrypt");
        return std::nullopt;
    }

    std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter> ctx(EVP_PKEY_CTX_new(pkey_.get(), nullptr));
    if (ctx == nullptr) {
        IAM_LOGE("EVP_PKEY_CTX_new failed");
        return std::nullopt;
    }

    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0) {
        IAM_LOGE("EVP_PKEY_encrypt_init failed");
        return std::nullopt;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) {
        IAM_LOGE("set RSA_PKCS1_OAEP_PADDING failed");
        return std::nullopt;
    }

    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0) {
        IAM_LOGE("set rsa_oaep_md SHA-256 failed");
        return std::nullopt;
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) <= 0) {
        IAM_LOGE("set rsa_mgf1_md SHA-256 failed");
        return std::nullopt;
    }

    size_t outLen = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outLen, plaintext.data(), plaintext.size()) <= 0) {
        IAM_LOGE("EVP_PKEY_encrypt query size failed");
        return std::nullopt;
    }

    std::vector<uint8_t> ciphertext(outLen);
    if (EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &outLen, plaintext.data(), plaintext.size()) <= 0) {
        IAM_LOGE("EVP_PKEY_encrypt failed");
        return std::nullopt;
    }
    ciphertext.resize(outLen);

    IAM_LOGI("RSA-OAEP encrypt success, ciphertext len:%{public}zu", ciphertext.size());
    return ciphertext;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
