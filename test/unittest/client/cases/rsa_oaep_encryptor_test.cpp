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

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "asym_encryptor.h"
#include "rsa_oaep_encryptor.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::UserIam::CompanionDeviceAuth;

namespace {
// RSA-2048 DER-encoded SubjectPublicKeyInfo (generated for testing only)
constexpr uint8_t TEST_RSA_2048_PUB_KEY_DER[] = { 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,
    0x01, 0x01, 0x00, 0x97, 0x1a, 0xbb, 0xde, 0x32, 0x7d, 0xf4, 0x7b, 0xae, 0xe8, 0x55, 0x8b, 0x08, 0xd9, 0x3c, 0xc5,
    0x28, 0x86, 0x98, 0x74, 0x99, 0x8f, 0xc2, 0xb8, 0x22, 0x7f, 0x15, 0xc8, 0x13, 0x12, 0x13, 0x54, 0xcc, 0xa1, 0x11,
    0x1d, 0xa8, 0x09, 0x56, 0xff, 0xaf, 0x35, 0x3c, 0x4c, 0x28, 0x3e, 0xb7, 0xce, 0x54, 0xc3, 0x56, 0xff, 0x6b, 0xff,
    0x0e, 0x63, 0xcb, 0xfb, 0x9c, 0xe8, 0x97, 0xea, 0x2d, 0x02, 0x69, 0x7d, 0x8d, 0x0b, 0xbb, 0xd1, 0x99, 0x95, 0x97,
    0xee, 0xad, 0xd7, 0x76, 0x62, 0x15, 0x98, 0xde, 0x5b, 0x1e, 0xfc, 0xa1, 0x36, 0xc3, 0xc9, 0x7c, 0x6c, 0x94, 0x0a,
    0x4a, 0xac, 0xcf, 0x17, 0xc8, 0x54, 0x17, 0xd7, 0x3a, 0x4b, 0xa6, 0x88, 0x6e, 0x85, 0x13, 0xe5, 0xc1, 0xd3, 0x6b,
    0x7b, 0x65, 0x7a, 0x0d, 0x22, 0x6a, 0xce, 0xb3, 0x72, 0x9b, 0x0c, 0x44, 0xd0, 0x4a, 0xd5, 0xf4, 0xf6, 0x01, 0x26,
    0xbb, 0x5d, 0x2c, 0x5b, 0xa7, 0xd1, 0xaa, 0x0f, 0x78, 0x24, 0x5f, 0x04, 0x8b, 0x9f, 0x48, 0x69, 0x8e, 0x2b, 0x9f,
    0x51, 0x8d, 0xf3, 0xb2, 0xeb, 0x47, 0x22, 0x83, 0xd9, 0x96, 0x54, 0x4a, 0x94, 0xc9, 0x12, 0x39, 0x15, 0x41, 0x3e,
    0xaf, 0x72, 0x9f, 0x28, 0x8a, 0x20, 0x3e, 0x56, 0x35, 0x1b, 0x74, 0x9f, 0x10, 0xa7, 0x98, 0xd0, 0x28, 0x98, 0xd0,
    0x2e, 0x74, 0x4f, 0xc6, 0xc5, 0x75, 0xb0, 0xf0, 0x50, 0x69, 0xc7, 0x41, 0x95, 0xb2, 0xdb, 0x05, 0x8f, 0xda, 0xd3,
    0x50, 0x60, 0x29, 0x5d, 0xda, 0xb3, 0xd6, 0x67, 0x0f, 0x39, 0x75, 0x66, 0xb2, 0x7f, 0xa6, 0xcf, 0x8a, 0x73, 0xe9,
    0x3f, 0xcd, 0xb3, 0x3c, 0x58, 0x17, 0x29, 0xe6, 0x9d, 0x11, 0x5a, 0x30, 0xe5, 0xd9, 0x19, 0x5d, 0x0e, 0x53, 0x05,
    0x34, 0x32, 0x10, 0x28, 0xb9, 0x62, 0x6a, 0x0e, 0xfb, 0xab, 0x97, 0xe1, 0x02, 0x03, 0x01, 0x00, 0x01 };
constexpr size_t TEST_RSA_2048_PUB_KEY_DER_LEN = 294;
// RSA-2048 ciphertext size
constexpr size_t RSA_2048_CIPHERTEXT_SIZE = 256;
// RSA-2048 OAEP max plaintext: 2048/8 - 2*32 - 2 = 190 bytes
constexpr size_t RSA_2048_MAX_PLAINTEXT = 190;
constexpr int32_t RSA_2048_KEY_BITS = 2048;

std::vector<uint8_t> GetValidRsa2048PublicKey()
{
    return std::vector<uint8_t>(TEST_RSA_2048_PUB_KEY_DER, TEST_RSA_2048_PUB_KEY_DER + TEST_RSA_2048_PUB_KEY_DER_LEN);
}
} // namespace

class RsaOaepEncryptorTest : public testing::Test {
public:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

// ============================================================================
// Create: invalid inputs return nullptr
// ============================================================================

HWTEST_F(RsaOaepEncryptorTest, EmptyKey_CreateReturnsNullptr, TestSize.Level0)
{
    std::unique_ptr<RsaOaepEncryptor> encryptor = RsaOaepEncryptor::Create(std::vector<uint8_t> {}, RSA_2048_KEY_BITS);
    EXPECT_EQ(encryptor, nullptr);
}

HWTEST_F(RsaOaepEncryptorTest, InvalidDerKey_CreateReturnsNullptr, TestSize.Level0)
{
    std::vector<uint8_t> garbage(100, 0xAB);
    std::unique_ptr<RsaOaepEncryptor> encryptor = RsaOaepEncryptor::Create(std::move(garbage), RSA_2048_KEY_BITS);
    EXPECT_EQ(encryptor, nullptr);
}

HWTEST_F(RsaOaepEncryptorTest, TruncatedDerKey_CreateReturnsNullptr, TestSize.Level0)
{
    auto key = GetValidRsa2048PublicKey();
    key.resize(key.size() / 2);
    std::unique_ptr<RsaOaepEncryptor> encryptor = RsaOaepEncryptor::Create(std::move(key), RSA_2048_KEY_BITS);
    EXPECT_EQ(encryptor, nullptr);
}

HWTEST_F(RsaOaepEncryptorTest, ValidKey_CreateSucceeds, TestSize.Level0)
{
    std::unique_ptr<RsaOaepEncryptor> encryptor =
        RsaOaepEncryptor::Create(GetValidRsa2048PublicKey(), RSA_2048_KEY_BITS);
    ASSERT_NE(encryptor, nullptr);
    EXPECT_TRUE(encryptor->HasPublicKey());
}

// ============================================================================
// Encrypt: no valid key
// ============================================================================

HWTEST_F(RsaOaepEncryptorTest, EncryptNoKey_ReturnsNullopt, TestSize.Level0)
{
    std::unique_ptr<RsaOaepEncryptor> encryptor = RsaOaepEncryptor::Create(std::vector<uint8_t> {}, RSA_2048_KEY_BITS);
    EXPECT_EQ(encryptor, nullptr);
}

HWTEST_F(RsaOaepEncryptorTest, EncryptInvalidKey_ReturnsNullopt, TestSize.Level0)
{
    std::vector<uint8_t> garbage(64, 0xFF);
    std::unique_ptr<RsaOaepEncryptor> encryptor = RsaOaepEncryptor::Create(std::move(garbage), RSA_2048_KEY_BITS);
    EXPECT_EQ(encryptor, nullptr);
}

// ============================================================================
// Encrypt: valid key
// ============================================================================

HWTEST_F(RsaOaepEncryptorTest, EncryptValidKey_ReturnsCiphertext, TestSize.Level0)
{
    std::unique_ptr<RsaOaepEncryptor> encryptor =
        RsaOaepEncryptor::Create(GetValidRsa2048PublicKey(), RSA_2048_KEY_BITS);
    ASSERT_NE(encryptor, nullptr);
    std::vector<uint8_t> plaintext = { 0x01, 0x02, 0x03, 0x04 };
    auto result = encryptor->Encrypt(plaintext);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), RSA_2048_CIPHERTEXT_SIZE);
    EXPECT_NE(*result, plaintext);
}

HWTEST_F(RsaOaepEncryptorTest, EncryptEmptyPlaintext_ReturnsCiphertext, TestSize.Level0)
{
    std::unique_ptr<RsaOaepEncryptor> encryptor =
        RsaOaepEncryptor::Create(GetValidRsa2048PublicKey(), RSA_2048_KEY_BITS);
    ASSERT_NE(encryptor, nullptr);
    std::vector<uint8_t> plaintext;
    auto result = encryptor->Encrypt(plaintext);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), RSA_2048_CIPHERTEXT_SIZE);
}

HWTEST_F(RsaOaepEncryptorTest, EncryptMaxPlaintext_Succeeds, TestSize.Level0)
{
    std::unique_ptr<RsaOaepEncryptor> encryptor =
        RsaOaepEncryptor::Create(GetValidRsa2048PublicKey(), RSA_2048_KEY_BITS);
    ASSERT_NE(encryptor, nullptr);
    std::vector<uint8_t> plaintext(RSA_2048_MAX_PLAINTEXT, 0x42);
    auto result = encryptor->Encrypt(plaintext);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), RSA_2048_CIPHERTEXT_SIZE);
}

HWTEST_F(RsaOaepEncryptorTest, EncryptTooLargePlaintext_ReturnsNullopt, TestSize.Level0)
{
    std::unique_ptr<RsaOaepEncryptor> encryptor =
        RsaOaepEncryptor::Create(GetValidRsa2048PublicKey(), RSA_2048_KEY_BITS);
    ASSERT_NE(encryptor, nullptr);
    std::vector<uint8_t> plaintext(RSA_2048_CIPHERTEXT_SIZE, 0x42);
    auto result = encryptor->Encrypt(plaintext);
    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// Encrypt: same plaintext produces different ciphertext (OAEP randomness)
// ============================================================================

HWTEST_F(RsaOaepEncryptorTest, EncryptSamePlaintextTwice_ProducesDifferentCiphertext, TestSize.Level0)
{
    std::unique_ptr<RsaOaepEncryptor> encryptor =
        RsaOaepEncryptor::Create(GetValidRsa2048PublicKey(), RSA_2048_KEY_BITS);
    ASSERT_NE(encryptor, nullptr);
    std::vector<uint8_t> plaintext = { 0xAA, 0xBB, 0xCC };
    auto result1 = encryptor->Encrypt(plaintext);
    auto result2 = encryptor->Encrypt(plaintext);
    ASSERT_TRUE(result1.has_value());
    ASSERT_TRUE(result2.has_value());
    EXPECT_NE(*result1, *result2);
}

// ============================================================================
// Encrypt: ciphertext can be decrypted back (round-trip with private key)
// ============================================================================

HWTEST_F(RsaOaepEncryptorTest, EncryptDecryptRoundTrip_RuntimeKeygen, TestSize.Level0)
{
    EVP_PKEY_CTX *keygenCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    ASSERT_NE(keygenCtx, nullptr);
    ASSERT_GT(EVP_PKEY_keygen_init(keygenCtx), 0);
    ASSERT_GT(EVP_PKEY_CTX_set_rsa_keygen_bits(keygenCtx, 2048), 0);
    EVP_PKEY *pkey = nullptr;
    ASSERT_GT(EVP_PKEY_keygen(keygenCtx, &pkey), 0);
    EVP_PKEY_CTX_free(keygenCtx);
    ASSERT_NE(pkey, nullptr);

    int derLen = i2d_PUBKEY(pkey, nullptr);
    ASSERT_GT(derLen, 0);
    std::vector<uint8_t> pubKeyDer(derLen);
    uint8_t *ptr = pubKeyDer.data();
    ASSERT_EQ(i2d_PUBKEY(pkey, &ptr), derLen);

    std::unique_ptr<RsaOaepEncryptor> encryptor = RsaOaepEncryptor::Create(std::move(pubKeyDer), RSA_2048_KEY_BITS);
    ASSERT_NE(encryptor, nullptr);
    ASSERT_TRUE(encryptor->HasPublicKey());
    std::vector<uint8_t> plaintext = { 0x48, 0x65, 0x6c, 0x6c, 0x6f }; // "Hello"
    auto ciphertext = encryptor->Encrypt(plaintext);
    ASSERT_TRUE(ciphertext.has_value());

    EVP_PKEY_CTX *decryptCtx = EVP_PKEY_CTX_new(pkey, nullptr);
    ASSERT_NE(decryptCtx, nullptr);
    ASSERT_GT(EVP_PKEY_decrypt_init(decryptCtx), 0);
    ASSERT_GT(EVP_PKEY_CTX_set_rsa_padding(decryptCtx, RSA_PKCS1_OAEP_PADDING), 0);
    ASSERT_GT(EVP_PKEY_CTX_set_rsa_oaep_md(decryptCtx, EVP_sha256()), 0);
    ASSERT_GT(EVP_PKEY_CTX_set_rsa_mgf1_md(decryptCtx, EVP_sha256()), 0);

    size_t outLen = 0;
    ASSERT_GT(EVP_PKEY_decrypt(decryptCtx, nullptr, &outLen, ciphertext->data(), ciphertext->size()), 0);
    std::vector<uint8_t> decrypted(outLen);
    ASSERT_GT(EVP_PKEY_decrypt(decryptCtx, decrypted.data(), &outLen, ciphertext->data(), ciphertext->size()), 0);
    decrypted.resize(outLen);

    EVP_PKEY_CTX_free(decryptCtx);
    EVP_PKEY_free(pkey);

    EXPECT_EQ(decrypted, plaintext);
}

// ============================================================================
// CreateAsymEncryptor factory tests
// ============================================================================

HWTEST_F(RsaOaepEncryptorTest, CreateAsymEncryptor_UnknownAlgorithm_ReturnsNullptr, TestSize.Level0)
{
    auto encryptor = CreateAsymEncryptor(AsymEncryptAlgorithm::UNKNOWN, GetValidRsa2048PublicKey());
    EXPECT_EQ(encryptor, nullptr);
}

HWTEST_F(RsaOaepEncryptorTest, CreateAsymEncryptor_OutOfRangeAlgorithm_ReturnsNullptr, TestSize.Level0)
{
    auto encryptor = CreateAsymEncryptor(static_cast<AsymEncryptAlgorithm>(255), GetValidRsa2048PublicKey());
    EXPECT_EQ(encryptor, nullptr);
}
