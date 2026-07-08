// Known-answer tests (see doc/TESTING.md).
//
// Tier 1: primitive vectors from public standards (RFC 5869, RFC 4231,
//         RFC 7914, NIST SP 800-38A, phc-winner-argon2 test suite).
// Tier 2: protocol composition vectors from Bitwarden's own SDK test suite
//         (bitwarden/sdk-internal @ 4963a281, crate bitwarden-crypto) —
//         these prove byte-identical compatibility with the official client.
//
// Every vector cites its source. Do not edit a vector without re-fetching it
// from that source.
#include <cstring>
#include <string>

#include "base64.h"
#include "encstring.h"
#include "kdf.h"
#include "keys.h"
#include "../check.h"

using namespace BitVault::Crypto;

namespace {

SecureBytes fromTextS(const std::string &text)
{
    return SecureBytes(reinterpret_cast<const uint8_t *>(text.data()),
                       text.size());
}

SecureBytes fromHexS(const std::string &hex)
{
    std::vector<uint8_t> raw = fromHex(hex);
    return SecureBytes(raw.data(), raw.size());
}

bool equalsHex(const SecureBytes &bytes, const std::string &hex)
{
    return toHex(bytes.data(), bytes.size()) == hex;
}

// --- Tier 1: primitives ---

// RFC 7914 §11: PBKDF2-HMAC-SHA-256 test vectors.
// https://www.rfc-editor.org/rfc/rfc7914.txt
void testPbkdf2Rfc7914()
{
    {
        SecureBytes dk = pbkdf2Sha256(fromTextS("passwd"),
                                      reinterpret_cast<const uint8_t *>("salt"),
                                      4, 1, 64);
        CHECK(equalsHex(dk,
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"));
    }
    {
        SecureBytes dk = pbkdf2Sha256(fromTextS("Password"),
                                      reinterpret_cast<const uint8_t *>("NaCl"),
                                      4, 80000, 64);
        CHECK(equalsHex(dk,
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
            "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"));
    }
}

// RFC 5869 Appendix A.1 and A.2 (SHA-256): PRK -> OKM is exactly the
// expand-only mode we use.
// https://www.rfc-editor.org/rfc/rfc5869.txt
void testHkdfRfc5869()
{
    {
        SecureBytes prk = fromHexS(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        std::vector<uint8_t> info = fromHex("f0f1f2f3f4f5f6f7f8f9");
        SecureBytes okm = hkdfExpandSha256(
            prk, std::string(info.begin(), info.end()), 42);
        CHECK(equalsHex(okm,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"));
    }
    {
        SecureBytes prk = fromHexS(
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
        std::vector<uint8_t> info = fromHex(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        SecureBytes okm = hkdfExpandSha256(
            prk, std::string(info.begin(), info.end()), 82);
        CHECK(equalsHex(okm,
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f1d87"));
    }
}

// RFC 4231 test cases 1, 2 and 6 for HMAC-SHA-256.
// https://www.rfc-editor.org/rfc/rfc4231.txt
void testHmacRfc4231()
{
    {
        SecureBytes key = fromHexS("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        const std::string data = "Hi There";
        std::vector<uint8_t> mac = hmacSha256(
            key, reinterpret_cast<const uint8_t *>(data.data()), data.size());
        CHECK(toHex(mac.data(), mac.size()) ==
              "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }
    {
        SecureBytes key = fromTextS("Jefe");
        const std::string data = "what do ya want for nothing?";
        std::vector<uint8_t> mac = hmacSha256(
            key, reinterpret_cast<const uint8_t *>(data.data()), data.size());
        CHECK(toHex(mac.data(), mac.size()) ==
              "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }
    {
        SecureBytes key(131);
        std::memset(key.data(), 0xaa, key.size());
        const std::string data =
            "Test Using Larger Than Block-Size Key - Hash Key First";
        std::vector<uint8_t> mac = hmacSha256(
            key, reinterpret_cast<const uint8_t *>(data.data()), data.size());
        CHECK(toHex(mac.data(), mac.size()) ==
              "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }
}

// Argon2id KAT from the vendored reference implementation's own test suite
// (password+salt only; the RFC 9106 §5.3 vector needs secret/AD inputs the
// simple API does not expose).
// https://github.com/P-H-C/phc-winner-argon2/blob/f57e61e/src/test.c
void testArgon2idKat()
{
    SecureBytes out = argon2id(fromTextS("password"),
                               reinterpret_cast<const uint8_t *>("somesalt"),
                               8, /*iterations=*/2, /*memoryMiB=*/64,
                               /*parallelism=*/1, 32);
    CHECK(equalsHex(out,
        "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"));
}

// NIST SP 800-38A F.2.5 CBC-AES256.Encrypt (4 blocks, no padding involved:
// we encrypt the 64-byte plaintext and compare the first 4 output blocks;
// block 5 is PKCS#7 padding and not part of the NIST vector).
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
void testAesCbcNist()
{
    SymmetricKey key;
    key.encKey = fromHexS(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    key.macKey = SecureBytes(32); // irrelevant to the cipher check
    const std::vector<uint8_t> iv =
        fromHex("000102030405060708090a0b0c0d0e0f");
    SecureBytes plaintext = fromHexS(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710");
    EncString enc = encryptAes256CbcHmacWithIv(plaintext, key, iv.data());
    CHECK(enc.ciphertext.size() == 80); // 64 data + 16 padding
    CHECK(toHex(enc.ciphertext.data(), 64) ==
        "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
        "9cfc4e967edb808d679f777bc6702c7d"
        "39f23369a9d9bacfa530e26304231461"
        "b2eb05e2c39be9fcda6c19078c6a9d1b");
    // And it round-trips through our own decrypt.
    CHECK(decryptAes256CbcHmac(enc, key) == plaintext);
}

// --- Tier 2: Bitwarden protocol composition ---
// All vectors from bitwarden/sdk-internal @ 4963a281, crate bitwarden-crypto.

// kdf.rs test_master_key_derive_pbkdf2 + utils.rs test_stretch_kdf_key:
// master key derivation chained into the HKDF enc/mac stretch.
void testBitwardenMasterKeyPbkdf2AndStretch()
{
    KdfParams params;
    params.type = KdfType::Pbkdf2Sha256;
    params.iterations = 10000;
    SecureBytes masterKey = deriveMasterKey(fromTextS("67t9b5g67$%Dh89n"),
                                            "test_key", params);
    CHECK(equalsHex(masterKey,
        "1f4f68e29647b15ac250acd1118184518aa745a7fe95021b27c5402a16c3564b"));

    SymmetricKey stretched = stretchMasterKey(masterKey);
    CHECK(equalsHex(stretched.encKey,
        "6f1fb22dee9825728fd77c5387adc3178e8678f93d84a3b671c5bdccbc15ed60"));
    CHECK(equalsHex(stretched.macKey,
        "dd7fceea651bca265634221c4e1cb910303d7fa6d1f7c257e81a3055c1f9b39b"));
}

// kdf.rs test_master_key_derive_argon2 (salt fed to Argon2 is SHA-256 of the
// email — deriveMasterKey handles that internally).
void testBitwardenMasterKeyArgon2id()
{
    KdfParams params;
    params.type = KdfType::Argon2id;
    params.iterations = 4;
    params.memoryMiB = 32;
    params.parallelism = 2;
    SecureBytes masterKey = deriveMasterKey(fromTextS("67t9b5g67$%Dh89n"),
                                            "test_key", params);
    CHECK(equalsHex(masterKey,
        "cff0e1b1a213a34c626ab3afe00911f01493ed2ff6968db83ee183f23335e1f2"));
}

// master_key.rs test_password_hash_pbkdf2 / test_password_hash_argon2id,
// and master_password.rs test_master_password_authentication_data_derive:
// the server authorization hash (PBKDF2 with masterKey/password swapped).
void testBitwardenMasterPasswordHash()
{
    {
        KdfParams params;
        params.type = KdfType::Pbkdf2Sha256;
        params.iterations = 100000;
        SecureBytes password = fromTextS("asdfasdf");
        SecureBytes masterKey =
            deriveMasterKey(password, "test@bitwarden.com", params);
        SecureBytes hash = deriveMasterPasswordHash(masterKey, password);
        CHECK(base64Encode(hash.data(), hash.size()) ==
              "wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw=");
    }
    {
        KdfParams params;
        params.type = KdfType::Argon2id;
        params.iterations = 4;
        params.memoryMiB = 32;
        params.parallelism = 2;
        SecureBytes password = fromTextS("asdfasdf");
        SecureBytes masterKey = deriveMasterKey(password, "test_salt", params);
        SecureBytes hash = deriveMasterPasswordHash(masterKey, password);
        CHECK(base64Encode(hash.data(), hash.size()) ==
              "PR6UjYmjmppTYcdyTiNbAhPJuQQOmynKbdEl1oyi/iQ=");
    }
    {
        // The current default cloud configuration: PBKDF2, 600k iterations.
        KdfParams params;
        params.type = KdfType::Pbkdf2Sha256;
        params.iterations = 600000;
        SecureBytes password = fromTextS("test_password");
        SecureBytes masterKey =
            deriveMasterKey(password, "test@example.com", params);
        SecureBytes hash = deriveMasterPasswordHash(masterKey, password);
        CHECK(base64Encode(hash.data(), hash.size()) ==
              "Lyry95vlXEJ5FE0EXjeR9zgcsFSU0qGhP9l5X2jwE38=");
    }
}

// util.rs test_hkdf_expand: the generic expand-only primitive with a 64-byte
// output, exactly as we use it.
void testBitwardenHkdfExpand()
{
    SecureBytes prk = fromHexS(
        "17987829d6109c8547e2b287d0ff4265bd46ad1e27d7afec26b4b43ec4049f46");
    SecureBytes okm = hkdfExpandSha256(prk, "info", 64);
    CHECK(equalsHex(okm,
        "06722a2657e71e6d1eff6881ff5e5c6c7c91d7d0113c8716469e28352db6083f"
        "4157efeab9e3997a73cd903866955c8bd96677392539fbb212345e4d84d7ef64"));
}

// pure_crypto.rs test_symmetric_decrypt: a literal 64-byte symmetric key and
// a real EncString produced by the official client.
void testBitwardenEncStringDecrypt()
{
    SecureBytes raw = fromHexS(
        "518e01e4de03038522b0234296066d46be952f2f591790575c2edc0d946aa2ea"
        "ca8b882110c80849b0acb9bbe00a41dfe4365cb508d5a2dd75fef56f37d34d1d");
    SymmetricKey key = symmetricKeyFromBytes(raw);

    EncString enc = EncString::parse(
        "2.Dh7AFLXR+LXcxUaO5cRjpg==|uXyhubjAoNH8lTdy/zgJDQ==|"
        "cHEMboj0MYsU5yDRQ1rLCgxcjNbKRc1PWKuv8bpU5pM=");
    SecureBytes plain = decryptAes256CbcHmac(enc, key);
    CHECK(std::string(reinterpret_cast<const char *>(plain.data()),
                      plain.size()) == "test");

    // And our own encrypt with the same key produces something the same
    // decrypt path accepts (round-trip through the official key material).
    EncString reenc = encryptAes256CbcHmac(fromTextS("test"), key);
    SecureBytes replain = decryptAes256CbcHmac(reenc, key);
    CHECK(std::string(reinterpret_cast<const char *>(replain.data()),
                      replain.size()) == "test");
}

} // namespace

void runVectorTests()
{
    testPbkdf2Rfc7914();
    testHkdfRfc5869();
    testHmacRfc4231();
    testArgon2idKat();
    testAesCbcNist();
    testBitwardenMasterKeyPbkdf2AndStretch();
    testBitwardenMasterKeyArgon2id();
    testBitwardenMasterPasswordHash();
    testBitwardenHkdfExpand();
    testBitwardenEncStringDecrypt();
}
