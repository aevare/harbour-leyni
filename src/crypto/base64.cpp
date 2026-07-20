#include "base64.h"

#include "crypto.h"

namespace Leyni {
namespace Crypto {

namespace {

const char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// 255 marks characters outside the alphabet.
uint8_t decodeChar(char c)
{
    if (c >= 'A' && c <= 'Z') return static_cast<uint8_t>(c - 'A');
    if (c >= 'a' && c <= 'z') return static_cast<uint8_t>(c - 'a' + 26);
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    return 255;
}

} // namespace

std::string base64Encode(const uint8_t *data, size_t len)
{
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        uint32_t v = (static_cast<uint32_t>(data[i]) << 16)
                   | (static_cast<uint32_t>(data[i + 1]) << 8)
                   | data[i + 2];
        out.push_back(kAlphabet[(v >> 18) & 63]);
        out.push_back(kAlphabet[(v >> 12) & 63]);
        out.push_back(kAlphabet[(v >> 6) & 63]);
        out.push_back(kAlphabet[v & 63]);
    }
    if (i + 1 == len) {
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        out.push_back(kAlphabet[(v >> 18) & 63]);
        out.push_back(kAlphabet[(v >> 12) & 63]);
        out.push_back('=');
        out.push_back('=');
    } else if (i + 2 == len) {
        uint32_t v = (static_cast<uint32_t>(data[i]) << 16)
                   | (static_cast<uint32_t>(data[i + 1]) << 8);
        out.push_back(kAlphabet[(v >> 18) & 63]);
        out.push_back(kAlphabet[(v >> 12) & 63]);
        out.push_back(kAlphabet[(v >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

std::vector<uint8_t> base64Decode(const std::string &text)
{
    if (text.size() % 4 != 0) {
        throw CryptoError("base64Decode: length not a multiple of 4");
    }
    std::vector<uint8_t> out;
    if (text.empty()) {
        return out;
    }
    out.reserve((text.size() / 4) * 3);

    size_t padding = 0;
    if (text[text.size() - 1] == '=') padding++;
    if (text[text.size() - 2] == '=') padding++;

    for (size_t i = 0; i < text.size(); i += 4) {
        uint32_t v = 0;
        int validChars = 0;
        for (size_t j = 0; j < 4; ++j) {
            char c = text[i + j];
            if (c == '=') {
                // '=' is only valid as the final padding characters.
                if (i + j < text.size() - padding) {
                    throw CryptoError("base64Decode: unexpected padding");
                }
                v <<= 6;
                continue;
            }
            uint8_t d = decodeChar(c);
            if (d == 255) {
                throw CryptoError("base64Decode: invalid character");
            }
            v = (v << 6) | d;
            validChars++;
        }
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        if (validChars >= 3) {
            out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        }
        if (validChars == 4) {
            out.push_back(static_cast<uint8_t>(v & 0xff));
        }
    }
    return out;
}

} // namespace Crypto
} // namespace Leyni
