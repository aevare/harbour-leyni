// SecureBytes: the only container allowed to hold secrets (keys, passwords,
// decrypted key material). Memory is mlock()ed on allocation (best-effort)
// and explicitly zeroed on destruction. Move-only, so a secret has exactly
// one owner. Deliberately has NO conversion to std::string or QString —
// upper layers cannot accidentally copy a secret into unzeroed memory.
#pragma once

#include <cstddef>
#include <cstdint>

namespace BitVault {
namespace Crypto {

// Zeroes n bytes at p in a way the compiler must not optimize away.
void secureZero(void *p, size_t n);

// Constant-time equality; safe for comparing MACs and keys.
// Returns false on length mismatch (lengths are not secret).
bool constantTimeEqual(const uint8_t *a, const uint8_t *b, size_t n);

class SecureBytes
{
public:
    SecureBytes();                                  // empty, no allocation
    explicit SecureBytes(size_t size);              // zero-filled
    SecureBytes(const uint8_t *data, size_t size);  // copies data
    ~SecureBytes();

    SecureBytes(SecureBytes &&other) noexcept;
    SecureBytes &operator=(SecureBytes &&other) noexcept;
    SecureBytes(const SecureBytes &) = delete;
    SecureBytes &operator=(const SecureBytes &) = delete;

    uint8_t *data() { return m_data; }
    const uint8_t *data() const { return m_data; }
    size_t size() const { return m_size; }
    bool empty() const { return m_size == 0; }

    bool operator==(const SecureBytes &other) const; // constant-time
    bool operator!=(const SecureBytes &other) const { return !(*this == other); }

private:
    void allocate(size_t size);
    void release();

    uint8_t *m_data;
    size_t m_size;
};

} // namespace Crypto
} // namespace BitVault
