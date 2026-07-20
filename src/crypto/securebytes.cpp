#include "securebytes.h"

#include <cstdlib>
#include <cstring>
#include <new>

#include <sys/mman.h>

namespace Leyni {
namespace Crypto {

void secureZero(void *p, size_t n)
{
    if (p == nullptr || n == 0) {
        return;
    }
#if defined(__GLIBC__)
    explicit_bzero(p, n);
#else
    // Volatile pointer writes cannot be elided by the optimizer.
    volatile uint8_t *vp = static_cast<volatile uint8_t *>(p);
    while (n--) {
        *vp++ = 0;
    }
#endif
}

bool constantTimeEqual(const uint8_t *a, const uint8_t *b, size_t n)
{
    if (a == nullptr || b == nullptr) {
        return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

SecureBytes::SecureBytes()
    : m_data(nullptr)
    , m_size(0)
{
}

SecureBytes::SecureBytes(size_t size)
    : m_data(nullptr)
    , m_size(0)
{
    allocate(size);
}

SecureBytes::SecureBytes(const uint8_t *data, size_t size)
    : m_data(nullptr)
    , m_size(0)
{
    allocate(size);
    if (m_size > 0) {
        std::memcpy(m_data, data, m_size);
    }
}

SecureBytes::~SecureBytes()
{
    release();
}

SecureBytes::SecureBytes(SecureBytes &&other) noexcept
    : m_data(other.m_data)
    , m_size(other.m_size)
{
    other.m_data = nullptr;
    other.m_size = 0;
}

SecureBytes &SecureBytes::operator=(SecureBytes &&other) noexcept
{
    if (this != &other) {
        release();
        m_data = other.m_data;
        m_size = other.m_size;
        other.m_data = nullptr;
        other.m_size = 0;
    }
    return *this;
}

bool SecureBytes::operator==(const SecureBytes &other) const
{
    if (m_size != other.m_size) {
        return false;
    }
    if (m_size == 0) {
        return true;
    }
    return constantTimeEqual(m_data, other.m_data, m_size);
}

void SecureBytes::allocate(size_t size)
{
    if (size == 0) {
        return;
    }
    m_data = static_cast<uint8_t *>(std::calloc(size, 1));
    if (m_data == nullptr) {
        throw std::bad_alloc();
    }
    m_size = size;
    // Best-effort: keeps the secret out of swap. Failure (RLIMIT_MEMLOCK)
    // is not fatal — the alternative would be refusing to run at all.
    mlock(m_data, m_size);
}

void SecureBytes::release()
{
    if (m_data != nullptr) {
        secureZero(m_data, m_size);
        munlock(m_data, m_size);
        std::free(m_data);
        m_data = nullptr;
    }
    m_size = 0;
}

} // namespace Crypto
} // namespace Leyni
