# Vendored: Argon2 reference implementation

- Upstream: https://github.com/P-H-C/phc-winner-argon2
- Release: `20190702` (tag), the latest upstream release
- License: CC0 1.0 / Apache 2.0 dual (see LICENSE)
- Files: `include/argon2.h`, and from `src/`: `argon2.c core.c core.h encoding.c
  encoding.h ref.c thread.c thread.h blake2/` — copied verbatim, zero modifications.
  The optimized backend (`opt.c`, SSE/AVX) is intentionally NOT vendored; we build
  the portable `ref.c` backend so the same code runs on armv7hl, aarch64, and x86.

To verify this copy against upstream:

```
curl -fsSL https://github.com/P-H-C/phc-winner-argon2/archive/refs/tags/20190702.tar.gz | tar xz
diff -r phc-winner-argon2-20190702/src/blake2 third_party/argon2/blake2
for f in argon2.c core.c core.h encoding.c encoding.h ref.c thread.c thread.h; do
  diff phc-winner-argon2-20190702/src/$f third_party/argon2/$f
done
diff phc-winner-argon2-20190702/include/argon2.h third_party/argon2/argon2.h
```
