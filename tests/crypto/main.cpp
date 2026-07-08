#include <cstdio>

#include "crypto.h"
#include "../check.h"

void runSecureBytesTests();
void runBase64Tests();
void runEncStringTests();
void runKdfBoundsTests();
void runVectorTests();
void runRsaTests();

int main()
{
    CHECK(std::string(BitVault::Crypto::version()) == "0.1.0");

    runSecureBytesTests();
    std::printf("securebytes: OK\n");
    runBase64Tests();
    std::printf("base64: OK\n");
    runEncStringTests();
    std::printf("encstring: OK\n");
    runKdfBoundsTests();
    std::printf("kdf bounds: OK\n");
    runVectorTests();
    std::printf("known-answer vectors: OK\n");
    runRsaTests();
    std::printf("rsa oaep: OK\n");

    std::printf("crypto_tests: all checks passed\n");
    return 0;
}
