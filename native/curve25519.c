#include <string.h>
#include <stdint.h>

#include "curve25519-donna.h"
#include "curve_sigs.h"
#include "xeddsa.h"
#include "internal_fast_tests.h"
#include "gen_x.h"

void generatePrivateKey(uint8_t random[]) {
    random[0] &= 248;
    random[31] &= 127;
    random[31] |= 64;
}

void generatePublicKey(uint8_t publicKey[], uint8_t privateKey[]) {
    static const uint8_t  basepoint[32] = {9};
    curve25519_donna(publicKey, privateKey, basepoint);
}

void calculateAgreement(uint8_t sharedKey[], uint8_t privateKey[], uint8_t publicKey[]) {
    curve25519_donna(sharedKey, privateKey, publicKey);
}

int calculateSignature(uint8_t signature[], uint8_t random[], uint8_t privateKey[], uint8_t message[], uint64_t messageLength) {
    return xed25519_sign(signature, privateKey, message, messageLength, random);
}

int verifySignature(uint8_t publicKey[], uint8_t message[], uint64_t messageLength, uint8_t signature[]) {
    return curve25519_verify(signature, publicKey, message, messageLength);
}

int calculateVrfSignature(uint8_t signature[], uint8_t random[], uint8_t privateKey[], uint8_t message[], uint64_t messageLength) {
    return generalized_xveddsa_25519_sign(signature, privateKey, message, messageLength, random, NULL, 0);
}

int verifyVrfSignature(uint8_t vrf[], uint8_t publicKey[], uint8_t message[], uint64_t messageLength, uint8_t signature[]) {
    return generalized_xveddsa_25519_verify(vrf, signature, publicKey, message, messageLength, NULL, 0);
}

int smokeCheck(int dummy) {
    return 0;
}

int internalTest() {
    return all_fast_tests(1);
}
