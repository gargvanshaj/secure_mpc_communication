#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <vector>
#include <string>
#include <cstddef>
#include <cstdint>

#include "ecdsa.h"
#include "curves.h" // Provides secp256k1 definition
#include "sha2.h"
#include "rand.h"

#include <stdint.h>

#include "bip32.h"

extern const ecdsa_curve nist256p1;
extern const curve_info nist256p1_info;

// --- Constants ---
const size_t HASH_SIZE = 32;        // SHA-256 output size
const size_t SIGNATURE_SIZE = 64;   // ECDSA raw signature (r||s) size for secp256k1
const size_t PRIVATE_KEY_SIZE = 32; // secp256k1 private key size
const size_t PUBLIC_KEY_SIZE = 65;  // secp256k1 public key size (uncompressed 0x04 || x || y)

// --- Hashing ---
std::vector<uint8_t> sha256(const std::vector<uint8_t> &data);
std::vector<uint8_t> sha256(const std::string &data);

// --- Key Loading ---
std::vector<uint8_t> loadPrivateKeyBytes(const std::string &file_path);
std::vector<uint8_t> loadPublicKeyBytes(const std::string &file_path);

// --- Key Derivation ---
std::vector<uint8_t> derivePublicKey(const std::vector<uint8_t> &privateKey);

// --- ECDSA Operations (secp256k1, Raw Signature r||s) ---
std::vector<uint8_t> ecdsaSign(const std::vector<uint8_t> &hash, const std::vector<uint8_t> &privateKey);
bool ecdsaVerify(const std::vector<uint8_t> &hash, const std::vector<uint8_t> &signature, const std::vector<uint8_t> &publicKey);

// --- Random Number Generation ---
std::vector<uint8_t> generateRandomBytes(size_t len);

#endif // CRYPTO_UTILS_H