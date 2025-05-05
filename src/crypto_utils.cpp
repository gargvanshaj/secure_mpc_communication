#include "crypto_utils.h"
#include <stdexcept>
#include <fstream>
#include <iostream>
#include "trezor-firmware/crypto/secp256k1.h"
#include "trezor-firmware/crypto/sha2.h"
#include "secp256k1.h"
#include "ecdsa.h"

const ecdsa_curve nist256p1 = {
    /* .prime */ {/*.val =*/{0x1fffffff, 0x1fffffff, 0x1fffffff, 0x000001ff,
                             0x00000000, 0x00000000, 0x00040000, 0x1fe00000,
                             0xffffff}},

    /* G */
    {/*.x =*/{/*.val =*/{0x1898c296, 0x0509ca2e, 0x1acce83d, 0x06fb025b,
                         0x040f2770, 0x1372b1d2, 0x091fe2f3, 0x1e5c2588,
                         0x6b17d1}},
     /*.y =*/{/*.val =*/{0x17bf51f5, 0x1db20341, 0x0c57b3b2, 0x1c66aed6,
                         0x19e162bc, 0x15a53e07, 0x1e6e3b9f, 0x1c5fc34f,
                         0x4fe342}}},

    /* order */
    {/*.val =*/{0x1c632551, 0x1dce5617, 0x05e7a13c, 0x0df55b4e, 0x1ffffbce,
                0x1fffffff, 0x0003ffff, 0x1fe00000, 0xffffff}},

    /* order_half */
    {/*.val =*/{0x1e3192a8, 0x0ee72b0b, 0x02f3d09e, 0x06faada7, 0x1ffffde7,
                0x1fffffff, 0x0001ffff, 0x1ff00000, 0x7fffff}},

    /* a */ -3,

    /* b */
    {/*.val =*/{0x07d2604b, 0x1e71e1f1, 0x14ec3d8e, 0x1a0d6198, 0x086bc651,
                0x1eaabb4c, 0x0f9ecfae, 0x1b154752, 0x005ac635}}

#if USE_PRECOMPUTED_CP
    ,
    /* cp */
    {
#include "nist256p1.table"
    }
#endif
};

const curve_info nist256p1_info = {
    .bip32_name = "Nist256p1 seed",
    .params = &nist256p1,
    .hasher_base58 = HASHER_SHA2D,
    .hasher_sign = HASHER_SHA2D,
    .hasher_pubkey = HASHER_SHA2_RIPEMD,
    .hasher_script = HASHER_SHA2,
};

// --- Hashing ---
std::vector<uint8_t> sha256(const std::vector<uint8_t> &data)
{
    std::vector<uint8_t> hash(HASH_SIZE);
    sha256_Raw(data.data(), data.size(), hash.data());
    return hash;
}

std::vector<uint8_t> sha256(const std::string &data)
{
    std::vector<uint8_t> hash(HASH_SIZE);
    sha256_Raw(reinterpret_cast<const uint8_t *>(data.c_str()), data.length(), hash.data());
    return hash;
}

// --- Key Loading ---
std::vector<uint8_t> loadPrivateKeyBytes(const std::string &file_path)
{
    std::ifstream keyFile(file_path, std::ios::binary | std::ios::ate); // Open at the end
    if (!keyFile)
    {
        throw std::runtime_error("Failed to open private key file: " + file_path);
    }

    std::streamsize size = keyFile.tellg();
    keyFile.seekg(0, std::ios::beg); // Go back to the beginning

    if (size != PRIVATE_KEY_SIZE)
    {
        keyFile.close();
        throw std::runtime_error("Invalid private key file size: " + std::to_string(size) + " for " + file_path + ". Expected " + std::to_string(PRIVATE_KEY_SIZE));
    }

    std::vector<uint8_t> keyBytes(PRIVATE_KEY_SIZE);
    if (!keyFile.read(reinterpret_cast<char *>(keyBytes.data()), PRIVATE_KEY_SIZE))
    {
        keyFile.close();
        throw std::runtime_error("Failed to read private key file: " + file_path);
    }
    keyFile.close();
    return keyBytes;
}

std::vector<uint8_t> loadPublicKeyBytes(const std::string &file_path)
{
    std::ifstream keyFile(file_path, std::ios::binary | std::ios::ate);
    if (!keyFile)
    {
        throw std::runtime_error("Failed to open public key file: " + file_path);
    }

    std::streamsize size = keyFile.tellg();
    keyFile.seekg(0, std::ios::beg);

    if (size != PUBLIC_KEY_SIZE)
    {
        keyFile.close();
        throw std::runtime_error("Invalid public key file size: " + std::to_string(size) + " for " + file_path + ". Expected " + std::to_string(PUBLIC_KEY_SIZE));
    }

    std::vector<uint8_t> keyBytes(PUBLIC_KEY_SIZE);
    if (!keyFile.read(reinterpret_cast<char *>(keyBytes.data()), PUBLIC_KEY_SIZE))
    {
        keyFile.close();
        throw std::runtime_error("Failed to read public key file: " + file_path);
    }
    keyFile.close();

    // Basic validation: Check for uncompressed key prefix
    if (keyBytes[0] != 0x04)
    {
        throw std::runtime_error("Public key file does not contain an uncompressed key (missing 0x04 prefix): " + file_path);
    }
    return keyBytes;
}

// --- Key Derivation ---
std::vector<uint8_t> derivePublicKey(const std::vector<uint8_t> &privateKey)
{
    if (privateKey.size() != PRIVATE_KEY_SIZE)
    {
        throw std::invalid_argument("Invalid private key size (" + std::to_string(privateKey.size()) + ") for public key derivation.");
    }
    std::vector<uint8_t> publicKeyBytes(PUBLIC_KEY_SIZE);

    // Call ecdsa_get_public_key65. It has a void return type.
    // We assume it succeeds if it returns. Robust error handling might
    // involve checking internal states if the library provides such mechanisms.
    if (ecdsa_get_public_key65(&secp256k1, privateKey.data(), publicKeyBytes.data(), nullptr, nullptr) != 0)
    {
        throw std::runtime_error("ECDSA signing failed (ecdsa_sign_digest returned non-zero).");
    }

    // Add a basic check if the derived key seems invalid (e.g., still zeroed)
    bool all_zero = true;
    for (uint8_t byte : publicKeyBytes)
    {
        if (byte != 0)
        {
            all_zero = false;
            break;
        }
    }
    if (all_zero || publicKeyBytes[0] != 0x04)
    {
        throw std::runtime_error("Failed to derive a valid public key (result invalid or zeroed).");
    }

    return publicKeyBytes;
}

// --- ECDSA Operations ---
std::vector<uint8_t> ecdsaSign(const std::vector<uint8_t> &hash, const std::vector<uint8_t> &privateKey)
{
    if (hash.size() != HASH_SIZE)
    {
        throw std::invalid_argument("Hash size must be " + std::to_string(HASH_SIZE) + " bytes.");
    }
    if (privateKey.size() != PRIVATE_KEY_SIZE)
    {
        throw std::invalid_argument("Private key size must be " + std::to_string(PRIVATE_KEY_SIZE) + " bytes.");
    }

    std::vector<uint8_t> signature(SIGNATURE_SIZE);
    // Use ecdsa_sign_digest which produces the 64-byte r||s format directly
    // Calls the Trezor C function, passing the curve parameters (&secp256k1)
    if (ecdsa_sign_digest(&secp256k1, privateKey.data(), hash.data(), signature.data(), nullptr, nullptr) != 0)
    {
        throw std::runtime_error("ECDSA signing failed (ecdsa_sign_digest returned non-zero).");
    }

    return signature;
}

bool ecdsaVerify(const std::vector<uint8_t> &hash, const std::vector<uint8_t> &signature, const std::vector<uint8_t> &publicKey)
{
    if (hash.size() != HASH_SIZE)
    {
        std::cerr << "Warning: Verifying hash of size " << hash.size() << " (expected " << HASH_SIZE << ")" << std::endl;
    }
    if (signature.size() != SIGNATURE_SIZE)
    {
        std::cerr << "Error: Raw signature size is " << signature.size() << ", expected " << SIGNATURE_SIZE << std::endl;
        return false;
    }
    if (publicKey.size() != PUBLIC_KEY_SIZE)
    {
        std::cerr << "Error: Public key size is " << publicKey.size() << ", expected " << PUBLIC_KEY_SIZE << " (uncompressed)" << std::endl;
        return false;
    }
    if (publicKey[0] != 0x04)
    {
        std::cerr << "Error: Public key does not appear to be uncompressed (missing 0x04 prefix)." << std::endl;
        return false;
    }

    // Use ecdsa_verify_digest with the raw signature format
    // It returns 0 for success, non-zero for failure.
    int result = ecdsa_verify_digest(&secp256k1, publicKey.data(), signature.data(), hash.data());

    return (result == 0);
}

// --- Random Number Generation ---
std::vector<uint8_t> generateRandomBytes(size_t len)
{
    if (len == 0)
    {
        return {};
    }
    std::vector<uint8_t> buf(len);
    // random_buffer fills the buffer with random bytes. No explicit error return.
    random_buffer(buf.data(), len);
    return buf;
}