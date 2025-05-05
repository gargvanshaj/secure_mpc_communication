#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <fstream>
#include <cstring>

// --- Project Headers ---
#include "auth.pb.h"       // Nanopb generated header
#include "nanopb_utils.h"  // Our Nanopb helpers
#include "network_utils.h" // Boost Asio network helpers with framing

// --- Trezor Headers (within extern "C") ---
#ifdef __cplusplus
extern "C"
{
#endif
#include <ecdsa.h>
#include <curves.h> // Declares secp256k1 as extern const ecdsa_curve
#include <sha2.h>
#include <rand.h>
#ifdef __cplusplus
} // extern "C"
#endif

// --- Explicit extern "C" declaration for the global variable ---
// Make the C global variable 'secp256k1' visible to C++ code
#ifdef __cplusplus
extern "C"
{
#endif
    extern const ecdsa_curve secp256k1;
#ifdef __cplusplus
} // extern "C"
#endif

// --- Crypto Constants ---
const size_t HASH_SIZE = 32;
const size_t SIGNATURE_SIZE = 64;
const size_t PRIVATE_KEY_SIZE = 32;
const size_t PUBLIC_KEY_SIZE = 65;
// --- End of Crypto Constants ---

// --- Crypto Helper Functions (Implementations) ---
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
std::vector<uint8_t> loadPrivateKeyBytes(const std::string &file_path)
{
    std::ifstream keyFile(file_path, std::ios::binary | std::ios::ate);
    if (!keyFile)
        throw std::runtime_error("Failed to open private key file: " + file_path);
    std::streamsize size = keyFile.tellg();
    keyFile.seekg(0, std::ios::beg);
    if (size != PRIVATE_KEY_SIZE)
    {
        keyFile.close();
        throw std::runtime_error("Invalid private key file size: " + std::to_string(size) + " for " + file_path);
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
        throw std::runtime_error("Failed to open public key file: " + file_path);
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
    if (keyBytes[0] != 0x04)
        throw std::runtime_error("Public key file does not contain an uncompressed key (missing 0x04 prefix): " + file_path);
    return keyBytes;
}
std::vector<uint8_t> derivePublicKey(const std::vector<uint8_t> &privateKey)
{
    if (privateKey.size() != PRIVATE_KEY_SIZE)
        throw std::invalid_argument("Invalid private key size (" + std::to_string(privateKey.size()) + ") for public key derivation.");
    std::vector<uint8_t> publicKeyBytes(PUBLIC_KEY_SIZE);
    ecdsa_get_public_key65(&secp256k1, privateKey.data(), publicKeyBytes.data());
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
        throw std::runtime_error("Failed to derive a valid public key (result invalid or zeroed).");
    return publicKeyBytes;
}
std::vector<uint8_t> ecdsaSign(const std::vector<uint8_t> &hash, const std::vector<uint8_t> &privateKey)
{
    if (hash.size() != HASH_SIZE)
        throw std::invalid_argument("Hash size must be " + std::to_string(HASH_SIZE) + " bytes.");
    if (privateKey.size() != PRIVATE_KEY_SIZE)
        throw std::invalid_argument("Private key size must be " + std::to_string(PRIVATE_KEY_SIZE) + " bytes.");
    std::vector<uint8_t> signature(SIGNATURE_SIZE);
    if (ecdsa_sign_digest(&secp256k1, privateKey.data(), hash.data(), signature.data(), nullptr, nullptr) != 0)
    {
        throw std::runtime_error("ECDSA signing failed (ecdsa_sign_digest returned non-zero).");
    }
    return signature;
}
bool ecdsaVerify(const std::vector<uint8_t> &hash, const std::vector<uint8_t> &signature, const std::vector<uint8_t> &publicKey)
{
    if (hash.size() != HASH_SIZE)
        std::cerr << "Warning: Verifying hash of size " << hash.size() << std::endl;
    if (signature.size() != SIGNATURE_SIZE)
    {
        std::cerr << "Error: Signature size " << signature.size() << std::endl;
        return false;
    }
    if (publicKey.size() != PUBLIC_KEY_SIZE)
    {
        std::cerr << "Error: Public key size " << publicKey.size() << std::endl;
        return false;
    }
    if (publicKey[0] != 0x04)
    {
        std::cerr << "Error: Public key not uncompressed." << std::endl;
        return false;
    }
    int result = ecdsa_verify_digest(&secp256k1, publicKey.data(), signature.data(), hash.data());
    return (result == 0);
}
std::vector<uint8_t> generateRandomBytes(size_t len)
{
    if (len == 0)
        return {};
    std::vector<uint8_t> buf(len);
    random_buffer(buf.data(), len); // Depends on random32 being linked
    return buf;
}
// --- End of Crypto Helper Functions ---

namespace ip = boost::asio::ip;
using tcp = ip::tcp;

// --- Configuration ---
const std::string CLIENT_SERIAL_ID = "CLIENT_SN_001";
const std::string CLIENT_PRIVATE_KEY_FILE = "../../keys/client_private_key.bin";
const std::string SERVER_PUBLIC_KEY_FILE = "../../keys/server_public_key.bin";
const std::string SERVER_ADDRESS = "127.0.0.1";
const short SERVER_PORT = 9999;

// --- Authentication Logic ---
bool performClientAuthentication(
    tcp::socket &socket,
    const std::string &serial_id_str,
    const std::vector<uint8_t> &clientPrivKey,
    const std::vector<uint8_t> &serverPubKey)
{
    try
    {
        std::cout << "Starting authentication for SN: " << serial_id_str << std::endl;

        // 1. Client -> Server: Send ClientHello
        std::cout << "   [1] Generating ClientHello..." << std::endl;
        ClientHello helloMsg = ClientHello_init_zero;
        strncpy(helloMsg.serial_id, serial_id_str.c_str(), sizeof(helloMsg.serial_id) - 1);
        helloMsg.serial_id[sizeof(helloMsg.serial_id) - 1] = '\0';

        std::vector<uint8_t> serialHash = sha256(serial_id_str);
        std::vector<uint8_t> clientSigOnSerial = ecdsaSign(serialHash, clientPrivKey);

        if (!setNanopbBytes(&helloMsg.signature, clientSigOnSerial))
        {
            throw std::runtime_error("Failed to set signature bytes in ClientHello");
        }
        std::vector<uint8_t> helloEncoded = encodeClientHello(helloMsg);
        std::cout << "   [1] Sending ClientHello (" << helloEncoded.size() << " bytes)..." << std::endl;
        sendFramedData(socket, helloEncoded);

        // 2. Client <- Server: Receive ServerChallenge
        std::cout << "   [2] Waiting for ServerChallenge..." << std::endl;
        std::vector<uint8_t> challengeEncoded = receiveFramedData(socket);
        if (challengeEncoded.empty())
        {
            std::cerr << "Error: Server disconnected or sent empty challenge." << std::endl;
            return false;
        }
        std::cout << "   [2] Received ServerChallenge (" << challengeEncoded.size() << " bytes)." << std::endl;
        ServerChallenge challengeMsg = ServerChallenge_init_zero;
        if (!decodeServerChallenge(challengeEncoded, challengeMsg))
        {
            std::cerr << "Error: Failed to decode ServerChallenge." << std::endl;
            return false;
        }
        std::vector<uint8_t> nonce = getNanopbBytes(&challengeMsg.nonce);
        std::vector<uint8_t> serverSigOnNonce = getNanopbBytes(&challengeMsg.server_signature);
        if (nonce.empty())
        {
            std::cerr << "Error: Invalid nonce received." << std::endl;
            return false;
        }
        if (serverSigOnNonce.size() != SIGNATURE_SIZE)
        {
            std::cerr << "Error: Invalid server signature size." << std::endl;
            return false;
        }
        std::cout << "   [2] Nonce received (" << nonce.size() << " bytes)." << std::endl;

        // 3. Client: Verify Server's Signature
        std::cout << "   [3] Verifying server signature..." << std::endl;
        std::vector<uint8_t> nonceHash = sha256(nonce);
        if (!ecdsaVerify(nonceHash, serverSigOnNonce, serverPubKey))
        {
            std::cerr << "Error: Server signature verification failed!" << std::endl;
            return false;
        }
        std::cout << "   [3] Server signature verified." << std::endl;

        // 4. Client -> Server: Send ClientResponse
        std::cout << "   [4] Generating ClientResponse..." << std::endl;
        ClientResponse responseMsg = ClientResponse_init_zero;
        std::vector<uint8_t> clientSigOnNonce = ecdsaSign(nonceHash, clientPrivKey);
        if (!setNanopbBytes(&responseMsg.client_signature, clientSigOnNonce))
        {
            throw std::runtime_error("Failed to set signature bytes in ClientResponse");
        }
        std::vector<uint8_t> responseEncoded = encodeClientResponse(responseMsg);
        std::cout << "   [4] Sending ClientResponse (" << responseEncoded.size() << " bytes)..." << std::endl;
        sendFramedData(socket, responseEncoded);

        // 5. Client: Authentication successful
        std::cout << "Authentication sequence completed successfully from client side." << std::endl;
        return true;
    }
    catch (const boost::system::system_error &e)
    {
        std::cerr << "Network Error Auth: " << e.what() << std::endl;
        return false;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error Auth: " << e.what() << std::endl;
        return false;
    }
}

// --- Main ---
int main(int argc, char *argv[])
{
    std::vector<uint8_t> clientPrivKey;
    std::vector<uint8_t> serverPubKey;
    try
    {
        // Load keys using local helpers
        std::cout << "Loading client private key from " << CLIENT_PRIVATE_KEY_FILE << std::endl;
        clientPrivKey = loadPrivateKeyBytes(CLIENT_PRIVATE_KEY_FILE);
        std::cout << "Loading server public key from " << SERVER_PUBLIC_KEY_FILE << std::endl;
        serverPubKey = loadPublicKeyBytes(SERVER_PUBLIC_KEY_FILE);

        // Optional: Derive client public key using local helper
        try
        {
            std::vector<uint8_t> derivedClientPub = derivePublicKey(clientPrivKey);
            std::cout << "   Derived Client Public Key (" << derivedClientPub.size() << " bytes)" << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Warning: derivePublicKey failed: " << e.what() << std::endl;
        }

        boost::asio::io_context io_context;
        tcp::socket client_socket(io_context);
        tcp::resolver resolver(io_context);
        std::cout << "Connecting to server " << SERVER_ADDRESS << ":" << SERVER_PORT << "..." << std::endl;
        auto endpoints = resolver.resolve(SERVER_ADDRESS, std::to_string(SERVER_PORT));
        boost::asio::connect(client_socket, endpoints);
        std::cout << "Connected!" << std::endl;

        // Perform Authentication
        if (!performClientAuthentication(client_socket, CLIENT_SERIAL_ID, clientPrivKey, serverPubKey))
        {
            std::cerr << "Authentication failed. Exiting." << std::endl;
            if (client_socket.is_open())
                client_socket.close();
            return 1;
        }
        std::cout << "\nAuthentication Successful!" << std::endl;

        // Service Phase Placeholder
        std::cout << "--- Service Phase Start (MTA/CoT Not Implemented) ---" << std::endl;
        // TODO: Implement MTA/CoT logic here
        std::cout << "--- Service Phase End ---" << std::endl;

        // Clean disconnect
        std::cout << "Closing connection." << std::endl;
        boost::system::error_code ec;
        client_socket.shutdown(tcp::socket::shutdown_both, ec); // Signal shutdown gracefully
        client_socket.close();                                  // Close the socket
    }
    catch (const boost::system::system_error &e)
    {
        std::cerr << "Network Error: " << e.what() << " (Code: " << e.code() << ")" << std::endl;
        return 1;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        std::cerr << "An unknown error occurred." << std::endl;
        return 1;
    }

    std::cout << "Client exiting normally." << std::endl;
    return 0;
}