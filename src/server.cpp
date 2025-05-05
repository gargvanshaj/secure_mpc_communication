#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <map>
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
const std::string SERVER_PRIVATE_KEY_FILE = "../../keys/server_private_key.bin";
const std::map<std::string, std::string> CLIENT_PUBLIC_KEYS = {
    {"CLIENT_SN_001", "../../keys/client_public_key.bin"}
    // Add more clients here
};
const short SERVER_PORT = 9999;

// --- Authentication Logic ---
bool performServerAuthentication(
    tcp::socket &socket,
    const std::vector<uint8_t> &serverPrivKey,
    std::string &authenticated_serial_id, // Output parameter
    std::vector<uint8_t> &clientPubKey    // Output parameter
)
{
    clientPubKey.clear();
    authenticated_serial_id = "UNKNOWN";

    try
    {
        std::cout << "Starting authentication for client " << socket.remote_endpoint() << "..." << std::endl;

        // 1. Server <- Client: Receive ClientHello
        std::cout << "   [1] Waiting for ClientHello..." << std::endl;
        std::vector<uint8_t> helloEncoded = receiveFramedData(socket);
        if (helloEncoded.empty())
        {
            std::cerr << "Error: Client disconnected or sent empty hello." << std::endl;
            return false;
        }
        std::cout << "   [1] Received ClientHello (" << helloEncoded.size() << " bytes)." << std::endl;
        ClientHello helloMsg = ClientHello_init_zero;
        if (!decodeClientHello(helloEncoded, helloMsg))
        {
            std::cerr << "Error: Failed to decode ClientHello." << std::endl;
            return false;
        }
        helloMsg.serial_id[sizeof(helloMsg.serial_id) - 1] = '\0'; // Ensure null termination
        std::string serial_id(helloMsg.serial_id);
        std::vector<uint8_t> clientSigOnSerial = getNanopbBytes(&helloMsg.signature);
        if (serial_id.empty() || strlen(helloMsg.serial_id) == 0)
        {
            std::cerr << "Error: Received empty serial ID." << std::endl;
            return false;
        }
        if (clientSigOnSerial.size() != SIGNATURE_SIZE)
        {
            std::cerr << "Error: Invalid client signature size." << std::endl;
            return false;
        }
        std::cout << "   [1] Received Serial ID: " << serial_id << std::endl;

        // 2. Server: Verify Client's Signature on Serial ID
        std::cout << "   [2] Verifying client signature on Serial ID..." << std::endl;
        auto key_it = CLIENT_PUBLIC_KEYS.find(serial_id);
        if (key_it == CLIENT_PUBLIC_KEYS.end())
        {
            std::cerr << "Error: Unknown Serial ID: " << serial_id << std::endl;
            return false;
        }
        std::string clientPubKeyFile = key_it->second;
        try
        {
            clientPubKey = loadPublicKeyBytes(clientPubKeyFile); // Call local helper
            if (clientPubKey.empty())
                throw std::runtime_error("Loaded empty pubkey");
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error loading client pubkey(" << clientPubKeyFile << "): " << e.what() << std::endl;
            return false;
        }
        std::cout << "   [2] Loaded public key for " << serial_id << "." << std::endl;
        std::vector<uint8_t> serialHash = sha256(serial_id); // Call local helper
        if (!ecdsaVerify(serialHash, clientSigOnSerial, clientPubKey))
        { // Call local helper
            std::cerr << "Error: Client signature verification failed for Serial ID!" << std::endl;
            return false;
        }
        std::cout << "   [2] Client signature on Serial ID verified." << std::endl;

        // 3. Server -> Client: Send ServerChallenge
        std::cout << "   [3] Generating ServerChallenge..." << std::endl;
        ServerChallenge challengeMsg = ServerChallenge_init_zero;
        std::vector<uint8_t> nonce = generateRandomBytes(HASH_SIZE);                 // Call local helper
        std::vector<uint8_t> nonceHash = sha256(nonce);                              // Call local helper
        std::vector<uint8_t> serverSigOnNonce = ecdsaSign(nonceHash, serverPrivKey); // Call local helper
        if (!setNanopbBytes(&challengeMsg.nonce, nonce) ||
            !setNanopbBytes(&challengeMsg.server_signature, serverSigOnNonce))
        {
            throw std::runtime_error("Failed to set bytes in ServerChallenge");
        }
        std::vector<uint8_t> challengeEncoded = encodeServerChallenge(challengeMsg);
        std::cout << "   [3] Sending ServerChallenge (" << challengeEncoded.size() << " bytes)..." << std::endl;
        sendFramedData(socket, challengeEncoded);

        // 4. Server <- Client: Receive ClientResponse
        std::cout << "   [4] Waiting for ClientResponse..." << std::endl;
        std::vector<uint8_t> responseEncoded = receiveFramedData(socket);
        if (responseEncoded.empty())
        {
            std::cerr << "Error: Client disconnected or sent empty response." << std::endl;
            return false;
        }
        std::cout << "   [4] Received ClientResponse (" << responseEncoded.size() << " bytes)." << std::endl;
        ClientResponse responseMsg = ClientResponse_init_zero;
        if (!decodeClientResponse(responseEncoded, responseMsg))
        {
            std::cerr << "Error: Failed to decode ClientResponse." << std::endl;
            return false;
        }
        std::vector<uint8_t> clientSigOnNonce = getNanopbBytes(&responseMsg.client_signature);
        if (clientSigOnNonce.size() != SIGNATURE_SIZE)
        {
            std::cerr << "Error: Invalid client signature size on nonce." << std::endl;
            return false;
        }

        // 5. Server: Verify Client's Signature on Nonce
        std::cout << "   [5] Verifying client signature on nonce..." << std::endl;
        if (!ecdsaVerify(nonceHash, clientSigOnNonce, clientPubKey))
        { // Call local helper
            std::cerr << "Error: Client signature verification failed for Nonce!" << std::endl;
            return false;
        }

        // --- SUCCESS ---
        std::cout << "   [5] Client signature on nonce verified." << std::endl;
        std::cout << "Client Verified! Serial ID: " << serial_id << std::endl;
        authenticated_serial_id = serial_id;
        // clientPubKey is already set via output parameter
        return true;
    }
    catch (const boost::system::system_error &e)
    {
        std::cerr << "Network Error Auth: " << e.what() << std::endl;
        clientPubKey.clear();
        return false;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error Auth: " << e.what() << std::endl;
        clientPubKey.clear();
        return false;
    }
}

// --- Main ---
int main(int argc, char *argv[])
{
    std::vector<uint8_t> serverPrivKey;
    try
    {
        // Load server private key using local helper
        std::cout << "Loading server private key from " << SERVER_PRIVATE_KEY_FILE << std::endl;
        serverPrivKey = loadPrivateKeyBytes(SERVER_PRIVATE_KEY_FILE);
        if (serverPrivKey.empty())
            throw std::runtime_error("Loaded empty server key");

        // Derive and save server public key using local helper
        try
        {
            std::vector<uint8_t> derivedServerPub = derivePublicKey(serverPrivKey);
            std::cout << "   Derived Server Public Key (" << derivedServerPub.size() << " bytes)" << std::endl;
            std::ofstream pubKeyFile("server_public_key.bin", std::ios::binary | std::ios::trunc);
            if (pubKeyFile)
            {
                pubKeyFile.write(reinterpret_cast<const char *>(derivedServerPub.data()), derivedServerPub.size());
                pubKeyFile.close();
                std::cout << "   Saved server_public_key.bin" << std::endl;
            }
            else
            {
                std::cerr << "   Warning: Could not write server_public_key.bin" << std::endl;
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << "Warning: derivePublicKey failed: " << e.what() << std::endl;
        }

        boost::asio::io_context io_context;
        tcp::acceptor acceptor_server(io_context, tcp::endpoint(tcp::v4(), SERVER_PORT));
        std::cout << "Server started. Waiting for connection on port " << SERVER_PORT << "..." << std::endl;

        while (true)
        { // Loop to accept multiple clients
            tcp::socket server_socket(io_context);
            acceptor_server.accept(server_socket); // Blocking call

            std::string client_serial_id = "UNKNOWN";
            std::vector<uint8_t> clientPubKey;

            try
            {
                auto remote_ep = server_socket.remote_endpoint();
                std::cout << "\nClient connected from: " << remote_ep << std::endl;

                // Perform Authentication
                if (!performServerAuthentication(server_socket, serverPrivKey, client_serial_id, clientPubKey))
                {
                    std::cerr << "Authentication failed for client from " << remote_ep << ". Closing connection." << std::endl;
                    if (server_socket.is_open())
                        server_socket.close(); // Close socket on auth fail
                    continue;                  // Wait for next client
                }
                std::cout << "Authentication Successful! Client: " << client_serial_id << std::endl;

                // --- Service Phase (Placeholder) ---
                std::cout << "--- Service Phase Start with " << client_serial_id << " (MTA/CoT Not Implemented) ---" << std::endl;
                // TODO: Implement MTA/CoT logic here
                std::cout << "--- Service Phase End with " << client_serial_id << " ---" << std::endl;

                // Wait for client to close or signal end gracefully
                std::cout << "Waiting for client " << client_serial_id << " to close..." << std::endl;
                boost::system::error_code read_ec;
                // Use receiveFramedData to detect potential clean close (empty vector) or error
                std::vector<uint8_t> end_data = receiveFramedData(server_socket);
                if (read_ec && read_ec != boost::asio::error::eof)
                {
                    std::cerr << "Network error waiting for client close: " << read_ec.message() << std::endl;
                }
                else if (read_ec == boost::asio::error::eof)
                {
                    std::cout << "Client " << client_serial_id << " closed connection (EOF)." << std::endl;
                }
                else
                {
                    std::cout << "Client " << client_serial_id << " potentially sent final data (" << end_data.size() << " bytes) before closing." << std::endl;
                }
            }
            catch (const boost::system::system_error &e)
            {
                if (e.code() == boost::asio::error::eof)
                {
                    std::cout << "Client " << client_serial_id << " disconnected cleanly during session." << std::endl;
                }
                else
                {
                    std::cerr << "Network Error during session with " << client_serial_id << ": " << e.what() << " (Code: " << e.code() << ")" << std::endl;
                }
            }
            catch (const std::exception &e)
            {
                std::cerr << "Error during session with " << client_serial_id << ": " << e.what() << std::endl;
            }

            // Close socket for this client if still open
            if (server_socket.is_open())
            {
                std::cout << "Closing connection socket for client " << client_serial_id << "." << std::endl;
                server_socket.close();
            }
            std::cout << "\nReady for next connection..." << std::endl;

        } // End accept loop
    }
    catch (const boost::system::system_error &e)
    {
        std::cerr << "Server Network Error: " << e.what() << " (Code: " << e.code() << ")" << std::endl;
        return 1;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Server Error: " << e.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        std::cerr << "An unknown server error occurred." << std::endl;
        return 1;
    }

    std::cout << "Server exiting." << std::endl;
    return 0;
}