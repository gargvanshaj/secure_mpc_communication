#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <boost/asio.hpp>
#include <vector>
#include <cstdint>
#include <stdexcept>

namespace ip = boost::asio::ip;
using tcp = ip::tcp;

// --- Simple Framing Protocol ---
// Prepends a 4-byte network-order (big-endian) length header to the data.

// Sends data prefixed with its size
// Throws boost::system::system_error on network error
void sendFramedData(tcp::socket &socket, const std::vector<uint8_t> &data);

// Receives size-prefixed data
// Returns the payload data. Returns an empty vector if the peer closes connection cleanly
// after sending size = 0, or if an error occurs immediately.
// Throws boost::system::system_error on network error during read.
std::vector<uint8_t> receiveFramedData(tcp::socket &socket);

#endif // NETWORK_UTILS_H