#include "network_utils.h"
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/endian/conversion.hpp>
#include <iostream>

// Sends data prefixed with its size
void sendFramedData(tcp::socket &socket, const std::vector<uint8_t> &data)
{
    if (!socket.is_open())
    {
        throw std::runtime_error("Socket is not open for sending.");
    }

    uint32_t data_len_host = static_cast<uint32_t>(data.size());
    // Convert length to network byte order (Big Endian)
    uint32_t data_len_net = boost::endian::native_to_big(data_len_host);

    std::vector<boost::asio::const_buffer> buffers;
    buffers.push_back(boost::asio::buffer(&data_len_net, sizeof(data_len_net)));
    buffers.push_back(boost::asio::buffer(data));

    // Use write() which ensures all data is sent
    boost::system::error_code ec;
    boost::asio::write(socket, buffers, ec);

    if (ec)
    {
        throw boost::system::system_error(ec); // Re-throw Boost ASIO error
    }
}

// Receives size-prefixed data
std::vector<uint8_t> receiveFramedData(tcp::socket &socket)
{
    if (!socket.is_open())
    {
        throw std::runtime_error("Socket is not open for receiving.");
    }

    uint32_t data_len_net = 0;
    boost::system::error_code ec;

    // Read the 4-byte length header
    boost::asio::read(socket, boost::asio::buffer(&data_len_net, sizeof(data_len_net)), ec);

    if (ec)
    {
        if (ec == boost::asio::error::eof)
        {
            std::cerr << "Network Info: Connection closed cleanly by peer while reading length." << std::endl;
            return {}; // Return empty vector on clean close
        }
        else
        {
            throw boost::system::system_error(ec); // Throw on other read errors
        }
    }

    // Convert length from network byte order to host byte order
    uint32_t data_len_host = boost::endian::big_to_native(data_len_net);

    // Basic sanity check for length (prevent huge allocations)
    const uint32_t MAX_ALLOWED_SIZE = 10 * 1024 * 1024; // Example: 10 MB limit
    if (data_len_host > MAX_ALLOWED_SIZE)
    {
        throw std::runtime_error("Received data frame size (" + std::to_string(data_len_host) + ") exceeds maximum allowed size (" + std::to_string(MAX_ALLOWED_SIZE) + ").");
    }

    if (data_len_host == 0)
    {
        // Peer might send 0-length message to signal something or just an empty message.
        return {};
    }

    std::vector<uint8_t> data(data_len_host);

    // Read the actual payload data
    boost::asio::read(socket, boost::asio::buffer(data.data(), data.size()), ec);

    if (ec)
    {
        if (ec == boost::asio::error::eof)
        {
            // This is an unexpected EOF, as we expected 'data_len_host' bytes
            std::cerr << "Network Error: Connection closed by peer unexpectedly after receiving size header." << std::endl;
            // Depending on protocol, might want to throw or return empty
            throw boost::system::system_error(ec, "Unexpected EOF reading payload");
        }
        else
        {
            throw boost::system::system_error(ec); // Throw on other read errors
        }
    }

    return data;
}