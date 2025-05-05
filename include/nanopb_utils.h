// nanopb_utils.h
#ifndef NANOPB_UTILS_H
#define NANOPB_UTILS_H

#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>
#include <type_traits>

// Include Nanopb core and generated message headers
#include "pb_encode.h"
#include "pb_decode.h"
#include "auth.pb.h"

// --- Template functions for Nanopb Encoding/Decoding ---
template <typename T>
std::vector<uint8_t> nanopbEncode(const T &message, const pb_msgdesc_t *fields)
{
    pb_ostream_t sizestream = PB_OSTREAM_SIZING;
    if (!pb_encode(&sizestream, fields, &message))
    {
        throw std::runtime_error("Nanopb encoding failed (size calculation): " + std::string(PB_GET_ERROR(&sizestream)));
    }
    std::vector<uint8_t> buffer(sizestream.bytes_written);
    pb_ostream_t bufferstream = pb_ostream_from_buffer(buffer.data(), buffer.size());
    if (!pb_encode(&bufferstream, fields, &message))
    {
        throw std::runtime_error("Nanopb encoding failed (buffer writing): " + std::string(PB_GET_ERROR(&bufferstream)));
    }
    return buffer;
}

template <typename T>
bool nanopbDecode(const std::vector<uint8_t> &buffer, T &message, const pb_msgdesc_t *fields)
{

    pb_istream_t stream = pb_istream_from_buffer(buffer.data(), buffer.size());
    if (!pb_decode(&stream, fields, &message))
    {
        fprintf(stderr, "Nanopb decoding failed: %s\n", PB_GET_ERROR(&stream));
        return false;
    }
    return true;
}

// --- Specific Wrappers for Auth Messages ---
inline std::vector<uint8_t> encodeClientHello(const ClientHello &msg)
{
    return nanopbEncode(msg, ClientHello_fields);
}
inline bool decodeClientHello(const std::vector<uint8_t> &buf, ClientHello &msg)
{
    ClientHello msg_zero = ClientHello_init_zero;
    msg = msg_zero;
    return nanopbDecode(buf, msg, ClientHello_fields);
}

inline std::vector<uint8_t> encodeServerChallenge(const ServerChallenge &msg)
{
    return nanopbEncode(msg, ServerChallenge_fields);
}
inline bool decodeServerChallenge(const std::vector<uint8_t> &buf, ServerChallenge &msg)
{
    ServerChallenge msg_zero = ServerChallenge_init_zero;
    msg = msg_zero;
    return nanopbDecode(buf, msg, ServerChallenge_fields);
}

inline std::vector<uint8_t> encodeClientResponse(const ClientResponse &msg)
{
    return nanopbEncode(msg, ClientResponse_fields);
}
inline bool decodeClientResponse(const std::vector<uint8_t> &buf, ClientResponse &msg)
{
    ClientResponse msg_zero = ClientResponse_init_zero;
    msg = msg_zero;
    return nanopbDecode(buf, msg, ClientResponse_fields);
}

// --- TEMPLATE Helper Functions for Nanopb Fixed Bytes Arrays ---

// Template Helper to copy vector data TO a Nanopb fixed bytes array field
// Works for any type 'T' that has 'size' and 'bytes' members.
template <typename T>
bool setNanopbBytes(T *target, const std::vector<uint8_t> &source)
{
    // Determine max size from the target type (compile time)
    constexpr size_t max_size_in_struct = sizeof(target->bytes);

    if (source.size() > max_size_in_struct)
    {
        fprintf(stderr, "Error: Source data size (%zu) exceeds max nanopb bytes size (%zu).\n", source.size(), max_size_in_struct);
        return false; // Prevent buffer overflow
    }
    if (target == nullptr)
    {
        fprintf(stderr, "Error: Target nanopb bytes field is null.\n");
        return false;
    }
    memcpy(target->bytes, source.data(), source.size());
    target->size = static_cast<pb_size_t>(source.size()); // Set the actual size used
    return true;
}

// Template Helper to copy data FROM a Nanopb fixed bytes array field to a vector
// Works for any type 'T' that has 'size' and 'bytes' members.
template <typename T>
std::vector<uint8_t> getNanopbBytes(const T *source)
{
    if (source == nullptr || source->size == 0)
    {
        return {};
    }
    // Create vector from the data pointer and the size field
    // Ensure source->bytes is treated as uint8_t*
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t *>(source->bytes),
                                reinterpret_cast<const uint8_t *>(source->bytes + source->size));
}

#endif // NANOPB_UTILS_H