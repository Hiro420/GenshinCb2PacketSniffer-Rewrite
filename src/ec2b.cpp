#include "ec2b.h"
#include "magic.h"
#include <cstdint>
#include <cstring>
#include <array>
#include <string>
#include <vector>
#include <random>

#if defined(_MSC_VER)
#include <intrin.h>
#define BSWAP64 _byteswap_uint64
#else
#define BSWAP64 __builtin_bswap64
#endif

#if defined(_WIN32) || (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
#define HOST_IS_LITTLE_ENDIAN 1
#else
#define HOST_IS_LITTLE_ENDIAN 0
#endif

static inline uint64_t load64_le(const uint8_t* p) {
    uint64_t v; std::memcpy(&v, p, sizeof(v));
#if HOST_IS_LITTLE_ENDIAN
    return v;
#else
    return BSWAP64(v);
#endif
}
static inline void store64_le(uint8_t* p, uint64_t v) {
#if HOST_IS_LITTLE_ENDIAN
    std::memcpy(p, &v, sizeof(v));
#else
    uint64_t w = BSWAP64(v); std::memcpy(p, &w, sizeof(w));
#endif
}

static std::vector<uint8_t> base64_decode(const std::string& s) {
    static const int8_t T[256] = {
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 0..15
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 16..31
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, 62,-1,-1,-1, 63, // '+'/ '/'
      52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,   // '0'..'9', '=' -> -2
      -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,   // 'A'..'O'
      15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,   // 'P'..'Z'
      -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,   // 'a'..'o'
      41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,   // 'p'..'z'
      // rest default -1
    };
    std::vector<uint8_t> out; out.reserve((s.size() * 3) / 4);
    int val = 0, valb = -8, pads = 0;
    for (unsigned char c : s) {
        if (c <= 32) continue;           // skip whitespace
        if (c > 127) throw std::runtime_error("b64: bad char");
        int8_t d = T[c];
        if (d == -1) throw std::runtime_error("b64: bad char");
        if (d == -2) { pads++; continue; } // '='
        if (pads) throw std::runtime_error("b64: data after '='");
        val = (val << 6) | d; valb += 6;
        if (valb >= 0) { out.push_back(uint8_t((val >> valb) & 0xFF)); valb -= 8; }
    }
    if (pads == 1) { if (!out.empty()) out.pop_back(); }
    else if (pads == 2) { if (out.size() >= 2) { out.pop_back(); out.pop_back(); } }
    else if (pads > 2) throw std::runtime_error("b64: bad padding");
    return out;
}

// ---- extern "C" AES quirk funcs come from aes.c ----
extern void oqs_mhy128_enc_c(const uint8_t* plaintext, const void* _schedule, uint8_t* ciphertext);

// ---- MHY helpers copied from earlier port ----
static void key_scramble(uint8_t* key) {
    uint8_t round_keys[11 * 16] = { 0 };
    for (int round = 0; round <= 10; ++round)
        for (int i = 0; i < 16; ++i)
            for (int j = 0; j < 16; ++j) {
                const uint64_t idx = (uint64_t(round) << 8) + i * 16 + j;
                round_keys[round * 16 + i] ^= aes_xorpad_table[1][idx] ^ aes_xorpad_table[0][idx];
            }
    uint8_t chip[16];
    oqs_mhy128_enc_c(key, round_keys, chip);
    std::memcpy(key, chip, 16);
}

static void get_decrypt_vector(const uint8_t* key,
    const uint8_t* crypt, uint64_t crypt_size,
    uint8_t* output, uint64_t output_size) {
    uint64_t val = 0xFFFFFFFFFFFFFFFFull;
    const uint64_t n_in = crypt_size >> 3;
    for (uint64_t i = 0; i < n_in; ++i) val ^= load64_le(crypt + i * 8);

    const uint64_t k0 = load64_le(key + 0);
    const uint64_t k1 = load64_le(key + 8);
    std::mt19937_64 mt(k1 ^ 0xCEAC3B5A867837ACull ^ val ^ k0);

    const uint64_t n_out = output_size >> 3;
    for (uint64_t i = 0; i < n_out; ++i) store64_le(output + i * 8, mt());
}

static std::array<uint8_t, 4096> derive_xorpad_from_ec2b(const uint8_t* ec2b, std::size_t size) {
    if (size != 2076) throw std::invalid_argument("ec2b size != 2076");
    uint8_t key[16];   std::memcpy(key, ec2b + 8, 16);
    uint8_t data[2048]; std::memcpy(data, ec2b + 28, 2048);
    key_scramble(key);
    for (int i = 0; i < 16; ++i) key[i] ^= key_xorpad_table[i];
    std::array<uint8_t, 4096> xorpad{};
    get_decrypt_vector(key, data, 2048, xorpad.data(), 4096);
    return xorpad;
}

// **** THIS is the symbol the linker is missing ****
std::array<uint8_t, 4096> derive_xorpad_from_b64(const char* b64, std::size_t len) {
    std::string input(b64, b64 + len);
    auto decoded = base64_decode(input);
    return derive_xorpad_from_ec2b(decoded.data(), decoded.size());
}
