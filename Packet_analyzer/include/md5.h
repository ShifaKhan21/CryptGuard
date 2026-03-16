#ifndef MD5_H
#define MD5_H

#include <string>
#include <cstdint>

namespace DPI {

// Compact MD5 implementation for JA3 hashing
class MD5 {
public:
    static std::string hash(const std::string& input);

private:
    struct Context {
        uint32_t state[4];
        uint32_t count[2];
        uint8_t buffer[64];
    };

    static void init(Context* ctx);
    static void update(Context* ctx, const uint8_t* input, uint32_t inputLen);
    static void final(uint8_t digest[16], Context* ctx);
    static void transform(uint32_t state[4], const uint8_t block[64]);
    static void encode(uint8_t* output, const uint32_t* input, uint32_t len);
    static void decode(uint32_t* output, const uint8_t* input, uint32_t len);
};

} // namespace DPI

#endif // MD5_H
