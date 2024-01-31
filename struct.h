#include <stdint.h>
#include <array>

#pragma pack(push, 1)
struct radiotap_header {
    uint8_t version = 0;
    uint8_t pad = 0;
    uint16_t len = 8;
    uint32_t present = 0;
};
#pragma pack(pop)

std::array<uint8_t, 6> broadcast_byte = {255,255,255,255,255,255};

#pragma pack(push, 1)
struct csa_tag {
    uint8_t number = 25;
    uint8_t len = 3;
    uint8_t mode = 1;
    uint8_t new_channel;
    uint8_t count = 3;
};
#pragma pack(pop)