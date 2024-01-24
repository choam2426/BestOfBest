#include <stdint.h>
#include <array>


#pragma pack(push, 1)
struct radiotap_header {
    uint8_t it_version = 0;
    uint8_t it_pad = 0;
    uint16_t it_len = 8;
    uint32_t it_present = 0;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct deauth_frame{
    uint16_t type = 0x000c;
    uint16_t duration = 0;
    std::array<uint8_t, 6> d_address;
    std::array<uint8_t, 6> s_address;
    std::array<uint8_t, 6> bssid;
    uint16_t sequence = 0x0000;
    uint16_t reason_code = 0x0004;
    uint32_t frame_check = 0;
};
#pragma pack(pop)