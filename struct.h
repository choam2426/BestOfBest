#include <stdint.h>

#pragma pack(push, 1)
struct radiotap_header {
    uint8_t it_version = 0;
    uint8_t it_pad = 0;
    uint16_t it_len = 8;
    uint32_t it_present = 0;
} __attribute__((__packed__));
#pragma pack(pop)