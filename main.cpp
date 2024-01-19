#include <pcap.h>
#include <string>
#include <cstring>
#include <array>
#include <thread>
#include <chrono>
#include <vector>
#include <fstream>

struct ssid_param_set_tag{
    uint8_t tag = 0;
    uint8_t tag_len;
};

struct supported_rate_tag_struct{
    uint8_t tag = 1;
    uint8_t tag_len = 8;
    uint8_t data[8] = {0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24};    
}__attribute__((__packed__));

struct rsn_tag_struct{
    uint8_t tag = 0x30;
    uint8_t tag_len = 20;
    uint16_t rsn_version = 1;
    uint32_t gcs = 0x04ac0f00;
    uint16_t pcsc = 1;
    uint32_t pcsl = 0x04ac0f00;
    uint16_t akmsc = 1;
    uint32_t akml = 0x02ac0f00;
    uint16_t rsn_capa = 0;
}__attribute__((__packed__));

struct beacon_frame_struct{
    uint8_t version = 0x00;
    uint8_t pad = 0x00;
    uint16_t length = 0x000f; 
    uint32_t present_flag = 0x0000002e;
    uint8_t rt_flags = 0x10;
    uint8_t rate = 0x02;
    uint16_t channel_frequency = 0x097b;
    uint16_t channel_flag = 0xa0;
    uint8_t antenna_signal = 0xc4;
    uint16_t type = 0x0080;
    uint16_t duration = 0;
    std::array<unsigned char, 6> d_address = {255,255,255,255,255,255};
    std::array<unsigned char, 6> s_address = {0x50,0x46,0xae,0x4f,0x27,0x9c};
    std::array<unsigned char, 6> bssid = {0x50,0x46,0xae,0x4f,0x27,0x9c};
    // uint16_t sequence = 0x82a0;
    uint16_t sequence = 0x0000;
    uint64_t timestamp = 0x00000277c7d0c1a8;
    uint16_t interval = 0x0064;
    uint16_t cap_info = 0x11;
    uint8_t ssid_param_set_tag = 0;
    // uint32_t frame_check = 0x37aa8c9d;
}__attribute__((__packed__));

void send_beacon(pcap_t* pcap, std::string essid){
    std::vector<char> packet_stream;
    struct beacon_frame_struct beacon_frame = {};
    size_t vector_size = packet_stream.size();
    packet_stream.resize(vector_size + sizeof(beacon_frame));
    std::memcpy(packet_stream.data() + vector_size, &beacon_frame, sizeof(beacon_frame_struct));
    uint8_t ssid_param_set_tag_length = essid.size();
    packet_stream.push_back(ssid_param_set_tag_length);
    for (char c : essid) {
        packet_stream.push_back(c);
    }
    struct supported_rate_tag_struct supported_rate_tag;
    vector_size = packet_stream.size();
    packet_stream.resize(vector_size + sizeof(supported_rate_tag));
    std::memcpy(packet_stream.data() + vector_size, &supported_rate_tag, sizeof(supported_rate_tag_struct));
    struct rsn_tag_struct rsn_tag;
    vector_size = packet_stream.size();
    packet_stream.resize(vector_size + sizeof(rsn_tag));
    std::memcpy(packet_stream.data() + vector_size, &rsn_tag, sizeof(rsn_tag_struct));
    // uint32_t frame_check = 0x37aa8c9d;
    uint32_t frame_check = 0;
    const char* frame_check_bytes = reinterpret_cast<const char*>(&frame_check);

    // frame_check의 각 바이트를 벡터에 추가
        for (size_t i = 0; i < sizeof(frame_check); ++i) {
            packet_stream.push_back(frame_check_bytes[i]);
    }
    pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(packet_stream.data()), packet_stream.size());
}

int main(int argc, char* argv[]){
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    std::ifstream file(argv[2]);
    
    while (true){
        std::string line;
        while (std::getline(file, line)) {
            send_beacon(pcap, line);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        file.clear();
        file.seekg(0, std::ios::beg);
    }

    return 0;
}