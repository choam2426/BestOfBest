#include <pcap.h>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <array>
#include <iostream>

struct radiotap_header {
    uint8_t it_version;     /* set to 0 */
    uint8_t it_pad;
    uint16_t it_len;         /* entire length */
    uint32_t it_present;     /* fields present */
} __attribute__((__packed__));

enum present_flag {
	TSFT,
	FLAGS,
	RATE,
	CHANNEL,
	FHSS,
	DBM_ANTENNA_SIGNAL,
	DBM_ANTENNA_NOISE,
	LOCK_QUALITY,
	TX_ATTENUATION,
	DB_TX_ATTENUATION,
	DBM_TX_POWER,
	ANTENNA,
	DB_ANTENNA_SIGNAL,
	DB_ANTENNA_NOISE,
	RX_FLAGS,
	TX_FLAGS,
    RTS_RETRIES,
	DATA_RETRIES,
    CHANNEL_PLUS,
	MCS,
	AMPDU_STATUS,
	VHT,
	TIMESTAMP,
    HE,
    RESERVED,
    HEMU,
    ZERO_LENGTH,
    L_SIG,
    TLVS,
	RADIOTAP_NAMESPACE,
	VENDOR_NAMESPACE,
	EXT
};

// struct airodump_data {
//     uint16_t channel;
//     int8_t pwr;
//     char bssid[6];
// };

enum airodump_data_index {
    ad_PWR,
    ad_Beacons,
    ad_Data,
    ad_CH,
    ad_MB,
    ad_ENC,
    ad_CIPTHER,
    ad_AUTH,
};

enum ENC_type{
    WEP,
    WPA,
    WPA2,
    WPA3
};

// present flag가 끝나는 위치를 찾는 함수
int find_offset_of_last_present(const u_char *packet, uint32_t first_present){
    int offset_of_last_present = 8; 
    int present_bit[32];
    for (int i = 0; i < 32; i++) {
        present_bit[i] = (first_present >> i) & 1;
    }
    struct present_flag {
        uint32_t present;
    };
    while(1){
        if (present_bit[31]){
            present_flag *next_present = (struct present_flag *)(packet + offset_of_last_present);
            for (int i = 0; i < 32; i++) {
                present_bit[i] = (next_present->present >> i) & 1;
            }
            offset_of_last_present+=4;
        }
        else{
            break;
        }
    }
    return offset_of_last_present;
}

int main(){
    std::map<std::array<char, 6>, std::array<int, 8>> airodump_data_map;
    std::map<std::array<char, 6>, std::string> airodump_essid_map;
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live("wlan0", BUFSIZ, 1, 1, errbuf);
    // pcap_t *pcap = pcap_open_offline("/home/kali/airodump/pcap/beacon-a2000ua-testap.pcap", errbuf);
    while(true){
        struct pcap_pkthdr *header;
		const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res <= 0) break;

        radiotap_header *rthdr = (struct radiotap_header *)packet;
        int8_t pwr = 0;
        int channel = 0;
        // char bssid[6];
        // printf("Radiotap Header Values:\n");
        // printf("Version: %u\n", rthdr->it_version);
        // printf("Pad: %u\n", rthdr->it_pad);
        // printf("Length: %u\n", rthdr->it_len);
        // printf("Present: %u\n", rthdr->it_present);

        //첫 번째 present flag bit 저장
        int first_present_bit[32];
        for (int i = 0; i < 32; i++) {
            first_present_bit[i] = (rthdr->it_present >> i) & 1;
        }
        //present flag가 끝나는 지점 계산
        int temp = find_offset_of_last_present(packet, rthdr->it_present);

        if (first_present_bit[TSFT]){ // TSFT flag가 1인 경우
            temp += 8;
        }
        if (first_present_bit[FLAGS]){ // Flags flag가 1인 경우
            temp += 1;
        }
        if (first_present_bit[RATE]){ // Rate flag가 1인 경우
            temp += 1;
        }
        if (first_present_bit[CHANNEL]){ // Channel flag가 1인 경우
            uint16_t channel_frequency = *(uint16_t *)(packet + temp);
            temp += 2;
            uint16_t channel_flag = *(uint16_t *)(packet + temp);
            // 대역 확인 후 채널 저장
            if (channel_flag & (1 << 7)){ // 2.4ghz
                channel = (channel_frequency - 2407) / 5;
            }
            else if (channel_flag & (1 << 8)){ // 5ghz
                channel = (channel_frequency - 5000) / 5;
            }
            else{// 나오면 안되는 것
                continue;
            }
            temp += 2;
        }
        if (first_present_bit[FHSS]){ // FHSS flag가 1인 경우
            temp += 2;
        }
        if (first_present_bit[DBM_ANTENNA_SIGNAL]){ // dBm Antenna Signal flag가 1인 경우
            pwr = *(packet + temp);
            temp += 2;
        }
        uint8_t packet_type = *(uint8_t *)(packet + rthdr->it_len);
        
        // for (int i = 0; i<6; i++){
        //     printf("%x", airodump_data->bssid[i]);
        // }
        std::array<char, 6> bssid;
        std::memcpy(bssid.data(), packet + rthdr->it_len + 16, 6);

        if (packet_type == 0x80){
            auto is_exist_key = airodump_data_map.find(bssid);
            if (is_exist_key == airodump_data_map.end()){
                airodump_data_map[bssid] = {0,0,0,0,0,0,0,0};
            }
            airodump_data_map[bssid][ad_PWR] = pwr;
            airodump_data_map[bssid][ad_CH] = channel;
            int beaconsValue = airodump_data_map[bssid][ad_Beacons];
            beaconsValue += 1;
            airodump_data_map[bssid][ad_Beacons] = beaconsValue;
            int tagged_parameters_offset = rthdr->it_len + 36;
            int essid_len = *(packet + tagged_parameters_offset+1);
            char essid[essid_len + 1];
            strncpy(essid, (const char *)(packet + tagged_parameters_offset + 2), essid_len);
            essid[essid_len] = '\0';
            std::string essid_str(essid, essid_len);
            airodump_essid_map[bssid] = essid_str;

            uint temp_offset = tagged_parameters_offset + 2 + essid_len;
            uint8_t tag_number = *(packet + temp_offset);
            uint8_t tag_len = *(packet + temp_offset + 1);
            while(true){
                temp_offset += 2 + tag_len;
                tag_number = *(packet + temp_offset);
                tag_len = *(packet + temp_offset + 1);
                if (tag_number == 48){
                    uint8_t cipher_type = *(packet + temp_offset + 13);
                    airodump_data_map[bssid][ad_CIPTHER] = cipher_type;
                    uint8_t cipher_count = *(packet + temp_offset + 8);
                    uint8_t auth_type = *(packet + temp_offset + 15 + (cipher_count * 4));
                    airodump_data_map[bssid][ad_AUTH] = auth_type;
                    switch(auth_type){
                        case 8:
                            airodump_data_map[bssid][ad_ENC] = WPA3;
                        case 2:
                            airodump_data_map[bssid][ad_ENC] = WPA2;
                    }
                    break;
                }
                if(tag_number == 221){
                    uint32_t OUI = *(uint32_t *)(packet + temp_offset + 2);
                    if(ntohl(OUI)==0x50f201){
                        printf("WPA1!!!!!\n");
                        airodump_data_map[bssid][ad_ENC] = WPA;
                    }
                }
                if(temp_offset>header->len){
                    printf("bad\n");
                    break;
                }
            }
            


            //데이터 출력
            for(int i = 0; i < 8; i++){
            std::cout << (airodump_data_map[bssid][i]) << std::endl;
            }
            std::cout << airodump_essid_map[bssid] << std::endl;
        }

        
    }
    pcap_close(pcap);
    return 0;
}