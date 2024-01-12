#include <pcap.h>
#include <cstring>
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

struct airodump_data {
    uint16_t channel;
    int8_t pwr;
    uint8_t bssid[6];
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
    char errbuf[PCAP_ERRBUF_SIZE];
	// pcap_t *pcap = pcap_open_live("wlan0", BUFSIZ, 1, 1, errbuf);
    pcap_t *pcap = pcap_open_offline("/home/kali/airodump/pcap/beacon-a2000ua-testap.pcap", errbuf);
    while(true){
        struct pcap_pkthdr *header;
		const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res <= 0) continue;

        radiotap_header *rthdr = (struct radiotap_header *)packet;
        //출력할 데이터 저장할 구조체 초기화
        struct airodump_data *airodump_data;
        airodump_data = new struct airodump_data;

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
                airodump_data->channel = (channel_frequency - 2407) / 5;
            }
            else if (channel_flag & (1 << 8)){ // 5ghz
                airodump_data->channel = (channel_frequency - 5000) / 5;
            }
            else{// 나오면 안되는 것
                continue;
            }
            // printf("%d\n",airodump_data->channel);
            temp += 2;
        }
        if (first_present_bit[FHSS]){ // FHSS flag가 1인 경우
            temp += 2;
        }
        if (first_present_bit[DBM_ANTENNA_SIGNAL]){ // dBm Antenna Signal flag가 1인 경우
            airodump_data->pwr = *(packet + temp);
            temp += 2;
            // printf("%d\n", airodump_data->pwr);
        }

        uint8_t packet_type = *(uint8_t *)(packet + rthdr->it_len);
        memcpy(airodump_data->bssid, packet + rthdr->it_len + 16, 6);
        for (int i = 0; i<6; i++){
            printf("%x ", airodump_data->bssid[i]);
        }
        if (packet_type == 0x80){
            printf("beacon frame\n");
        }


    }

    return 0;
}