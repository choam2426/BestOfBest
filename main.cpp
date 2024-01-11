#include <pcap.h>
struct radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
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

// present flag가 끝나는 위치를 찾는 함수
int find_offset_of_last_present(const u_char *packet, u_int32_t first_present){
    int offset_of_last_present = 8; 
    int present_bit[32];
    for (int i = 0; i < 32; i++) {
        present_bit[i] = (first_present >> i) & 1;
    }
    struct present_flag {
        u_int32_t present;
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

        // printf("Radiotap Header Values:\n");
        // printf("Version: %u\n", rthdr->it_version);
        // printf("Pad: %u\n", rthdr->it_pad);
        // printf("Length: %u\n", rthdr->it_len);
        // printf("Present: %u\n", rthdr->it_present);
        int first_present_bit[32];
        for (int i = 0; i < 32; i++) {
            first_present_bit[i] = (rthdr->it_present >> i) & 1;
        }
        int temp = find_offset_of_last_present(packet, rthdr->it_present);
        printf("%d\n",temp);
        // if (rthdr->it_present & 0x01){ // tsft flag가 1인 경우
        //     end_of_present += 8;
        // }
    }

    return 0;
}