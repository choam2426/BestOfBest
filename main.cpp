#include "struct.h"
#include <pcap.h>
#include <string>
#include <array>


std::array<uint8_t, 6> mac_parser(std::string string_mac){
    std::array<uint8_t, 6> byte_mac = {};
    std::istringstream stream(string_mac);
    std::string byte_string;

    for (int i = 0; i < 6; ++i) {
        std::getline(stream, byteString, ':');
        byte_mac[i] = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
    }

    return byte_mac;
}


void deauth_broadcast(){
    struct radiotap_header radiotap_header = {};
    struct deauth_frame deauth_frame = {};
    
    

}

void deauth_unicast(){
    pass;
}

void auth_attack(){
    pass;
}



int main(int argc, char* argv[]){
    if (argc < 3) {
        std::cerr << "Usage: deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n";
        return 1;
    }
    std::string interface = argv[1];
    std::string ap_mac = argv[2];
    if (argc == 3){
        //브로드캐스트
    }
    elif (argc == 4){
        //유니캐스트
    }
    elif (argc > 4 && std::string(argv[4]) == "-auth"){
        //auth attack
    }
    else{
        std::cerr << "Usage: deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n";
        return 1;
    }


    return 0;
}