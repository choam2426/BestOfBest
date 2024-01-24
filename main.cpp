#include "struct.h"
#include <pcap.h>
#include <string>

void deauth_broadcast(){
    pass;
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