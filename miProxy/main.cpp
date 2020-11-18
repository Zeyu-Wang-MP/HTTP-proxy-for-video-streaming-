#include "proxy.h"
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

using std::cerr;
using std::endl;
using std::cout;

int main(int argc, char* argv[]){
    if(argc != 6 && argc != 7){
        cerr << "./miProxy --nodns <listen-port> <www-ip> <alpha> <log> or \n";
        cerr << "./miProxy --dns <listen-port> <dns-ip> <dns-port> <alpha> <log>" << endl;
        exit(1);
    }
    bool dns = strcmp(argv[1], "--nodns") == 0 ? false : true;
    int listen_port = atoi(argv[2]);
    const char* server_ip = (argc == 6 ? argv[3] : "");
    double alpha = atof(argc == 6 ? argv[4] : argv[5]);
    const char* log_path = (argc == 6 ? argv[5] : argv[6]);
    const char* dns_ip = (argc == 6 ? "" : argv[3]);
    int dns_port = (argc == 6 ? -1 : atoi(argv[4]));

    try{
        proxy proxy_server(dns, listen_port, server_ip, alpha, log_path, dns_ip, dns_port);
        proxy_server.start();
    }
    catch(const std::exception& err){
        cerr << err.what() << endl;
        return 1;
    }
    return 0;
}