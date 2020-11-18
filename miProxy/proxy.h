#ifndef _PROXY_H_
#define _PROXY_H_

#include <netinet/in.h>
#include <string>
#include <vector>
#include <thread>
#include <set>
#include <unordered_set>
#include <fstream>


class proxy{
private:
    // proxy mode related member
    bool whether_dns;
    int port_number;    
    const std::string server_ip;
    double alpha;

    std::string dns_ip;
    int dns_port;
    
    // socket member
    int main_sock_fd;
    sockaddr_in server_addr;

    // all client threads, used to make sure proxy object died
    // after all client threads finishing execution
    std::vector<std::thread> client_threads;
    
    std::set<int> availble_bitrates;

    // store the no list f4m file we receive
    std::string cached_f4m;

    // to avoid a browser try to connect multiple times
    std::unordered_set<std::string> connected_ip;

    std::ofstream outFile;
    
    // thread function to serve each client
    void serve_client(std::string browser_ip, int new_client_sockfd);
    
    void process_manifest(int client_sockfd, int server_sockfd, const char* browser_receive_buffer);

    double receive_server_send_client_helper(int client_sockfd, int server_sockfd, int& server_response_size);

    void receive_and_process_video_chunk_request(int client_sockfd, int server_sockfd, 
            char* buffer, std::string& browser_ip, std::string& server_ip);

    // helper function to search dns for server ip
    std::string dns_query();

public:
    // set use mode and create main socket for this proxy
    // throw runtime_error when it can not create socket
    proxy(bool _whether_dns, int _port_number, const char* _server_ip, 
        double _alpha, const char* _log_path, const char* _dns_ip, int _dns_port);
    
    // start the proxy
    void start() noexcept;



    proxy(const proxy&) = delete;
    proxy(proxy&&) = delete;
    proxy& operator=(const proxy&) = delete;
    proxy& operator=(proxy&&) = delete;
};


#endif