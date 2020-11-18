#include "proxy.h"
#include "../starter_files/DNSHeader.h"
#include "../starter_files/DNSQuestion.h"
#include "../starter_files/DNSRecord.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>


#include <stdexcept>
#include <cstring>
#include <iostream>
#include <string>
#include <memory>
#include <mutex>
#include <utility>
#include <chrono>
#include <fstream>



using std::set;
using std::unique_ptr;
using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::ofstream;
using std::chrono::steady_clock;
using std::chrono::duration;
using std::chrono::duration_cast;

std::mutex proxy_mutex;

constexpr size_t BUFFER_SIZE = 4096;
constexpr size_t LENGTH_BUFFER_SIZE = 30;


// helper function to connect to server when accept a new client connect
// return sockfd to server
// throw when error occurs
int connect_to_server_helper(const char* server_ip_addr, const char* server_port){
    addrinfo hints, *server_infos, *each;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(server_ip_addr, server_port, &hints, &server_infos) != 0){
        throw std::runtime_error("Error: getaddrinfo failed!");
    }
    int sockfd_to_server;
    for(each = server_infos; each != NULL; each = each->ai_next){
        if((sockfd_to_server = socket(each->ai_family, each->ai_socktype, each->ai_protocol)) == -1) continue;
        
        if(connect(sockfd_to_server, each->ai_addr, each->ai_addrlen) == -1) {
            close(sockfd_to_server);
            continue;
        }
        break;
    }
    if(each == NULL){
        freeaddrinfo(server_infos);
        throw std::runtime_error("Error: connect failed!");
    }
    freeaddrinfo(server_infos);
    return sockfd_to_server;
}

// helper function to calculate the total size of server's response
// must call this functino with server's response buffer
int calculate_total_size(const char* buffer){
    char length_buffer[LENGTH_BUFFER_SIZE];
    {   // points to start of the content length
        const char* length_start_ptr = strstr(buffer, "Content-Length") + 16;
        const char* length_end_ptr = strchr(length_start_ptr, '\r');
        memcpy(length_buffer, length_start_ptr, length_end_ptr - length_start_ptr);
        length_buffer[length_end_ptr - length_start_ptr] = '\0';
    }
    int content_length = atoi(length_buffer);
    int header_bytes;
    {
        const char* header_end_ptr = strstr(buffer, "\r\n\r\n") + 4;
        header_bytes = header_end_ptr - buffer;
    }
    return content_length + header_bytes;
}

proxy::proxy(bool _whether_dns, int _port_number, const char* _server_ip, 
    double _alpha, const char* _log_path, const char* _dns_ip, int _dns_port):
    whether_dns(_whether_dns), port_number(_port_number), server_ip(_server_ip),
    alpha(_alpha), dns_ip(_dns_ip), dns_port(_dns_port){
    
    main_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(main_sock_fd < 0){
        throw std::runtime_error("Error: opening socket failed!");
    }
    int enable = 1;
    if(setsockopt(main_sock_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
        throw std::runtime_error("Error: setsockopt failed!");
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port_number);

    if(bind(main_sock_fd, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0){
        throw std::runtime_error("Error: binding socket failed!");
    }
    outFile.open(_log_path);
    outFile.precision(3);
    outFile << std::fixed;
}

void proxy::start() noexcept{
    listen(main_sock_fd, 5);
    while(true){
        sockaddr_in client_sock_addr;
        socklen_t sock_addr_len = sizeof(sockaddr);
        int new_client_sockfd = accept(main_sock_fd, reinterpret_cast<sockaddr*>(&client_sock_addr), &sock_addr_len);

        if(new_client_sockfd == -1){
            proxy_mutex.lock();
            cerr << "Error: accepting new connection failed!" << endl;
            proxy_mutex.unlock();
            continue;
        }
        // if connect succeed, get browser ip address
        char browser_ip_buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_sock_addr.sin_addr), browser_ip_buffer, INET_ADDRSTRLEN);
        string browser_ip(browser_ip_buffer);
        {
            std::lock_guard<std::mutex> raii_lock(proxy_mutex);
            // if this ip is already connected, we don't create another thread
            if(this->connected_ip.find(browser_ip) != this->connected_ip.end()){
                close(new_client_sockfd);
                continue;
            }
            else{
                this->connected_ip.insert(browser_ip);
            }
            this->client_threads.push_back(std::thread(&proxy::serve_client, this, std::move(browser_ip), new_client_sockfd));
        }
    }
}

// helper function to deal with the large chunk from server
// throw when error occurs
// return the duration of receiving server's response
// server_response_size unit is Byte
double proxy::receive_server_send_client_helper(int client_sockfd, int server_sockfd, int& server_response_size){
    char buffer[BUFFER_SIZE];

    steady_clock::time_point t_start1 = steady_clock::now();
    ssize_t receive_bytes = recv(server_sockfd, buffer, BUFFER_SIZE-1, 0);
    steady_clock::time_point t_end1 = steady_clock::now();

    if(receive_bytes <= 0){
        throw std::runtime_error("Error: receiving from server failed!");
    }
    buffer[receive_bytes] = '\0';
    
    int total_response_size = calculate_total_size(buffer);
    server_response_size = total_response_size;

    // if the response from server is equal to receive_bytes, we directly forward it to client
    if(total_response_size == static_cast<int>(receive_bytes)){
        // if this time we need to save manifest file and we receive the whole file
        proxy_mutex.lock();
        if(!this->availble_bitrates.empty() && this->cached_f4m.empty()){
            this->cached_f4m = buffer;
        }
        proxy_mutex.unlock();

        if(send(client_sockfd, buffer, receive_bytes, 0) == -1){
            throw std::runtime_error("Error: sending to client failed!");
        }
        duration<double> res = duration_cast< duration<double> >(t_end1 - t_start1);
        return res.count();
    }
    // else we need to receive again
    // bytes number remain for us to receive
    size_t remain_buffer_size = static_cast<size_t>(total_response_size) - static_cast<size_t>(receive_bytes);

    // cout << "helper: receive again, remain bytes needed: " << remain_buffer_size << endl;

    // allocate one more byte for '\0'
    unique_ptr<char[]> remain_buffer(new char[remain_buffer_size+1]);
    ssize_t remain_bytes;

    steady_clock::time_point t_start2 = steady_clock::now();
    remain_bytes = recv(server_sockfd, remain_buffer.get(), remain_buffer_size, MSG_WAITALL);
    steady_clock::time_point t_end2 = steady_clock::now();

    if(remain_bytes <= 0){
        throw std::runtime_error("Error: receiving from server second time failed!");
    }
    remain_buffer[remain_bytes] = '\0';
    // cout << "helper: actually receive again: " << remain_bytes << endl;
    
    // if this time we need to save manifest file we received
    proxy_mutex.lock();
    if(!this->availble_bitrates.empty() && this->cached_f4m.empty()){
        string first_half(buffer);
        string second_half(remain_buffer.get());
        this->cached_f4m = first_half + second_half;
    }
    proxy_mutex.unlock();

    ssize_t send_bytes1;
    // then forward all buffer to client
    send_bytes1 = send(client_sockfd, buffer, receive_bytes, 0);
    if(send_bytes1 == -1){
        throw std::runtime_error("Error: sending to client failed!");
    }
    ssize_t send_bytes2;
    send_bytes2 = send(client_sockfd, remain_buffer.get(), remain_bytes, 0);
    if(send_bytes2 == -1){
        throw std::runtime_error("Error: sending to client failed!");
    }
    duration<double> res = duration_cast< duration<double> >((t_end1 - t_start1) + (t_end2 - t_start2));
    return res.count();
    // cout << "helper: actually send: " << send_bytes1 + send_bytes2 << endl;
}

// helper function to process the manifest file from server
// throw when error occurs
void proxy::process_manifest(int client_sockfd, int server_sockfd, const char* browser_receive_buffer){
    // first check if we already cached the manifest file
    {   // critical section
        std::lock_guard<std::mutex> raii_lock(proxy_mutex);
        if(!this->availble_bitrates.empty() && !this->cached_f4m.empty()){
            if(send(client_sockfd, this->cached_f4m.c_str(), this->cached_f4m.size(), 0) == -1){
                throw std::runtime_error("Error: sending cached f4m file to client failed!");
            }
            return;
        }
    }

    // send original request to server
    if(send(server_sockfd, browser_receive_buffer, strlen(browser_receive_buffer), 0) == -1){
        throw std::runtime_error("Erro: sending original f4m to server failed!");
    }

    // then deal with the response from server
    unique_ptr<char[]> big_memory(new char[BUFFER_SIZE * 20]);
    ssize_t receive_bytes = recv(server_sockfd, big_memory.get(), BUFFER_SIZE, 0);
    if(receive_bytes <= 0){
        throw std::runtime_error("Error: receving manifest from server failed!");
    }
    big_memory[receive_bytes] = '\0';
    int manifest_size = calculate_total_size(big_memory.get());
    // if we need to receive again
    if(manifest_size > receive_bytes){
        ssize_t receive_bytes_again = recv(server_sockfd, big_memory.get()+receive_bytes, 
                                           manifest_size - receive_bytes, MSG_WAITALL);
        if(receive_bytes_again <= 0){
            throw std::runtime_error("Error: receving manifest from server failed!");
        }
        big_memory[manifest_size] = '\0';
    }
    // now we have all manifest file in big_memory
    set<int> bitrates;
    char* bitrate_start_ptr = big_memory.get();
    while(true){
        bitrate_start_ptr = strstr(bitrate_start_ptr, "bitrate=");
        if(bitrate_start_ptr == nullptr) break;
        bitrate_start_ptr += 9;
        char* bitrate_end_ptr = strchr(bitrate_start_ptr, '"');
        char bitrate_length_buffer[LENGTH_BUFFER_SIZE];
        memcpy(bitrate_length_buffer, bitrate_start_ptr, bitrate_end_ptr - bitrate_start_ptr);
        bitrate_length_buffer[bitrate_end_ptr - bitrate_start_ptr] = '\0';
        bitrates.insert(atoi(bitrate_length_buffer));
        bitrate_start_ptr = bitrate_end_ptr;
    }
    // move this set to the set in proxy object
    proxy_mutex.lock();
    if(this->availble_bitrates.empty()){
        this->availble_bitrates = std::move(bitrates);
    }
    proxy_mutex.unlock();
    
    // then we send request to get nolist
    // reuse the big_memory
    memset(big_memory.get(), 0, BUFFER_SIZE * 20);
    {
        const char* video_name_start_ptr = strstr(browser_receive_buffer, "big_buck_bunny.f4m");
        const char* video_name_end_ptr = video_name_start_ptr + 18;
        const char* browser_receive_buffer_end = strchr(browser_receive_buffer, '\0');
        memcpy(big_memory.get(), browser_receive_buffer, video_name_start_ptr - browser_receive_buffer);
        memcpy(big_memory.get() + (video_name_start_ptr - browser_receive_buffer), "big_buck_bunny_nolist.f4m", 25);
        memcpy(big_memory.get() + (video_name_start_ptr - browser_receive_buffer + 25), 
               video_name_end_ptr, (browser_receive_buffer_end - video_name_end_ptr + 1));
    }
    ssize_t send_bytes = send(server_sockfd, big_memory.get(), strlen(big_memory.get()), 0);
    if(send_bytes == -1){
        throw std::runtime_error("Error: sending modified f4m failed!");
    }
    int dummy;
    this->receive_server_send_client_helper(client_sockfd, server_sockfd, dummy);
    
}

// receive and modify user's video chunk request and forward it back
// throw when error occurs
// return when client close the connection
void proxy::receive_and_process_video_chunk_request(int client_sockfd, int server_sockfd, char* buffer,
    string& browser_ip, string& server_ip){
    proxy_mutex.lock();
    // T_cur unit is Kbps
    double T_cur = static_cast<double>(*this->availble_bitrates.begin());
    proxy_mutex.unlock();
 

    

    while(true){
        // receive original request from client
        ssize_t receive_bytes = recv(client_sockfd, buffer, BUFFER_SIZE-1, 0);
        if(receive_bytes == -1){
            throw std::runtime_error("Error: receiving video chunks from client failed!");
        }
        buffer[receive_bytes] = '\0';
        // if the client close the connect(done request)
        if(receive_bytes == 0){
            return;
        }
        
        // then choose the highest bitrate we can support
        int current_highest_supportable_bitrate = static_cast<int>(T_cur / 1.5);
        int bitrates_choosed;
        {// critical section
            std::lock_guard<std::mutex> raii_lock(proxy_mutex);
            // if we can not even support lowest bitrate
            if(current_highest_supportable_bitrate < *this->availble_bitrates.begin()){
                bitrates_choosed = *this->availble_bitrates.begin();
            }
            else{
                set<int>::iterator it = this->availble_bitrates.upper_bound(current_highest_supportable_bitrate);
                --it;
                bitrates_choosed = *it;
            }
        }
        // then we modify the client request
        char modified_request_buffer[BUFFER_SIZE];
        memset(modified_request_buffer, 0, BUFFER_SIZE);
        string modified_chunk_name;
        {   //extract seg-frag string
            char* seg_start_ptr = strstr(buffer, "Seg");
            char* seg_end_ptr = strchr(seg_start_ptr, ' ');
            string seg_str(seg_start_ptr, seg_end_ptr - seg_start_ptr);

            // find bitrate start location
            char* bitrate_start_ptr = seg_start_ptr;
            while(*bitrate_start_ptr != '/') --bitrate_start_ptr;
            ++bitrate_start_ptr;
            
            // create chunk name string
            string bitrate_str = std::to_string(bitrates_choosed);
            modified_chunk_name = bitrate_str + seg_str;

            // create modifed request
            memcpy(modified_request_buffer, buffer, (bitrate_start_ptr - buffer));
            
            memcpy(modified_request_buffer + (bitrate_start_ptr - buffer), bitrate_str.c_str(), bitrate_str.size());
            char* buffer_end_ptr = strchr(buffer, '\0');
            memcpy(modified_request_buffer + (bitrate_start_ptr - buffer) + bitrate_str.size(), 
                   seg_start_ptr, buffer_end_ptr - seg_start_ptr + 1);
        }
        
        // send modified buffer
        ssize_t send_bytes = send(server_sockfd, modified_request_buffer, strlen(modified_request_buffer), 0);
        if(send_bytes == -1){
            throw std::runtime_error("Error: sending video chunks to server failed!");
        }
        
        int server_response_size;
        double duration = this->receive_server_send_client_helper(client_sockfd, server_sockfd, server_response_size);
        
        long long response_bits = static_cast<long long>(server_response_size) * 8LL;
    
        double T_new = (static_cast<double>(response_bits) / 1000.0) / duration;

        proxy_mutex.lock();
        T_cur = this->alpha * T_new + (1 - this->alpha) * T_cur;
        this->outFile << browser_ip << " " << modified_chunk_name << " " << server_ip << " ";
        this->outFile << duration << " " << T_new << " " << T_cur << " " << bitrates_choosed << endl;
        proxy_mutex.unlock();
    }
    
}


// every time using this / cerr 
// needs lock
void proxy::serve_client(string browser_ip, int new_client_sockfd){
    
    // try to connect to server
    int sockfd_to_server;
    string server_ip_addr;
    try{
        proxy_mutex.lock();
        if(this->whether_dns){
            proxy_mutex.unlock();
            server_ip_addr = this->dns_query();
        }
        else{
            server_ip_addr = this->server_ip;
            proxy_mutex.unlock();
        }
        
        sockfd_to_server = connect_to_server_helper(server_ip_addr.c_str(), "80");
    }
    catch(const std::exception& err){
        close(new_client_sockfd);
        proxy_mutex.lock();
        cerr << err.what() << endl;
        proxy_mutex.unlock();
        return;
    }

    // now we connect to both server and client(browser)
    
    // buffer to receive browser's GET request
    char browser_receive_buffer[BUFFER_SIZE];
    
    try{
        while(true){
            ssize_t receive_bytes = recv(new_client_sockfd, browser_receive_buffer, BUFFER_SIZE-1, 0);
            if(receive_bytes <= 0){
                throw std::runtime_error("Error: receiving browser request failed!(not video chunk)");
            }
            browser_receive_buffer[receive_bytes] = '\0';

            // cout << "receive from client :\n" << browser_receive_buffer << endl;

            // check if this is the f4m file request
            if(strstr(browser_receive_buffer, ".f4m") != NULL){
                break;
            }
            
            ssize_t send_bytes = send(sockfd_to_server, browser_receive_buffer, receive_bytes, 0);
            if(send_bytes == -1){
                throw std::runtime_error("Error: forwarding request to server failed!(not video chunk)");
            }
            
            int dummy;
            this->receive_server_send_client_helper(new_client_sockfd, sockfd_to_server, dummy);
        }
        // process the user's manifest request and send no_list f4m back
        this->process_manifest(new_client_sockfd, sockfd_to_server, browser_receive_buffer);
        
        
        // user start to request video chunk
        this->receive_and_process_video_chunk_request(new_client_sockfd, sockfd_to_server, browser_receive_buffer,
            browser_ip, server_ip_addr);  
    }
    catch(const std::exception& err){
        close(sockfd_to_server);
        close(new_client_sockfd);
        proxy_mutex.lock();
        cerr << err.what() << endl;
        proxy_mutex.unlock();
        return;
    }
    // now the client close the connection
    close(sockfd_to_server);
    close(new_client_sockfd);
    // this service ends
    // cout << "Browser close the connection " << endl;
}


// send dns query and return the server ip address as a string
// throw when an error occurs
string proxy::dns_query(){
    proxy_mutex.lock();
    string dns_server_ip = this->dns_ip;
    string dns_port = std::to_string(this->dns_port);
    proxy_mutex.unlock();

    int dns_server_fd = connect_to_server_helper(dns_server_ip.c_str(), dns_port.c_str());

    // now connect to dns server
    DNSHeader question_header;
    question_header.AA = 0;
    question_header.RD = 0;
    question_header.RA = 0;
    question_header.Z = 0;
    question_header.NSCOUNT = 0;
    question_header.ARCOUNT = 0;
    
    DNSQuestion question;
    question.QTYPE = 1;
    question.QCLASS = 1;
    memcpy(question.QNAME, "video.cse.umich.edu", 19);
    question.QNAME[19] = '\0';
    
    
    string question_header_str = DNSHeader::encode(question_header);
    unsigned question_header_size =  htonl(static_cast<unsigned>(question_header_str.size()) );
    
    
    string question_str = DNSQuestion::encode(question);
    unsigned question_size = htonl(static_cast<unsigned>(question_str.size()) );
    
    
    try{
        // send question
        if(send(dns_server_fd, &question_header_size, sizeof(unsigned), 0) == -1){
            throw std::runtime_error("Error: sending header size failed!");
        }
        if(send(dns_server_fd, question_header_str.c_str(), question_header_str.size(), 0) == -1){
            throw std::runtime_error("Error: sending header failed!");
        }
        if(send(dns_server_fd, &question_size, sizeof(unsigned), 0) == -1){
            throw std::runtime_error("Error: sending question size failed!");
        }
        if(send(dns_server_fd, question_str.c_str(), question_str.size(), 0) == -1){
            throw std::runtime_error("Error: sending question failed!");
        }
        unsigned response_header_size, response_size;
        
        // receive header
        if(recv(dns_server_fd, &response_header_size, sizeof(unsigned), MSG_WAITALL) == -1){
            throw std::runtime_error("Error: receiving header size failed!");
        }
        response_header_size = ntohl(response_header_size);
        unique_ptr<char[]> response_header(new char[response_header_size + 1]);

        if(recv(dns_server_fd, response_header.get(), response_header_size, MSG_WAITALL) == -1){
            throw std::runtime_error("Error: receiving header failed!");
        }
        response_header[response_header_size] = '\0';


        // receive record
        if(recv(dns_server_fd, &response_size, sizeof(unsigned), MSG_WAITALL) == -1){
            throw std::runtime_error("Error: receiving record size failed!");
        }
        response_size = ntohl(response_size);
        unique_ptr<char[]> response(new char[response_size + 1]);

        if(recv(dns_server_fd, response.get(), response_size, MSG_WAITALL) == -1){
            throw std::runtime_error("Error: receiving record failed!");
        }
        response[response_size] = '\0';

        DNSRecord record = DNSRecord::decode(string(response.get(), response_size));
        
        return string(record.RDATA);
    }
    catch(const std::exception& err){
        close(dns_server_fd);
        proxy_mutex.lock();
        cerr << err.what() << endl;
        proxy_mutex.unlock();
        throw std::runtime_error("Error: DNS query failed!");
    }
}
