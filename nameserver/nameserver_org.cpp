#include "nameserver.h"
#include "../starter_files/DNSHeader.h"
#include "../starter_files/DNSQuestion.h"
#include "../starter_files/DNSRecord.h"

#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <queue>
#include <limits.h>

using namespace std;


int main(int argc, char** argv) {
    if (argc != 5) {
        cout << "Usage: ./nameserver [--geo|--rr] <port> <servers> <log>\n";
        return -1;
    }
    
    string flag = argv[1];
    int port = atoi(argv[2]);
    string server = argv[3];
    string log = argv[4];

    Nameserver nameserver(flag, port, server, log);
    flag == "--geo" ? nameserver.parse_geo_distance() : nameserver.parse_rr();
    nameserver.server();
}


void Nameserver::parse_rr() {
    rr_server_ip_index = 0;
    ifstream input(serverfile);
    if (!input.is_open()) {
        cout << "Error opening " << serverfile << endl;
        exit(1);
    }
    string ip;
    while(input >> ip) {
        server_ips.push_back(ip);
    }
    input.close();
}

void Nameserver::parse_geo_distance() {
    ifstream input(serverfile);
    if (!input.is_open()) {
        cout << "Error opening " << serverfile << endl;
        exit(1);
    }
    string first_line;
    int num_nodes;
    input >> first_line >> num_nodes;
    for (int i = 0; i < num_nodes; i++) {
        int id;
        string type;
        string ip;
        input >> id >> type >> ip;
        nodes.emplace_back(id, type, ip);
        nodes[i].cost.resize(num_nodes);
    }
    
    string line;
    int num_links;
    input >> line >> num_links;
    
    
    for (int i = 0; i < num_links; i++) {
        int id1;
        int id2;
        int cost;
        input >> id1 >> id2 >> cost;
        nodes[id1].cost[id2] = cost;
        nodes[id2].cost[id1] = cost;
    }
    input.close();
}

string Nameserver::dijkstra() {
    priority_queue<pair<int, int>, vector<pair<int, int>>, Node_less> pq; // <Cost, ID>
    vector<vector<int>> table;
    table.emplace_back(vector<int>(nodes.size(), 0)); //Visited column
    table.emplace_back(vector<int>(nodes.size(), INT_MAX)); //Cost column
    int id = get_id(connected_ip);
    pq.push(make_pair(0, id));
    table[1][id] = 0;
    while (pq.size()) {
        pair<int, int> v = pq.top();
        int node_id = v.second;
        pq.pop();
        if (table[0][node_id]) continue; //Skip already visited nodes
        table[0][node_id] = true; 
        for (int i = 0; i < (int)nodes[node_id].cost.size(); i++) {
            int edge_node_cost = nodes[node_id].cost[i];
            if (edge_node_cost && table[0][i] == 0) {
                //Have an unvisited edge
                int cost = table[1][node_id] + nodes[node_id].cost[i];
                if (table[1][i] > cost) {
                    table[1][i] = cost;
                    pq.push(make_pair(cost, i));
                }
            }
        }
    }
    
    //Find the closest server
    int min_cost = INT_MAX;
    int server_node = -1;
    for (int i = 0; i < (int)nodes.size(); ++i) {
        if (nodes[i].type == "SERVER" && table[1][i] < min_cost) {
            min_cost = table[1][i];
            server_node = i;
        }
    }
    return nodes[server_node].ip;
}

void Nameserver::server() {
    // (1) Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Error opening stream socket");
        return;
    }

    // (2) Set the "reuse port" socket option
    int yesval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yesval, sizeof(yesval)) == -1) {
        perror("Error setting socket options");
        return;
    }

    // (3) Create a sockaddr_in struct for the proper port and bind() to it.
    struct sockaddr_in addr;
    if (make_server_sockaddr(&addr, port) == -1) {
        return;
    }

    // (3b) Bind to the port.
    if (bind(sockfd, (sockaddr *) &addr, sizeof(addr)) == -1) {
        perror("Error binding stream socket");
        return;
    }

    // (3c) Detect which port was chosen.
    port = get_port_number(sockfd);

    // (4) Begin listening for incoming connections.
    listen(sockfd, 10 /*Queue size*/);

    // (5) Serve incoming connections one by one forever.
    while(true) {
        struct sockaddr_in client_info; 
        int size_of_client_info = sizeof(client_info);
        int connectionfd = accept(sockfd, (sockaddr *)&client_info, (socklen_t *)&size_of_client_info);
        connected_ip = inet_ntoa(client_info.sin_addr);

        if (connectionfd == -1) {
            perror("Error accepting connection");
            return;
        }
        //Handle the connection
        if (handle_connection(connectionfd) != 0) {
            perror("Error handling connection");
            return;
        }
        
    }
}

int Nameserver::handle_connection(int connectionfd) {
    unsigned size_of_DNS_header = 0;
    recv(connectionfd, &size_of_DNS_header, 4, 0);
    size_of_DNS_header = ntohl(size_of_DNS_header);
    
    const int MAX_MESSAGE_SIZE = 1000;
    char buffer[MAX_MESSAGE_SIZE];
    memset(buffer, 0, sizeof(buffer));
    recv(connectionfd, &buffer, size_of_DNS_header, 0);
    DNSHeader dns_header = DNSHeader::decode(buffer);

    unsigned size_of_DNS_question = 0;
    recv(connectionfd, &size_of_DNS_question, 4, 0);
    size_of_DNS_question = ntohl(size_of_DNS_question);

    memset(buffer, 0, sizeof(buffer));
    recv(connectionfd, &buffer, size_of_DNS_question, 0);
    DNSQuestion dns_question = DNSQuestion::decode(buffer);

    DNSRecord dns_record;
    string ip_address;

    if (strcmp(dns_question.QNAME, "video.cse.umich.edu")) {
        //Return RCODE 3
        dns_header.RCODE = 3;
    }
    else{
        dns_header.AA = 1;
        dns_header.RD = 0;
        dns_header.RA = 0;
        dns_header.Z = 0;
        dns_header.NSCOUNT = 0;
        dns_header.ARCOUNT = 0;
        dns_header.QDCOUNT = 0;

        ip_address = get_ip_address();
        string url = "video.cse.umich.edu";
        memcpy(dns_record.RDATA, ip_address.c_str(), ip_address.size());
        memcpy(dns_record.NAME, url.c_str(), url.size());
        dns_record.TYPE = 1;
        dns_record.CLASS = 1;
        dns_record.TTL = 0;
        dns_record.RDLENGTH = ip_address.size();
    }
    string dns_header_encoded = DNSHeader::encode(dns_header);
    string dns_record_encoded = DNSRecord::encode(dns_record);

    size_of_DNS_header = htonl(static_cast<unsigned>(dns_header_encoded.size()));
    unsigned size_of_DNS_record = htonl(static_cast<unsigned>(dns_record_encoded.size()));

    
    send(connectionfd, &size_of_DNS_header, 4, 0);
    
    send(connectionfd, dns_header_encoded.c_str(), dns_header_encoded.size(), 0);

    send(connectionfd, &size_of_DNS_record, 4, 0);
    
    send(connectionfd, dns_record_encoded.c_str(), dns_record_encoded.size(), 0);
    

    close(connectionfd);

    ofstream output;
    if (!has_opened_file) {
        output = ofstream(logfile);
        has_opened_file = true;
    }
    else {
        output = ofstream(logfile, std::fstream::app);
    }
    output << connected_ip << " video.cse.umich.edu " << ip_address << endl;
    output.close();

    return 0;
}

string Nameserver::get_ip_address() {
    string ip;
    if (flag == "--rr") {
        ip = server_ips[rr_server_ip_index++ % server_ips.size()];
    }
    else {
        // geographic distance
        ip = dijkstra();
    }
    return ip;
}


int Nameserver::make_server_sockaddr(struct sockaddr_in *addr, int port) {
    // Step (1): specify socket family.
    // This is an internet socket.
    addr->sin_family = AF_INET;

    // Step (2): specify socket address (hostname).
    // The socket will be a server, so it will only be listening.
    // Let the OS map it to the correct address.
    addr->sin_addr.s_addr = INADDR_ANY;

    // Step (3): Set the port value.
    // If port is 0, the OS will choose the port for us.
    // Use htons to convert from local byte order to network byte order.
    addr->sin_port = htons(port);

    return 0;
}

int Nameserver::get_port_number(int sockfd) {
    struct sockaddr_in addr;
    socklen_t length = sizeof(addr);
    if (getsockname(sockfd, (sockaddr *) &addr, &length) == -1) {
        perror("Error getting port of socket");
        return -1;
    }
    // Use ntohs to convert from network byte order to host byte order.
    return ntohs(addr.sin_port);
}
