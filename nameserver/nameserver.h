#ifndef NAME_SERVER_H
#define NAME_SERVER_H

#include <string>
#include <vector>
#include <unordered_map>

class Node {
public:
    Node(int id, std::string type, std::string ip) :
        id(id), type(type), ip(ip) { }
    int id;
    std::string type;
    std::string ip;
    std::vector<int> cost;
};

class Node_less {
public:
    bool operator()(const std::pair<int, int> &lhs, const std::pair<int, int>&rhs) const {
        return lhs.first < rhs.first;
    }
};

class Nameserver {
public:
    Nameserver(std::string flag, int port, std::string serverfile, std::string logfile) : 
        flag(flag), port(port), serverfile(serverfile), logfile(logfile), has_opened_file(false) { }

    void parse_rr();
    void parse_geo_distance();

    void server();
    std::string get_ip_address();

    std::string dijkstra();

private:
    std::string flag;
    int port;
    std::string serverfile;
    std::string logfile;
    std::vector<std::string> server_ips;
    int rr_server_ip_index;
    std::vector<Node> nodes;
    std::string connected_ip;
    bool has_opened_file;

    int handle_connection(int connectionfd);
    int make_server_sockaddr(struct sockaddr_in *addr, int port);
    int get_port_number(int sockfd);

    int get_id(std::string ip) {
        for (int i = 0; i < (int)nodes.size(); i++) {
            if (ip == nodes[i].ip) return nodes[i].id;
        }
        return -1;
    }
};

#endif