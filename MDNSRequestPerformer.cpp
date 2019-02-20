//
// Created by Simon Lang on 2019-02-14.
//

#include "MDNSRequestPerformer.hpp"

#include <vector>
#include <string>

#ifdef _WIN32
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif

extern "C" {
#include "mdns.h"
}

using mdns::Status;

std::shared_ptr<mdns::MDNSRequestPerformer> mdns::MDNSRequestPerformer::create()
{
    ifaddrs* addrs = (ifaddrs*)malloc(sizeof(ifaddrs));
    int error = getifaddrs(&addrs);

    // TODO: proper error handling
    if (error)
    {
        freeifaddrs(addrs);
        return nullptr;
    }

    return std::make_shared<MDNSRequestPerformer>(addrs);
}

mdns::MDNSRequestPerformer::MDNSRequestPerformer(ifaddrs* const addrs)
{
    this->addrs = addrs;

    ifaddrs *next = this->addrs;
    while (next != nullptr)
    {
        if (next->ifa_addr->sa_family == AF_INET)
        {
            sockaddr_in* sa = (sockaddr_in*)next->ifa_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sa->sin_addr, addressBuffer, INET_ADDRSTRLEN);
            std::string address = addressBuffer;
            ipv4addresses[address] = sa->sin_addr;
        }
        next = next->ifa_next;
    }

    buffer = malloc(capacity);
}

mdns::MDNSRequestPerformer::~MDNSRequestPerformer()
{
    freeifaddrs(addrs);
    free(buffer);
}

void mdns::MDNSRequestPerformer::closeSocket(std::string& interfaceAddress)
{
    if (sockets.find(interfaceAddress) != sockets.end())
        mdns_socket_close(sockets[interfaceAddress]);
}

void mdns::MDNSRequestPerformer::closeAllSockets()
{
    for (auto& pair : sockets)
        mdns_socket_close(pair.second);
}

std::vector<std::string> mdns::MDNSRequestPerformer::listIPv4InterfaceAddresses()
{
    std::vector<std::string> addresses;

    for (auto& pair : ipv4addresses)
        addresses.emplace_back(pair.first);

    return addresses;
}

Status mdns::MDNSRequestPerformer::mDNSDiscoverySend(std::string& interfaceAddress)
{
    Status status;
    if ((status = openSocket(interfaceAddress)) != SUCCESS)
        return status;

    if (mdns_discovery_send(sockets[interfaceAddress]))
        return ERROR_SENDING_DISCOVERY;

    return SUCCESS;
}

mdns::Reply mdns::MDNSRequestPerformer::mDNSDiscoveryReceive(std::string& interfaceAddress)
{
    mdns_reply_t reply;
    mdns_discovery_recv(sockets[interfaceAddress], buffer, capacity, &reply);

    return Reply::from_mdns_reply_t(reply);
}

Status mdns::MDNSRequestPerformer::mDNSQuerySend(std::string& interfaceAddress)
{
    if (mdns_query_send(sockets[interfaceAddress],
            MDNS_RECORDTYPE_PTR, MDNS_STRING_CONST("_http._tcp.local."),
            buffer, capacity))
        return ERROR_SENDING_QUERY;

    return SUCCESS;
}

mdns::Reply mdns::MDNSRequestPerformer::mDNSQueryReceive(std::string& interfaceAddress)
{
    mdns_reply_t reply;
    mdns_query_recv(sockets[interfaceAddress], buffer, capacity, &reply);

    return Reply::from_mdns_reply_t(reply);
}

Status mdns::MDNSRequestPerformer::openSocket(std::string& interfaceAddress)
{
    if (sockets.find(interfaceAddress) != sockets.end())
        return SUCCESS;

    int socket = mdns_socket_open_ipv4(ipv4addresses[interfaceAddress]);
    if (socket < 0)
        return ERROR_OPENING_SOCKET;

    sockets[interfaceAddress] = socket;
    return SUCCESS;
}