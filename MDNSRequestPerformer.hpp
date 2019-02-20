//
// Created by Simon Lang on 2019-02-14.
//

#pragma once


#include <ifaddrs.h>
#include <netinet/in.h>
#include <memory>
#include <unordered_map>

#include "mdnstypes.hpp"

namespace mdns
{

class MDNSRequestPerformer
{
public:
    /**
     * Creates an mDNS request performer for all available interfaces
     * @return
     */
    static std::shared_ptr<MDNSRequestPerformer> create();

    /**
     * Constructs an mDNS request performer. Use create() instead.
     * @param addrs addresses obtained by getifaddrs
     */
    explicit MDNSRequestPerformer(ifaddrs* addrs);
    virtual ~MDNSRequestPerformer();

    std::vector<std::string> listIPv4InterfaceAddresses();

    void closeSocket(std::string& interfaceAddress);
    void closeAllSockets();

    Status mDNSDiscoverySend(std::string& interfaceAddress);
    Reply mDNSDiscoveryReceive(std::string& interfaceAddress);

    Status mDNSQuerySend(std::string& interfaceAddress);
    Reply mDNSQueryReceive(std::string& interfaceAddress);

private:
    ifaddrs* addrs;
    std::unordered_map<std::string, in_addr> ipv4addresses;
    std::unordered_map<std::string, int> sockets;
    void* buffer;
    size_t capacity = 2048;

    Status openSocket(std::string& interfaceAddress);

};

} // namespace mdns

