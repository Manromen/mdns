//
// Created by Simon Lang on 2019-02-14.
//

#include <vector>
#include "MDNSRequestPerformer.hpp"


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
}

mdns::MDNSRequestPerformer::~MDNSRequestPerformer()
{
    freeifaddrs(addrs);
}

std::vector<in_addr> mdns::MDNSRequestPerformer::listIPv4Addresses()
{
    std::vector<in_addr> addresses;

    ifaddrs *next = this->addrs;
    while (next != nullptr)
    {
        if (next->ifa_addr->sa_family == AF_INET)
        {
            sockaddr_in* sa = (sockaddr_in*)next->ifa_addr;
            addresses.emplace_back(sa->sin_addr);
        }
        next = next->ifa_next;
    }

    return addresses;
}

