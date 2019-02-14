//
// Created by Simon Lang on 2019-02-14.
//

#pragma once


#include <ifaddrs.h>
#include <memory>
#include <netinet/in.h>

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
    explicit MDNSRequestPerformer(ifaddrs* const addrs);
    virtual ~MDNSRequestPerformer();

    std::vector<in_addr> listIPv4Addresses();

private:
    ifaddrs* addrs;
};

} // namespace mdns


