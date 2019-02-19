//
// Created by Simon Lang on 2019-02-14.
//

#pragma once

#include <string>
#include <vector>
#include "mdns.h"

namespace mdns
{

struct Record
{
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    size_t length;
};

struct PTRRecord : public Record
{
    std::string name;
};

struct TXTRecord : public Record
{
    std::string key;
    std::string value;
};

struct SRVRecord : public Record
{
    std::string name;
    unsigned priority;
    unsigned weight;
    unsigned port;
};

struct AddressRecord : public Record
{
    std::string address;
};

struct Entry {
    std::vector<PTRRecord> ptrRecords;
    std::vector<TXTRecord> txtRecords;
    std::vector<SRVRecord> srvRecords;
    std::vector<AddressRecord> aRecords;
    std::vector<AddressRecord> aaaaRecords;
};

struct Reply
{
    std::string srcAddress;
    int srcPort;
    Entry answer;
    Entry authority;
    Entry additional;
};

} // namespace mdns