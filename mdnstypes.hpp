//
// Created by Simon Lang on 2019-02-14.
//

#pragma once

#include <string>
#include <vector>

extern "C" {
#include "mdns.h"
}

namespace mdns
{

enum Status
{
    SUCCESS,
    ERROR_OPENING_SOCKET,
    ERROR_SENDING_DISCOVERY,
    ERROR_SENDING_QUERY,
    UNKNOWN_ERROR
};

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

    static PTRRecord from_mdns_records_t(const mdns_records_t& record);
};

struct TXTRecord : public Record
{
    std::string key;
    std::string value;

    static TXTRecord from_mdns_records_t(const mdns_records_t& record);
};

struct SRVRecord : public Record
{
    std::string name;
    unsigned priority;
    unsigned weight;
    unsigned port;

    static SRVRecord from_mdns_records_t(const mdns_records_t& record);
};

struct AddressRecord : public Record
{
    std::string address;

    static AddressRecord from_mdns_records_t(const mdns_records_t& record);
};

struct Entry
{
    std::vector<PTRRecord> ptrRecords;
    std::vector<TXTRecord> txtRecords;
    std::vector<SRVRecord> srvRecords;
    std::vector<AddressRecord> aRecords;
    std::vector<AddressRecord> aaaaRecords;

    void merge(const Entry& entry);
    static Entry from_mdns_entry_t(const mdns_entry_t& entry);
};

struct Reply
{
    std::string srcAddress;
    int srcPort;
    Entry answer;
    Entry authority;
    Entry additional;

    static Reply from_mdns_reply_t(const mdns_reply_t& reply);
};

} // namespace mdns