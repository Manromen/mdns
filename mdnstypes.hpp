//
// Created by Simon Lang on 2019-02-14.
//

#pragma once

#include <string>
#include "mdns.h"

namespace mdns
{

enum EntryType
{
    ENTRY_ANSWER,
    ENTRY_AUTHORITY,
    ENTRY_ADDITIONAL
};

enum RecordType
{
    RECORD_PTR,
    RECORD_TXT,
    RECORD_SRV,
    RECORD_A,
    RECORD_AAAA,
};

struct Record
{
    EntryType entryType;
    RecordType recordType;
    std::string content;
};

struct PTRRecord : public Record
{
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    size_t length;
};

struct TXTRecord : public Record
{

};

struct Reply
{
    std::string srcAddress;
    int srcPort;

};

} // namespace mdns