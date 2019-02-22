//
// Created by Simon Lang on 2019-02-20.
//

#include "mdnstypes.hpp"

mdns::PTRRecord mdns::PTRRecord::from_mdns_records_t(const mdns_records_t& record)
{
    PTRRecord result{};

    result.type = record.type;
    result.rclass = record.rclass;
    result.ttl = record.ttl;
    result.length = record.length;
    result.name = record.content.ptr.str;

    return result;
}

mdns::TXTRecord mdns::TXTRecord::from_mdns_records_t(const mdns_records_t& record)
{
    TXTRecord result{};

    result.type = record.type;
    result.rclass = record.rclass;
    result.ttl = record.ttl;
    result.length = record.length;

    for (size_t i = 0; i < record.content.txts.size; ++i) {
        result.records[record.content.txts.txts[i].key.str] = record.content.txts.txts[i].value.str;
    }

    return result;
}

mdns::SRVRecord mdns::SRVRecord::from_mdns_records_t(const mdns_records_t& record)
{
    SRVRecord result{};

    result.type = record.type;
    result.rclass = record.rclass;
    result.ttl = record.ttl;
    result.length = record.length;
    result.name = record.content.srv.name.str;
    result.priority = record.content.srv.priority;
    result.weight = record.content.srv.weight;
    result.port = record.content.srv.port;

    return result;
}

mdns::AddressRecord mdns::AddressRecord::from_mdns_records_t(const mdns_records_t& record)
{
    AddressRecord result{};

    result.type = record.type;
    result.rclass = record.rclass;
    result.ttl = record.ttl;
    result.length = record.length;

    // .aaaa.str resides in the same memory, no need to access .aaaa
    result.address = record.content.a.str;

    return result;
}

mdns::Entry mdns::Entry::from_mdns_entry_t(const mdns_entry_t& entry)
{
    Entry result{};

    mdns_records_t* currentRecord = entry.record;
    while (currentRecord != nullptr)
    {
        switch (currentRecord->record_type)
        {
            case MDNS_RECORDTYPE_PTR:
                result.ptrRecords.emplace_back(PTRRecord::from_mdns_records_t(*currentRecord));
                break;
            case MDNS_RECORDTYPE_TXT:
                result.txtRecords.emplace_back(TXTRecord::from_mdns_records_t(*currentRecord));
                break;
            case MDNS_RECORDTYPE_SRV:
                result.srvRecords.emplace_back(SRVRecord::from_mdns_records_t(*currentRecord));
                break;
            case MDNS_RECORDTYPE_A:
                result.aRecords.emplace_back(AddressRecord::from_mdns_records_t(*currentRecord));
                break;
            case MDNS_RECORDTYPE_AAAA:
                result.aaaaRecords.emplace_back(AddressRecord::from_mdns_records_t(*currentRecord));
                break;
            default:
                break;
        }
        currentRecord = currentRecord->next;
    }

    return result;
}

void mdns::Entry::merge(const mdns::Entry& entry)
{
    ptrRecords.insert(ptrRecords.end(), entry.ptrRecords.begin(), entry.ptrRecords.end());
    txtRecords.insert(txtRecords.end(), entry.txtRecords.begin(), entry.txtRecords.end());
    srvRecords.insert(srvRecords.end(), entry.srvRecords.begin(), entry.srvRecords.end());
    aRecords.insert(aRecords.end(), entry.aRecords.begin(), entry.aRecords.end());
    aaaaRecords.insert(aaaaRecords.end(), entry.aaaaRecords.begin(), entry.aaaaRecords.end());
}

mdns::Reply mdns::Reply::from_mdns_reply_t(const mdns_reply_t& reply)
{
    Reply result{};

    result.srcAddress = reply.from_address.str;
    result.srcPort = reply.from_port;
    result.answer = {};
    result.authority = {};
    result.additional = {};

    mdns_entry_t* currentEntry = reply.entry;
    while (currentEntry != nullptr)
    {
        Entry entry = Entry::from_mdns_entry_t(*currentEntry);
        switch (currentEntry->entry_type)
        {
            case MDNS_ENTRYTYPE_ANSWER:
                result.answer.merge(entry);
                break;
            case MDNS_ENTRYTYPE_AUTHORITY:
                result.authority.merge(entry);
                break;
            case MDNS_ENTRYTYPE_ADDITIONAL:
                result.additional.merge(entry);
                break;
            default:
                break;
        }

        currentEntry = currentEntry->next;
    }

    return result;
}
