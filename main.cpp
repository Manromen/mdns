//
// Created by Simon Lang on 2019-02-14.
//

#ifdef _WIN32
#  define _CRT_SECURE_NO_WARNINGS 1
#endif


#include <iostream>
#include <vector>

extern "C" {
#include "mdns.h"
}

#include <cstdio>
#include <stdio.h>
#include <errno.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#ifdef _WIN32
#  define sleep(x) Sleep(x * 1000)
#else
#  include <netdb.h>

#endif

#include "MDNSRequestPerformer.hpp"


int
dnssd_and_mdns(in_addr if_addr) {
    size_t capacity = 2048;
    void* buffer = 0;
    size_t records;

#ifdef _WIN32
    WORD versionWanted = MAKEWORD(1, 1);
	WSADATA wsaData;
	WSAStartup(versionWanted, &wsaData);
#endif

    int sock = mdns_socket_open_ipv4(if_addr);
    if (sock < 0) {
        printf("Failed to open socket: %s\n", strerror(errno));
        return -1;
    }
    printf("Opened IPv4 socket for mDNS\n");

    printf("Sending DNS-SD discovery\n");
    if (mdns_discovery_send(sock)) {
        printf("Failed to send DNS-DS discovery: %s\n", strerror(errno));
        goto quit;
    }

    printf("Reading DNS-SD replies\n");
    buffer = malloc(capacity);
    for (int i = 0; i < 10; ++i) {
        mdns_reply_t reply;
        records = mdns_discovery_recv(sock, buffer, capacity, &reply);
//        sleep(1);
    }

    printf("Sending mDNS query\n");
    if (mdns_query_send(sock, MDNS_RECORDTYPE_PTR,
                        MDNS_STRING_CONST("_http._tcp.local."),
                        buffer, capacity)) {
        printf("Failed to send mDNS query: %s\n", strerror(errno));
        goto quit;
    }

    printf("Reading mDNS replies\n");
    for (int i = 0; i < 10; ++i) {
        mdns_reply_t reply;
        records = mdns_query_recv(sock, buffer, capacity, &reply);
        sleep(1);
    }

    quit:
    free(buffer);

    mdns_socket_close(sock);
    printf("Closed socket\n");

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}

int
main() {
    std::shared_ptr<mdns::MDNSRequestPerformer> performer = mdns::MDNSRequestPerformer::create();
    std::vector<std::string> addresses = performer->listIPv4InterfaceAddresses();

//    std::string address = "192.168.42.131";

    for (auto& address : addresses)
    {
        std::cout << "Checking interface " << address << std::endl;
        mdns::Status status = performer->mDNSDiscoverySend(address);
        performer->mDNSDiscoveryReceive(address);
        status = performer->mDNSQuerySend(address);

        for (int i = 0; i < 10; ++i) {
            std::cout << "Reply on interface " << address << std::endl;
            mdns::Reply reply = performer->mDNSQueryReceive(address);
            std::cout << reply.srcAddress << ":" << reply.srcPort << ": " << reply.answer.ptrRecords.size()
                      << " PTR records" << std::endl;
            sleep(1);
        }
    }

    performer->closeAllSockets();

    return 0;
}
