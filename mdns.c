/* mdns.c  -  mDNS/DNS-SD library  -  Public Domain  -  2017 Mattias Jansson / Rampant Pixels, 2019 Simon Lang
 *
 * This library provides a cross-platform mDNS and DNS-SD library in C.
 * The implementation is based on RFC 6762 and RFC 6763.
 *
 * The latest source code maintained by Rampant Pixels is always available at
 *
 * https://github.com/rampantpixels/mdns
 *
 *
 * The fork maintained by Simon Lang is always available at
 *
 * https://github.com/simonlang7/mdns
 *
 * This library is put in the public domain; you can redistribute it and/or modify it without any restrictions.
 *
 */

#include "mdns.h"


#ifdef _WIN32
#define strncasecmp _strnicmp
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif

static const uint8_t mdns_services_query[] = {
	// Transaction ID
	0x00, 0x00,
	// Flags
	0x00, 0x00,
	// 1 question
	0x00, 0x01,
	// No answer, authority or additional RRs
	0x00, 0x00,
	0x00, 0x00,
	0x00, 0x00,
	// _services._dns-sd._udp.local.
	0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
	0x07, '_', 'd', 'n', 's', '-', 's', 'd',
	0x04, '_', 'u', 'd', 'p',
	0x05, 'l', 'o', 'c', 'a', 'l',
	0x00,
	// PTR record
	0x00, MDNS_RECORDTYPE_PTR,
	// QU (unicast response) and class IN
	0x80, MDNS_CLASS_IN
};
static uint16_t mdns_transaction_id = 0;

struct sockaddr_in*
mdns_record_parse_a(const void* buffer, size_t size, size_t offset, size_t length,
                    struct sockaddr_in* addr) {
	memset(addr, 0, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
#ifdef __APPLE__
	addr->sin_len = sizeof(struct sockaddr_in);
#endif
	if ((size >= offset + length) && (length == 4))
		addr->sin_addr.s_addr = *(const uint32_t*)((const char*)buffer + offset);
	return addr;
}

struct sockaddr_in6*
mdns_record_parse_aaaa(const void* buffer, size_t size, size_t offset, size_t length,
                       struct sockaddr_in6* addr) {
	memset(addr, 0, sizeof(struct sockaddr_in6));
	addr->sin6_family = AF_INET6;
#ifdef __APPLE__
	addr->sin6_len = sizeof(struct sockaddr_in6);
#endif
	if ((size >= offset + length) && (length == 16))
		addr->sin6_addr = *(const struct in6_addr*)((const char*)buffer + offset);
	return addr;
}

int
mdns_socket_open_ipv4(struct in_addr if_addr) {
	int sock = (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
		return -1;
	if (mdns_socket_setup_ipv4(sock, if_addr)) {
		mdns_socket_close(sock);
		return -1;
	}
	return sock;
}

int
mdns_socket_setup_ipv4(int sock, struct in_addr if_addr) {
	struct sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr = if_addr;

#ifdef __APPLE__
	saddr.sin_len = sizeof(saddr);
#endif

	if (bind(sock, (struct sockaddr*)&saddr, sizeof(saddr)))
		return -1;

#ifdef _WIN32
	unsigned long param = 1;
	ioctlsocket(sock, FIONBIO, &param);
#else
	const int flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

	unsigned char ttl = 1;
	unsigned char loopback = 1;
	struct ip_mreq req;

	setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (const char*)&ttl, sizeof(ttl));
	setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (const char*)&loopback, sizeof(loopback));

	memset(&req, 0, sizeof(req));
	req.imr_multiaddr.s_addr = htonl((((uint32_t)224U) << 24U) | ((uint32_t)251U));
	req.imr_interface.s_addr = INADDR_ANY;
	if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&req, sizeof(req)))
		return -1;

	return 0;
}

int
mdns_socket_open_ipv6(struct in6_addr if_addr) {
	int sock = (int)socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
		return -1;
	if (mdns_socket_setup_ipv6(sock, if_addr)) {
		mdns_socket_close(sock);
		return -1;
	}
	return sock;
}

int
mdns_socket_setup_ipv6(int sock, struct in6_addr if_addr) {
	struct sockaddr_in6 saddr;
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin6_family = AF_INET6;
	saddr.sin6_addr = if_addr;
#ifdef __APPLE__
	saddr.sin6_len = sizeof(saddr);
#endif

	if (bind(sock, (struct sockaddr*)&saddr, sizeof(saddr)))
		return -1;

#ifdef _WIN32
	unsigned long param = 1;
	ioctlsocket(sock, FIONBIO, &param);
#else
	const int flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

	int hops = 1;
	unsigned int loopback = 1;
	struct ipv6_mreq req;

	setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (const char*)&hops, sizeof(hops));
	setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const char*)&loopback, sizeof(loopback));

	memset(&req, 0, sizeof(req));
	req.ipv6mr_multiaddr.s6_addr[0] = 0xFF;
	req.ipv6mr_multiaddr.s6_addr[1] = 0x02;
	req.ipv6mr_multiaddr.s6_addr[15] = 0xFB;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char*)&req, sizeof(req)))
		return -1;

	return 0;
}

void
mdns_socket_close(int sock) {
#ifdef _WIN32
	closesocket(sock);
#else
	close(sock);
#endif
}

int
mdns_is_string_ref(uint8_t val) {
	return (0xC0 == (val & 0xC0));
}

mdns_string_pair_t
mdns_get_next_substring(const void* rawdata, size_t size, size_t offset) {
	const uint8_t* buffer = rawdata;
	mdns_string_pair_t pair = {MDNS_INVALID_POS, 0, 0};
	if (!buffer[offset]) {
		pair.offset = offset;
		return pair;
	}
	if (mdns_is_string_ref(buffer[offset])) {
		if (size < offset + 2)
			return pair;

		offset = (((size_t)(0x3f & buffer[offset]) << 8) | (size_t)buffer[offset + 1]);
		if (offset >= size)
			return pair;

		pair.ref = 1;
	}

	size_t length = (size_t)buffer[offset++];
	if (size < offset + length)
		return pair;

	pair.offset = offset;
	pair.length = length;

	return pair;
}

int
mdns_string_skip(const void* buffer, size_t size, size_t* offset) {
	size_t cur = *offset;
	mdns_string_pair_t substr;
	do {
		substr = mdns_get_next_substring(buffer, size, cur);
		if (substr.offset == MDNS_INVALID_POS)
			return 0;
		if (substr.ref) {
			*offset = cur + 2;
			return 1;
		}
		cur = substr.offset + substr.length;
	}
	while (substr.length);

	*offset = cur + 1;
	return 1;
}

int
mdns_string_equal(const void* buffer_lhs, size_t size_lhs, size_t* ofs_lhs,
                  const void* buffer_rhs, size_t size_rhs, size_t* ofs_rhs) {
	size_t lhs_cur = *ofs_lhs;
	size_t rhs_cur = *ofs_rhs;
	size_t lhs_end = MDNS_INVALID_POS;
	size_t rhs_end = MDNS_INVALID_POS;
	mdns_string_pair_t lhs_substr;
	mdns_string_pair_t rhs_substr;
	do {
		lhs_substr = mdns_get_next_substring(buffer_lhs, size_lhs, lhs_cur);
		rhs_substr = mdns_get_next_substring(buffer_rhs, size_rhs, rhs_cur);
		if ((lhs_substr.offset == MDNS_INVALID_POS) || (rhs_substr.offset == MDNS_INVALID_POS))
			return 0;
		if (lhs_substr.length != rhs_substr.length)
			return 0;
		if (strncasecmp((const char*)buffer_rhs + rhs_substr.offset,
		                (const char*)buffer_lhs + lhs_substr.offset, rhs_substr.length))
			return 0;
		if (lhs_substr.ref && (lhs_end == MDNS_INVALID_POS))
			lhs_end = lhs_cur + 2;
		if (rhs_substr.ref && (rhs_end == MDNS_INVALID_POS))
			rhs_end = rhs_cur + 2;
		lhs_cur = lhs_substr.offset + lhs_substr.length;
		rhs_cur = rhs_substr.offset + rhs_substr.length;
	}
	while (lhs_substr.length);

	if (lhs_end == MDNS_INVALID_POS)
		lhs_end = lhs_cur + 1;
	*ofs_lhs = lhs_end;

	if (rhs_end == MDNS_INVALID_POS)
		rhs_end = rhs_cur + 1;
	*ofs_rhs = rhs_end;

	return 1;
}

void
mdns_string_alloc(mdns_string_t* str, const char* content, size_t length) {
	str->str = malloc((length + 1) * sizeof(char));
	strncpy(str->str, content, length);
	str->str[length] = '\0';
	str->length = length;
}

void
mdns_string_free(mdns_string_t* str) {
	free(str->str);
}

void
mdns_record_srv_free(mdns_record_srv_t* record_srv) {
	mdns_string_free(&record_srv->name);
}

void
mdns_record_txt_free(mdns_record_txt_t* record_txt) {
	mdns_string_free(&record_txt->key);
	mdns_string_free(&record_txt->value);
}

void
mdns_record_free(mdns_records_t* record) {
	switch (record->record_type) {
		case MDNS_RECORDTYPE_AAAA:
			mdns_string_free(&record->content.aaaa);
			break;
		case MDNS_RECORDTYPE_A:
			mdns_string_free(&record->content.a);
			break;
		case MDNS_RECORDTYPE_PTR:
			mdns_string_free(&record->content.ptr);
			break;
		case MDNS_RECORDTYPE_TXT:
			mdns_record_txt_free(&record->content.txt);
			break;
		case MDNS_RECORDTYPE_SRV:
			mdns_record_srv_free(&record->content.srv);
			break;
		default:
			break;
	}
}

void
mdns_records_free(mdns_records_t* records) {
	mdns_records_t* current_record = records;
	mdns_records_t* next;

	while (current_record != NULL) {
		next = current_record->next;
		mdns_record_free(current_record);
		free(current_record);
		current_record = next;
	}
}

void
mdns_entry_free(mdns_entry_t* entry) {
	mdns_records_free(entry->record);
}

void
mdns_entries_free(mdns_entry_t* entry) {
	mdns_entry_t* current_entry = entry;
	mdns_entry_t* next;

	while (current_entry != NULL) {
		next = current_entry->next;
		mdns_entry_free(current_entry);
		free(current_entry);
		current_entry = next;
	}
}

void
mdns_reply_free(mdns_reply_t* reply) {
	mdns_string_free(&reply->from_address);
	mdns_entries_free(reply->entry);
}

mdns_string_t
mdns_string_extract(const void* buffer, size_t size, size_t* offset) {
    char strbuffer[256];
    size_t capacity = 256;

	size_t cur = *offset;
	size_t end = MDNS_INVALID_POS;
	mdns_string_pair_t substr;
	mdns_string_t result = {NULL, 0};
	char* dst = strbuffer;
	size_t remain = capacity;
	do {
		substr = mdns_get_next_substring(buffer, size, cur);
		if (substr.offset == MDNS_INVALID_POS) {
			result.str = NULL;
			return result;
		}
		if (substr.ref && (end == MDNS_INVALID_POS))
			end = cur + 2;
		if (substr.length) {
			size_t to_copy = (substr.length < remain) ? substr.length : remain;
			memcpy(dst, (const char*)buffer + substr.offset, to_copy);
			dst += to_copy;
			remain -= to_copy;
			if (remain) {
				*dst++ = '.';
				--remain;
			}
		}
		cur = substr.offset + substr.length;
	}
	while (substr.length);

	if (end == MDNS_INVALID_POS)
		end = cur + 1;
	*offset = end;

	mdns_string_alloc(&result, strbuffer, capacity - remain);
	return result;
}

size_t
mdns_string_find(const char* str, size_t length, char c, size_t offset) {
	const void* found;
	if (offset >= length)
		return MDNS_INVALID_POS;
	found = memchr(str + offset, c, length - offset);
	if (found)
		return (size_t)((const char*)found - str);
	return MDNS_INVALID_POS;
}

void*
mdns_string_make(void* data, size_t capacity, const char* name, size_t length) {
	size_t pos = 0;
	size_t last_pos = 0;
	size_t remain = capacity;
	unsigned char* dest = data;
	while ((last_pos < length) && ((pos = mdns_string_find(name, length, '.', last_pos)) != MDNS_INVALID_POS)) {
		size_t sublength = pos - last_pos;
		if (sublength < remain) {
			*dest = (unsigned char)sublength;
			memcpy(dest + 1, name + last_pos, sublength);
			dest += sublength + 1;
			remain -= sublength + 1;
		}
		else {
			return 0;
		}
		last_pos = pos + 1;
	}
	if (last_pos < length) {
		size_t sublength = length - last_pos;
		if (sublength < capacity) {
			*dest = (unsigned char)sublength;
			memcpy(dest + 1, name + last_pos, sublength);
			dest += sublength + 1;
			remain -= sublength + 1;
		}
		else {
			return 0;
		}
	}
	if (!remain)
		return 0;
	*dest++ = 0;
	return dest;
}

void
init_record(mdns_records_t** record,
			uint16_t rtype,
			uint16_t rclass,
			uint32_t ttl,
			size_t length) {
	*record = malloc(sizeof(mdns_records_t));
	(*record)->record_type = rtype;
	(*record)->type = rtype;
	(*record)->rclass = rclass;
	(*record)->ttl = ttl;
	(*record)->length = length;
	(*record)->next = NULL;
}

void
init_entry(mdns_entry_t** entry) {
	*entry = malloc(sizeof(mdns_entry_t));
	(*entry)->next = NULL;
	(*entry)->record = NULL;
}

void
mdns_record_parse(mdns_records_t*** records, uint16_t rtype, uint16_t rclass, uint32_t ttl,
				  const void* data, size_t size, size_t offset, size_t length) {
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	char address[INET6_ADDRSTRLEN];

	if (rtype != MDNS_RECORDTYPE_TXT)
		init_record(*records, rtype, rclass, ttl, length);

	switch (rtype) {
		case MDNS_RECORDTYPE_PTR:
			(**records)->content.ptr = mdns_record_parse_ptr(data, size, offset, length);
			break;
		case MDNS_RECORDTYPE_SRV:
			(**records)->content.srv = mdns_record_parse_srv(data, size, offset, length);
			break;
		case MDNS_RECORDTYPE_A:
			mdns_record_parse_a(data, size, offset, length, &sin);
			inet_ntop(AF_INET, &sin.sin_addr, address, INET_ADDRSTRLEN);
			mdns_string_alloc(&(**records)->content.a, address, INET_ADDRSTRLEN);
			break;
		case MDNS_RECORDTYPE_AAAA:
			mdns_record_parse_aaaa(data, size, offset, length, &sin6);
			inet_ntop(AF_INET6, &sin6.sin6_addr, address, INET6_ADDRSTRLEN);
			mdns_string_alloc(&(**records)->content.a, address, INET6_ADDRSTRLEN);
			break;
		case MDNS_RECORDTYPE_TXT:
			mdns_record_parse_txt(records, data, size, offset, rclass, ttl, length);
			break;
		default:
			(**records)->record_type = MDNS_RECORDTYPE_IGNORE;
			break;
	}
}

size_t
mdns_records_parse(mdns_entry_t** entry, const void* buffer, size_t size, size_t* offset,
				   mdns_entry_type_t type, size_t num_records) {
	size_t parsed = 0;

	init_entry(entry);
	(*entry)->entry_type = type;

	mdns_records_t** current_record = &(*entry)->record;
	for (size_t i = 0; i < num_records; ++i) {
		mdns_string_skip(buffer, size, offset);
		const uint16_t* data = (const uint16_t*)((const char*)buffer + (*offset));

		uint16_t rtype = ntohs(*data++);
		uint16_t rclass = ntohs(*data++);
		uint32_t ttl = ntohs(*(const uint32_t*)(const void*)data); data += 2;
		uint16_t length = ntohs(*data++);

		*offset += 10;

		mdns_record_parse(&current_record, rtype, rclass, ttl, buffer, size, *offset, length);

		*offset += length;

		++parsed;
		current_record = &(*current_record)->next;
	}
	(*entry)->records_size = parsed;
	return parsed;
}

mdns_string_t
mdns_parse_ip_address(struct sockaddr* saddr) {
	mdns_string_t addr_string;

	if (saddr->sa_family == AF_INET6) {
		char address[INET6_ADDRSTRLEN];
		struct sockaddr_in6* sin6from = (struct sockaddr_in6*)saddr;
		inet_ntop(AF_INET6, &sin6from->sin6_addr, address, INET6_ADDRSTRLEN);
		mdns_string_alloc(&addr_string, address, INET6_ADDRSTRLEN);
	}
	else {
		char address[INET_ADDRSTRLEN];
		struct sockaddr_in* sinfrom = (struct sockaddr_in*)saddr;
		inet_ntop(AF_INET, &sinfrom->sin_addr, address, INET_ADDRSTRLEN);
		mdns_string_alloc(&addr_string, address, INET_ADDRSTRLEN);
	}

	return addr_string;
}

int
mdns_discovery_send(int sock) {
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	struct sockaddr* saddr = (struct sockaddr*)&addr;
	socklen_t saddrlen = sizeof(struct sockaddr);
	if (getsockname(sock, saddr, &saddrlen))
		return -1;
	if (saddr->sa_family == AF_INET6) {
		memset(&addr6, 0, sizeof(struct sockaddr_in6));
		addr6.sin6_family = AF_INET6;
#ifdef __APPLE__
		addr6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		addr6.sin6_addr.s6_addr[0] = 0xFF;
		addr6.sin6_addr.s6_addr[1] = 0x02;
		addr6.sin6_addr.s6_addr[15] = 0xFB;
		addr6.sin6_port = htons((unsigned short)5353);
		saddr = (struct sockaddr*)&addr6;
		saddrlen = sizeof(struct sockaddr_in6);
	}
	else {
		memset(&addr, 0, sizeof(struct sockaddr_in));
		addr.sin_family = AF_INET;
#ifdef __APPLE__
		addr.sin_len = sizeof(struct sockaddr_in);
#endif
		addr.sin_addr.s_addr = htonl((((uint32_t)224U) << 24U) | ((uint32_t)251U));
		addr.sin_port = htons((unsigned short)5353);
		saddr = (struct sockaddr*)&addr;
		saddrlen = sizeof(struct sockaddr_in);
	}

	if (sendto(sock, mdns_services_query, sizeof(mdns_services_query), 0,
	           saddr, saddrlen) < 0)
		return -1;
	return 0;
}

size_t
mdns_discovery_recv(int sock, void* buffer, size_t capacity, mdns_reply_t* reply) {
	struct sockaddr_in6 addr;
	struct sockaddr* saddr = (struct sockaddr*)&addr;
	memset(&addr, 0, sizeof(addr));
	saddr->sa_family = AF_INET;
#ifdef __APPLE__
	saddr->sa_len = sizeof(addr);
#endif
	socklen_t addrlen = sizeof(addr);
	ssize_t ret = recvfrom(sock, buffer, capacity, 0,
						   saddr, &addrlen);
	reply->entry = NULL;
	reply->from_address = mdns_parse_ip_address(saddr);

	if (ret <= 0)
		return 0;


	size_t data_size = (size_t)ret;
	size_t records = 0;
	uint16_t* data = (uint16_t*)buffer;

	uint16_t transaction_id = ntohs(*data++);
	uint16_t flags          = ntohs(*data++);
	uint16_t questions      = ntohs(*data++);
	uint16_t answer_rrs     = ntohs(*data++);
	uint16_t authority_rrs  = ntohs(*data++);
	uint16_t additional_rrs = ntohs(*data++);

	if (transaction_id || (flags != 0x8400))
		return 0; //Not a reply to our question

	if (questions > 1)
		return 0;

	int i;
	for (i = 0; i < questions; ++i) {
		size_t ofs = (size_t)((char*)data - (char*)buffer);
		size_t verify_ofs = 12;
		//Verify it's our question, _services._dns-sd._udp.local.
		if (!mdns_string_equal(buffer, data_size, &ofs,
							   mdns_services_query, sizeof(mdns_services_query), &verify_ofs))
			return 0;
		data = (uint16_t*)((char*)buffer + ofs);

		uint16_t type = ntohs(*data++);
		uint16_t rclass = ntohs(*data++);

		//Make sure we get a reply based on our PTR question for class IN
		if ((type != MDNS_RECORDTYPE_PTR) || ((rclass & 0x7FFF) != MDNS_CLASS_IN))
			return 0;
	}

	mdns_entry_t** current_entry = &reply->entry;
	init_entry(current_entry);
	(*current_entry)->entry_type = MDNS_ENTRYTYPE_ANSWER;

	mdns_records_t** current_record = &(*current_entry)->record;
	for (i = 0; i < answer_rrs; ++i) {
		size_t ofs = (size_t)((char*)data - (char*)buffer);
		size_t verify_ofs = 12;
		//Verify it's an answer to our question, _services._dns-sd._udp.local.
		int is_answer = mdns_string_equal(buffer, data_size, &ofs,
										  mdns_services_query, sizeof(mdns_services_query), &verify_ofs);
		data = (uint16_t*)((char*)buffer + ofs);

		uint16_t type = ntohs(*data++);
		uint16_t rclass = ntohs(*data++);
		uint32_t ttl = ntohl(*(uint32_t*)(void*)data); data += 2;
		uint16_t length = ntohs(*data++);

		if (is_answer) {
			++records;

			size_t offset = (size_t)((char*)data - (char*)buffer);
			mdns_record_parse(&current_record, type, rclass, ttl, buffer, data_size, offset, length);

			current_record = &(*current_record)->next;
		}
		data = (void*)((char*)data + length);
	}
	(*current_entry)->records_size = records;

	size_t offset = (size_t)((char*)data - (char*)buffer);

	current_entry = &(*current_entry)->next;
	records += mdns_records_parse(current_entry, buffer, data_size, &offset,
								  MDNS_ENTRYTYPE_AUTHORITY, authority_rrs);

	current_entry = &(*current_entry)->next;
	records += mdns_records_parse(current_entry, buffer, data_size, &offset,
								  MDNS_ENTRYTYPE_ADDITIONAL, additional_rrs);

	return records;
}

int
mdns_query_send(int sock, mdns_record_type_t type, const char* name, size_t length,
                void* buffer, size_t capacity) {
	if (capacity < (17 + length))
		return -1;

	uint16_t* data = buffer;
	//Transaction ID
	*data++ = htons(++mdns_transaction_id);
	//Flags
	*data++ = 0;
	//Questions
	*data++ = htons(1);
	//No answer, authority or additional RRs
	*data++ = 0;
	*data++ = 0;
	*data++ = 0;
	//Name string
	data = mdns_string_make(data, capacity - 17, name, length);
	if (!data)
		return -1;
	//Record type
	*data++ = htons(type);
	//! Unicast response, class IN
	*data++ = htons(0x8000U | MDNS_CLASS_IN);

	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	struct sockaddr* saddr = (struct sockaddr*)&addr;
	socklen_t saddrlen = sizeof(struct sockaddr);
	if (getsockname(sock, saddr, &saddrlen))
		return -1;
	if (saddr->sa_family == AF_INET6) {
		memset(&addr6, 0, sizeof(struct sockaddr_in6));
		addr6.sin6_family = AF_INET6;
#ifdef __APPLE__
		addr6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		addr6.sin6_addr.s6_addr[0] = 0xFF;
		addr6.sin6_addr.s6_addr[1] = 0x02;
		addr6.sin6_addr.s6_addr[15] = 0xFB;
		addr6.sin6_port = htons((unsigned short)5353);
		saddr = (struct sockaddr*)&addr6;
		saddrlen = sizeof(struct sockaddr_in6);
	}
	else {
		memset(&addr, 0, sizeof(struct sockaddr_in));
		addr.sin_family = AF_INET;
#ifdef __APPLE__
		addr.sin_len = sizeof(struct sockaddr_in);
#endif
		addr.sin_addr.s_addr = htonl((((uint32_t)224U) << 24U) | ((uint32_t)251U));
		addr.sin_port = htons((unsigned short)5353);
		saddr = (struct sockaddr*)&addr;
		saddrlen = sizeof(struct sockaddr_in);
	}

	if (sendto(sock, buffer, (char*)data - (char*)buffer, 0,
	           saddr, saddrlen) < 0)
		return -1;
	return 0;
}

size_t
mdns_query_recv(int sock, void* buffer, size_t capacity,
				mdns_reply_t* reply) {
	struct sockaddr_in6 addr;
	struct sockaddr* saddr = (struct sockaddr*)&addr;
	memset(&addr, 0, sizeof(addr));
	saddr->sa_family = AF_INET;
#ifdef __APPLE__
	saddr->sa_len = sizeof(addr);
#endif
	socklen_t addrlen = sizeof(addr);
	ssize_t ret = recvfrom(sock, buffer, capacity, 0,
	                   saddr, &addrlen);
	reply->entry = NULL;
	reply->from_address = mdns_parse_ip_address(saddr);

	if (ret <= 0)
		return 0;


	size_t data_size = (size_t)ret;
	uint16_t* data = (uint16_t*)buffer;

	uint16_t transaction_id = ntohs(*data++);
	++data;// uint16_t flags = ntohs(*data++);
	uint16_t questions      = ntohs(*data++);
	uint16_t answer_rrs     = ntohs(*data++);
	uint16_t authority_rrs  = ntohs(*data++);
	uint16_t additional_rrs = ntohs(*data++);

	if (transaction_id != mdns_transaction_id)// || (flags != 0x8400))
		return 0; //Not a reply to our last question

	if (questions > 1)
		return 0;

	//Skip questions part
	int i;
	for (i = 0; i < questions; ++i) {
		size_t ofs = (size_t)((char*)data - (char*)buffer);
		if (!mdns_string_skip(buffer, data_size, &ofs))
			return 0;
		data = (void*)((char*)buffer + ofs);
		++data;
		++data;
	}

	size_t records = 0;
	size_t offset = (size_t)((char*)data - (char*)buffer);

	mdns_entry_t** current_entry = &reply->entry;
	records += mdns_records_parse(current_entry, buffer, data_size, &offset,
								  MDNS_ENTRYTYPE_ANSWER, answer_rrs);

	current_entry = &(*current_entry)->next;
	records += mdns_records_parse(current_entry, buffer, data_size, &offset,
								  MDNS_ENTRYTYPE_AUTHORITY, authority_rrs);

	current_entry = &(*current_entry)->next;
	records += mdns_records_parse(current_entry, buffer, data_size, &offset,
								  MDNS_ENTRYTYPE_ADDITIONAL, additional_rrs);
	return records;
}

mdns_string_t
mdns_record_parse_ptr(const void* buffer, size_t size, size_t offset, size_t length) {
	//PTR record is just a string
	if ((size >= offset + length) && (length >= 2))
		return mdns_string_extract(buffer, size, &offset);
	mdns_string_t empty = {NULL, 0};
	return empty;
}

mdns_record_srv_t
mdns_record_parse_srv(const void* buffer, size_t size, size_t offset, size_t length) {
	mdns_record_srv_t srv;
	memset(&srv, 0, sizeof(mdns_record_srv_t));
	// Read the priority, weight, port number and the discovery name
	// SRV record format (http://www.ietf.org/rfc/rfc2782.txt):
	// 2 bytes network-order unsigned priority
	// 2 bytes network-order unsigned weight
	// 2 bytes network-order unsigned port
	// string: discovery (domain) name, minimum 2 bytes when compressed
	if ((size >= offset + length) && (length >= 8)) {
		const uint16_t* recorddata = (const uint16_t*)((const char*)buffer + offset);
		srv.priority = ntohs(*recorddata++);
		srv.weight = ntohs(*recorddata++);
		srv.port = ntohs(*recorddata++);
		offset += 6;
		srv.name = mdns_string_extract(buffer, size, &offset);
	}
	return srv;
}

size_t
mdns_record_parse_txt(mdns_records_t*** records, const void* buffer, size_t size, size_t offset,
					  uint16_t rclass, uint32_t ttl, size_t length) {
    size_t parsed = 0;
    const char* strdata;
    size_t separator, sublength;
    size_t end = offset + length;

    mdns_records_t** current_record = *records;

    if (size < end)
        end = size;

    while ((offset < end) /*&& (parsed < capacity)*/) {
        strdata = (const char*)buffer + offset;
        sublength = *(const unsigned char*)strdata;

        ++strdata;
        offset += sublength + 1;

        separator = 0;
        for (size_t c = 0; c < sublength; ++c) {
            //DNS-SD TXT record keys MUST be printable US-ASCII, [0x20, 0x7E]
            if ((strdata[c] < 0x20) || (strdata[c] > 0x7E))
                break;
            if (strdata[c] == '=') {
                separator = c;
                break;
            }
        }

        if (!separator)
            continue;

		init_record(current_record, MDNS_RECORDTYPE_TXT, rclass, ttl, length);
        mdns_record_txt_t* txt_record = &(*current_record)->content.txt;

        if (separator < sublength) {
			size_t key_length = separator;
			mdns_string_alloc(&txt_record->key, strdata, key_length);

			size_t value_length = sublength - (separator + 1);
			mdns_string_alloc(&txt_record->value, strdata + separator + 1, value_length);
        }
        else {
			size_t key_length = sublength;
			mdns_string_alloc(&txt_record->key, strdata, key_length);
        }

        ++parsed;
		*records = current_record;
        current_record = &(*current_record)->next;
    }

    return parsed;
}


#ifdef _WIN32
#undef strncasecmp
#endif