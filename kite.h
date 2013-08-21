/*
 *  Linux User Mode Keyed IPv6 Tunnel Endpoint
 *  Copyright (C) 2013 Cisco Systems, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  Developed by Damjan Marion (damarion@cisco.com)
 */

/*
 *	Defines
 */

#define MTU			10000
#define PROTOCOL_UDP		17
#define PROTOCOL_ICMPV6		58
#define PROTOCOL_L2TPV3		115
#define ETHERTYPE_IPV6		0x86dd
#define ND_CACHE_SZ		16	/* How many mac address we learn per tunnel */
#define INTERFACE_ID_MAX_SZ	64	/* maximum size of interface-id string*/
#define COOKIE_LENGTH		8
#define MAC_ADDR_SZ		6
#define IPV6_ADDR_SZ		16
#define IPV6_HDR_SZ		sizeof(ipv6_hdr_t)
#define UDP_HDR_SZ		sizeof(udp_hdr_t)
#define ETH_HDR_SZ		sizeof(eth_hdr_t)
#define L2TPV3_HDR_SZ		sizeof(l2tpv3_hdr_t)
#define ICMPV6_HDR_SZ		sizeof(icmpv6_na_hdr_t)
#define TUN_HDRS_SZ		(ETH_HDR_SZ + IPV6_HDR_SZ + L2TPV3_HDR_SZ)

typedef struct __attribute__ ((packed)) {
	uint32_t		ver_tc_fl;
	uint16_t		payload_length;
	uint8_t			next_hdr;
	uint8_t			hop_limit;
	uint8_t			src[IPV6_ADDR_SZ];
	uint8_t			dst[IPV6_ADDR_SZ];
} ipv6_hdr_t;

typedef struct __attribute__ ((packed)) {
	uint16_t		src_port;
	uint16_t		dst_port;
	uint16_t		length;
	uint16_t		checksum;
} udp_hdr_t;

typedef struct __attribute__ ((packed)) {
	uint32_t		session_id;
	uint8_t			cookie[COOKIE_LENGTH];
//	uint32_t seq_number;
} l2tpv3_hdr_t;

typedef struct __attribute__ ((packed)) {
	uint8_t			dst[MAC_ADDR_SZ];
	uint8_t			src[MAC_ADDR_SZ];
	uint16_t		type;
} eth_hdr_t;

typedef struct __attribute__ ((packed)) {
	uint8_t 		type;
	uint8_t 		code;
	uint16_t 		checksum;
	uint8_t			flags[4];
	uint8_t			target_addr[IPV6_ADDR_SZ];
} icmpv6_na_hdr_t;

typedef struct __attribute__ ((packed)) {
	uint8_t 		type;
	uint8_t 		code;
	uint16_t 		checksum;
	uint8_t			cur_hop_limit;
	uint8_t			flag;
	uint16_t 		router_lifetime;
	uint32_t 		reachable_time;
	uint32_t 		retrans_timer;
} icmpv6_ra_hdr_t;

typedef struct __attribute__ ((packed)) {
	uint8_t		type;
	uint8_t	 	length;
	uint8_t		lla[MAC_ADDR_SZ];
} icmpv6_lla_opt_t;

typedef struct __attribute__ ((packed)) {
	uint8_t			type;
	uint8_t			length;
	uint8_t			prefix_length;
	uint8_t			flags;
	uint32_t		valid_lifetime;
	uint32_t		preferred_lifetime;
	uint32_t		reserved2;
	uint8_t			prefix[IPV6_ADDR_SZ];
} icmpv6_pio_opt_t;


typedef struct __attribute__ ((packed)) {
	uint8_t 		msg_type;
	uint8_t 		hop_count;
	uint8_t 		link_addr[IPV6_ADDR_SZ];
	uint8_t 		peer_addr[IPV6_ADDR_SZ];
} dhcpv6r_hdr_t;

typedef struct nd_cache_entry {
	struct nd_cache_entry	*next;
	uint8_t			mac[MAC_ADDR_SZ];
	uint8_t			ip[IPV6_ADDR_SZ];
} nd_cache_entry_t;

typedef struct tunnel_entry {
	time_t			age;
	uint8_t			mac[MAC_ADDR_SZ];
	uint8_t			rip6[IPV6_ADDR_SZ];
	uint32_t		session_id;
	uint8_t 		cookie[COOKIE_LENGTH];
	uint8_t 		interface_id[INTERFACE_ID_MAX_SZ+1];
	uint8_t			prefix[IPV6_ADDR_SZ];
	uint8_t			prefix_len;
	nd_cache_entry_t	*nd_cache;
	int			nd_cache_entries;
} tunnel_entry_t;

typedef struct fib_entry {
	struct fib_entry	*parent;
	struct fib_entry	*kids[2];
	uint8_t			prefix[IPV6_ADDR_SZ];
	uint8_t			prefix_len;
	uint8_t			lla[MAC_ADDR_SZ];
	tunnel_entry_t		*te;
} fib_entry_t;


/* util.c */
void hexdump(uint8_t *data, uint16_t len);
uint16_t rfc1071_ckecksum(uint8_t *src, uint8_t *dst, uint16_t nxt_hdr,
    uint16_t *payload, int count);
int prefix6cmp(uint8_t *a, uint8_t *b, uint8_t prefix);
void prefix6zero(uint8_t *a, uint8_t prefix);

/* fib.c */
extern pthread_mutex_t fib_mtx;

void fib_init();
void fib_destroy();
void fib_dump(fib_entry_t *fe);
fib_entry_t *fib_add(fib_entry_t **root, uint8_t *prefix, uint8_t prefix_len, tunnel_entry_t *te);
fib_entry_t *fib_find(fib_entry_t **root, uint8_t *prefix, uint8_t prefix_len);
int fib_remove_aged_entries(fib_entry_t **fe, int maxage, time_t tm, int remove_te);

#define fib_unlock()	do {							\
				pthread_mutex_unlock(&fib_mtx);			\
			} while(0)

#define fib_unlock_and_return(r)	do {					\
						fib_unlock();			\
						return r;			\
					} while(0)


#ifdef DEBUG
#define fib_lock()	do {							\
				int i = 0;					\
				while (pthread_mutex_trylock(&fib_mtx)) {	\
					if (i==1)				\
					debugf("waiting for unlock\n");		\
					if (i>10000000) {			\
						debugf("deadlock at %s:%u\n",	\
							__FILE__, __LINE__);	\
						exit(1);			\
					}					\
					i++;					\
				}						\
			} while(0)
#else
#define fib_lock()	do {						\
				pthread_mutex_lock(&fib_mtx);		\
			} while(0)
#endif

#ifdef DEBUG
#define debugf(fmt, args...)	do {					\
	 				printf("%s: ", __func__);	\
					printf(fmt, ##args);		\
				} while (0)
#else
#define debugf(fmt, args...)
#endif

#define MAC_TO_STR(mac, str)	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", \
				*(mac), *(mac+1), *(mac+2), *(mac+3), \
				*(mac+4), *(mac+5));
