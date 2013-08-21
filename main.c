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


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>
#include <dlfcn.h>

#include "kite.h"

static int tunfd;				/* TUN interface file descr */
static int aging_time = 300;			/* Max age for FIB entries */
static int periodic_run = 9;
static int ra_interval = 10;
static int ra_priority = 0;
static int pio_valid_lifetime = 7200;
static int pio_preferred_lifetime = 7200;

static uint8_t my_ip6addr[IPV6_ADDR_SZ];	/* Local tunnel  IPv6 address */
static uint8_t dhcpv6_addr[IPV6_ADDR_SZ];	/* DHCPv6 IPv6 address */
static int  _do_exit = 0;

static fib_entry_t	*tfib = NULL;		/* Tunnel FIB */
static fib_entry_t	*rfib = NULL;		/* Route FIB */

static uint8_t my_mac_addr[] = { 0x20, 0x00, 0x00, 0x00, 0x00, 0x01 };

static uint8_t my_lla[] = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
			    0x22, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01 };

static uint8_t tun_mac_addr[MAC_ADDR_SZ];

static int tt_count=0;
static int rt_count=0;

static struct {
	uint64_t pkts_encap;
	uint64_t pkts_decap;
	uint64_t dhcp_relay_forward;
	uint64_t dhcp_relay_reply;
} stats;

void
(*calc_wan_prefix_for_tunnel)(uint8_t *tunnel_ip, uint8_t *prefix,
    uint8_t *prefix_len);

#if DEBUG
static uint8_t dbg_str[40];
#endif

static void
l2tpv3_icmpv6_send_ns(tunnel_entry_t *te, uint8_t *addr)
{
	struct __attribute__ ((packed)) {
		eth_hdr_t		o_eth_hdr;
		ipv6_hdr_t		o_ipv6_hdr;
		l2tpv3_hdr_t		l2tpv3_hdr;
		eth_hdr_t		eth_hdr;
		ipv6_hdr_t		ipv6_hdr;
		icmpv6_na_hdr_t		icmpv6_na_hdr;
		icmpv6_lla_opt_t	icmpv6_tgt_lla_opt;
	} ns_msg;

	memset(&ns_msg, 0 , sizeof(ns_msg));

	/* TAP Ethernet */
	memcpy(ns_msg.o_eth_hdr.dst, tun_mac_addr, MAC_ADDR_SZ);
	memcpy(ns_msg.o_eth_hdr.src, my_mac_addr, MAC_ADDR_SZ);
	ns_msg.o_eth_hdr.type = htons(ETHERTYPE_IPV6);

	/* Outer IPv6 Header */
	ns_msg.o_ipv6_hdr.ver_tc_fl = 0x60;		// IPv6
	ns_msg.o_ipv6_hdr.next_hdr = PROTOCOL_L2TPV3;
	ns_msg.o_ipv6_hdr.hop_limit = 255;
	ns_msg.o_ipv6_hdr.payload_length = htons(sizeof(ns_msg) - IPV6_HDR_SZ -
	    ETH_HDR_SZ);
	memcpy(ns_msg.o_ipv6_hdr.src, my_ip6addr, IPV6_ADDR_SZ);
	memcpy(ns_msg.o_ipv6_hdr.dst, te->rip6, IPV6_ADDR_SZ);
	
	/* L2TPv3 Header */
	ns_msg.l2tpv3_hdr.session_id = te->session_id;
	memcpy(ns_msg.l2tpv3_hdr.cookie, te->cookie, COOKIE_LENGTH);
	
	/* Ethernet */
	ns_msg.eth_hdr.dst[0] = 0x33;
	ns_msg.eth_hdr.dst[1] = 0x33;
	ns_msg.eth_hdr.dst[2] = 0xFF;
	memcpy(&ns_msg.eth_hdr.dst[3], (char *) &addr[13], 3);
	memcpy(&ns_msg.eth_hdr.src, my_mac_addr, MAC_ADDR_SZ);
	ns_msg.eth_hdr.type = htons(ETHERTYPE_IPV6);
	
	/* Inner IPv6 Header */
	ns_msg.ipv6_hdr.ver_tc_fl = 0x60;		// IPv6
	ns_msg.ipv6_hdr.next_hdr = PROTOCOL_ICMPV6;
	ns_msg.ipv6_hdr.hop_limit = 255;
	ns_msg.ipv6_hdr.payload_length = htons(sizeof(icmpv6_na_hdr_t) + 
	    sizeof(icmpv6_lla_opt_t));
	memcpy(ns_msg.ipv6_hdr.src, my_lla, IPV6_ADDR_SZ);

	/* Construct Solicited-node multicast address */
	inet_pton(AF_INET6, "ff02::1:ff00:0000", &ns_msg.ipv6_hdr.dst);
	memcpy(&ns_msg.ipv6_hdr.dst[13], (char *) &addr[13], 3);

	/* icmpv6 header */
	ns_msg.icmpv6_na_hdr.type = 135;
	ns_msg.icmpv6_na_hdr.flags[0] = 0xC0;
	memcpy(&ns_msg.icmpv6_na_hdr.target_addr, addr, IPV6_ADDR_SZ);

	/* icmpv6 source link-local-address */
	ns_msg.icmpv6_tgt_lla_opt.type =  1;
	ns_msg.icmpv6_tgt_lla_opt.length =  1;
	memcpy(ns_msg.icmpv6_tgt_lla_opt.lla, my_mac_addr, MAC_ADDR_SZ);

	/* checksum */
	ns_msg.icmpv6_na_hdr.checksum = rfc1071_ckecksum(ns_msg.ipv6_hdr.src, 
		ns_msg.ipv6_hdr.dst, PROTOCOL_ICMPV6, 
		(uint16_t *) &ns_msg.icmpv6_na_hdr, sizeof(icmpv6_na_hdr_t) + 
		sizeof(ns_msg.icmpv6_tgt_lla_opt));

	write(tunfd, &ns_msg, sizeof(ns_msg));
}

static void
l2tpv3_icmpv6_send_ra(tunnel_entry_t *te)
{
	struct __attribute__ ((packed)) {
		eth_hdr_t		o_eth_hdr;
		ipv6_hdr_t		o_ipv6_hdr;
		l2tpv3_hdr_t		l2tpv3_hdr;
		eth_hdr_t		eth_hdr;
		ipv6_hdr_t		i_ipv6_hdr;
		icmpv6_ra_hdr_t		hdr;
		icmpv6_lla_opt_t	src_lla_opt;
		icmpv6_pio_opt_t	pio_opt;
	} ra_msg;
	int sz = sizeof(icmpv6_ra_hdr_t) + sizeof(icmpv6_lla_opt_t);

	uint8_t dst_mac[] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
	memset(&ra_msg, 0 , sizeof(ra_msg));

	/* TAP Ethernet */
	memcpy(ra_msg.o_eth_hdr.dst, tun_mac_addr, MAC_ADDR_SZ);
	memcpy(ra_msg.o_eth_hdr.src, my_mac_addr, MAC_ADDR_SZ);
	ra_msg.o_eth_hdr.type = htons(ETHERTYPE_IPV6);

	/* Outer IPv6 Header */
	ra_msg.o_ipv6_hdr.ver_tc_fl = 0x60;		// IPv6
	ra_msg.o_ipv6_hdr.next_hdr = PROTOCOL_L2TPV3;
	ra_msg.o_ipv6_hdr.hop_limit = 255;
	memcpy(ra_msg.o_ipv6_hdr.src, my_ip6addr, IPV6_ADDR_SZ);
	memcpy(ra_msg.o_ipv6_hdr.dst, te->rip6, IPV6_ADDR_SZ);
	
	/* L2TPv3 Header */
	ra_msg.l2tpv3_hdr.session_id = te->session_id;
	memcpy(ra_msg.l2tpv3_hdr.cookie, te->cookie, COOKIE_LENGTH);
	
	/* Ethernet */
	memcpy(ra_msg.eth_hdr.dst, dst_mac, MAC_ADDR_SZ);
	memcpy(ra_msg.eth_hdr.src, my_mac_addr, MAC_ADDR_SZ);
	ra_msg.eth_hdr.type = htons(ETHERTYPE_IPV6);
	
	/* Inner IPv6 Header */
	ra_msg.i_ipv6_hdr.ver_tc_fl = 0x60;		// IPv6
	ra_msg.i_ipv6_hdr.next_hdr = PROTOCOL_ICMPV6;
	ra_msg.i_ipv6_hdr.hop_limit = 255;
	memcpy(ra_msg.i_ipv6_hdr.src, my_lla, IPV6_ADDR_SZ);
	inet_pton(AF_INET6, "ff02::1", &ra_msg.i_ipv6_hdr.dst);

	/* ICMPv6 Header */
	ra_msg.hdr.type = 134;
	ra_msg.hdr.code = 0;
	ra_msg.hdr.cur_hop_limit = 64;

	ra_msg.hdr.router_lifetime = htons(30);
	ra_msg.hdr.reachable_time = htonl(0);
	ra_msg.hdr.retrans_timer = htonl(0);

	/* Source Link Local Address Option */
	ra_msg.src_lla_opt.type = 1;
	ra_msg.src_lla_opt.length = 1;
	memcpy(&ra_msg.src_lla_opt.lla, my_mac_addr, MAC_ADDR_SZ);

	if (te->prefix_len) {
		sz += sizeof(icmpv6_pio_opt_t);
		ra_msg.hdr.flag = 0x40;		/* M not bit set, O bit set */

		/* Prefix Information Option */
		ra_msg.pio_opt.type = 3;
		ra_msg.pio_opt.length = 4;
		ra_msg.pio_opt.prefix_length = te->prefix_len;
		ra_msg.pio_opt.flags = 0xC0;	/* L & A bit set */
		ra_msg.pio_opt.valid_lifetime = htonl(pio_valid_lifetime);
		ra_msg.pio_opt.preferred_lifetime = htonl(pio_preferred_lifetime);
		memcpy(&ra_msg.pio_opt.prefix, te->prefix, IPV6_ADDR_SZ);
	} else {
		ra_msg.hdr.flag = 0x80;		/* M bit set */
	}

	ra_msg.hdr.flag |= ra_priority << 3; 	/* Set priority per RFC4191 */

	ra_msg.o_ipv6_hdr.payload_length = htons(TUN_HDRS_SZ + sz);
	ra_msg.i_ipv6_hdr.payload_length = htons(sz);

	ra_msg.hdr.checksum = rfc1071_ckecksum(ra_msg.i_ipv6_hdr.src, 
	    ra_msg.i_ipv6_hdr.dst, PROTOCOL_ICMPV6, (uint16_t *) &ra_msg.hdr, sz);

	write(tunfd, &ra_msg, TUN_HDRS_SZ + ETH_HDR_SZ + IPV6_HDR_SZ + sz);
}

static void
l2tpv3_icmpv6_send_na(tunnel_entry_t *te, uint8_t *mac_addr, uint8_t *ip_addr)
{
	struct __attribute__ ((packed)) {
		eth_hdr_t		o_eth_hdr;
		ipv6_hdr_t		o_ipv6_hdr;
		l2tpv3_hdr_t		l2tpv3_hdr;
		eth_hdr_t		eth_hdr;
		ipv6_hdr_t		ipv6_hdr;
		icmpv6_na_hdr_t		icmpv6_na_hdr;
		icmpv6_lla_opt_t	icmpv6_tgt_lla_opt;
	} na_msg;

	memset(&na_msg, 0 , sizeof(na_msg));

	/* TAP Ethernet */
	memcpy(na_msg.o_eth_hdr.dst, tun_mac_addr, MAC_ADDR_SZ);
	memcpy(na_msg.o_eth_hdr.src, my_mac_addr, MAC_ADDR_SZ);
	na_msg.o_eth_hdr.type = htons(ETHERTYPE_IPV6);

	/* Outer IPv6 Header */
	na_msg.o_ipv6_hdr.ver_tc_fl = 0x60;		// IPv6
	na_msg.o_ipv6_hdr.next_hdr = PROTOCOL_L2TPV3;
	na_msg.o_ipv6_hdr.hop_limit = 255;
	na_msg.o_ipv6_hdr.payload_length = htons(sizeof(na_msg) - IPV6_HDR_SZ -
	    ETH_HDR_SZ);
	memcpy(na_msg.o_ipv6_hdr.src, my_ip6addr, IPV6_ADDR_SZ);
	memcpy(na_msg.o_ipv6_hdr.dst, te->rip6, IPV6_ADDR_SZ);
	
	/* L2TPv3 Header */
	na_msg.l2tpv3_hdr.session_id = te->session_id;
	memcpy(na_msg.l2tpv3_hdr.cookie, te->cookie, COOKIE_LENGTH);
	
	/* Ethernet */
	memcpy(na_msg.eth_hdr.dst, mac_addr, MAC_ADDR_SZ);
	memcpy(na_msg.eth_hdr.src, my_mac_addr, MAC_ADDR_SZ);
	na_msg.eth_hdr.type = htons(ETHERTYPE_IPV6);
	
	/* Inner IPv6 Header */
	na_msg.ipv6_hdr.ver_tc_fl = 0x60;		// IPv6
	na_msg.ipv6_hdr.next_hdr = PROTOCOL_ICMPV6;
	na_msg.ipv6_hdr.hop_limit = 255;
	na_msg.ipv6_hdr.payload_length = htons(sizeof(icmpv6_na_hdr_t) + 
	    sizeof(icmpv6_lla_opt_t));
	memcpy(na_msg.ipv6_hdr.src, my_lla, IPV6_ADDR_SZ);
	memcpy(na_msg.ipv6_hdr.dst, ip_addr, IPV6_ADDR_SZ);

	/* icmpv6 header */
	na_msg.icmpv6_na_hdr.type = 136;
	na_msg.icmpv6_na_hdr.flags[0] = 0xC0;
	memcpy(&na_msg.icmpv6_na_hdr.target_addr, my_lla, IPV6_ADDR_SZ);

	/* icmpv6 target link-local-address */
	na_msg.icmpv6_tgt_lla_opt.type =  2;
	na_msg.icmpv6_tgt_lla_opt.length =  1;
	memcpy(na_msg.icmpv6_tgt_lla_opt.lla, my_mac_addr, MAC_ADDR_SZ);

	/* checksum */
	na_msg.icmpv6_na_hdr.checksum = rfc1071_ckecksum(na_msg.ipv6_hdr.src, 
		na_msg.ipv6_hdr.dst, PROTOCOL_ICMPV6, 
		(uint16_t *) &na_msg.icmpv6_na_hdr, sizeof(icmpv6_na_hdr_t) + 
		sizeof(na_msg.icmpv6_tgt_lla_opt));

	write(tunfd, &na_msg, sizeof(na_msg));
}

static void
dhcpv6_relay_to_server(tunnel_entry_t *te, uint8_t *pkt)
{
	uint16_t rpkt_sz;
	size_t if_id_len;
	uint8_t *rpkt;
	// FIXME mutex on te

	if_id_len=strlen((char *) te->interface_id);
	ipv6_hdr_t *sip = (ipv6_hdr_t *) pkt;
	udp_hdr_t *sudp = (udp_hdr_t *) (pkt + IPV6_HDR_SZ);

	rpkt_sz = ETH_HDR_SZ + IPV6_HDR_SZ + UDP_HDR_SZ + sizeof(dhcpv6r_hdr_t) + 
	    ntohs(sudp->length) - 8 + 4 +	/* Relay-Message option */
	    if_id_len + 4;			/* Interface-ID option */

	rpkt = (uint8_t *) malloc(rpkt_sz);
	assert(rpkt);
	memset(rpkt, 0, rpkt_sz);

	eth_hdr_t *reth = (eth_hdr_t *) rpkt;
	ipv6_hdr_t *rip = (ipv6_hdr_t *) ((uint8_t *)reth + ETH_HDR_SZ);
	udp_hdr_t *rudp = (udp_hdr_t *) ((uint8_t *)rip + IPV6_HDR_SZ);
	dhcpv6r_hdr_t *dhcp6r = (dhcpv6r_hdr_t *) ((uint8_t *)rudp + UDP_HDR_SZ);

	memcpy(reth->src, my_mac_addr, MAC_ADDR_SZ);
	memcpy(reth->dst, tun_mac_addr, MAC_ADDR_SZ);
	reth->type = htons(ETHERTYPE_IPV6);

	rip->ver_tc_fl = 0x60;
	rip->hop_limit = 255;
	rip->next_hdr = PROTOCOL_UDP;
	rip->payload_length = htons(rpkt_sz - IPV6_HDR_SZ - ETH_HDR_SZ);
	memcpy(rip->src, my_ip6addr, IPV6_ADDR_SZ);
	memcpy(rip->dst, dhcpv6_addr, IPV6_ADDR_SZ);

	rudp->src_port = htons(547);
	rudp->dst_port = htons(547);
	rudp->length = rip->payload_length;

	dhcp6r->msg_type = 12;		/* RELAY-FORW */
	dhcp6r->hop_count = 64;
	memcpy(dhcp6r->link_addr, te->rip6, IPV6_ADDR_SZ);
	memcpy(dhcp6r->peer_addr, sip->src, IPV6_ADDR_SZ);

	/* options */
	uint8_t *optr = ((uint8_t *)dhcp6r + sizeof(dhcpv6r_hdr_t));

	/* Add relay option */
	*((uint16_t *) optr) = htons(9);	/* OPTION_RELAY_MSG */
	optr+=2;
	*((uint16_t *) optr) = htons(ntohs(sudp->length) - 8);
	optr+=2;
	memcpy(optr, (uint8_t *)sudp + UDP_HDR_SZ, ntohs(sudp->length) - 8);
	optr+=ntohs(sudp->length) - 8;

	/* Add link-id option */
	*((uint16_t *) optr) = htons(18);	/* OPTION_INTERFACE_ID */
	optr+=2;
	*((uint16_t *) optr) = htons(if_id_len);
	optr+=2;
	memcpy(optr, &te->interface_id, if_id_len);

	rudp->checksum = rfc1071_ckecksum(rip->src, rip->dst, PROTOCOL_UDP, 
		(uint16_t *) rudp, rpkt_sz - IPV6_HDR_SZ - ETH_HDR_SZ);

	write(tunfd, rpkt, rpkt_sz);
	stats.dhcp_relay_forward++;
	free(rpkt);
}

static int
dhcpv6_reply_snoop(tunnel_entry_t *te, uint8_t *lla, uint8_t *data, uint16_t len)
{
	fib_entry_t *fe;
	uint16_t offset = 4;

	while(offset < len) {
		uint16_t option = ntohs(*((uint16_t *)(data + offset)));
		uint16_t length = ntohs(*((uint16_t *)(data + offset + 2)));

		if ((option == 3) || (option == 25)) {	/* IA_NA or IA_PD */
			uint16_t ia_off = 16; /* opt + len + IAID + T1 + T2 */
			uint16_t status_code = 0;
			
			/* 1st we should take a look 1f there is status code */
			while (ia_off < length) {
				uint16_t ia_option = ntohs(*((uint16_t *)(data +
				    offset + ia_off)));
				uint16_t ia_len = ntohs(*((uint16_t *)(data +
				    offset + ia_off + 2)));

				/* IA_NA && OPTION_STATUS_CODE */
				if (ia_option  == 13) {
					status_code = ntohs(*((uint16_t *)
					    (data + offset + ia_off + 4)));
				}
				ia_off += 4 + ia_len;
			}

			ia_off = 16;
			while (ia_off < length) {
				uint16_t ia_option = ntohs(*((uint16_t *)(data +
				    offset + ia_off)));
				uint16_t ia_len = ntohs(*((uint16_t *)(data +
				    offset + ia_off + 2)));
		
				/* IA_NA && OPTION_IAADDR */
				if ((!status_code) && (option == 3) && 
				    (ia_option  == 5)) {
					uint8_t *ia_na_addr = data + offset +
					    ia_off + 4;
#ifdef DEBUG
					inet_ntop(AF_INET6, ia_na_addr,
					    (char *) dbg_str, 40);
					debugf("IA_NA address learned: %s\n",
					    dbg_str);
#endif
					if (!fib_find(&rfib, ia_na_addr, 128)
					    ) {
						if ((fe = fib_add(&rfib,
						    ia_na_addr, 128, te))) {
							rt_count++;
							memcpy(fe->lla, lla,
							    MAC_ADDR_SZ);
						}
					}
				}

				/* IA_PD && OPTION_IAPREFIX */
				if ((!status_code) && (option == 25) &&
				    (ia_option  == 26)) {
					uint8_t ia_pd_pfx_len  = *(data +
					    offset + ia_off + 12);
					uint8_t *ia_pd_pfx = data + offset + 
					    ia_off + 13;
#ifdef DEBUG
					inet_ntop(AF_INET6, ia_pd_pfx,
					    (char *) dbg_str, 40);
					debugf("IA_PD prefix learned: %s/%u\n",
					    dbg_str, ia_pd_pfx_len);
#endif
					if (!fib_find(&rfib, ia_pd_pfx,
					    ia_pd_pfx_len)) {
						if ((fe = fib_add(&rfib,
						    ia_pd_pfx, ia_pd_pfx_len,
						    te))) {
							rt_count++;
							memcpy(fe->lla, lla,
							    MAC_ADDR_SZ);
						}
					}
				}
				ia_off += 4 + ia_len;
			}
		}
		offset += 4 + length;
	}
	return 0;
}

static void
dhcpv6_relay_to_client(uint8_t *pkt)
{
	tunnel_entry_t *te;
	fib_entry_t *fe;
	uint8_t *rpkt = NULL;
	uint8_t *rmsg = NULL;
	uint8_t *if_id = NULL;
	uint16_t rpkt_sz = 0;
	uint16_t rmsg_sz = 0;
	ipv6_hdr_t *ip = (ipv6_hdr_t *) pkt;
	udp_hdr_t *udp = (udp_hdr_t *) (((uint8_t *) ip) + IPV6_HDR_SZ);
	dhcpv6r_hdr_t *dhcp6r = (dhcpv6r_hdr_t *) ((uint8_t *)udp + UDP_HDR_SZ);
	uint16_t offset = IPV6_HDR_SZ + UDP_HDR_SZ + sizeof(dhcpv6r_hdr_t);

	if(dhcp6r->msg_type != 13) {
		debugf("this is not relay-reply, drop\n");
		return;
	};

	while (offset < ntohs(udp->length) + IPV6_HDR_SZ) {
		uint16_t option = ntohs(*((uint16_t *)(pkt + offset)));
		uint16_t length = ntohs(*((uint16_t *)(pkt + offset + 2)));

		if (!length) {
			debugf("corrupted relay-reply packet\n");
			return;
		}

		if ((option == 18) && !if_id) {	/* Interface-ID */
			if_id = (uint8_t*) malloc(length+1);
			assert(if_id);

			if (length > INTERFACE_ID_MAX_SZ)
				return;

			memcpy(if_id, pkt + offset + 4, length);
			if_id[length] = 0;
		}

		if ((option == 9) && !rpkt) {	/* Relay Message */
			rpkt_sz = length + TUN_HDRS_SZ + ETH_HDR_SZ + 
			    IPV6_HDR_SZ + UDP_HDR_SZ;
			rmsg_sz = length;

			rpkt = (uint8_t*) malloc(rpkt_sz);
			assert(rpkt);
			rmsg = rpkt + TUN_HDRS_SZ + ETH_HDR_SZ + IPV6_HDR_SZ + 
			    UDP_HDR_SZ;

			memset(rpkt, 0, rpkt_sz);
			memcpy(rmsg, pkt + offset + 4, rmsg_sz);
		}
		offset += 4 + length;
	}

	/* continue only if both options are present */
	if ((if_id==NULL) || (rpkt == NULL))
		goto exit;

	fib_lock();
	if ((fe = fib_find(&tfib, dhcp6r->link_addr, 128))) {
		te = fe->te;
		te->age = time(NULL);
	} else {
		fib_unlock();
		goto exit;
	}
	
	eth_hdr_t *reeth = (eth_hdr_t *) rpkt;
	ipv6_hdr_t *rtip = (ipv6_hdr_t *) (((uint8_t *) reeth) + ETH_HDR_SZ);
	l2tpv3_hdr_t *rl2tp = (l2tpv3_hdr_t *) (((uint8_t *) rtip) +
	    IPV6_HDR_SZ);
	eth_hdr_t *reth = (eth_hdr_t *) (((uint8_t *) rl2tp) + L2TPV3_HDR_SZ);
	ipv6_hdr_t *rip = (ipv6_hdr_t *) (((uint8_t *) reth) + ETH_HDR_SZ);
	udp_hdr_t *rudp = (udp_hdr_t *) (((uint8_t *) rip) + IPV6_HDR_SZ);

	/* FIXME learn this in proper way */
	reth->dst[0] = dhcp6r->peer_addr[8] & 0xfd;
	reth->dst[1] = dhcp6r->peer_addr[9];
	reth->dst[2] = dhcp6r->peer_addr[10];
	reth->dst[3] = dhcp6r->peer_addr[13];
	reth->dst[4] = dhcp6r->peer_addr[14];
	reth->dst[5] = dhcp6r->peer_addr[15];

	if(*(rmsg) == 7)	/* if this is REPLY, snoop */
		if (dhcpv6_reply_snoop(te, reth->dst, rmsg, rmsg_sz) < 0 ) {
			fib_unlock();
			goto exit;
		}

	memcpy(rtip->dst, te->rip6, IPV6_ADDR_SZ);
	rl2tp->session_id = te->session_id;
	memcpy(rl2tp->cookie, te->cookie, COOKIE_LENGTH);

	fib_unlock();

	/* Fill tunnel eth header */
	reeth->type = htons(ETHERTYPE_IPV6);
	memcpy(reeth->src, my_mac_addr, MAC_ADDR_SZ);
	memcpy(reeth->dst, tun_mac_addr, MAC_ADDR_SZ);

	/* Fill tunnel ipv6 header */
	rtip->ver_tc_fl = 0x60;
	rtip->hop_limit = 255;
	rtip->next_hdr = PROTOCOL_L2TPV3;
	rtip->payload_length = htons(rpkt_sz - ETH_HDR_SZ - IPV6_HDR_SZ);
	memcpy(rtip->src, my_ip6addr, IPV6_ADDR_SZ);

	/* fill l2tp header */

	/* Fill ethernet header */
	reth->type = htons(ETHERTYPE_IPV6);
	memcpy(reth->src, my_mac_addr, MAC_ADDR_SZ);

	/* fill IPv6 header */
	rip->ver_tc_fl = 0x60;
	rip->hop_limit = 255;
	rip->next_hdr = PROTOCOL_UDP;
	rip->payload_length = htons(rpkt_sz - TUN_HDRS_SZ - IPV6_HDR_SZ -
	    ETH_HDR_SZ);
	memcpy(rip->src, my_lla, IPV6_ADDR_SZ);
	memcpy(rip->dst, dhcp6r->peer_addr, IPV6_ADDR_SZ);

	rudp->src_port = htons(547);
	rudp->dst_port = htons(546);
	rudp->length = rip->payload_length;

	rudp->checksum = rfc1071_ckecksum(rip->src, rip->dst, PROTOCOL_UDP,
	    (uint16_t *) rudp, rpkt_sz - IPV6_HDR_SZ - ETH_HDR_SZ - TUN_HDRS_SZ);

	write(tunfd, rpkt, rpkt_sz);
	stats.dhcp_relay_reply++;

exit:
	free(if_id);
	free(rpkt);
}


static void
decapsulate_l2tpv3(uint8_t *pkt, uint16_t pkt_sz)
{
	uint8_t addr[40];
	uint16_t sz;
	ipv6_hdr_t *eip = (ipv6_hdr_t *) pkt;
	l2tpv3_hdr_t *l2tpv3_hdr = (l2tpv3_hdr_t *) (((uint8_t *) eip) + 
	    IPV6_HDR_SZ);
	eth_hdr_t *eth = (eth_hdr_t *) (((uint8_t *) l2tpv3_hdr) +
	    L2TPV3_HDR_SZ);
	ipv6_hdr_t *ip = (ipv6_hdr_t *) (((uint8_t *) eth) + ETH_HDR_SZ);
	icmpv6_na_hdr_t *icmp6 = (icmpv6_na_hdr_t *) (((uint8_t *) ip) +
	    IPV6_HDR_SZ);
	udp_hdr_t *udp = (udp_hdr_t *) (((uint8_t *) ip) + IPV6_HDR_SZ);

	fib_entry_t *fe;
	tunnel_entry_t *te;

	if (((ip->ver_tc_fl >> 4 ) & 0xF) != 6) {
		debugf("non-ipv6 packet dropped\n");
		return;
	}

#ifdef DEBUG
	uint8_t smac_str[20];
	uint8_t dmac_str[20];
	MAC_TO_STR(eth->src, (char *) &smac_str);
	MAC_TO_STR(eth->dst, (char *) &dmac_str);
	debugf("rcv %4u bytes %s -> %s, next_hdr = %u\n",
		pkt_sz, smac_str, dmac_str, ip->next_hdr);
#endif

	/* See if packet is coming from known tunnel */
	/* If not create new tunnel entry */
	fib_lock();
	if ((fe = fib_find(&tfib, eip->src, 128))) {
		te = fe->te;
		te->age = time(NULL);
	} else {
		te = (tunnel_entry_t *) malloc(sizeof(tunnel_entry_t));
		assert(te);
		memset(te, 0, sizeof(tunnel_entry_t));

		if (calc_wan_prefix_for_tunnel)
			calc_wan_prefix_for_tunnel(eip->src, te->prefix,
			    &te->prefix_len);

		fe = fib_add(&tfib, eip->src, 128, (void *) te);
		tt_count++;
		if (!fe) {
			/* Entry cannot be crated, drop packet */
			free(te);
			fib_unlock();
			return;
		}

		if (te->prefix_len) {
			rt_count++;
			fib_add(&rfib, te->prefix, te->prefix_len, te);
		}

		memcpy(te->rip6, eip->src, IPV6_ADDR_SZ);
		memcpy(te->cookie, l2tpv3_hdr->cookie, COOKIE_LENGTH);
		te->session_id = l2tpv3_hdr->session_id;
		inet_ntop(AF_INET6, te->rip6, (char *) addr, 40);
		snprintf((char *) te->interface_id, INTERFACE_ID_MAX_SZ, 
		    "Tunnel-%s/%08x", addr, te->session_id);

		/* this is new user, so pass RA */
		l2tpv3_icmpv6_send_ra(te);
	}

	/* special treatment for ICMPv6 packets */
	if (ip->next_hdr == PROTOCOL_ICMPV6) {

		/* Router Solicitation */
		if (icmp6->type == 133)  {
			debugf("RS received, sending back RA\n");
			l2tpv3_icmpv6_send_ra(te);
			fib_unlock();
			return;
		}

		/* Neighbor Solicitation */
		if (icmp6->type == 135) {
			if (!(memcmp((char *) icmp6->target_addr, (char *)
			    my_lla, IPV6_ADDR_SZ))) {
				debugf("ns received, replying with na\n");
				l2tpv3_icmpv6_send_na(te, eth->src, ip->src );
				fib_unlock();
				return;
			} else {
				/* not for us */
#if DEBUG
				inet_ntop(AF_INET6, icmp6->target_addr,
				    (char *) &dbg_str, 40);
				debugf("ns received, not for us (%s)\n", dbg_str);
#endif
				fib_unlock();
				return;
			}
		}

		/* Neighbor Advertisment */
		if (icmp6->type == 136) {
			nd_cache_entry_t *ndce;

			/* We are not interested in link local */
			if (*((uint16_t *) icmp6->target_addr) ==
			    htons(0xfe80))
   				 fib_unlock_and_return();

			/* Protect from ND exhaustion attack */
			if (te->nd_cache_entries >= ND_CACHE_SZ)
				 fib_unlock_and_return();

			/* if we have entry no action is needed */
			ndce = te->nd_cache;
			while (ndce) {
				if (!memcmp(ndce->ip, icmp6->target_addr,
				    IPV6_ADDR_SZ))
					fib_unlock_and_return();
				ndce = ndce->next;
			}

			sz = pkt_sz - TUN_HDRS_SZ - IPV6_HDR_SZ -
			    sizeof(icmpv6_na_hdr_t);

			while(sz>0) {
				uint8_t type = *(pkt + pkt_sz - sz);
				uint8_t length = *(pkt + pkt_sz - sz + 1);

				/* protect from packet corruption */
				if (!length)
					fib_unlock_and_return();

				if ((type = 2) && (length == 1)) {
					/* Target LLA Option found */
					ndce = malloc(sizeof(nd_cache_entry_t));
					assert(ndce);
					te->nd_cache_entries++;
					ndce->next = te->nd_cache;
					te->nd_cache = ndce;
					memcpy(ndce->ip, icmp6->target_addr,
					    IPV6_ADDR_SZ);
					memcpy(ndce->mac, pkt + pkt_sz - sz + 2,
					    MAC_ADDR_SZ);
#ifdef DEBUG
					uint8_t nd_mac[20];
					uint8_t nd_ip[40];
					MAC_TO_STR(ndce->mac, (char *) &nd_mac);
					inet_ntop(AF_INET6, (char *) ndce->ip, 
					    (char *) &nd_ip, 40);
					debugf("nd cache entry %s->%s created\n", 
					    nd_ip, nd_mac);
#endif
					
					fib_unlock_and_return();
				}
				sz-= length * 8;
			}
			fib_unlock_and_return();
		}
	}

	fib_unlock();

	/* special treatment for DHCPv6 packets */
	if (ip->next_hdr == PROTOCOL_UDP) {
		if (ntohs(udp->dst_port) == 547)  { /* DHCPv6 */
			// FIXME be more strict
			dhcpv6_relay_to_server(te, (uint8_t *) ip);
			return;
		}
	};

	/* we don't support HbH */ 
	if (ip->next_hdr == 0) {
		debugf("packet with hop-by-hop option dropped\n");
		return;
	}
	
	/* drop link local packets */
	if ((*((uint16_t *) ip->src) == htons(0xfe80)) || 
	    (*((uint16_t *) ip->dst) == htons(0xfe80))) {
		debugf("drop link local packet\n");
		return;
	}

	memcpy(eth->src, my_mac_addr, MAC_ADDR_SZ);
	memcpy(eth->dst, tun_mac_addr, MAC_ADDR_SZ);
	eth->type = htons(ETHERTYPE_IPV6);

	write(tunfd, (uint8_t *) eth, pkt_sz - IPV6_HDR_SZ - L2TPV3_HDR_SZ);
	stats.pkts_decap++;
}

static void
encapsulate_l2tpv3(uint8_t *pkt, uint16_t pkt_sz)
{
	uint64_t zeros[] = {0, 0};
	fib_entry_t *fe;
	nd_cache_entry_t *ne;
	eth_hdr_t *eeth = (eth_hdr_t *) pkt;
	ipv6_hdr_t *eip = (ipv6_hdr_t *) (((uint8_t *) eeth) + ETH_HDR_SZ);
	l2tpv3_hdr_t *l2tp = (l2tpv3_hdr_t *) (((uint8_t *) eip) + IPV6_HDR_SZ);
	eth_hdr_t *eth = (eth_hdr_t *) (((uint8_t *) l2tp) + L2TPV3_HDR_SZ);
	ipv6_hdr_t *ip = (ipv6_hdr_t *) (((uint8_t *) eth) + ETH_HDR_SZ);
	
	fib_lock();
	
	if(!(fe = fib_find(&rfib, ip->dst, 128))) {
		fib_unlock();
#ifdef DEBUG
		inet_ntop(AF_INET6, ip->dst, (char *) dbg_str, 40);
		debugf("no FIB entry for %s\n", dbg_str);
#endif
		return;
	}

	ne = fe->te->nd_cache;
	while (ne) {
		if (!memcmp(ne->ip, ip->dst, IPV6_ADDR_SZ)) {
			memcpy(eth->dst, ne->mac, MAC_ADDR_SZ);
			goto lla_found;
		}
		ne = ne->next;
	}

	if (!memcmp(fe->lla, &zeros, MAC_ADDR_SZ)) {
		/* Next Hop Layer 2 address not known */
		/* so send NS and drop packet */
		l2tpv3_icmpv6_send_ns(fe->te, ip->dst);
		fib_unlock_and_return();
	} else {
		memcpy(eth->dst, fe->lla, MAC_ADDR_SZ);
	}

lla_found:
	memcpy(eip->dst, fe->te->rip6, IPV6_ADDR_SZ);
	memcpy(l2tp->cookie, fe->te->cookie, COOKIE_LENGTH);
	l2tp->session_id = fe->te->session_id;

	fib_unlock();

	memcpy(eeth->dst, tun_mac_addr, MAC_ADDR_SZ);
	memcpy(eeth->src, my_mac_addr, MAC_ADDR_SZ);
	eeth->type = htons(ETHERTYPE_IPV6);

	eip->ver_tc_fl = 0x60;
	eip->hop_limit = 255;
	eip->next_hdr = PROTOCOL_L2TPV3;
	eip->payload_length = htons(pkt_sz - IPV6_HDR_SZ - ETH_HDR_SZ);
	memcpy(eip->src, my_ip6addr, IPV6_ADDR_SZ);
	memcpy(eth->src, my_mac_addr, MAC_ADDR_SZ);
	eth->type = htons(ETHERTYPE_IPV6);

	write(tunfd, pkt, pkt_sz);
	stats.pkts_encap++;
}

static void
tun_icmpv6_send_na(int fd, uint8_t *ip_dst)
{
	struct __attribute__ ((packed)) {
		eth_hdr_t	eth_hdr;
		ipv6_hdr_t	ipv6_hdr;
		icmpv6_na_hdr_t	icmpv6_hdr;
		struct {
			uint8_t		type;
			uint8_t	 	length;
			uint8_t		lla[MAC_ADDR_SZ];
		} icmpv6_tgt_lla_opt;
	} na_msg;
	
	memset(&na_msg, 0, sizeof(na_msg));

	/* ethernet header */
	memcpy(&na_msg.eth_hdr.dst, tun_mac_addr, MAC_ADDR_SZ);
	memcpy(&na_msg.eth_hdr.src, my_mac_addr, MAC_ADDR_SZ);
	na_msg.eth_hdr.type = htons(ETHERTYPE_IPV6);
	
	/* ipv6 header */
	na_msg.ipv6_hdr.ver_tc_fl = 0x60;
	na_msg.ipv6_hdr.hop_limit = 255;
	na_msg.ipv6_hdr.next_hdr = PROTOCOL_ICMPV6;
	na_msg.ipv6_hdr.payload_length = htons(ICMPV6_HDR_SZ + 8);
	memcpy(&na_msg.ipv6_hdr.src, my_ip6addr, IPV6_ADDR_SZ);
	memcpy(&na_msg.ipv6_hdr.dst, ip_dst, IPV6_ADDR_SZ);

	/* icmpv6 header */
	na_msg.icmpv6_hdr.type = 136;
	na_msg.icmpv6_hdr.flags[0] = 0x60;
	memcpy(&na_msg.icmpv6_hdr.target_addr, my_ip6addr, IPV6_ADDR_SZ);

	/* icmpv6 target link-local-address */
	na_msg.icmpv6_tgt_lla_opt.type =  2;
	na_msg.icmpv6_tgt_lla_opt.length =  1;
	memcpy(na_msg.icmpv6_tgt_lla_opt.lla, my_mac_addr, MAC_ADDR_SZ);

	/* checksum */
	na_msg.icmpv6_hdr.checksum = rfc1071_ckecksum(na_msg.ipv6_hdr.src, 
		na_msg.ipv6_hdr.dst, PROTOCOL_ICMPV6, 
		(uint16_t *) &na_msg.icmpv6_hdr, sizeof(icmpv6_na_hdr_t) + 
		sizeof(na_msg.icmpv6_tgt_lla_opt));

	write(fd, &na_msg, sizeof(na_msg));
}

static void
*tun_handler(void *data)
{
	struct timeval to = {1,0};
        fd_set ms; 

	uint8_t buffer[MTU];
	/* same buffer is used for both encaps and decaps, so we need to
	   leave some space for L2TPv3 headers */
	uint8_t *dbuf = ((uint8_t *)& buffer) + TUN_HDRS_SZ;
	eth_hdr_t *eth = (eth_hdr_t *) dbuf;
	ipv6_hdr_t *ip = (ipv6_hdr_t *) (((uint8_t *) eth) + ETH_HDR_SZ);
	icmpv6_na_hdr_t *icmp = (icmpv6_na_hdr_t *) (((uint8_t *) ip) +
	    IPV6_HDR_SZ);

	FD_ZERO(&ms);
        FD_SET(tunfd, &ms);

        while (!_do_exit) {
		fd_set ws;
		int r;
		ssize_t rl;

		memcpy(&ws, &ms, sizeof(ms));
		to.tv_sec=1;
		do {
			r = select(tunfd + 1, &ws, NULL, NULL, &to);
		} while ( r == -1 && errno == EINTR);

		if (r<0) {
			fprintf(stderr, "%s: error\n", __func__);
			break;
		}
		
		if (!r)
			continue;

		do {
			rl = read(tunfd, dbuf, MTU - IPV6_HDR_SZ -
			    L2TPV3_HDR_SZ - ETH_HDR_SZ);
		} while (rl == -1 && errno == EINTR);

		if (rl < 1) 
			continue;	// FIXME smallest allowed packet

		/* Check if this is IPv6 packet, drop if it isn't */
		if ((((ip->ver_tc_fl) & 0xF0) != 0x60))
			  	continue; 

		if (((ip->next_hdr) == PROTOCOL_L2TPV3) && 
		    (!(memcmp((char *) ip->dst, (char *) my_ip6addr,
		    IPV6_ADDR_SZ)))) {
			decapsulate_l2tpv3( (uint8_t *) ip, rl - ETH_HDR_SZ);
		} else {
			if (!(memcmp((char *) ip->dst, (char *) my_ip6addr,
			    IPV6_ADDR_SZ))) {
				/* Local delivery */
				udp_hdr_t *udp = (udp_hdr_t *)
				    (((uint8_t *) ip) + IPV6_HDR_SZ);
				if((ip->next_hdr == PROTOCOL_UDP) &&
				    (udp->dst_port = 547 )) {
					dhcpv6_relay_to_client((uint8_t *) ip);
					continue;
				}
			} 

			/* Network Solicitation from kernel */
			if ((ip->next_hdr == PROTOCOL_ICMPV6) &&
				(icmp->type == 135)) {
					if (!(memcmp((char *) icmp->target_addr,
					    (char *) my_ip6addr,
					    IPV6_ADDR_SZ))) {
						memcpy(tun_mac_addr, eth->src,
						    MAC_ADDR_SZ);
						tun_icmpv6_send_na(tunfd,
						    ip->src);
					}
				continue;
			} 
			
			/* wo do not forward multicast */
			if (*((uint8_t *) ip->dst) == 0xFF) {
				continue;
			}

			/* do not encapsulate link local traffic */
			if ((*((uint16_t *) ip->src) == htons(0xfe80)) || 
			    (*((uint16_t *) ip->dst) == htons(0xfe80))) {
				continue;
			}
			
			encapsulate_l2tpv3((uint8_t *)&buffer, rl + 
			    IPV6_HDR_SZ + L2TPV3_HDR_SZ + ETH_HDR_SZ);
		}
	}
	return NULL;
}

static void
fib_recurse_send_ra(fib_entry_t *fe, int bit)
{
	char buff[40];

	if(fe) {
		inet_ntop(AF_INET6,fe->prefix, buff, 40);
		if(!fe->kids[0] && !fe->kids[1]) {
			debugf("send RA to %s/%u\n", buff, fe->prefix_len);
			l2tpv3_icmpv6_send_ra(fe->te);
		} else {
			fib_recurse_send_ra(fe->kids[0], bit + 1);
			fib_recurse_send_ra(fe->kids[1], bit + 1);
		}
	}
}

static void
*per_ra_sndr(void *data)
{
	while (!_do_exit) {
		fib_lock();
		fib_recurse_send_ra(tfib, 0);
		fib_unlock();
		sleep(ra_interval);
	}
	return NULL;
}

static void
*periodic(void *data)
{
	while (!_do_exit) {
		time_t tm = time(NULL);
		fib_lock();
		rt_count -= fib_remove_aged_entries(&rfib, aging_time, tm, 0);
		tt_count -= fib_remove_aged_entries(&tfib, aging_time, tm, 1);
		fib_unlock();
#ifdef DEBUG
		debugf("%i tunnels, %i routes, ", tt_count, rt_count);
#else
		printf("%i tunnels, %i routes, ", tt_count, rt_count);
#endif
		printf(" pkts_encap %lu, pkts_decap %lu, "
			"dhcp_relay_forward %lu, dhcp_relay_reply %lu\n",
			(long unsigned int) stats.pkts_encap,
			(long unsigned int) stats.pkts_decap,
			(long unsigned int) stats.dhcp_relay_forward,
			(long unsigned int) stats.dhcp_relay_reply);		
		memset(&stats, 0, sizeof(stats));
		sleep(periodic_run);
	}
	return NULL;
}

static void
sig_exit(int signo)
{
	_do_exit = 1;
}

static void
set_signal(int signo, void (*handler)(int))
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = (void (*)(int))handler;
    sigaction(signo, &sa, NULL);
}

static void
help_and_exit(char *arg) 
{
	printf("\n");
	printf("User Mode L2TPv3-over-IPv6 Tunnel Termination v1.0 "
	    "(c) 2013 Cisco Systems, Inc.\n");
#ifdef BUILD
	printf("Build: %s\n", BUILD);
#endif
	printf("\nusage: %s [parameters]\n", arg);
	printf("	-u name		TUN interface name\n");
	printf("	-a address	L2TPv3 local endpoint address\n");
	printf("	-d address	DHCPv6 address\n");
	printf("	-t seconds	Tunnel aging time [default %u sec]\n",
	    aging_time);
	printf("	-r seconds	RA interval [default %u sec]\n",
	    ra_interval);
	printf("	-R priority	RA Priority per RFC4191: low, normal (default), high\n");
	printf("	-p seconds	PIO preferred lifetime [default %u sec]\n",
	    pio_preferred_lifetime);
	printf("	-v seconds	PIO valid lifetime [default %u sec]\n",
	    pio_valid_lifetime);
	printf("	-h		This help\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int opt;
	struct ifreq ifr;
	uint8_t my_ip6addr_str[40] = "";
	uint8_t dhcpv6_addr_str[40] = "";
	uint8_t ra_priority_str[7] = "normal";
	pthread_t tid_decap; 
	pthread_t tid_periodic; 
	pthread_t tid_per_ra_sndr;
	void *wan_prefix_handle;
	char *error;

	memset(&ifr, 0, sizeof(ifr));

	while((opt = getopt(argc, argv, "a:d:hp:r:R:t:u:v:")) > 0) {
		switch(opt) {
		case 'a':
			strncpy((char *) my_ip6addr_str, optarg, 40-1);
			break;
		case 'd':
			strncpy((char *) dhcpv6_addr_str, optarg, 40-1);
			break;
		case 'h':
			help_and_exit(argv[0]);
			break;
		case 'p':
			if(atoi(optarg)>0)
				pio_preferred_lifetime = atoi(optarg);
			else {
				fprintf(stderr, "Bad preferred lifetime!\n");
				help_and_exit(argv[0]);
			}
			break;
		case 'r':
			if(atoi(optarg)>0)
				ra_interval = atoi(optarg);
			else {
				fprintf(stderr, "Bad RA interval!\n");
				help_and_exit(argv[0]);
			}
			break;
		case 'R':
			strncpy((char *) ra_priority_str, optarg, 6);
			break;
		case 't':
			if(atoi(optarg)>0)
				aging_time = atoi(optarg);
			else {
				fprintf(stderr, "Bad aging time!\n");
				help_and_exit(argv[0]);
			}
			break;
		case 'u':
			strncpy(ifr.ifr_name, optarg, IFNAMSIZ-1);
			break;
		case 'v':
			if(atoi(optarg)>0)
				pio_valid_lifetime = atoi(optarg);
			else {
				fprintf(stderr, "Bad valid lifetime!\n");
				help_and_exit(argv[0]);
			}
			break;
		default:
	        	printf("Unknown option %c\n", opt);
		}
	}

	if(*my_ip6addr_str == 0) {
		fprintf(stderr, "Missing local tunnel IPv6 address!\n");
		help_and_exit(argv[0]);
	}

	if(*dhcpv6_addr_str == 0) {
		fprintf(stderr, "Missing DHCPv6 server IPv6 address!\n");
		help_and_exit(argv[0]);
	}

	if(ifr.ifr_name[0] == 0) {
		fprintf(stderr, "Must specify tun interface name!\n");
		help_and_exit(argv[0]);
	};

	if (!inet_pton(AF_INET6, (char *) &my_ip6addr_str, &my_ip6addr)){
		fprintf(stderr, "Bad local tunnel IPv6 address %s\n",
		    my_ip6addr_str);
    		exit(1);
	}

	if (!inet_pton(AF_INET6, (char *) &dhcpv6_addr_str, &dhcpv6_addr)){
		fprintf(stderr, "Bad DHCPv6 server IPv6 address %s\n",
		    dhcpv6_addr_str);
    		exit(1);
	}
	if (!strcmp((char *) ra_priority_str, "normal"))
		ra_priority = 0;
	else if (!strcmp((char *) ra_priority_str, "low"))
		ra_priority = 3;
	else if (!strcmp((char *) ra_priority_str, "high"))
		ra_priority = 1;
	else {
		fprintf(stderr, "Bad RA priority. Should be normal, low or high\n");
		exit(1);
	}

	if ((tunfd = open("/dev/net/tun", O_RDWR)) < 0) {
		fprintf(stderr, "Cannot open tun interface %s (error: %s)\n",
		    ifr.ifr_name, strerror(errno));
		exit(1);
	}

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if ((ioctl(tunfd, TUNSETIFF, &ifr)) < 0) {
		printf("IOCTL error (TUNSETIFF): %s\n", strerror(errno));
		close(tunfd);
		exit(1);
	}

	/* execute startup script */
	setenv("TT_IF_NAME", (char *) ifr.ifr_name, 1);
	setenv("TT_IPV6_ADDR", (char *) my_ip6addr_str, 1);
	system("./start.sh");

	/* load wan prefix calc plugin */
	wan_prefix_handle = dlopen("./wan_prefix.so", RTLD_LAZY);
	if (!wan_prefix_handle) {
		debugf("%s\n", dlerror());
	} else {
		calc_wan_prefix_for_tunnel = dlsym(wan_prefix_handle,
		    "calc_wan_prefix_for_tunnel");
		if ((error = dlerror()) != NULL)  {
			debugf("%s\n", error);
		}
	}
	if(!calc_wan_prefix_for_tunnel)
		fprintf(stderr, "WARNING: Failed to load WAN prefix calculation"
			" plugin (wan_prefix.so). SLAAC disabled.\n");

	set_signal(SIGINT,  sig_exit);
	set_signal(SIGQUIT, sig_exit);

	/* Initialize FIB */
	fib_init();

	pthread_create(&tid_decap, NULL, tun_handler, NULL);
	pthread_create(&tid_periodic, NULL, periodic, NULL);
	pthread_create(&tid_per_ra_sndr, NULL, per_ra_sndr, NULL);

	while (!_do_exit) 
		sleep(1);

	fib_destroy();
	close(tunfd);
	dlclose(wan_prefix_handle);
	return 0;
}
