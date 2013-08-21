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
#include <string.h>
#include <arpa/inet.h>

#include "kite.h"

void hexdump(uint8_t *data, uint16_t len)
{
	uint16_t x;
	printf("0000: ");
	for (x=0;x<len;x++) {
		printf("%02x ", data[x]);
		if (!((x+1) % 16))
			printf("\n%04x: ", x+1);
	}
	printf("\n");
}

uint16_t rfc1071_ckecksum(uint8_t *src, uint8_t *dst, uint16_t nxt_hdr, uint16_t *payload, int count)
{
	/* IPv6 pseudo-header */
	struct __attribute__ ((packed)) {
		uint8_t		src[IPV6_ADDR_SZ];
		uint8_t 	dst[IPV6_ADDR_SZ];
		uint32_t	length;
		uint8_t 	zeros[3];
		uint8_t		next_header;
	} pseudo_hdr;

	uint16_t *php = (uint16_t *) &pseudo_hdr;
	uint32_t sum = 0;
	int c = sizeof(pseudo_hdr);
	
	memcpy(&pseudo_hdr.src,src,IPV6_ADDR_SZ);
	memcpy(&pseudo_hdr.dst,dst,IPV6_ADDR_SZ);
	pseudo_hdr.length = htonl(count);
	memset(&pseudo_hdr.zeros, 0, 3);
	pseudo_hdr.next_header = nxt_hdr;

	/* sum pseudo-header */
	while( c > 1 )  {
		sum +=  *(uint16_t *) php++;
		c -= 2;
	}

	/* sum payload */
	while( count > 1 )  {
		sum +=  *(uint16_t *) payload++;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if( count > 0 )
		sum += *(uint8_t *) payload;

	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	
	return ~sum;
}

int prefix6cmp(uint8_t *a, uint8_t *b, uint8_t prefix)
{
	if(memcmp(a, b, prefix/8))
		return 1;

	uint8_t mask = 0xff & ~((1<<(8-(prefix % 8)))-1);

	if ((mask == 0) || (a[prefix/8] & mask) == (b[prefix/8] & mask)) {
		return 0;
	}
	return 1;
}

void prefix6zero(uint8_t *a, uint8_t prefix)
{
	uint8_t i;

	a[prefix/8] &= 0xff & ~((1<<(8-(prefix % 8)))-1); 

	for (i=(prefix/8)+1; i<16;i++)
		a[i] = 0;
}

