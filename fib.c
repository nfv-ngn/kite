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

#include "kite.h"

#define BIT(x, n) (((x[n / 8]) & (0x1 << (7 - n % 8))) != 0)

pthread_mutex_t fib_mtx;

#ifdef DEBUG
static char dbg_str[40];
#endif

void
fib_init()
{
	pthread_mutex_init(&fib_mtx, NULL);
}

void
fib_destroy()
{
	pthread_mutex_destroy(&fib_mtx);
}

static fib_entry_t * 
make_fib_entry(const uint8_t *prefix, uint8_t prefix_len)
{
	fib_entry_t *fe;

#ifdef DEBUG_FIB
	inet_ntop(AF_INET6, (char *) prefix, (char *) dbg_str, 40);
	debugf("%s: new entry %s/%u\n", __func__, dbg_str, prefix_len);
#endif

	fe = malloc(sizeof(*fe));
	assert(fe);

	memcpy(fe->prefix, prefix, 16);
	prefix6zero(fe->prefix, prefix_len);
	fe->prefix_len=prefix_len;
	fe->kids[0] = 0;
	fe->kids[1] = 0;
	fe->parent = 0;
	return fe;
}

fib_entry_t *
fib_add(fib_entry_t **root, uint8_t *prefix, uint8_t prefix_len, tunnel_entry_t *te)
{

#ifdef DEBUG_FIB
	inet_ntop(AF_INET6, (char *) prefix, (char *) dbg_str, 40);
	printf("%s: %s/%u\n",__func__, dbg_str, prefix_len);
#endif

	uint8_t bit = 0;
	int bitvalue, nextbit;
	fib_entry_t *fe, *new_fe, *old_fe = NULL;

	if (!root) 
		return NULL;

	if(!(*root)) {
		*root = make_fib_entry(prefix, prefix_len);
		(*root)->te = te;
		return *root;
	}

	fe = *root;

	while (fe && !prefix6cmp((uint8_t *) fe->prefix, (uint8_t *) prefix, fe->prefix_len)) {
		old_fe = fe;
		fe = old_fe->kids[nextbit = (BIT(prefix, old_fe->prefix_len))];
	}

	if (old_fe && !old_fe->kids[0] && !old_fe->kids[1]) {
		/* node alredy exists */
		return NULL;
	}
	while(BIT(fe->prefix, bit) == (bitvalue = BIT(prefix, bit))) {
		bit++;
	}

	new_fe = make_fib_entry(prefix, bit);
	new_fe->kids[bitvalue] = make_fib_entry(prefix, prefix_len);
	new_fe->kids[bitvalue]->parent = new_fe;
	new_fe->kids[!bitvalue] = fe;
	new_fe->kids[!bitvalue]->parent = new_fe;
	new_fe->kids[bitvalue]->te = te;

	if (old_fe) {
		old_fe->kids[nextbit] = new_fe;
		new_fe->parent = old_fe;
	}
	else {
		*root = new_fe;
		new_fe->parent = NULL;
	}

	return new_fe->kids[bitvalue];
}

fib_entry_t *
fib_find(fib_entry_t **root, uint8_t *prefix, uint8_t prefix_len)
{
	fib_entry_t *fe;
	if (!(root) || !(*root))
		return NULL;

	fe = *root;
	while (!prefix6cmp(prefix, (uint8_t *) fe->prefix, fe->prefix_len)) {
		if (fe->prefix_len == prefix_len)
			return fe;

		if (!(fe->kids[BIT(prefix, fe->prefix_len)])) {
			return fe;
		}

		fe = fe->kids[BIT(prefix, fe->prefix_len)];
	}
	return NULL;
}

void
fib_remove(fib_entry_t **root, fib_entry_t *fe)
{
	fib_entry_t *grandpa;
	int gpbit, bit=0;
	
	if (!fe || !root || !(*root))
		return;

	if (fe->kids[0] || fe->kids[1]) {
		printf("This is not leaf node\n");
		return;
	}
	
	if (fe == *root) {
		free(*root);
		*root = NULL;
		return;
	}

	grandpa = fe->parent->parent;
	bit = (fe->parent->kids[1] == fe);

	if (grandpa) {
		gpbit = (grandpa->kids[1] == fe->parent);
		grandpa->kids[gpbit] = fe->parent->kids[!bit];
		grandpa->kids[gpbit]->parent = grandpa;
	} else {
		/* Our parent is root, so new root will be his another child */
		*root = fe->parent->kids[!bit];
		(*root)->parent = NULL;
	}
	free(fe->parent);
	free(fe);
}

int
fib_remove_aged_entries(fib_entry_t **root, int maxage, time_t tm, int remove_te)
{
	fib_entry_t *l = NULL;
	fib_entry_t *c = *root;
	nd_cache_entry_t *nd, *nd2;
	int removed = 0;
	
	while (c) {
		if ((c->parent == l) || (!l)) {
			if(!c->kids[0] && !c->kids[1] && 
			    (difftime(tm, c->te->age) > maxage)) {
#ifdef DEBUG
				inet_ntop(AF_INET6,c->prefix, dbg_str, 40);
				debugf("Removing FIB entry for %s/%u\n", dbg_str,
				    c->prefix_len);
#endif
				if(remove_te) {
					nd = c->te->nd_cache;
					while (nd) {
#ifdef DEBUG
						inet_ntop(AF_INET6, nd->ip,
						    dbg_str, 40);
						debugf("Removing ND cache entry"
						    " for %s\n", dbg_str);
#endif
						nd2 = nd->next;
						free(nd);
						nd = nd2;
					}
					free(c->te);
				}
				fib_remove(root, c);
				removed++;
				/* this might be done without restart */
				l = NULL;
				c = *root;
				continue;
			}
		}
		if ((c->kids[0]) && (l!=c->kids[0]) && (l!=c->kids[1])) {
			l = c;
			c = c->kids[0];
		} else if ((c->kids[1]) && (l==c->kids[0])) {
			l = c;
			c = c->kids[1];
		} else if ((c->parent)) {
			l = c;
			c = c->parent;
		} else break;
	}
	return removed;
}

void
fib_dump(fib_entry_t *fe)
{
	char buff[40];
	int i, depth=0;
	fib_entry_t *l = NULL;
	fib_entry_t *c = fe;

	if (!c)
		return;

	while (1) {
		if ((c->parent == l) || ((!c->parent) && (!l))) {
			inet_ntop(AF_INET6,c->prefix, buff, 40);
			for(i=0;i<depth;i++)
				printf("  ");
			if(!c->kids[0] && !c->kids[1]) {
				printf("> %s/%u ptr:%p prnt: %p lla: "
				    "%02x:%02x:%02x:%02x:%02x:%02x\n",
				    buff, c->prefix_len, c, c->parent, c->lla[0],
				    c->lla[1], c->lla[2], c->lla[3], c->lla[4],
				    c->lla[5]);
			} else {
				printf("  %s/%u ptr:%p prnt: %p\n", buff,
				    c->prefix_len, c, c->parent);
			}
		}

		if ((c->kids[0]) && (l!=c->kids[0]) && (l!=c->kids[1])) {
			l = c;
			c = c->kids[0];
			depth++;
		} else if ((c->kids[1]) && (l==c->kids[0])) {
			l = c;
			c = c->kids[1];
			depth++;
		} else if ((c->parent)) {
			l = c;
			c = c->parent;
			depth--;
		} else break;
	}
}

