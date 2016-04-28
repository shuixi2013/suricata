//#include <bcc/proto.h>
#include <stdint.h>
#include <stddef.h>
#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <linux/ip.h>

#include "bpf_helpers.h"

#define IPPROTO_TCP 6

int loadbalancer(struct __sk_buff *skb) {
    uint8_t proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
	if (proto == IPPROTO_TCP) {
        return 1;
    } 
    return 0;
}
