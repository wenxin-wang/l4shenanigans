#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <uapi/linux/in.h>

#include "l4shenanigans_protocol.h"

#define ENCAP_MAGIC 0xdb57

static void __move_headroom(struct sk_buff *skb, int nhead, int payloadoff,
                            int csum_offset) {
  int nhdiff = skb_network_header(skb) - skb->data;
  int proto_header_len = nhdiff + payloadoff;
  bool should_change_csum_start =
      skb->ip_summed == CHECKSUM_PARTIAL &&
      skb_checksum_start_offset(skb) + skb->csum_offset == nhdiff + csum_offset;
  if (nhead > 0) { // expand headroom
    skb_push(skb, nhead);
  } else {
    skb_pull(skb, -nhead);
  }
  memmove(skb->data, skb->data + nhead, proto_header_len);
  skb->transport_header -= nhead;
  skb->network_header -= nhead;
  skb->mac_header -= nhead;
  if (should_change_csum_start) {
    skb->csum_start -= nhead;
  }
  skb_clear_hash(skb);
}

int encap_adjust_headroom(struct sk_buff *skb, int nhead, int payloadoff,
                          int csum_offset) {
  int ret;
  if (nhead < 0) {
    __move_headroom(skb, nhead, payloadoff, csum_offset);
    return 0;
  }
  if (skb_headroom(skb) < nhead) {
    ret = pskb_expand_head(skb, nhead - skb_headroom(skb), 0, GFP_ATOMIC);
    if (ret) {
      return ret;
    }
  }
  __move_headroom(skb, nhead, payloadoff, csum_offset);
  return 0;
}

void update_iphdr_len(struct sk_buff *skb, int nhead) {
  struct iphdr *iph = ip_hdr(skb);
  __be16 newlen = htons(ntohs(iph->tot_len) + nhead);
  csum_replace2(&iph->check, iph->tot_len, newlen);
  iph->tot_len = newlen;
}

void update_udp_len(struct sk_buff *skb, struct udphdr *udph, int nhead) {
  bool zero_csum = skb->ip_summed != CHECKSUM_PARTIAL && udph->check == 0;
  __be16 newlen = htons(ntohs(udph->len) + nhead);
  // pseudo header change
  inet_proto_csum_replace2(&udph->check, skb, udph->len, newlen, true);
  // real udp header change
  inet_proto_csum_replace2(&udph->check, skb, udph->len, newlen, false);
  udph->len = newlen;
  if (zero_csum) {
    udph->check = 0;
  }
}

static void __fill_encap(char *payload, struct sk_buff *skb, __be32 daddr,
                         __be16 dport, __sum16 *csum) {
  *(__be16 *)(&payload[0]) = htons(ENCAP_MAGIC);
  *(__be16 *)(&payload[2]) = dport;
  *(__be32 *)(&payload[4]) = daddr;
  if (csum) {
    inet_proto_csum_replace2(csum, skb, 0, htons(ENCAP_MAGIC), false);
    inet_proto_csum_replace2(csum, skb, 0, dport, false);
    inet_proto_csum_replace4(csum, skb, 0, daddr, false);
  }
}

static void __unfill_encap(struct sk_buff *skb, __be32 daddr, __be16 dport,
                           __sum16 *csum) {
  if (!csum) {
    return;
  }
  inet_proto_csum_replace2(csum, skb, htons(ENCAP_MAGIC), 0, false);
  inet_proto_csum_replace2(csum, skb, dport, 0, false);
  inet_proto_csum_replace4(csum, skb, daddr, 0, false);
}

static int __load_encap(const char *payload, __be32 *encap_daddr,
                        __be16 *encap_dport) {
  if (*(__be16 *)(&payload[0]) != htons(ENCAP_MAGIC)) {
    pr_err_ratelimited("__load_encap: magic mismatch %x\n",
                        *(__be16 *)(&payload[0]));
    return -1;
  }
  *encap_dport = *(__be16 *)(&payload[2]);
  *encap_daddr = *(__be32 *)(&payload[4]);
  return 0;
}

void udp_fill_encap(struct sk_buff *skb, struct udphdr *udph) {
  char *payload = ((char *)udph) + sizeof(struct udphdr);
  bool no_csum_update = skb->ip_summed == CHECKSUM_PARTIAL || udph->check == 0;
  struct iphdr *iph = ip_hdr(skb);
  __fill_encap(payload, skb, iph->daddr, udph->dest,
               no_csum_update ? NULL : &udph->check);
  if (!no_csum_update && udph->check == 0) {
    udph->check = 0xffff;
  }
}

void udp_unfill_encap(struct sk_buff *skb, struct udphdr *udph,
                      __be32 encap_daddr, __be16 encap_dport) {
  bool no_csum_update = skb->ip_summed == CHECKSUM_PARTIAL || udph->check == 0;
  __unfill_encap(skb, encap_daddr, encap_dport,
                 no_csum_update ? NULL : &udph->check);
  if (!no_csum_update && udph->check == 0) {
    udph->check = 0xffff;
  }
}

int udp_load_encap(struct udphdr *udph, __be32 *encap_daddr,
                   __be16 *encap_dport) {
  char *payload = ((char *)udph) + sizeof(struct udphdr);
  if (ntohs(udph->len) < sizeof(struct udphdr) + ENCAP_LEN) {
    pr_err_ratelimited("udp_load_encap: no room found for encap %d\n",
                        ntohs(udph->len));
    return -1;
  }
  return __load_encap(payload, encap_daddr, encap_dport);
}

void update_tcp_len(struct sk_buff *skb, struct tcphdr *tcph, int old_len,
                    int nhead) {
  // pseudo header change
  inet_proto_csum_replace2(&tcph->check, skb, htons(old_len),
                           htons(old_len + nhead), true);
}

void tcp_fill_encap(struct sk_buff *skb, struct tcphdr *tcph, int tcp_hdrl) {

  char *payload = ((char *)tcph) + tcp_hdrl;
  bool no_csum_update = skb->ip_summed == CHECKSUM_PARTIAL;
  struct iphdr *iph = ip_hdr(skb);
  __fill_encap(payload, skb, iph->daddr, tcph->dest,
               no_csum_update ? NULL : &tcph->check);
}

void tcp_unfill_encap(struct sk_buff *skb, struct tcphdr *tcph,
                      __be32 encap_daddr, __be16 encap_dport) {
  bool no_csum_update = skb->ip_summed == CHECKSUM_PARTIAL;
  __unfill_encap(skb, encap_daddr, encap_dport,
                 no_csum_update ? NULL : &tcph->check);
}

int tcp_load_encap(struct tcphdr *tcph, int tcp_hdrl, __be32 *encap_daddr,
                   __be16 *encap_dport) {
  char *payload = ((char *)tcph) + tcp_hdrl;
  return __load_encap(payload, encap_daddr, encap_dport);
}
