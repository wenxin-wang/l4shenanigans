#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <uapi/linux/in.h>

#include "l4shenanigans_protocol.h"

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

void udp_fill_encap(struct sk_buff *skb, struct udphdr *udph) {
  char *payload = ((char *)udph) + sizeof(struct udphdr);
  bool no_csum_update = skb->ip_summed == CHECKSUM_PARTIAL || udph->check == 0;
  struct iphdr *iph = ip_hdr(skb);
  *(__be32 *)(&payload[0]) = iph->daddr;
  *(__be16 *)(&payload[4]) = udph->dest;
  if (!no_csum_update) {
    inet_proto_csum_replace4(&udph->check, skb, 0, iph->daddr, false);
    inet_proto_csum_replace2(&udph->check, skb, 0, udph->dest, false);
    if (udph->check == 0) {
      udph->check = 0xffff;
    }
  }
}

void udp_unfill_encap(struct sk_buff *skb, struct udphdr *udph,
                      __be32 encap_daddr, __be16 encap_dport) {
  bool no_csum_update = skb->ip_summed == CHECKSUM_PARTIAL || udph->check == 0;
  if (!no_csum_update) {
    inet_proto_csum_replace4(&udph->check, skb, encap_daddr, 0, false);
    inet_proto_csum_replace2(&udph->check, skb, encap_dport, 0, false);
    if (udph->check == 0) {
      udph->check = 0xffff;
    }
  }
}

int udp_load_encap(struct udphdr *udph, __be32 *encap_daddr,
                   __be16 *encap_dport) {
  char *payload = ((char *)udph) + sizeof(struct udphdr);
  if (ntohs(udph->len) < sizeof(struct udphdr) + ENCAP_LEN) {
    pr_info_ratelimited("udp_load_encap: no room found for encap %d\n",
                        ntohs(udph->len));
    return -1;
  }
  *encap_daddr = *(__be32 *)payload;
  *encap_dport = *(__be16 *)(payload + sizeof(__be32));
  return 0;
}

void update_tcp_len(struct sk_buff *skb, struct tcphdr *tcph, int old_len,
                    int nhead) {
  __be16 old_val;
  // pseudo header change
  inet_proto_csum_replace2(&tcph->check, skb, htons(old_len),
                           htons(old_len + nhead), true);
  old_val = ((__be16 *)tcph)[6];
  tcph->doff += nhead / 4;
  // real tcp header change
  inet_proto_csum_replace2(&tcph->check, skb, old_val, ((__be16 *)tcph)[6],
                           false);
}

void tcp_fill_encap(struct sk_buff *skb, struct tcphdr *tcph) {
  struct iphdr *iph = ip_hdr(skb);
  char *payload = ((char *)tcph) + (int)sizeof(struct tcphdr);
  payload[0] = TCPOPT_EXP;
  payload[1] = TCPOLEN_ENCAP;
  *(__be16 *)(&payload[2]) = htons((ntohl(iph->daddr) & 0xffff0000) >> 16);
  *(__be16 *)(&payload[4]) = htons(ntohl(iph->daddr) & 0x0000ffff);
  *(__be16 *)(&payload[6]) = tcph->dest;
  if (skb->ip_summed == CHECKSUM_PARTIAL) {
    return;
  }
  inet_proto_csum_replace4(&tcph->check, skb, 0, *(__be32 *)(&payload[0]),
                           false);
  inet_proto_csum_replace4(&tcph->check, skb, 0, *(__be32 *)(&payload[4]),
                           false);
}

void tcp_unfill_encap(struct sk_buff *skb, struct tcphdr *tcph,
                      __be32 encap_daddr, __be16 encap_dport) {
  u8 opt[2];
  if (skb->ip_summed == CHECKSUM_PARTIAL) {
    return;
  }
  opt[0] = TCPOPT_EXP;
  opt[1] = TCPOLEN_ENCAP;
  inet_proto_csum_replace2(&tcph->check, skb, *(__be16 *)opt, 0, false);
  inet_proto_csum_replace4(&tcph->check, skb, encap_daddr, 0, false);
  inet_proto_csum_replace2(&tcph->check, skb, encap_dport, 0, false);
}

static inline unsigned int optlen(const u_int8_t *opt, unsigned int offset) {
  /* Beware zero-length options: make finite progress */
  if (opt[offset] <= TCPOPT_NOP || opt[offset + 1] == 0)
    return 1;
  else
    return opt[offset + 1];
}

int tcp_load_encap(struct tcphdr *tcph, __be32 *encap_daddr,
                   __be16 *encap_dport) {
  u8 *opt = (u8 *)tcph;
  int i, tcp_hdrlen = tcph->doff * 4;
  for (i = sizeof(struct tcphdr); i <= tcp_hdrlen - TCPOLEN_ENCAP;
       i += optlen(opt, i)) {
    if (opt[i] == TCPOPT_EXP && opt[i + 1] == TCPOLEN_ENCAP) {
      ((__be16 *)encap_daddr)[0] = *(__be16 *)(&opt[i + 2]);
      ((__be16 *)encap_daddr)[1] = *(__be16 *)(&opt[i + 4]);
      *encap_dport = *(__be16 *)(&opt[i + 6]);
      return 0;
    }
  }
  pr_info_ratelimited("tcp_load_encap: no encap found %d\n", tcp_hdrlen);
  return -1;
}
