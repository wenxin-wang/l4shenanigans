#include <arpa/inet.h>
#include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
#include <xtables.h>
// #include <linux/netfilter.h>

#include "l4shenanigans_uapi.h"

static void l4shenanigan_encap_help(void) {
  printf("L4SHENANIGAN_ENCAP target\n");
}

static void l4shenanigan_encap_x6_parse(struct xt_option_call *cb) {
  UNUSED(cb);
}

static void l4shenanigan_encap_check(unsigned int flags) {
  UNUSED(flags);
}

static void l4shenanigan_encap_print(const void * entry,
                                      const struct xt_entry_target * target,
                                      int numeric) {
  UNUSED(entry);
  UNUSED(target);
  UNUSED(numeric);
}

static void
l4shenanigan_encap_save(const void * entry,
                         const struct xt_entry_target * target) {
  UNUSED(entry);
  UNUSED(target);
}

static struct xtables_target l4shenanigan_encap_reg = {
    .version = XTABLES_VERSION,
    .name = ENCAP_TARGET_NAME,
    .revision = 0,
	.family = PF_INET,
    .help = l4shenanigan_encap_help,
    /* called when user enters new rule; it validates the args (--ipsrc). */
    .x6_parse = l4shenanigan_encap_x6_parse,
    /* last chance for sanity checks after parse. */
    .final_check = l4shenanigan_encap_check,
    /* called when user execs "ip6tables -L" */
    .print = l4shenanigan_encap_print,
    /* called when user execs "ip6tables-save" */
    .save = l4shenanigan_encap_save,
};

void _init(void) { xtables_register_target(&l4shenanigan_encap_reg); }
