#include <arpa/inet.h>
#include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
#include <xtables.h>
// #include <linux/netfilter.h>

#include "l4shenanigans_uapi.h"

static void l4shenanigan_invert_help(void) {
  printf("L4SHENANIGAN_INVERT target\n");
}

static void l4shenanigan_invert_x6_parse(struct xt_option_call *cb) {
  UNUSED(cb);
}

static void l4shenanigan_invert_check(unsigned int flags) {
  UNUSED(flags);
}

static void l4shenanigan_invert_print(const void * entry,
                                      const struct xt_entry_target * target,
                                      int numeric) {
  UNUSED(entry);
  UNUSED(target);
  UNUSED(numeric);
  printf(" L4SHENANIGAN_INVERT");
}

static void
l4shenanigan_invert_save(const void * entry,
                         const struct xt_entry_target * target) {
  UNUSED(entry);
  UNUSED(target);
  printf(" L4SHENANIGAN_INVERT");
}

static struct xtables_target l4shenanigan_invert_reg = {
    .version = XTABLES_VERSION,
    .name = INVERT_TARGET_NAME,
    .revision = 0,
	.family = PF_INET,
    .help = l4shenanigan_invert_help,
    /* called when user enters new rule; it validates the args (--ipsrc). */
    .x6_parse = l4shenanigan_invert_x6_parse,
    /* last chance for sanity checks after parse. */
    .final_check = l4shenanigan_invert_check,
    /* called when user execs "ip6tables -L" */
    .print = l4shenanigan_invert_print,
    /* called when user execs "ip6tables-save" */
    .save = l4shenanigan_invert_save,
};

void _init(void) { xtables_register_target(&l4shenanigan_invert_reg); }
