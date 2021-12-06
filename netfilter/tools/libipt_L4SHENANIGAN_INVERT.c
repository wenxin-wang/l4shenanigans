#include <arpa/inet.h>
#include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
#include <xtables.h>
// #include <linux/netfilter.h>

#include "l4shenanigan_uapi.h"

enum {
	O_XMASK = 0,
};

static void l4shenanigan_invert_help(void) {
  printf(
"L4SHENANIGAN_INVERT target\n"
" --xmask byte	byte mask fo inverting\n"
);
}

static const struct xt_option_entry l4shenanigan_invert_opts[] = {
	{.name = "xmask", .id = O_XMASK, .type = XTTYPE_UINT8,
	 .flags = XTOPT_MAND | XTOPT_PUT,
	 XTOPT_POINTER(struct l4shenanigan_invert_info, xmask)},
	XTOPT_TABLEEND,
};

static void l4shenanigan_invert_x6_parse(struct xt_option_call *cb) {
  xtables_option_parse(cb);
}

static void l4shenanigan_invert_check(unsigned int flags) {
  UNUSED(flags);
}

static void l4shenanigan_invert_print(const void * entry,
                                      const struct xt_entry_target * target,
                                      int numeric) {
  UNUSED(entry);
  UNUSED(numeric);
  const struct l4shenanigan_invert_info *invert_info =
      (const struct l4shenanigan_invert_info*)target->data;
  printf(" xmask %d",
         invert_info->xmask);
}

static void
l4shenanigan_invert_save(const void * entry,
                         const struct xt_entry_target * target) {
  UNUSED(entry);
  const struct l4shenanigan_invert_info *invert_info =
      (const struct l4shenanigan_invert_info*)target->data;
  printf(" --xmask %d",
         invert_info->xmask);
}

static struct xtables_target l4shenanigan_invert_reg = {
    .version = XTABLES_VERSION,
    .name = INVERT_TARGET_NAME,
    .revision = 0,
	.family = PF_INET,
	.size          = XT_ALIGN(sizeof(struct l4shenanigan_invert_info)),
    .help = l4shenanigan_invert_help,
    /* called when user enters new rule; it validates the args (--ipsrc). */
    .x6_parse = l4shenanigan_invert_x6_parse,
	.x6_options    = l4shenanigan_invert_opts,
    /* last chance for sanity checks after parse. */
    .final_check = l4shenanigan_invert_check,
    /* called when user execs "ip6tables -L" */
    .print = l4shenanigan_invert_print,
    /* called when user execs "ip6tables-save" */
    .save = l4shenanigan_invert_save,
};

void _init(void) { xtables_register_target(&l4shenanigan_invert_reg); }
