#ifndef VTXCTL_FMT_H
#define VTXCTL_FMT_H

#include <stdio.h>
#include <stdint.h>
#include "../../include/uapi/vtxhv.h"
#include "ksyms.h"

struct bitname {
	unsigned bit;
	const char *name;
};

extern int fmt_color;

const char *c_red(void);
const char *c_grn(void);
const char *c_yel(void);
const char *c_blu(void);
const char *c_mag(void);
const char *c_cyn(void);
const char *c_dim(void);
const char *c_bold(void);
const char *c_off(void);

const char *ev_type_name(uint32_t t);
const char *exit_reason_name(unsigned r);
const char *msr_name(uint32_t msr);
const char *dtr_op_name(unsigned op);
const char *pin_name(unsigned bit);
int pin_parse(const char *list, uint32_t *mask);
void pin_format(uint32_t mask, char *buf, size_t len);
int deny_parse(const char *s, uint32_t *deny);
void deny_format(uint32_t deny, char *buf);
void feature_format(uint32_t f, char *buf, size_t len);
void ev_access(const struct vtx_event *e, char *buf);
void ev_symbol(const struct ksyms *k, uint64_t addr, char *buf, size_t len);
void ev_print_text(FILE *o, const struct vtx_event *e, const struct ksyms *k, uint64_t tsc0);
void ev_print_json(FILE *o, const struct vtx_event *e, const struct ksyms *k);
void json_str(FILE *o, const char *s);

extern const struct bitname pin_ctl_bits[];
extern const struct bitname proc_ctl_bits[];
extern const struct bitname proc2_ctl_bits[];
extern const struct bitname exit_ctl_bits[];
extern const struct bitname entry_ctl_bits[];
extern const struct bitname ept_cap_bits[];
void caps_print(FILE *o, const struct vtx_caps *c, int json);

#endif
