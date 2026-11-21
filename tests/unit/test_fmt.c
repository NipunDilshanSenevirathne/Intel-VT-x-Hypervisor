#include "harness.h"
#include "../../tools/vtxctl/fmt.h"

static void test_pins(void)
{
	uint32_t m;
	char buf[256];

	CHECK_EQ(pin_parse("cr0.wp,cr4.smep", &m), 0);
	CHECK_EQ(m, VTX_PIN_CR0_WP | VTX_PIN_CR4_SMEP);
	CHECK_EQ(pin_parse("all", &m), 0);
	CHECK_EQ(m, VTX_PIN_ALL);
	CHECK_EQ(pin_parse("cr,msr", &m), 0);
	CHECK_EQ(m, VTX_PIN_CR0_WP | VTX_PIN_CR4_SMEP | VTX_PIN_CR4_SMAP | VTX_PIN_MSR_SYSCALL | VTX_PIN_MSR_SYSENTER | VTX_PIN_MSR_EFER);
	CHECK_EQ(pin_parse("DTR", &m), 0);
	CHECK_EQ(m, VTX_PIN_IDTR | VTX_PIN_GDTR | VTX_PIN_TR);
	CHECK(pin_parse("cr0.wp,bogus", &m) != 0);
	CHECK(pin_parse("", &m) != 0);
	CHECK(pin_parse(NULL, &m) != 0);
	pin_format(VTX_PIN_CR0_WP | VTX_PIN_TR, buf, sizeof(buf));
	CHECK(!strcmp(buf, "cr0.wp,tr"));
	pin_format(0, buf, sizeof(buf));
	CHECK(!strcmp(buf, "none"));
	pin_format(VTX_PIN_ALL, buf, 8);
	CHECK(strlen(buf) < 8);
}

static void test_deny(void)
{
	uint32_t d;
	char b[4];

	CHECK_EQ(deny_parse("rwx", &d), 0);
	CHECK_EQ(d, VTX_DENY_ALL);
	CHECK_EQ(deny_parse("W", &d), 0);
	CHECK_EQ(d, VTX_DENY_W);
	CHECK(deny_parse("rq", &d) != 0);
	CHECK(deny_parse("", &d) != 0);
	deny_format(VTX_DENY_R | VTX_DENY_X, b);
	CHECK(!strcmp(b, "r-x"));
}

static void test_json_escape(void)
{
	char *out = NULL;
	size_t len = 0;
	FILE *f = open_memstream(&out, &len);

	json_str(f, "a\"b\\c\n\x01z");
	fclose(f);
	CHECK(!strcmp(out, "\"a\\\"b\\\\c\\u000a\\u0001z\""));
	free(out);
}

static void test_event_render(void)
{
	struct vtx_event e;
	char *out = NULL;
	size_t len = 0;
	FILE *f;

	memset(&e, 0, sizeof(e));
	e.seq = 7;
	e.type = VTX_EV_MSR;
	e.info = 0xc0000082;
	e.old_val = 0xffffffff81e00080ull;
	e.new_val = 0xffffffffdeadbeefull;
	e.flags = VTX_EVF_DENIED | VTX_EVF_TASK;
	e.pid = 1234;
	memcpy(e.comm, "evil\"loader", 11);
	f = open_memstream(&out, &len);
	ev_print_json(f, &e, NULL);
	fclose(f);
	CHECK(strstr(out, "\"type\":\"msr-write\"") != NULL);
	CHECK(strstr(out, "\"denied\":true") != NULL);
	CHECK(strstr(out, "\"comm\":\"evil\\\"loader\"") != NULL);
	CHECK(strstr(out, "\"pid\":1234") != NULL);
	free(out);
	out = NULL;
	f = open_memstream(&out, &len);
	fmt_color = 0;
	ev_print_text(f, &e, NULL, 0);
	fclose(f);
	CHECK(strstr(out, "IA32_LSTAR") != NULL);
	CHECK(strstr(out, "DENIED") != NULL);
	CHECK(strstr(out, "via-emulator") == NULL);
	free(out);
	memset(&e, 0, sizeof(e));
	e.type = VTX_EV_TAMPER;
	e.watch_id = 3;
	e.gpa = 0x1234567;
	e.gla = 0xffffffffc0001000ull;
	e.new_val = 0x00ff00000000ffffull;
	e.flags = VTX_EVF_DENIED | VTX_EVF_EMUL | VTX_EVF_GLA;
	out = NULL;
	f = open_memstream(&out, &len);
	ev_print_text(f, &e, NULL, 0);
	fclose(f);
	CHECK(strstr(out, "hypervisor-image") != NULL);
	CHECK(strstr(out, "via-emulator") != NULL);
	free(out);
	out = NULL;
	f = open_memstream(&out, &len);
	ev_print_json(f, &e, NULL);
	fclose(f);
	CHECK(strstr(out, "\"emulated\":true") != NULL);
	CHECK(strstr(out, "\"type\":\"tamper\"") != NULL);
	free(out);
	memset(&e, 0, sizeof(e));
	e.type = VTX_EV_HYPERCALL;
	e.info = 0x565448000000000bull;
	e.gpa = 0x1f00ff0;
	e.new_val = 0x1f01000;
	e.flags = VTX_EVF_DENIED | VTX_EVF_EMUL;
	out = NULL;
	f = open_memstream(&out, &len);
	ev_print_text(f, &e, NULL, 0);
	fclose(f);
	CHECK(strstr(out, "refused") != NULL);
	CHECK(strstr(out, "0x1f01000") != NULL);
	free(out);
	e.flags = VTX_EVF_DENIED;
	out = NULL;
	f = open_memstream(&out, &len);
	ev_print_text(f, &e, NULL, 0);
	fclose(f);
	CHECK(strstr(out, "unprivileged hypercall") != NULL);
	free(out);
}

static void test_names(void)
{
	CHECK(!strcmp(exit_reason_name(48), "EPT_VIOLATION"));
	CHECK(!strcmp(exit_reason_name(37), "MONITOR_TRAP_FLAG"));
	CHECK(!strcmp(exit_reason_name(9999), "UNKNOWN"));
	CHECK(!strcmp(ev_type_name(VTX_EV_TAMPER), "tamper"));
	CHECK(!strcmp(ev_type_name(1000), "unknown"));
	CHECK(!strcmp(dtr_op_name(3), "LIDT"));
	CHECK(!strcmp(dtr_op_name(8), "?"));
	CHECK(!strcmp(msr_name(0xc0000080), "IA32_EFER"));
}

int t_checks, t_failures;
const char *t_current;

int main(void)
{
	printf("cli formatting\n");
	T_RUN(test_pins);
	T_RUN(test_deny);
	T_RUN(test_json_escape);
	T_RUN(test_event_render);
	T_RUN(test_names);
	printf("  %d checks, %d failures\n", t_checks, t_failures);
	return t_failures != 0;
}
