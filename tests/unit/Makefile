CC ?= cc
K := ../../kmod
T := ../../tools/vtxctl
SAN ?= -fsanitize=address,undefined -fno-sanitize-recover=all
CFLAGS := -O1 -g -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -I$(K) $(SAN)
LDLIBS := -lpthread

TESTS := test_mtrr test_ept test_walk test_ring test_dtr test_ctl test_ksyms test_fmt

all: $(TESTS)

test_mtrr: test_mtrr.c $(K)/mtrr.c $(K)/prep.c $(K)/policy.c $(K)/ept.c
test_ept: test_ept.c $(K)/ept.c $(K)/prep.c $(K)/policy.c $(K)/mtrr.c
test_walk: test_walk.c $(K)/walk.c $(K)/policy.c
test_ring: test_ring.c $(K)/ring.c $(K)/prep.c $(K)/ept.c $(K)/policy.c $(K)/mtrr.c
test_dtr: test_dtr.c $(K)/dtr.c
test_ctl: test_ctl.c $(K)/ctl.c
test_ksyms: test_ksyms.c $(T)/ksyms.c
test_fmt: test_fmt.c $(T)/fmt.c $(T)/ksyms.c

$(TESTS):
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

run: all
	@fail=0; for t in $(TESTS); do ./$$t || fail=1; done; exit $$fail

clean:
	rm -f $(TESTS)

.PHONY: all run clean
