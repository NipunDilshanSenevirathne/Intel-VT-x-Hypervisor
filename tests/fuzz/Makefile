CLANG ?= clang
K := ../../kmod
T := ../../tools/vtxctl
FUZZ_TIME ?= 30
CFLAGS := -O1 -g -std=gnu11 -I$(K) -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all

FUZZERS := fuzz_walk fuzz_dtr fuzz_ept fuzz_ksyms

all: $(FUZZERS)

fuzz_walk: fuzz_walk.c $(K)/walk.c $(K)/policy.c
fuzz_dtr: fuzz_dtr.c $(K)/dtr.c
fuzz_ept: fuzz_ept.c $(K)/ept.c $(K)/prep.c $(K)/policy.c $(K)/mtrr.c
fuzz_ksyms: fuzz_ksyms.c $(T)/ksyms.c

$(FUZZERS):
	$(CLANG) $(CFLAGS) -o $@ $^

regress: all
	@for f in $(FUZZERS); do \
		if [ -d regressions/$$f ]; then \
			./$$f regressions/$$f/* > /dev/null 2>&1 || { echo "== $$f: regression input fails"; exit 1; }; \
			echo "== $$f: $$(ls regressions/$$f | wc -l) regression input(s) replayed clean"; \
		fi; \
	done

run: regress
	@for f in $(FUZZERS); do \
		mkdir -p corpus/$$f; \
		echo "== $$f ($(FUZZ_TIME)s)"; \
		./$$f -max_total_time=$(FUZZ_TIME) -print_final_stats=1 corpus/$$f 2>&1 | grep -E "stat::number_of_executed_units|stat::peak_rss|ERROR|SUMMARY|cov:" | tail -3 || exit 1; \
	done

clean:
	rm -f $(FUZZERS) crash-* leak-* timeout-*

.PHONY: all regress run clean
