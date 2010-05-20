OUTDIR  = $(realpath out)
DUMMY  := $(shell mkdir -p out)
GNATMAKE_FLAGS = -we

SPARK_PROGS = \
	test_aes \
	test_sha2 \
	test_hmac \
   sha512perf \
   sha512sum

PROOFS = \
   $(addsuffix .sum, $(SPARK_PROGS))

C_PROGS = \
   sha512openssl

all: $(addprefix $(OUTDIR)/,$(SPARK_PROGS) $(C_PROGS))
proof: $(addprefix $(OUTDIR)/,$(PROOFS))

debug: GNATMAKE_FLAGS += -aIdebug
debug: all

$(OUTDIR)/test_aes.sum: $(OUTDIR)/test_aes.prf/lsc_/aes/encrypt.rlu

$(OUTDIR)/sha512openssl: CFLAGS += -lssl

#
# how to build an Ada program
#
$(OUTDIR)/%: progs/%/main.adb
	@mkdir -p $@.bin
	@gnatmake $(GNATMAKE_FLAGS) -aIshadow -aIsrc -D $@.bin -o $@ $<

#
# how to build a C program
#
$(OUTDIR)/%: progs/%/main.c
	$(CC) $(CFLAGS) -o $@ $^

#
# how to examine a program
#
$(OUTDIR)/%.sum: $(OUTDIR)/target.cfg $(OUTDIR)/%.prf/spark.idx $(OUTDIR)/%.prf/spark.smf
	mkdir -p $(OUTDIR)/$(*F).prf
	spark \
		-brief \
		-vcg \
		-config=$< \
		-warn=warnings.conf \
		-output_dir=$(OUTDIR)/$(*F).prf \
		-index=$(OUTDIR)/$(*F).prf/spark.idx \
		@$(OUTDIR)/$(*F).prf/spark.smf
	(cd $(OUTDIR)/$(*F).prf && sparksimp -t -p=4)
	pogs -d=$(OUTDIR)/$(*F).prf -o=$@

#
# how to create index and meta files
#
$(OUTDIR)/%.prf/spark.idx $(OUTDIR)/%.prf/spark.smf:
	mkdir -p $(@D)
	(cd progs/$(*F); sparkmake -duplicates_are_errors -dir=$(realpath src) -index=$(@D)/spark.idx -meta=$(@D)/spark.smf)

#
# how to build the target configuration generator
#
$(OUTDIR)/confgen: $(SPARK_DIR)/lib/spark/confgen.adb
	@gnatmake -D $(OUTDIR) -o $@ $^

#
# how to generate the target configuration file
#
$(OUTDIR)/target.cfg: $(OUTDIR)/confgen
	@$< > $@

#
# how to create (i.e. copy) an RLU file
#
$(OUTDIR)/%.rlu:
	@mkdir -p $(@D)
	@cp rules/$(@F) $@

#
# clean up
#
clean:
	rm -rf $(OUTDIR)
