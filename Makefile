OUTDIR  = $(CURDIR)/out
DUMMY  := $(shell mkdir -p $(OUTDIR))

SPARK_PROGS = test_aes test_sha2 test_hmac
ADA_PROGS   = benchmark
PROOFS      = $(addsuffix .sum, $(SPARK_PROGS))

# Disable proof dependency if NOPROOF environment variable is set.
ifeq ($(NOPROOF),)
PROOF_DEP = $(OUTDIR)/libsparkcrypto/adalib/libsparkcrypto.sum
endif

ifneq ($(DEBUG),)
GNATMAKE_FLAGS += -Xmode=debug
endif

all: $(addprefix $(OUTDIR)/,$(SPARK_PROGS)) $(addprefix $(OUTDIR)/,$(ADA_PROGS))

proof: $(addprefix $(OUTDIR)/,$(PROOFS))

test: $(addprefix $(OUTDIR)/,$(filter test_%,$(SPARK_PROGS)))
	@for f in $^; do $$f; done;

$(OUTDIR)/libsparkcrypto/libsparkcrypto.gpr: $(PROOF_DEP)
	@gnatmake $(GNATMAKE_FLAGS) -p -P gnat/build_libsparkcrypto
	@install -D -m 644 gnat/libsparkcrypto.gpr.tmpl $(OUTDIR)/libsparkcrypto/libsparkcrypto.gpr
	@install -d -m 755 $(OUTDIR)/libsparkcrypto/adainclude
	@install -m 644 src/*.ad? $(OUTDIR)/libsparkcrypto/adainclude
	@install -m 644 shadow/src/*.ad? $(OUTDIR)/libsparkcrypto/adainclude
	@install -m 644 shadow/x86_64/*.ad? $(OUTDIR)/libsparkcrypto/adainclude
ifneq ($(DEBUG),)
	@install -m 644 shadow/debug/*.ad? $(OUTDIR)/libsparkcrypto/adainclude
endif

$(OUTDIR)/libsparkcrypto/adalib/libsparkcrypto.sum: $(OUTDIR)/target.cfg $(OUTDIR)/libsparkcrypto.idx src/*.adb src/*.ads
	@mkdir -p $(@D) $(OUTDIR)/proof
	@spark \
		-brief \
		-vcg \
		-dpc \
		-nosli \
		-config=$(OUTDIR)/target.cfg \
		-warn=warnings.conf \
		-output_dir=$(OUTDIR)/proof \
		-index=$(OUTDIR)/libsparkcrypto.idx \
		src/*.adb
	(cd $(OUTDIR)/proof && sparksimp -t -p=5)
	@pogs -s -d=$(OUTDIR)/proof -o=$@
	@tail -n14 $@ | head -n13
	@echo

$(OUTDIR)/libsparkcrypto.idx:
	(cd src && sparkmake -duplicates_are_errors -index=$@ -nometafile)

#
# how to build an Ada program
#
$(OUTDIR)/%: $(CURDIR)/tests/% $(OUTDIR)/libsparkcrypto/libsparkcrypto.gpr
	gnatmake $(GNATMAKE_FLAGS) -aP$(OUTDIR)/libsparkcrypto -Xsources=$< -Xoutdir=$(OUTDIR) -o $@ -P gnat/build.gpr

#
# how to examine a program
#
$(OUTDIR)/%.sum: $(OUTDIR)/target.cfg $(OUTDIR)/%.prf/spark.idx $(OUTDIR)/%.prf/spark.smf $(OUTDIR)/libsparkcrypto/adalib/libsparkcrypto.sum
	@mkdir -p $(OUTDIR)/$(*F).prf
	@spark \
		-brief \
		-vcg \
		-config=$< \
		-warn=warnings.conf \
		-output_dir=$(OUTDIR)/$(*F).prf \
		-index=$(OUTDIR)/$(*F).prf/spark.idx \
		@$(OUTDIR)/$(*F).prf/spark.smf
	(cd $(OUTDIR)/$(*F).prf && sparksimp -t -p=5)
	@pogs -d=$(OUTDIR)/$(*F).prf -o=$@
	@tail -n14 $@ | head -n13
	@echo

#
# how to create index and meta files
#
$(OUTDIR)/%.prf/spark.idx $(OUTDIR)/%.prf/spark.smf:
	mkdir -p $(@D)
	(cd tests/$(*F); sparkmake -duplicates_are_errors -dir=$(OUTDIR)/libsparkcrypto/adainclude -index=$(@D)/spark.idx -meta=$(@D)/spark.smf)

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
