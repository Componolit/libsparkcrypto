OUTDIR  = $(realpath out)
DUMMY  := $(shell mkdir -p out)
GNATMAKE_FLAGS = -we

SPARK_PROGS = \
	test_aes \
	test_sha2 \
	test_hmac \
   benchmark

PROOFS = \
   $(addsuffix .sum, $(SPARK_PROGS))

all: $(addprefix $(OUTDIR)/,$(SPARK_PROGS) $(C_PROGS))
proof: $(addprefix $(OUTDIR)/,$(PROOFS))

test: $(addprefix $(OUTDIR)/,$(filter test_%,$(SPARK_PROGS)))
	@for f in $^; do $$f; done;

debug: GNATMAKE_FLAGS += -aIdebug
debug: all

lib: $(OUTDIR)/lib.sum

$(OUTDIR)/lib.sum: $(OUTDIR)/target.cfg $(OUTDIR)/libsparkcrypto.idx src/*.adb src/*.ads
	@mkdir -p $(@D) $(OUTDIR)/lib
	@spark \
		-brief \
		-vcg \
		-dpc \
		-nosli \
		-config=$(OUTDIR)/target.cfg \
		-warn=warnings.conf \
		-output_dir=$(OUTDIR)/lib \
		-index=$(OUTDIR)/libsparkcrypto.idx \
		src/*.adb
	(cd $(OUTDIR)/lib && sparksimp -t -p=5)
	@pogs -d=$(OUTDIR)/lib -o=$@
	@tail -n14 $@ | head -n13
	@echo

$(OUTDIR)/benchmark: GNATMAKE_FLAGS += -O3 -gnatB -gnatn -gnatp -gnatVn

$(OUTDIR)/libsparkcrypto.idx:
	(cd src && sparkmake -duplicates_are_errors -index=$@ -nometafile)

#
# how to build an Ada program
#
$(OUTDIR)/%: progs/%/main.adb
	@mkdir -p $(@D)/build/$(@F)
	@gnatmake $(GNATMAKE_FLAGS) -aIshadow -aIsrc -D $(@D)/build/$(@F) -o $@ $<

#
# how to build a C program
#
$(OUTDIR)/%: progs/%/main.c
	$(CC) $(CFLAGS) -o $@ $^

#
# how to examine a program
#
$(OUTDIR)/%.sum: $(OUTDIR)/target.cfg $(OUTDIR)/%.prf/spark.idx $(OUTDIR)/%.prf/spark.smf
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
