OUTDIR  = out
DUMMY  := $(shell mkdir -p out)
GNATMAKE_FLAGS = -we

FILES = \
    $(OUTDIR)/test_all \
    $(OUTDIR)/test_all.sum \
    $(OUTDIR)/sha512openssl \
    $(OUTDIR)/sha512perf \
    $(OUTDIR)/sha512sum \
    $(OUTDIR)/sha512sum.sum \

all: $(FILES)

debug: GNATMAKE_FLAGS += -aIdebug
debug: all

simplify:
	@sparksimp -p=8
	@pogs -d=$(OUTDIR)

$(OUTDIR)/%: tests/%/main.adb
	@mkdir -p $@.bin
	@gnatmake $(GNATMAKE_FLAGS) -aIada -aIsrc -D $@.bin -o $@ $<

$(OUTDIR)/sha512openssl: CFLAGS += -lssl

$(OUTDIR)/%: tests/%/main.c
	$(CC) $(CFLAGS) -o $@ $^

$(OUTDIR)/%.sum: $(OUTDIR)/target.cfg $(OUTDIR)/%.idx $(OUTDIR)/%.smf
	@mkdir -p $(OUTDIR)/$(*F).proof
	@spark \
		-brief \
		-vcg \
		-config=$< \
		-warn=warnings.conf \
		-output_dir=$(OUTDIR)/$(*F).proof \
		-index=$(OUTDIR)/$(*F).idx \
		@$(OUTDIR)/$(*F).smf

$(OUTDIR)/%.idx $(OUTDIR)/%.smf:
	@(cd tests/$(*F); sparkmake -duplicates_are_errors -dir=$(realpath src) -index=$(realpath $(OUTDIR))/$(*F).idx -meta=$(realpath $(OUTDIR))/$(*F).smf)

$(OUTDIR)/confgen: $(SPARK_DIR)/lib/spark/confgen.adb
	@gnatmake -D $(OUTDIR) -o $@ $^

$(OUTDIR)/target.cfg: $(OUTDIR)/confgen
	@$< > $@

clean:
	rm -rf $(OUTDIR)
