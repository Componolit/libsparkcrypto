OUTDIR  = out
DUMMY  := $(shell mkdir -p out)
GNATMAKE_FLAGS =

all: $(OUTDIR)/sha512sum $(OUTDIR)/sha512sum.sum $(OUTDIR)/test_sha2 $(OUTDIR)/test_sha2.sum

debug: GNATMAKE_FLAGS += -aIdebug
debug: all

$(OUTDIR)/%: tests/%/main.adb
	mkdir -p $@.bin
	gnatmake $(GNATMAKE_FLAGS) -aIada -aIsrc -D $@.bin -o $@ $<

$(OUTDIR)/%.sum: $(OUTDIR)/target.cfg $(OUTDIR)/%.idx $(OUTDIR)/%.smf
	mkdir -p $(OUTDIR)/$(*F).proof
	spark \
		-brief \
		-vcg \
		-config=$< \
		-warn=warnings.conf \
		-output_dir=$(OUTDIR)/$(*F).proof \
		-index=$(OUTDIR)/$(*F).idx \
		@$(OUTDIR)/$(*F).smf
	sparksimp -p=8
	pogs -d=$(OUTDIR)/$(*F).proof

$(OUTDIR)/%.idx $(OUTDIR)/%.smf:
	(cd tests/$(*F); sparkmake -duplicates_are_errors -dir=$(realpath src) -index=$(realpath $(OUTDIR))/$(*F).idx -meta=$(realpath $(OUTDIR))/$(*F).smf)

$(OUTDIR)/confgen: $(SPARK_DIR)/lib/spark/confgen.adb
	gnatmake -D $(OUTDIR) -o $@ $^

$(OUTDIR)/target.cfg: $(OUTDIR)/confgen
	$< > $@

clean:
	rm -rf $(OUTDIR)
