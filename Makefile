OUTDIR  = out
DUMMY  := $(shell mkdir -p out)
GNATMAKE_FLAGS =

all: $(OUTDIR)/all.sum
	gnatmake $(GNATMAKE_FLAGS) -aIsrc -D $(OUTDIR) test/test_sha2.adb

debug: GNATMAKE_FLAGS += -aIdebug
debug: all

$(OUTDIR)/all.sum: $(OUTDIR)/target.cfg
	spark \
        -brief \
        -vcg \
        -output_dir=$(OUTDIR) \
        -index=sparkcrypto.idx \
        -warn=warnings.conf \
	    -config=$< \
        @sparkcrypto.smf
	sparksimp
	pogs -d=$(OUTDIR)

$(OUTDIR)/confgen: $(SPARK_DIR)/lib/spark/confgen.adb
	gnatmake -D $(OUTDIR) -o $@ $^

$(OUTDIR)/target.cfg: $(OUTDIR)/confgen
	$< > $@

clean:
	rm -f *.rep *.fdl *.rls *.vcg *.lst *.ali *.o *.siv *.slg test_sha2
	rm -rf $(OUTDIR)
