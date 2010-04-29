OUTDIR  = out
DUMMY  := $(shell mkdir -p out)

all: $(OUTDIR)/all.sum
	gnatmake -D $(OUTDIR) src/test_sha2.adb

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
