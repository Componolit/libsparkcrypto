OUTDIR  = out
DUMMY  := $(shell mkdir -p out)

all: $(OUTDIR)/all.sum
	gnatmake -D $(OUTDIR) src/test_sha2.adb

$(OUTDIR)/all.sum:
	spark \
        -brief \
        -vcg \
        -output_dir=$(OUTDIR) \
        -index=sha2.idx \
        -warn=warnings.conf \
        @sha2.smf
	sparksimp
	pogs -d=$(OUTDIR)

clean:
	rm -f *.rep *.fdl *.rls *.vcg *.lst *.ali *.o *.siv *.slg test_sha2
	rm -rf $(OUTDIR)
