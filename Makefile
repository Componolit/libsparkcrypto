OUTDIR  = out
DUMMY  := $(shell mkdir -p out)

all:
	spark \
        -brief \
        -vcg \
        -output_dir=$(OUTDIR) \
        -index=sha2.idx \
        -warn=warnings.conf \
        @sha2.smf
	sparksimp
	pogs -d=$(OUTDIR)

test_sha2: src/*.ad?
	gnatmake -D $(OUTDIR) src/test_sha2.adb

clean:
	rm -f *.rep *.fdl *.rls *.vcg *.lst *.ali *.o *.siv *.slg test_sha2
	rm -rf $(OUTDIR)
