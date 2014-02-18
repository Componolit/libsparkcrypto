OUTPUT_DIR ?= $(CURDIR)/out

ifneq ($(MAKECMDGOALS),clean)
ifeq ($(LSC_DIR),)
$(error "LSC_DIR not set")
endif
endif

ifeq ($(SPARK_DIR),)
$(error "SPARK_DIR not set")
endif

ifeq ($(SPARKUNIT_DIR),)
$(error "SPARKUNIT_DIR not set")
endif

DUMMY := $(shell mkdir -p $(OUTPUT_DIR)/proof)

SPARK_OPTS = \
   -brief \
   -vcg \
   -nosli \
   -rules=lazy \
   -warn=warnings.conf \
   -index=$(OUTPUT_DIR)/spark.idx \
   -output_dir=$(OUTPUT_DIR)/proof

SPARKMAKE_OPTS = \
   -include=\*.ads \
   -include=\*.shs \
   -dir=$(SPARK_DIR)/lib/spark \
   -dir=$(LSC_DIR)/sharedinclude \
   -dir=$(SPARKUNIT_DIR)

GOALS = $(OUTPUT_DIR)/tests

REPORT_DEPS = $(OUTPUT_DIR)/proof/sparksimp.log

# Feature: NO_SPARK
ifeq ($(NO_SPARK),)
   GOALS += $(OUTPUT_DIR)/tests.sum

   # Feature: NO_ISABELLE
   ifeq ($(NO_ISABELLE),)
      GOALS += isabelle
      REPORT_DEPS += isabelle
      $(eval $(shell isabelle getenv ISABELLE_OUTPUT))
   endif
endif

all: $(GOALS) $(OUTPUT_DIR)/genhmac

isabelle: $(ISABELLE_OUTPUT)/log/HOL-SPARK-libsparkcrypto-tests.gz

$(OUTPUT_DIR)/%.a: %.o
	ar cru $@ $^

install: all
	install -D -m 755 $(OUTPUT_DIR)/tests $(DESTDIR)/tests
ifeq ($(NO_SPARK),)
	install -D -m 644 $(OUTPUT_DIR)/tests.sum $(DESTDIR)/tests.sum
endif

$(OUTPUT_DIR)/tests: $(OUTPUT_DIR)/libglue.a *.ad?
	gnatmake -aP$(LSC_DIR) -aP$(SPARKUNIT_DIR) -L$(OUTPUT_DIR) -D$(OUTPUT_DIR)/build -o $@ -P build.gpr

$(OUTPUT_DIR)/proof/sparksimp.log: $(OUTPUT_DIR)/target.cfg $(OUTPUT_DIR)/spark.idx $(OUTPUT_DIR)/spark.idx spark.smf
	spark -config=$< $(SPARK_OPTS) @spark.smf
	(cd $(OUTPUT_DIR)/proof && sparksimp -t -p=5) > $@.tmp
	mv $@.tmp $@

$(OUTPUT_DIR)/tests.sum: $(REPORT_DEPS)
	pogs -d=$(OUTPUT_DIR) -o=tests.sum
	@tail -n14 $@ | head -n13
	@echo

$(ISABELLE_OUTPUT)/log/HOL-SPARK-libsparkcrypto-tests.gz: $(OUTPUT_DIR)/proof/sparksimp.log
	VCG_DIR=$(OUTPUT_DIR)/proof LSC_THYS_DIR=$(CURDIR)/../src/theories isabelle build -o document=false -o threads=5 -D theories

$(OUTPUT_DIR)/spark.idx:
	sparkmake -nometa -index=$(OUTPUT_DIR)/spark.idx $(SPARKMAKE_OPTS)

$(OUTPUT_DIR)/confgen: $(SPARK_DIR)/lib/spark/confgen.adb
	gnatmake -D $(OUTPUT_DIR) -o $@ $^

$(OUTPUT_DIR)/target.cfg: $(OUTPUT_DIR)/confgen
	@$< > $@

$(OUTPUT_DIR)/genhmac:
	$(CC) -W -Wall -Werror -o $@ genhmac.c -lcrypto
