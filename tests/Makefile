OUTPUT_DIR ?= $(CURDIR)/out

ifneq ($(MAKECMDGOALS),clean)
ifeq ($(LSC_DIR),)
$(error "LSC_DIR not set")
endif
endif

DUMMY := $(shell mkdir -p $(OUTPUT_DIR)/proof)

GOALS = $(OUTPUT_DIR)/tests

SPARK_LOG = $(OUTPUT_DIR)/../libsparkcrypto/gnatprove.log
REPORT_DEPS = $(SPARK_LOG)

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
	ADA_PROJECT_PATH=$(SPARKUNIT_DIR):$(ADA_PROJECT_PATH) gprbuild -P build.gpr

$(ISABELLE_OUTPUT)/log/HOL-SPARK-libsparkcrypto-tests.gz: $(SPARK_LOG)
	VCG_DIR=$(OUTPUT_DIR)/proof LSC_THYS_DIR=$(CURDIR)/../src/theories isabelle build -c -o document=false -o threads=5 -D theories

$(OUTPUT_DIR)/genhmac:
	$(CC) -W -Wall -Werror -o $@ genhmac.c -lcrypto

clean:
	rm -r -f *.o *.ali out *.stderr *.stdout b__*.ad? *.bexch
