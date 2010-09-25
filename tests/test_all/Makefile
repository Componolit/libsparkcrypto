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
		-warn=warnings.conf \
		-index=$(OUTPUT_DIR)/spark.idx \
      -output_dir=$(OUTPUT_DIR)/proof

SPARKMAKE_OPTS = \
   -nometa \
   -include=\*.ads \
   -include=\*.shs \
   -index=$(OUTPUT_DIR)/spark.idx \
   -dir=$(SPARK_DIR)/lib/spark \
   -dir=$(LSC_DIR)/sharedinclude \
   -dir=$(SPARKUNIT_DIR)

GOALS = $(OUTPUT_DIR)/test_all

ifeq ($(NO_PROOF),)
GOALS += $(OUTPUT_DIR)/test_all.sum
endif

all: $(GOALS)

install: all
	install -D -m 755 $(OUTPUT_DIR)/test_all $(DESTDIR)/test_all
ifeq ($(NO_PROOF),)
	install -D -m 644 $(OUTPUT_DIR)/test_all.sum $(DESTDIR)/test_all.sum
endif

$(OUTPUT_DIR)/test_all:
	gnatmake -aP$(LSC_DIR) -aP$(SPARKUNIT_DIR) -o test_all -P build.gpr

$(OUTPUT_DIR)/test_all.sum: $(OUTPUT_DIR)/target.cfg $(OUTPUT_DIR)/spark.idx $(OUTPUT_DIR)/spark.idx $(OUTPUT_DIR)/spark.smf
	spark -config=$< $(SPARK_OPTS) main.adb
	(cd $(OUTPUT_DIR) && sparksimp -t -p=5)
	pogs -o=$@
	@tail -n14 $@ | head -n13
	@echo

$(OUTPUT_DIR)/spark.idx $(OUTPUT_DIR)/spark.smf:
	sparkmake $(SPARKMAKE_OPTS)

$(OUTPUT_DIR)/confgen: $(SPARK_DIR)/lib/spark/confgen.adb
	gnatmake -D $(OUTPUT_DIR) -o $@ $^

$(OUTPUT_DIR)/target.cfg: $(OUTPUT_DIR)/confgen
	@$< > $@

clean:
	rm -rf $(OUTPUT_DIR)
