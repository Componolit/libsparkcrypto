OUTPUT_DIR ?= $(CURDIR)/out

ifneq ($(MAKECMDGOALS),clean)
ifeq ($(LSC_DIR),)
$(error "LSC_DIR not set")
endif
endif

ifeq ($(SPARK_DIR),)
$(error "SPARK_DIR not set")
endif

DUMMY := $(shell mkdir -p $(OUTPUT_DIR)/proof)

SPARK_OPTS = \
		-brief \
		-vcg \
      -nosli \
		-warn=warnings.conf \
		-index=$(OUTPUT_DIR)/global.idx \
      -output_dir=$(OUTPUT_DIR)/proof

GOALS = $(OUTPUT_DIR)/test_ripemd160

ifeq ($(NO_PROOF),)
GOALS += $(OUTPUT_DIR)/test_ripemd160.sum
endif

all: $(GOALS)

install: all
	install -D -m 755 $(OUTPUT_DIR)/test_ripemd160 $(DESTDIR)/test_ripemd160
ifeq ($(NO_PROOF),)
	install -D -m 644 $(OUTPUT_DIR)/test_ripemd160.sum $(DESTDIR)/test_ripemd160.sum
endif

$(OUTPUT_DIR)/test_ripemd160:
	gnatmake -aP$(LSC_DIR) -o test_ripemd160 -P build.gpr

$(OUTPUT_DIR)/test_ripemd160.sum: $(OUTPUT_DIR)/target.cfg $(OUTPUT_DIR)/global.idx $(OUTPUT_DIR)/spark.idx $(OUTPUT_DIR)/spark.smf
	spark -config=$< $(SPARK_OPTS) main.adb
	(cd $(OUTPUT_DIR) && sparksimp -t -p=5)
	pogs -o=$@
	@tail -n14 $@ | head -n13
	@echo

$(OUTPUT_DIR)/spark.idx $(OUTPUT_DIR)/spark.smf:
	sparkmake -nometa -duplicates_are_errors -index=$(OUTPUT_DIR)/spark.idx -meta=$(OUTPUT_DIR)/spark.smf

$(OUTPUT_DIR)/global.idx: $(OUTPUT_DIR)/spark.idx
	@cat $(LSC_DIR)/libsparkcrypto.idx $< > $@

$(OUTPUT_DIR)/confgen: $(SPARK_DIR)/lib/spark/confgen.adb
	gnatmake -D $(OUTPUT_DIR) -o $@ $^

$(OUTPUT_DIR)/target.cfg: $(OUTPUT_DIR)/confgen
	@$< > $@

clean:
	rm -rf $(OUTPUT_DIR)
