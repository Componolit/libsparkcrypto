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

GOALS = $(OUTPUT_DIR)/tests

ifeq ($(NO_PROOF),)
GOALS += $(OUTPUT_DIR)/tests.sum
endif

all: $(GOALS) $(OUTPUT_DIR)/genhmac

$(OUTPUT_DIR)/tests: $(OUTPUT_DIR)/libglue.a

$(OUTPUT_DIR)/%.a: %.o
	ar cru $@ $^

install: all
	install -D -m 755 $(OUTPUT_DIR)/tests $(DESTDIR)/tests
ifeq ($(NO_PROOF),)
	install -D -m 644 $(OUTPUT_DIR)/tests.sum $(DESTDIR)/tests.sum
endif

$(OUTPUT_DIR)/tests:
	gnatmake -aP$(LSC_DIR) -aP$(SPARKUNIT_DIR) -L$(OUTPUT_DIR) -D$(OUTPUT_DIR)/build -o $@ -P build.gpr

$(OUTPUT_DIR)/tests.sum: $(OUTPUT_DIR)/target.cfg $(OUTPUT_DIR)/spark.idx $(OUTPUT_DIR)/spark.idx $(OUTPUT_DIR)/spark.smf
	spark -config=$< $(SPARK_OPTS) main.adb
	(cd $(OUTPUT_DIR) && sparksimp -t -p=5)
	pogs -d=$(OUTPUT_DIR) -o=tests.sum
	@tail -n14 $@ | head -n13
	@echo

$(OUTPUT_DIR)/spark.idx $(OUTPUT_DIR)/spark.smf:
	sparkmake $(SPARKMAKE_OPTS)

$(OUTPUT_DIR)/confgen: $(SPARK_DIR)/lib/spark/confgen.adb
	gnatmake -D $(OUTPUT_DIR) -o $@ $^

$(OUTPUT_DIR)/target.cfg: $(OUTPUT_DIR)/confgen
	@$< > $@

$(OUTPUT_DIR)/genhmac:
	$(CC) -W -Wall -Werror -o $@ genhmac.c -lssl
