OUTPUT_DIR = $(abspath out)
SPARK_DIR  = $(shell dirname `which spark`)/..

DUMMY := $(shell mkdir -p $(OUTPUT_DIR)/lib)

SPARK_OPTS = \
  -vcg \
  -brief \
  -warning=warnings.conf \
  -error_explanation=first_occurrence \
  -output_directory=$(OUTPUT_DIR)

SPARK_FILES = \
  shadow/interfaces.ads \
  types.ads \
  bignum.ads \
  bignum.adb

SIV_FILES = \
  $(OUTPUT_DIR)/bignum/double_inplace.siv

PRV_FILES = \
  $(OUTPUT_DIR)/bignum/double_inplace.prv

all: $(OUTPUT_DIR)/bignum.sum

$(SIV_FILES): $(OUTPUT_DIR)/target.cfg $(SPARK_FILES)
	spark $(SPARK_OPTS) -config=$< $(SPARK_FILES)
	sparksimp

$(PRV_FILES): $(SIV_FILES)
	cd ..; OUTPUT_DIR=$(OUTPUT_DIR) isabelle usedir HOL-SPARK spark-bignum

$(OUTPUT_DIR)/bignum.sum: $(PRV_FILES)
	pogs -d=$(OUTPUT_DIR) -o=bignum.sum
	cat $@

$(OUTPUT_DIR)/target.cfg: $(OUTPUT_DIR)/confgen
	$(OUTPUT_DIR)/confgen > $@

$(OUTPUT_DIR)/confgen: $(SPARK_DIR)/lib/spark/confgen.adb
	gnatmake -D$(OUTPUT_DIR) -o $@ $^

$(OUTPUT_DIR)/test: test.adb types.adb $(SPARK_FILES)
	gnatmake -gnata -O2 -D $(OUTPUT_DIR) -o $(OUTPUT_DIR)/test test
