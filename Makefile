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
  $(OUTPUT_DIR)/bignum/initialize.siv \
  $(OUTPUT_DIR)/bignum/copy.siv \
  $(OUTPUT_DIR)/bignum/word_of_boolean.siv \
  $(OUTPUT_DIR)/bignum/double_inplace.siv \
  $(OUTPUT_DIR)/bignum/sub_inplace.siv \
  $(OUTPUT_DIR)/bignum/less.siv \
  $(OUTPUT_DIR)/bignum/size_square_mod.siv \
  $(OUTPUT_DIR)/bignum/word_inverse.siv \
  $(OUTPUT_DIR)/bignum/single_add_mult_mult.siv \
  $(OUTPUT_DIR)/bignum/add_mult_mult.siv \
  $(OUTPUT_DIR)/bignum/mont_mult.siv \
  $(OUTPUT_DIR)/bignum/mont_exp.siv

PRV_FILES = \
  $(OUTPUT_DIR)/bignum/initialize.prv \
  $(OUTPUT_DIR)/bignum/copy.prv \
  $(OUTPUT_DIR)/bignum/word_of_boolean.prv \
  $(OUTPUT_DIR)/bignum/double_inplace.prv \
  $(OUTPUT_DIR)/bignum/sub_inplace.prv \
  $(OUTPUT_DIR)/bignum/less.prv \
  $(OUTPUT_DIR)/bignum/size_square_mod.prv \
  $(OUTPUT_DIR)/bignum/word_inverse.prv \
  $(OUTPUT_DIR)/bignum/single_add_mult_mult.prv \
  $(OUTPUT_DIR)/bignum/add_mult_mult.prv \
  $(OUTPUT_DIR)/bignum/mont_mult.prv \
  $(OUTPUT_DIR)/bignum/mont_exp.prv

ISABELLE_FILES = \
  theories/ROOT.ML \
  theories/Facts.thy \
  theories/Mod_Simp.thy \
  theories/Bignum.thy \
  theories/Initialize.thy \
  theories/Copy.thy \
  theories/Word_Of_Boolean.thy \
  theories/Double_Inplace.thy \
  theories/Sub_Inplace.thy \
  theories/Less.thy \
  theories/Size_Square_Mod.thy \
  theories/Word_Inverse.thy \
  theories/Single_Add_Mult_Mult.thy \
  theories/Add_Mult_Mult.thy \
  theories/Mont_Mult.thy \
  theories/Mont_Exp.thy

all: $(OUTPUT_DIR)/bignum.sum

$(SIV_FILES): $(OUTPUT_DIR)/target.cfg $(SPARK_FILES)
	spark $(SPARK_OPTS) -config=$< $(SPARK_FILES)
	sparksimp -p=4

$(PRV_FILES): $(SIV_FILES) $(ISABELLE_FILES)
	VCG_DIR=$(OUTPUT_DIR)/bignum isabelle usedir -s spark-bignum HOL-SPARK theories

$(OUTPUT_DIR)/bignum.sum: $(PRV_FILES)
	pogs -d=$(OUTPUT_DIR) -o=bignum.sum
	cat $@

$(OUTPUT_DIR)/target.cfg: $(OUTPUT_DIR)/confgen
	$(OUTPUT_DIR)/confgen > $@

$(OUTPUT_DIR)/confgen: $(SPARK_DIR)/lib/spark/confgen.adb
	gnatmake -D$(OUTPUT_DIR) -o $@ $^

$(OUTPUT_DIR)/test: test.adb types.adb $(SPARK_FILES)
	gnatmake -gnata -O2 -D $(OUTPUT_DIR) -o $(OUTPUT_DIR)/test test

clean:
	rm -rf $(OUTPUT_DIR)
