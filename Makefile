OUTPUT_DIR = $(CURDIR)/out
DUMMY     := $(shell mkdir -p $(OUTPUT_DIR)/empty $(OUTPUT_DIR)/build $(OUTPUT_DIR)/proof $(OUTPUT_DIR)/doc $(OUTPUT_DIR)/tree $(OUTPUT_DIR)/tests)
UNAME_M   := $(shell uname -m)

ARCH        ?= $(UNAME_M)
RUNTIME     ?= native
DESTDIR     ?= /usr/local
TARGET_CFG  ?= $(OUTPUT_DIR)/target.cfg

VERSION     ?= 0.1.1
TAG         ?= v$(VERSION)

SPARK_OPTS  = \
   -brief=fullpath \
   -debug=i \
   -vcg \
   -config=$(TARGET_CFG) \
   -warn=build/warnings.conf \
   -output_dir=$(OUTPUT_DIR)/proof \
   -casing=si \
   -noswitch \
   -nosli

RST2HTML_OPTS = \
   --generator \
   --date \
   --time \
   --stylesheet=doc/libsparkcrypto.css

SHARED_DIRS = src/shared/$(ENDIANESS) src/shared/generic
ARCH_FILES  = $(wildcard src/ada/$(ARCH)/*.ad?)
ADT_FILES   = $(addprefix $(OUTPUT_DIR)/tree/,$(notdir $(patsubst %.ads,%.adt,$(wildcard src/shared/generic/*.ads))))

ALL_GOALS      = install_local
INSTALL_DEPS   = install_files

# SPARK_DIR must be set
ifeq ($(SPARK_DIR),)
$(error SPARK_DIR is not set - set it to the base directory of your SPARK installation)
endif

# Feature: ARCH
ifeq      ($(ARCH),x86_64)
   ENDIANESS = little_endian
else ifeq ($(ARCH),i686)
   ENDIANESS = little_endian
# just used to test whether the generic big endian code compiles!
else ifeq ($(ARCH),generic_be)
   ENDIANESS = big_endian
else
   $(error Unsupported architecture: $(ARCH))
endif

# Feature: RUNTIME
ifeq      ($(RUNTIME),native)
   IO		= textio
else ifeq ($(RUNTIME),zfp)
   IO    = nullio
else
   $(error Unsupported runtime: $(RUNTIME))
endif

# Feature: NO_SPARK
ifeq ($(NO_SPARK),)
   ALL_GOALS += spark
   REPORT_DEPS += spark
   INSTALL_DEPS += install_spark

   # Feature: NO_ISABELLE
   ifeq ($(NO_ISABELLE),)
      ALL_GOALS += isabelle
      REPORT_DEPS += isabelle
      INSTALL_DEPS += install_isabelle
      $(eval $(shell isabelle getenv ISABELLE_OUTPUT))
   endif
endif

# Feature: NO_TESTS
ifeq ($(NO_TESTS),)
ALL_GOALS += tests
ifneq ($(MAKECMDGOALS),clean)
   ifeq ($(SPARKUNIT_DIR),)
   $(error SPARKUNIT_DIR is not set - set it to the base directory of your SPARKUnit installation)
   endif
endif
endif

# Feature: NO_APIDOC
ifeq ($(NO_APIDOC),)
ALL_GOALS += apidoc
endif

###############################################################################

#
# set gnatmake options
#

ifneq ($(ARCH),)
GNATMAKE_OPTS += -Xarch=$(ARCH)
endif

ifneq ($(ENDIANESS),)
GNATMAKE_OPTS += -Xendianess=$(ENDIANESS)
endif

ifneq ($(MODE),)
GNATMAKE_OPTS += -Xmode=$(MODE)
endif

ifneq ($(IO),)
GNATMAKE_OPTS += -Xio=$(IO)
endif

ifneq ($(RUNTIME),)
GNATMAKE_OPTS += -Xruntime=$(RUNTIME)
endif

ifneq ($(OPT),)
GNATMAKE_OPTS += -Xopt=$(OPT)
endif

###############################################################################

all: $(ALL_GOALS)

build:    $(OUTPUT_DIR)/build/libsparkcrypto.a
spark:    $(OUTPUT_DIR)/proof/libsparkcrypto.rep
isabelle: $(ISABELLE_OUTPUT)/log/HOL-SPARK-libsparkcrypto.gz

apidoc: $(ADT_FILES)
	echo $^ | xargs -n1 > $(OUTPUT_DIR)/tree.lst
	adabrowse -T $(OUTPUT_DIR)/tree -f @$(OUTPUT_DIR)/tree.lst -w1 -c doc/adabrowse.conf -o $(OUTPUT_DIR)/doc/
	install -m 644 doc/libsparkcrypto.css $(OUTPUT_DIR)/doc/libsparkcrypto.css
	install -m 644 doc/apidoc.css $(OUTPUT_DIR)/doc/apidoc.css
	install -m 644 doc/lsc_logo.png $(OUTPUT_DIR)/doc/lsc_logo.png

archive: $(OUTPUT_DIR)/doc/libsparkcrypto-$(VERSION).tgz

$(OUTPUT_DIR)/doc/libsparkcrypto-$(VERSION).tgz:
	git archive --format tar --prefix libsparkcrypto-$(VERSION)/ $(TAG) | gzip -c > $@

doc: apidoc
	rst2html $(RST2HTML_OPTS) README $(OUTPUT_DIR)/doc/index.html
	rst2html $(RST2HTML_OPTS) CHANGES $(OUTPUT_DIR)/doc/CHANGES.html
	rst2html $(RST2HTML_OPTS) TODO $(OUTPUT_DIR)/doc/TODO.html

tests: $(OUTPUT_DIR)/tests/tests
	$<

$(OUTPUT_DIR)/tests/tests: install_local
	make -C tests \
      LSC_DIR=$(OUTPUT_DIR)/libsparkcrypto \
      OUTPUT_DIR=$(OUTPUT_DIR)/tests

$(OUTPUT_DIR)/build/libsparkcrypto.a:
	gnatmake $(GNATMAKE_OPTS) -p -P build/build_libsparkcrypto

$(OUTPUT_DIR)/proof/libsparkcrypto.rep: $(OUTPUT_DIR)/proof/libsparkcrypto.idx $(OUTPUT_DIR)/proof/libsparkcrypto.smf $(TARGET_CFG)
	spark -index=$< $(SPARK_OPTS) -report_file=$@.tmp @$(OUTPUT_DIR)/proof/libsparkcrypto.smf
	(cd $(OUTPUT_DIR)/proof && sparksimp -t -p=5 -sargs -norenum)
	mv $@.tmp $@

$(OUTPUT_DIR)/proof/libsparkcrypto.sum: $(REPORT_DEPS)
	pogs -d=$(OUTPUT_DIR)/proof -o=$@
	@tail -n14 $@ | head -n13
	@echo

$(ISABELLE_OUTPUT)/log/HOL-SPARK-libsparkcrypto.gz: $(OUTPUT_DIR)/proof/libsparkcrypto.rep
	(cd src && VCG_DIR=$(OUTPUT_DIR)/proof isabelle usedir -d false -M 5 -s libsparkcrypto HOL-SPARK theories)

$(OUTPUT_DIR)/proof/libsparkcrypto.smf:
	find $(CURDIR)/src/shared/generic -name '*.adb' -print > $@

$(OUTPUT_DIR)/proof/libsparkcrypto.idx:
	(cd $(OUTPUT_DIR)/empty && sparkmake $(addprefix -dir=$(CURDIR)/, $(SHARED_DIRS)) -dir=$(CURDIR)/src/spark -nometa -index=$@)

install: $(INSTALL_DEPS)

install_files: build
	install -d -m 755 $(DESTDIR)/adalib $(DESTDIR)/adainclude $(DESTDIR)/sharedinclude
	install -p -m 755 $(OUTPUT_DIR)/build/adalib/libsparkcrypto.a $(DESTDIR)/adalib/libsparkcrypto.a
	install -p -m 644 build/libsparkcrypto.gpr $(DESTDIR)/libsparkcrypto.gpr
	install -p -m 644 src/shared/$(ENDIANESS)/*.ad? $(DESTDIR)/sharedinclude/
	install -p -m 644 src/shared/generic/*.ad? $(DESTDIR)/sharedinclude/
	install -p -m 644 src/ada/generic/*.ad? $(DESTDIR)/adainclude/
	install -p -m 644 src/ada/$(IO)/*.ad? $(DESTDIR)/adainclude/
ifneq ($(strip $(ARCH_FILES)),)
	install -p -m 644 $(ARCH_FILES) $(DESTDIR)/adainclude/
endif
	install -p -m 444 $(OUTPUT_DIR)/build/adalib/*.ali $(DESTDIR)/adalib/

install_spark: install_files $(OUTPUT_DIR)/proof/libsparkcrypto.sum
	install -D -p -m 444 $(OUTPUT_DIR)/proof/libsparkcrypto.sum $(DESTDIR)/libsparkcrypto.sum
	(cd $(OUTPUT_DIR)/empty && sparkmake -include=*\.ads -dir=$(DESTDIR)/sharedinclude -nometa -index=$(DESTDIR)/libsparkcrypto.idx)

install_isabelle: $(OUTPUT_DIR)/proof/HOL-SPARK-libsparkcrypto.gz

$(OUTPUT_DIR)/proof/HOL-SPARK-libsparkcrypto.gz: $(ISABELLE_OUTPUT)/log/HOL-SPARK-libsparkcrypto.gz
	install -p -m 644 -D $< $@

install_local: DESTDIR = $(OUTPUT_DIR)/libsparkcrypto
install_local: install

#
# how to create a tree file
#
$(OUTPUT_DIR)/tree/%.adt: $(CURDIR)/src/shared/generic/%.ads
	(cd $(OUTPUT_DIR)/tree && gcc -c -gnatc -gnatt $^)

#
# how to build the target configuration generator
#
$(OUTPUT_DIR)/confgen: $(SPARK_DIR)/lib/spark/confgen.adb
	gnatmake -D $(OUTPUT_DIR) -o $@ $^

#
# how to generate the target configuration file
# (We have to change *_ORDER_FIRST, as casing checks will fail otherwise)
#
$(OUTPUT_DIR)/target.cfg: $(OUTPUT_DIR)/confgen
	$< | sed -e 's/LOW_ORDER_FIRST/Low_Order_First/g' -e 's/HIGH_ORDER_FIRST/High_Order_First/g' > $@

clean:
	@rm -rf $(OUTPUT_DIR)

.PHONY: all install install_local install_files install_spark install_isabelle
.PHONY: build tests proof apidoc archive spark isabelle
