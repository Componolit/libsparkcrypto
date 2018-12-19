OUTPUT_DIR = $(CURDIR)/out
DUMMY     := $(shell mkdir -p $(OUTPUT_DIR)/empty $(OUTPUT_DIR)/build $(OUTPUT_DIR)/proof $(OUTPUT_DIR)/tree $(OUTPUT_DIR)/tests)
UNAME_M   := $(shell uname -m)

ARCH        ?= $(UNAME_M)
RUNTIME     ?= native
DESTDIR     ?= /usr/local
ATP         ?= sparksimp
CALLGRAPH   ?= none

VERSION     ?= 0.1.1
TAG         ?= v$(VERSION)

SHARED_DIRS = src/shared/$(ENDIANESS) src/shared/generic
ARCH_FILES  = $(wildcard src/ada/$(ARCH)/*.ad?)
ADT_FILES   = $(addprefix $(OUTPUT_DIR)/tree/,$(notdir $(patsubst %.ads,%.adt,$(wildcard src/shared/generic/*.ads))))

ALL_GOALS      = install_local
INSTALL_DEPS   = install_files \

export SPARKUNIT_DIR ?= $(CURDIR)/contrib/sparkunit/out/sparkunit

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

# Feature: NO_SPARK
ifeq ($(NO_SPARK),)
   ALL_GOALS += spark
   REPORT_DEPS += spark
   INSTALL_DEPS += install_spark
endif

# Feature: NO_TESTS
ifeq ($(NO_TESTS),)
ALL_GOALS += tests
endif

# Feature: SHARED
ifneq ($(SHARED),)
   LIBTYPE = dynamic
   LIBPREFIX = .so
else
   LIBTYPE = static
   LIBPREFIX = .a
endif

###############################################################################

#
# set gprbuild options
#

ifneq ($(ARCH),)
GPRBUILD_OPTS += -Xarch=$(ARCH)
endif

ifneq ($(ENDIANESS),)
GPRBUILD_OPTS += -Xendianess=$(ENDIANESS)
endif

ifneq ($(MODE),)
GPRBUILD_OPTS += -Xmode=$(MODE)
endif

ifneq ($(OPT),)
GPRBUILD_OPTS += -Xopt=$(OPT)
endif

GPRBUILD_OPTS += -Xlibtype=$(LIBTYPE)

ifneq ($(CALLGRAPH),)
GPRBUILD_OPTS += -Xcallgraph=$(CALLGRAPH)
endif

###############################################################################

all: $(ALL_GOALS)

build:    $(addprefix $(OUTPUT_DIR)/build/adalib/,$(addsuffix /libsparkcrypto$(LIBPREFIX),$(RUNTIME)))
spark: $(OUTPUT_DIR)/proof/gnatprove.log

archive: $(OUTPUT_DIR)/doc/libsparkcrypto-$(VERSION).tgz

$(OUTPUT_DIR)/doc/libsparkcrypto-$(VERSION).tgz:
	git archive --format tar --prefix libsparkcrypto-$(VERSION)/ $(TAG) | gzip -c > $@

tests: $(OUTPUT_DIR)/tests/tests
	$< | tee $(OUTPUT_DIR)/tests/tests.sum

$(OUTPUT_DIR)/tests/tests: install_local contrib/sparkunit/out/sparkunit/SPARKUnit.gpr
	make -C tests \
      LSC_DIR=$(OUTPUT_DIR)/libsparkcrypto \
      OUTPUT_DIR=$(OUTPUT_DIR)/tests

contrib/sparkunit/out/sparkunit/SPARKUnit.gpr:
	git submodule update --init contrib/sparkunit
	make -C contrib/sparkunit

$(OUTPUT_DIR)/build/adalib/%/libsparkcrypto$(LIBPREFIX):
	gprbuild $(GPRBUILD_OPTS) -XRTS=$* -p -P build/build_libsparkcrypto

$(OUTPUT_DIR)/proof/gnatprove.log:
	@echo -n "Started at " > $(OUTPUT_DIR)/proof/gnatprove.log
	@date >> $(OUTPUT_DIR)/proof/gnatprove.log
	gnatprove -P build/build_libsparkcrypto >> $(OUTPUT_DIR)/proof/gnatprove.log
	@echo -n "Finished at " >> $(OUTPUT_DIR)/proof/gnatprove.log
	@date >> $(OUTPUT_DIR)/proof/gnatprove.log

install: $(INSTALL_DEPS)

install_files: build
	$(foreach RTS,$(RUNTIME),install -d -m 755 $(DESTDIR)/adalib/$(RTS);)
	install -d -m 755 $(DESTDIR)/adainclude $(DESTDIR)/sharedinclude
	$(foreach RTS,$(RUNTIME),install -p -m 755 $(OUTPUT_DIR)/build/adalib/$(RTS)/libsparkcrypto$(LIBPREFIX) $(DESTDIR)/adalib/$(RTS)/libsparkcrypto$(LIBPREFIX);)
	install -p -m 644 build/libsparkcrypto.gpr $(DESTDIR)/libsparkcrypto.gpr
	install -p -m 644 src/shared/generic/*.ads $(DESTDIR)/sharedinclude/
	install -p -m 644 src/ada/generic/*.ad? $(DESTDIR)/adainclude/
	$(foreach IO,$(subst native,textio,$(subst zfp,nullio,$(RUNTIME))),install -d -m 755 $(DESTDIR)/adainclude/$(IO); install -p -m 644 src/ada/$(IO)/*.ad? $(DESTDIR)/adainclude/$(IO);)
	install -p -m 644 src/shared/$(ENDIANESS)/*.adb $(DESTDIR)/adainclude/
	install -p -m 644 src/shared/generic/*.adb $(DESTDIR)/adainclude/
ifneq ($(strip $(ARCH_FILES)),)
	install -p -m 644 $(ARCH_FILES) $(DESTDIR)/adainclude/
endif
	$(foreach RTS,$(RUNTIME),install -p -m 444 $(OUTPUT_DIR)/build/adalib/$(RTS)/*.ali $(DESTDIR)/adalib/$(RTS);)

install_spark: install_files $(OUTPUT_DIR)/proof/gnatprove.log
	install -D -p -m 444 $(OUTPUT_DIR)/proof/gnatprove.log $(DESTDIR)/gnatprove.log

install_local: DESTDIR = $(OUTPUT_DIR)/libsparkcrypto
install_local: install

#
# how to create a tree file
#
$(OUTPUT_DIR)/tree/%.adt: $(CURDIR)/src/shared/generic/%.ads
	(cd $(OUTPUT_DIR)/tree && gcc -c -gnatc -gnatt $^)

clean:
	@rm -rf $(OUTPUT_DIR)

.PHONY: all install install_local install_files install_spark
.PHONY: build tests proof archive spark
