OUTPUT_DIR = $(CURDIR)/out
DUMMY     := $(shell mkdir -p $(OUTPUT_DIR)/empty $(OUTPUT_DIR)/build $(OUTPUT_DIR)/proof)
ARCH      := $(shell uname -m)
MODE      ?= release
TESTS      = test_aes test_hmac test_ripemd160 test_sha2 test_shadow benchmark

SPARK_OPTS  = \
   -brief \
   -vcg \
   -config=$(OUTPUT_DIR)/target.cfg \
   -warn=warnings.conf \
   -output_dir=$(OUTPUT_DIR)/proof

SHARED_DIRS = src/shared/$(ENDIANESS) src/shared/generic
ADA_DIRS    = src/ada/$(ARCH) src/ada/generic
SPARK_DIRS  = src/spark
ARCH_FILES  = $(wildcard src/ada/$(ARCH)/*.ad?)

ALL_GOALS      = install_local
INSTALL_DEPS   = build

ifeq ($(SPARK8),)
SPARK_OPTS += -dpc -nosli
endif

ifeq ($(ARCH),x86_64)
ENDIANESS = little_endian
else
   ifeq ($(ARCH),i686)
      ENDIANESS = little_endian
   else
   $(error Unsupported architecture: $(ARCH))
   endif
endif

ifeq ($(NO_PROOF),)
ALL_GOALS += proof
INSTALL_DEPS += install_proof
endif

ifeq ($(NO_TESTS),)
ALL_GOALS += tests
endif

all: $(ALL_GOALS)
build: $(OUTPUT_DIR)/build/libsparkcrypto.a
proof: $(OUTPUT_DIR)/proof/libsparkcrypto.sum

tests: $(addprefix $(OUTPUT_DIR)/tests/, $(TESTS))
	(for t in $^; do $$t; done)

$(OUTPUT_DIR)/build/libsparkcrypto.a:
	gnatmake -Xarch=$(ARCH) -Xendianess=$(ENDIANESS) -Xmode=$(MODE) -p -P build/build_libsparkcrypto

$(OUTPUT_DIR)/proof/libsparkcrypto.sum: $(OUTPUT_DIR)/proof/libsparkcrypto.idx $(OUTPUT_DIR)/target.cfg
	spark -index=$< $(SPARK_OPTS) $(CURDIR)/src/shared/generic/*.adb
	(cd $(OUTPUT_DIR)/proof && sparksimp -t -p=5)
	pogs -s -d=$(OUTPUT_DIR)/proof -o=$@
	@tail -n14 $@ | head -n13
	@echo

$(OUTPUT_DIR)/proof/libsparkcrypto.idx:
	(cd $(OUTPUT_DIR)/empty && sparkmake $(addprefix -dir=$(CURDIR)/, $(SHARED_DIRS)) -dir=$(CURDIR)/src/spark -nometa -index=$@)

install: $(INSTALL_DEPS)
	install -d -m 755 $(DESTDIR)/adalib $(DESTDIR)/adainclude $(DESTDIR)/sparkinclude $(DESTDIR)/sharedinclude
	install -p -m 755 $(OUTPUT_DIR)/build/adalib/libsparkcrypto.a $(DESTDIR)/adalib/libsparkcrypto.a
	install -p -m 644 build/libsparkcrypto.gpr $(DESTDIR)/libsparkcrypto.gpr
	install -p -m 644 src/shared/$(ENDIANESS)/*.ad? $(DESTDIR)/sharedinclude/
	install -p -m 644 src/shared/generic/*.ad? $(DESTDIR)/sharedinclude/
	install -p -m 644 src/ada/generic/*.ad? $(DESTDIR)/adainclude/
ifneq ($(strip $(ARCH_FILES)),)
	install -p -m 644 $(ARCH_FILES) $(DESTDIR)/adainclude/
endif
	install -p -m 644 src/spark/*.ad? $(DESTDIR)/sparkinclude/
	install -p -m 444 $(OUTPUT_DIR)/build/adalib/*.ali $(DESTDIR)/adalib/

install_proof: proof
	install -d -m 755 $(DESTDIR)/sparkinclude $(DESTDIR)/sharedinclude
	install -D -p -m 444 $(OUTPUT_DIR)/proof/libsparkcrypto.sum $(DESTDIR)/libsparkcrypto.sum
	(cd $(OUTPUT_DIR)/empty && sparkmake -include=*\.ads -dir=$(DESTDIR)/sharedinclude -dir=$(DESTDIR)/sparkinclude -nometa -index=$(DESTDIR)/libsparkcrypto.idx)

install_local: DESTDIR = $(OUTPUT_DIR)/libsparkcrypto
install_local: install

#
# how to build a test
#
$(OUTPUT_DIR)/tests/%: install_local
	$(MAKE) -C tests/$(@F) DESTDIR=$(OUTPUT_DIR)/tests LSC_DIR=$(OUTPUT_DIR)/libsparkcrypto install

#
# how to clean a test
#
clean_%:
	@make -s -C tests/$(*F) clean

#
# how to build the target configuration generator
#
$(OUTPUT_DIR)/confgen: $(SPARK_DIR)/lib/spark/confgen.adb
	gnatmake -D $(OUTPUT_DIR) -o $@ $^

#
# how to generate the target configuration file
#
$(OUTPUT_DIR)/target.cfg: $(OUTPUT_DIR)/confgen
	$< > $@

clean: $(addprefix clean_, $(TESTS))
	@rm -rf $(OUTPUT_DIR)

.PHONY: all install install_local build tests proof
