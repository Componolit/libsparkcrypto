OUTPUT_DIR = $(CURDIR)/out
DUMMY     := $(shell mkdir -p $(OUTPUT_DIR)/empty $(OUTPUT_DIR)/build $(OUTPUT_DIR)/proof $(OUTPUT_DIR)/doc $(OUTPUT_DIR)/tree)
UNAME_M   := $(shell uname -m)

IO				?= textio
ARCH     	?= $(UNAME_M)
MODE     	?= release
RUNTIME  	?= native
TESTS    	?= test_aes test_hmac test_ripemd160 test_sha2 test_shadow benchmark
DESTDIR  	?= /usr/local
TARGET_CFG	?= $(OUTPUT_DIR)/target.cfg
OPT       	?= 3

SPARK_OPTS  = \
   -brief \
   -vcg \
   -config=$(TARGET_CFG) \
   -warn=warnings.conf \
   -output_dir=$(OUTPUT_DIR)/proof

SHARED_DIRS = src/shared/$(ENDIANESS) src/shared/generic
ARCH_FILES  = $(wildcard src/ada/$(ARCH)/*.ad?)
TREE_FILES  = $(addprefix $(OUTPUT_DIR)/tree/,$(notdir $(patsubst %.ads,%.adt,$(wildcard src/shared/generic/*.ads))))

ALL_GOALS      = install_local
INSTALL_DEPS   = install_files

# SPARK_DIR must be set
ifeq ($(SPARK_DIR),)
$(error SPARK_DIR is not set - set it to the base directory of your SPARK installation)
endif

# Feature: SPARK8
ifeq ($(SPARK8),)
SPARK_OPTS += -dpc -nosli
endif

# Feature: ARCH
ifeq      ($(ARCH),x86_64)
   ENDIANESS = little_endian
else ifeq ($(ARCH),i686)
   ENDIANESS = little_endian
else
   $(error Unsupported architecture: $(ARCH))
endif

# Feature: RUNTIME
ifeq      ($(RUNTIME),native)
   IO		= textio
else ifeq ($(RUNTIME),zfp)
	# Tests and Text_IO are unsupported for zfp
   TESTS =
   IO    = nullio
else
   $(error Unsupported runtime: $(RUNTIME))
endif

# Feature: NO_PROOF
ifeq ($(NO_PROOF),)
ALL_GOALS += proof
INSTALL_DEPS += install_proof
endif

# Feature: NO_TESTS
ifeq ($(NO_TESTS),)
ALL_GOALS += tests
endif

# Feature: NO_APIDOC
ifeq ($(NO_APIDOC),)
ALL_GOALS += apidoc
endif

###############################################################################

all: $(ALL_GOALS)
build: $(OUTPUT_DIR)/build/libsparkcrypto.a
proof: $(OUTPUT_DIR)/proof/libsparkcrypto.sum

apidoc: $(OUTPUT_DIR)/tree/tree.lst
	adabrowse \
      --all \
      -T $(OUTPUT_DIR)/tree \
      -f @$< \
      -w1 \
      -c build/adabrowse.conf \
      -o $(OUTPUT_DIR)/doc/
	install -m 644 build/style.css $(OUTPUT_DIR)/doc/style.css
	install -m 644 doc/lsc_logo.png $(OUTPUT_DIR)/doc/lsc_logo.png

$(OUTPUT_DIR)/tree/tree.lst: $(TREE_FILES)
	@echo $^ | xargs -n1 > $@

tests: $(addprefix $(OUTPUT_DIR)/tests/, $(TESTS))
	(for t in $^; do $$t; done)

$(OUTPUT_DIR)/build/libsparkcrypto.a:
	gnatmake \
		-Xarch=$(ARCH) \
		-Xendianess=$(ENDIANESS) \
		-Xmode=$(MODE) \
		-Xio=$(IO) \
		-Xruntime=$(RUNTIME) \
		-Xopt=$(OPT) \
		-p -P build/build_libsparkcrypto

$(OUTPUT_DIR)/proof/libsparkcrypto.sum: $(OUTPUT_DIR)/proof/libsparkcrypto.idx $(OUTPUT_DIR)/proof/libsparkcrypto.smf $(TARGET_CFG)
	spark -index=$< $(SPARK_OPTS) @$(OUTPUT_DIR)/proof/libsparkcrypto.smf
	(cd $(OUTPUT_DIR)/proof && sparksimp -t -p=5)
	pogs -d=$(OUTPUT_DIR)/proof -o=$@
	@tail -n14 $@ | head -n13
	@echo

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
ifeq ($(MODE), debug)
	install -p -m 644 src/debug/*.ad? $(DESTDIR)/adainclude/
endif

install_proof: install_files proof
	install -D -p -m 444 $(OUTPUT_DIR)/proof/libsparkcrypto.sum $(DESTDIR)/libsparkcrypto.sum
	(cd $(OUTPUT_DIR)/empty && sparkmake -include=*\.ads -dir=$(DESTDIR)/sharedinclude -nometa -index=$(DESTDIR)/libsparkcrypto.idx)

install_local: DESTDIR = $(OUTPUT_DIR)/libsparkcrypto
install_local: install

#
# how to create a tree file
#
$(OUTPUT_DIR)/tree/%.adt: $(CURDIR)/src/shared/generic/%.ads
	(cd $(OUTPUT_DIR)/tree && gcc -c -gnatc -gnatt $^)

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

.PHONY: all install install_local build tests proof apidoc
