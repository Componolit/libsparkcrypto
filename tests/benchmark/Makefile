OUTPUT_DIR ?= $(CURDIR)/out

ifneq ($(MAKECMDGOALS),clean)
ifeq ($(LSC_DIR),)
$(error "LSC_DIR not set")
endif
endif

DUMMY := $(shell mkdir -p $(OUTPUT_DIR)/proof)

all: $(OUTPUT_DIR)/benchmark

install: $(OUTPUT_DIR)/benchmark
	install -D -m 755 $< $(DESTDIR)/benchmark

$(OUTPUT_DIR)/benchmark:
	gnatmake -aP$(LSC_DIR) -o benchmark -P build.gpr

clean:
	rm -rf $(OUTPUT_DIR)
