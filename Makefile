
all: build-lib

build-lib:
	@echo "Building lib..."
	@cd $(PWD)/lib && $(MAKE) build-cross

