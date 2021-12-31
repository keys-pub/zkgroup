
all: build-lib

build-lib:
	@echo "Building lib..."
	@cd $(PWD)/lib && $(MAKE) build-cross

update-header:
	@cbindgen --lang c $(PWD)/lib/zkgroup/rust -o $(PWD)/lib/zkgroup.h 