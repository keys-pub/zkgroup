CARGO=$(shell which cargo)

all: build-lib

build:
	@echo "Building lib..."
	@$(CARGO) build --manifest-path lib/zkgroup/Cargo.toml --release

build-lib:
	@echo "Cross: Building lib..."
	@cd $(PWD)/lib && $(MAKE) build-cross

update-header:
	@cbindgen --lang c $(PWD)/lib/zkgroup/rust -o $(PWD)/lib/zkgroup.h 
