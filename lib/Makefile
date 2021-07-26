
all: build

build: cargo build --release

build-cross: 
	@echo "Building..."
	@cd zkgroup && cross build --target aarch64-unknown-linux-gnu --release --verbose --jobs=4
	@mv -f zkgroup/target/aarch64-unknown-linux-gnu/release/libzkgroup.so ./libzkgroup_linux_aarch64.so || true
	@cd zkgroup && cross build --target armv7-unknown-linux-gnueabihf --release --verbose --jobs=4
	@mv -f zkgroup/target/armv7-unknown-linux-gnueabihf/release/libzkgroup.so ./libzkgroup_linux_armv7.so || true
	@cd zkgroup && cross build --target x86_64-unknown-linux-gnu --release --verbose --jobs=4
	@mv -f zkgroup/target/x86_64-unknown-linux-gnu/release/libzkgroup.so ./libzkgroup_linux_x86_64.so || true