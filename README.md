# zkgroup

Go library for the Signal Private Group System.

See [github.com/signalapp/zkgroup](https://github.com/signalapp/zkgroup).

# build zkgroup

- checkout git submodules
-

# cross compile

`cargo install cross`
`cd lib/zkgroup/`

## linux aarch64


`cross build --target aarch64-unknown-linux-gnu`

`cp target/aarch64-unknown-linux-gnu/debug/libzkgroup.so ../libzkgroup_linux_aarch64.so`


## linux,armhf 

`cross build --target armv7-unknown-linux-gnueabihf`
`cp target/armv7-unknown-linux-gnueabihf/debug/libzkgroup.so ../libzkgroup_linux_armhf.so`

or install  arm-linux-gnueabihf-gcc and 

```
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=/usr/bin/arm-linux-gnueabihf-gcc

cargo build --target armv7-unknown-linux-gnueabihf --release --verbose
```