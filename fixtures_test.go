package zkgroup_test

import "encoding/hex"

var test16, _ = hex.DecodeString("000102030405060708090a0b0c0d0e0f")

var test32, _ = hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
var test32_1, _ = hex.DecodeString("6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283")
var test32_2, _ = hex.DecodeString("c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7")

var test32_5, _ = hex.DecodeString("030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122")
