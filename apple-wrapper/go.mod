module github.com/Jannerzhang/folo-xray-apple/apple-wrapper

go 1.26.4

require github.com/xtls/xray-core v0.0.0

require gvisor.dev/gvisor v0.0.0-20260701204157-69c2d17aea96

replace github.com/xtls/xray-core => ../upstream/xray-core
