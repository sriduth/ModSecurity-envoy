package(default_visibility = ["//visibility:public"])

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
)

load("@envoy_api//bazel:api_build_system.bzl", "api_proto_library", "api_proto_library_internal")


envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        ":http_filter_config",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
    # pcre is required by libmodsecurity
    # librt is for some realtime apis
    linkopts = ["-lpcre", "-ldl", "-lrt", "-lxml2"]
    # Other linking options disabled: "-ldl","-lyajl", "-lpcre", "-lcurl", "-lxml2", "-lGeoIP"
)

api_proto_library(
    name = "http_filter_proto",
    srcs = ["http_filter.proto"],
    deps = [
    	 "@envoy_api//envoy/api/v2/core:base_export"
    ]
)

cc_import(
    name = "libmodsecurity",
    static_library = "libmodsecurity.a"
)

envoy_cc_library(
    name = "http_filter_lib",
    copts=["-Wno-unused-function", "-Wno-unused-parameter", "-Wno-reorder", "-Wno-unused-variable", "-Wno-pmf-conversions"],
    srcs = ["http_filter.cc"],
    hdrs = glob(["http_filter.h", "modsecurity/**"]),
    repository = "@envoy",
    deps = [
    	"@envoy//include/envoy/server:filter_config_interface",
    	"@envoy//include/envoy/access_log:access_log_interface",
        ":http_filter_proto_cc",
        "@envoy//source/exe:envoy_common_lib",
        ":libmodsecurity"
    ],
)

envoy_cc_library(
    name = "http_filter_config",
    srcs = ["http_filter_config.cc"],
    hdrs = ["http_filter.h"],
    copts=["-Wno-unused-function", "-Wno-unused-parameter", "-Wno-reorder", "-Wno-unused-variable"],
    repository = "@envoy",
    deps = [
        ":http_filter_lib",
        "@envoy//include/envoy/server:filter_config_interface",
    ],
)

envoy_cc_test(
    name = "http_filter_integration_test",
    srcs = ["http_filter_integration_test.cc"],
    repository = "@envoy",
    deps = [
        ":http_filter_config",
        "@envoy//test/integration:http_integration_lib",
    ],
)
