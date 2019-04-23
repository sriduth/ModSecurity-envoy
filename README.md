# Envoy mod security build

Based on: [https://github.com/octarinesec/ModSecurity-envoy](https://github.com/octarinesec/ModSecurity-envoy).

Updated to use juspay's custom build of envoy with masking feature for file based access logs.

Envoy base source: v1.10.0 

# Building against Modsecurity (v3.0.1)

## Why v3.0.1?

**In the latest version there is an issue with some of the rule parsing logic. The c API allows users
to gracefully handle the error while the C++ api breaks.

Download the source of modsecurity checkout tag v3.0.1 and build with the following configuration options:

```sh
./configure --without-geoip --without-lua --without-curl --without-yajl
```

Some of the more exotic features of modsecurity (json parsing (libyajl), ip based threat intelligence (GeoIP), download of configuration (libcurl), lua scripting (lua5.3)).

If required, install the libs reconfigure modsecurity using the `configure` script and rebuild.

* When shared library dependencies like any of the previously mentioned are added or removed, appropriately change the linker options in the BUILD file inside http-filter-modsecurity.

Shared object and static lib should be created in `/usr/local/modsecurity/lib`.

Wherever you choose to put the output, symlink `libmodsecurity.so` (shared object) or
`libmodsecurity.a` (static library) into the http-filter-modsecurity folder.

## Building

To build the Envoy static binary:

1. `git submodule update --init`
2. `bazel build //http-filter-modsecurity:envoy`

# Configuration

Modsecurity  is configured as a http filter. Configuration takes 2 arguments - location of configuration and location of the logfile.

```yaml
- name: modsecurity
  config:
    rules: "file:///home/ubuntu/envoy-filter-example/modsec.conf"
    log_path: "/var/log/envoy/modsec.log"
```

## How it works

The [Envoy repository](https://github.com/envoyproxy/envoy/) is provided as a submodule.
The [`WORKSPACE`](WORKSPACE) file maps the `@envoy` repository to this local path.

The [`BUILD`](BUILD) file introduces a new Envoy static binary target, `envoy`,
that links together the new filter and `@envoy//source/exe:envoy_main_lib`. The
`echo2` filter registers itself during the static initialization phase of the
Envoy binary as a new filter.
