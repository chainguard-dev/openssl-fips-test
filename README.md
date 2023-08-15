# openssl-fips-test

A simple tool for validating whether or not OpenSSL is properly configured
to use its FIPS module.

## Caveats

This tool can only detect whether or not OpenSSL is properly configured:
applications and languages must be built to make use of libcrypto in order
for the OpenSSL FIPS configuration to actually be useful.

This tool does not validate whether any other element in an overall
delivered configuration is, or is not, FIPS 140-2/140-3 compliant.  It
only tests whether OpenSSL is properly configured and making use of the
FIPS module correctly.

## Usage

On Wolfi, simply install the `openssl-fips-test` package and run it.

On other systems, run `make` and `make install` as usual with whatever
escalation tool you normally use.  You must have the OpenSSL development
headers installed in order to build this tool, as well as a C compiler.
