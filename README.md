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

## About this tool

This code is a test suite designed to validate the configuration and operational status of the OpenSSL cryptographic library, particularly focusing on its compliance with the Federal Information Processing Standards (FIPS). It performs a series of checks to ensure that the OpenSSL library is correctly configured for FIPS mode, which is a requirement for many government and industry sectors that handle sensitive information. Here's a breakdown of its components and functionality:

### Includes and Global Definitions
- The code includes standard libraries for boolean types, input/output operations, and standard library functions.
- It also includes OpenSSL headers for cryptographic operations, specifically for working with encryption and provider contexts.
- A `struct test_` is defined to encapsulate test cases, including a test name, expected outcome, and a pointer to the test function.

### Test Functions
Each test function performs a specific check related to FIPS compliance or cryptographic provider availability:
- **test_fips_module_is_available**: Checks if the FIPS module is available in the OpenSSL context.
- **test_fips_module_is_enabled**: Verifies if FIPS mode is enabled by default in the OpenSSL context.
- **test_legacy_module_is_available**: Checks for the availability of legacy cryptographic algorithms, which are not allowed in FIPS mode.
- **test_unspec_md5_hashing_xfail**: Attempts to fetch the MD5 hashing algorithm without specifying a provider, expecting failure since MD5 is not FIPS compliant.
- **test_fips_md5_hashing_xfail**: Tries to fetch the MD5 hashing algorithm from the FIPS provider, expecting failure.
- **test_fips_sha2_512_hashing_xpass**: Ensures the SHA2-512 hashing algorithm is available from the FIPS provider, expecting success.
- **test_escape_fips**: Checks if requesting MD5 hashing from the default provider is rejected, as MD5 is not FIPS compliant.
- **test_crypto_is_fips_jailed**: Verifies that cryptographic operations are restricted to the FIPS module, ensuring compliance.
- **test_loading_providers_is_meaningless**: Tests if loading providers (e.g., "legacy" or "base") can circumvent FIPS restrictions, expecting that it cannot.

### Main Function
- The `main` function iterates over the array of test cases, executing each one.
- It prints the name of each test before running it and checks the test result against the expected outcome.
- If a test fails (i.e., the actual outcome does not match the expected outcome), the program prints a failure message and exits with `EXIT_FAILURE`.
- If all tests pass, it prints a success message indicating that OpenSSL is correctly configured for FIPS compliance and exits with `EXIT_SUCCESS`.

### Purpose and Importance
This test suite is crucial for verifying the FIPS compliance of the OpenSSL configuration in environments where strict cryptographic standards are required. FIPS compliance ensures that cryptographic software meets specific security standards, making this validation process essential for applications in government, finance, and other sectors handling sensitive or regulated data.
