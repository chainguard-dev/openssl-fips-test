# openssl-fips-test

A simple tool for validating whether or not OpenSSL is properly configured
to use its FIPS module.

## Caveats

This tool can only detect whether or not OpenSSL is properly configured:
applications and languages must be built to make use of shared linked system
libcrypto in order for the OpenSSL FIPS configuration to be used.

This tool does not validate whether any other element in an overall delivered
configuration is, or is not, FIPS 140-3 compliant. It only tests whether
OpenSSL is properly configured and is making use of the FIPS module correctly.

## Usage

All Chainguard FIPS images ship `openssl-fips-test` preinstalled.

On other systems, run `make` and `make install`.  You must have the OpenSSL
development headers installed in order to build this tool, as well as a C
compiler.

## About this tool

Prior to loading any providers, a callback is added to capture output of KAT
(known answer tests) selftests.

It then loads default OpenSSL library context, and verifies that a FIPS
provider is loaded. It checks that by default the FIPS variants of algorithms
are used.

It also retrieves FIPS module information and returns CMVP & ESV certificates
where known, or a CMVP search URL where one should be able to find applicable
certificates. If certificates cannot be located with matching versions, one is
using non-validated module.

It also provides a summary of available algorithms, which is useful to compare
different CMVP modules and the algorithms they offer.

## Example output

Systems without a FIPS provider will typically report this:

```
$ openssl-fips-test
Checking OpenSSL lifecycle assurance.

	✗ Check FIPS cryptographic module is available... FAILED.
	✗ Check FIPS approved only mode (EVP_default_properties_is_fips_enabled)... FAILED.
	✗ Check non-approved algorithm blocked (HMAC-MD5)... FAILED.

Failed to retrieve cryptographic module version information
```

Example of systems using OpenSSL Project FIPS provider:

```
$ openssl-fips-test
Checking OpenSSL lifecycle assurance.

	✓ Self-test KAT_Integrity HMAC ... passed.
	✓ Self-test Module_Integrity HMAC ... passed.
	✓ Self-test KAT_Digest SHA2 ... passed.
	✓ Self-test KAT_Digest SHA3 ... passed.
	✓ Self-test KAT_Cipher AES_GCM ... passed.
	✓ Self-test KAT_Cipher AES_ECB_Decrypt ... passed.
	✓ Self-test KAT_Signature RSA ... passed.
	✓ Self-test KAT_Signature ECDSA ... passed.
	✓ Self-test KAT_Signature EDDSA ... passed.
	✓ Self-test KAT_Signature EDDSA ... passed.
	✓ Self-test KAT_KDF TLS13_KDF_EXTRACT ... passed.
	✓ Self-test KAT_KDF TLS13_KDF_EXPAND ... passed.
	✓ Self-test KAT_KDF TLS12_PRF ... passed.
	✓ Self-test KAT_KDF PBKDF2 ... passed.
	✓ Self-test KAT_KDF KBKDF ... passed.
	✓ Self-test KAT_KDF KBKDF_KMAC ... passed.
	✓ Self-test KAT_KDF HKDF ... passed.
	✓ Self-test KAT_KDF SSKDF ... passed.
	✓ Self-test KAT_KDF X963KDF ... passed.
	✓ Self-test KAT_KDF X942KDF ... passed.
	✓ Self-test DRBG HASH ... passed.
	✓ Self-test DRBG CTR ... passed.
	✓ Self-test DRBG HMAC ... passed.
	✓ Self-test KAT_KA DH ... passed.
	✓ Self-test KAT_KA ECDH ... passed.

	✓ 25 out of 25 self-tests passed.
	✓ Check FIPS cryptographic module is available... passed.
	✓ Check FIPS approved only mode (EVP_default_properties_is_fips_enabled)... passed.
	✓ Check non-approved algorithm blocked (HMAC-MD5)... passed.

Digests available for non-security use as per FIPS 140-3 I.G. 2.4.A (fips=no):
	✓ MD5
	✓ SHA1

Available approved algorithms for security purposes (fips=yes):
	✗ MD5
	✓ SHA-1
	✓ SHA-2
	✓ SHA-3
	✗ DSA
	✓ RSA
	✓ ECDSA
	✓ Ed25519
	✗ DetECDSA
	✗ ML-DSA
	✗ SLH-DSA
	✗ ML-KEM
	✗ X25519MLKEM768
	✗ SecP256r1MLKEM768

Public OpenSSL API (libssl.so & libcrypto.so):
	name:     	OpenSSL 3.6.0 1 Oct 2025
	version:  	3.6.0

FIPS cryptographic module provider details (fips.so):
	name:     	Chainguard FIPS Provider for OpenSSL
	version:  	3.4.0
	build:    	3.4.0-r4

Locate applicable certificate(s) at: CMVP #5132 (with entropy #E191)

Lifecycle assurance satisfied.
```
