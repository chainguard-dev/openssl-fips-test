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

Prior to loading any providers, a callback is added to capture output of KAT
(known answer tests) selftests.

It then loads default OpenSSL library contects, and verifies that a FIPS
provider is loaded. And checks that by default FIPS variants of algorithms are
used.

It also retrieves FIPS module information and returns CMVP search URL where one
should be able to find applicable certificates.

## Example output

Uncertified systems will typically report this:

```
Checking OpenSSL lifecycle assurance.
*** Running check: FIPS module is available...
    Running check: FIPS module is available... failed.
*** Running check: EVP_default_properties_is_fips_enabled returns true... failed.
*** Running check: verify unapproved cryptographic routines are not available by default (e.g. MD5)... failed.
```

Example of systems using OpenSSL Project CMVP certificate:

```
# ./openssl-fips-test
Checking OpenSSL lifecycle assurance.
*** Running check: FIPS module is available...
    HMAC : (Module_Integrity) : Pass
    SHA1 : (KAT_Digest) : Pass
    SHA2 : (KAT_Digest) : Pass
    SHA3 : (KAT_Digest) : Pass
    TDES : (KAT_Cipher) : Pass
    AES_GCM : (KAT_Cipher) : Pass
    AES_ECB_Decrypt : (KAT_Cipher) : Pass
    RSA : (KAT_Signature) :     RNG : (Continuous_RNG_Test) : Pass
Pass
    ECDSA : (PCT_Signature) : Pass
    DSA : (PCT_Signature) : Pass
    TLS13_KDF_EXTRACT : (KAT_KDF) : Pass
    TLS13_KDF_EXPAND : (KAT_KDF) : Pass
    TLS12_PRF : (KAT_KDF) : Pass
    PBKDF2 : (KAT_KDF) : Pass
    SSHKDF : (KAT_KDF) : Pass
    KBKDF : (KAT_KDF) : Pass
    HKDF : (KAT_KDF) : Pass
    SSKDF : (KAT_KDF) : Pass
    X963KDF : (KAT_KDF) : Pass
    X942KDF : (KAT_KDF) : Pass
    HASH : (DRBG) : Pass
    CTR : (DRBG) : Pass
    HMAC : (DRBG) : Pass
    DH : (KAT_KA) : Pass
    ECDH : (KAT_KA) : Pass
    RSA_Encrypt : (KAT_AsymmetricCipher) : Pass
    RSA_Decrypt : (KAT_AsymmetricCipher) : Pass
    RSA_Decrypt : (KAT_AsymmetricCipher) : Pass
    Running check: FIPS module is available... passed.
*** Running check: EVP_default_properties_is_fips_enabled returns true... passed.
*** Running check: verify unapproved cryptographic routines are not available by default (e.g. MD5)... passed.

Lifecycle assurance satisfied.
Module details:
	name:     	OpenSSL FIPS Provider
	version:  	3.0.9
	build:    	3.0.9

Locate applicable CMVP certificates at
    https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&ModuleName=OpenSSL&CertificateStatus=Active&ValidationYear=0&SoftwareVersions=3.0.9
```

Example output on Ubuntu Pro FIPS instance:

```
./openssl-fips-test
Checking OpenSSL lifecycle assurance.
*** Running check: FIPS module is available...
    SHA1 : (KAT_Digest) : Pass
    SHA2 : (KAT_Digest) : Pass
    SHA3 : (KAT_Digest) : Pass
    AES_GCM : (KAT_Cipher) : Pass
    AES_ECB_Decrypt : (KAT_Cipher) : Pass
    RSA : (KAT_Signature) :     RNG : (Continuous_RNG_Test) : Pass
    RNG : (Continuous_RNG_Test) : Pass
    RNG : (Continuous_RNG_Test) : Pass
Pass
    ECDSA : (KAT_Signature) : Pass
    ECDSA : (KAT_Signature) : Pass
    TLS13_KDF_EXTRACT : (KAT_KDF) : Pass
    TLS13_KDF_EXPAND : (KAT_KDF) : Pass
    TLS12_PRF : (KAT_KDF) : Pass
    PBKDF2 : (KAT_KDF) : Pass
    SSHKDF : (KAT_KDF) : Pass
    KBKDF : (KAT_KDF) : Pass
    HKDF : (KAT_KDF) : Pass
    SSKDF : (KAT_KDF) : Pass
    X963KDF : (KAT_KDF) : Pass
    X942KDF : (KAT_KDF) : Pass
    HASH : (DRBG) : Pass
    CTR : (DRBG) : Pass
    HMAC : (DRBG) : Pass
    DH : (KAT_KA) : Pass
    ECDH : (KAT_KA) : Pass
    HMAC : (Module_Integrity) : Pass
    Running check: FIPS module is available... passed.
*** Running check: EVP_default_properties_is_fips_enabled returns true... passed.
*** Running check: verify unapproved cryptographic routines are not available by default (e.g. MD5)... passed.

Lifecycle assurance satisfied.
Module details:
	name:     	Ubuntu 22.04 OpenSSL Cryptographic Module
	version:  	3.0.5-0ubuntu0.1+Fips2.1
	build:    	3.0.5-0ubuntu0.1+Fips2.1

Locate applicable CMVP certificates at
    https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&ModuleName=OpenSSL&CertificateStatus=Active&ValidationYear=0&SoftwareVersions=3.0.5
```
