// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

struct test_ {
	const char *name;
	const bool expected;
	const bool (*test_fn)(void);
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

static bool
test_fips_module_is_available(void)
{
	OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_get0_global_default();

	if (!OSSL_PROVIDER_available(ctx, "fips"))
		return false;

	return true;
}

static bool
test_fips_module_is_enabled(void)
{
	OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_get0_global_default();

	if (!EVP_default_properties_is_fips_enabled(ctx))
		return false;

	return true;
}

static bool
test_legacy_module_is_available(void)
{
	OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_get0_global_default();

	if (!OSSL_PROVIDER_available(ctx, "legacy"))
		return false;

	return true;
}

static bool
test_unspec_md5_hashing_xfail(void)
{
	EVP_MD *md5 = EVP_MD_fetch(NULL, "MD5", NULL);
	if (md5 != NULL)
		return false;

	return true;
}

static bool
test_fips_md5_hashing_xfail(void)
{
	EVP_MD *md5 = EVP_MD_fetch(NULL, "MD5", "provider=fips");
	if (md5 != NULL)
		return false;

	return true;
}

static bool
test_fips_sha2_512_hashing_xpass(void)
{
	EVP_MD *sha2_512 = EVP_MD_fetch(NULL, "SHA2-512", "provider=fips");
	if (sha2_512 == NULL)
		return false;

	return true;
}

static bool
test_escape_fips(void)
{
	EVP_MD *md5 = EVP_MD_fetch(NULL, "MD5", "provider=default");
	if (md5 != NULL)
		return false;

	return true;
}

static bool
test_crypto_is_fips_jailed(void)
{
	/* This should always work. */
	EVP_MD *sha2_512 = EVP_MD_fetch(NULL, "SHA2-512", "provider=fips");
	if (sha2_512 == NULL)
		return false;

	/* This should not. */
	sha2_512 = EVP_MD_fetch(NULL, "SHA2-512", "provider=default");
	if (sha2_512 != NULL)
		return false;

	return true;
}

static bool
test_loading_providers_is_meaningless(void)
{
	OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
	if (legacy == NULL)
		return true;

	EVP_MD *whirlpool = EVP_MD_fetch(NULL, "WHIRLPOOL", "provider=legacy");
	if (whirlpool != NULL)
		return false;

	OSSL_PROVIDER *base = OSSL_PROVIDER_load(NULL, "base");
	if (base == NULL)
		return true;

	EVP_MD *md5 = EVP_MD_fetch(NULL, "MD5", "provider=base");
	if (md5 != NULL)
		return false;

	return true;
}

static const struct test_ tests[] = {
	{
		.name = "FIPS module is available",
		.expected = true,
		.test_fn = test_fips_module_is_available,
	},
	{
		.name = "EVP_default_properties_is_fips_enabled returns true",
		.expected = true,
		.test_fn = test_fips_module_is_enabled,
	},
	{
		.name = "legacy cryptographic routines are not available",
		.expected = false,
		.test_fn = test_legacy_module_is_available,
	},
	{
		.name = "non-specialized MD5 hashing operations are rejected",
		.expected = true,
		.test_fn = test_unspec_md5_hashing_xfail,
	},
	{
		.name = "the FIPS provider does not provide an MD5 hashing function",
		.expected = true,
		.test_fn = test_fips_md5_hashing_xfail,
	},
	{
		.name = "the FIPS provider does provide an SHA2-512 hashing function",
		.expected = true,
		.test_fn = test_fips_sha2_512_hashing_xpass,
	},
	{
		.name = "requesting MD5 from the default provider is rejected",
		.expected = true,
		.test_fn = test_escape_fips,
	},
	{
		.name = "cryptographic routines are restricted to the FIPS module",
		.expected = true,
		.test_fn = test_crypto_is_fips_jailed,
	},
	{
		.name = "using OSSL_PROVIDER_load cannot break out of the jail",
		.expected = true,
		.test_fn = test_loading_providers_is_meaningless,
	},
};

int
main(int argc, const char *argv[])
{
	fprintf(stderr, "Running OpenSSL FIPS validation tests.\n");

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++)
	{
		fprintf(stderr, "*** Running check: %s...", tests[i].name);

		bool ret = tests[i].test_fn();
		if (ret != tests[i].expected)
		{
			fprintf(stderr, " FAILED\n!!! TEST RESULT DID NOT MATCH EXPECTED RESULT !!!\n");
			return EXIT_FAILURE;
		}
		else
		{
			fprintf(stderr, " passed.\n");
		}
	}

	fprintf(stderr, "All FIPS validation tests pass, OpenSSL is configured correctly.\n");

	return EXIT_SUCCESS;
}
