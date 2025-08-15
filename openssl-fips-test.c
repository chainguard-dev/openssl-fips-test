// Copyright 2023-2024 Chainguard, Inc.
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
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/self_test.h>
#include <openssl/opensslv.h>

struct test_ {
	const char *name;
	const bool expected;
	const bool (*test_fn)(void);
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))

int selftest_passes = 0;
int selftest_failures = 0;
static bool
test_fips_module_is_available(void)
{
	fprintf(stderr, "\n");

	OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_get0_global_default();

	int rc = OSSL_PROVIDER_available(ctx, "fips");

	fprintf(stderr, "    Running check: FIPS module is available...");

	if (!rc)
		return false;

	if (selftest_passes == 0)
		return false;

	return (selftest_failures == 0);
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
test_hmac_md5_not_available(void)
{
	size_t outlen = 0;

	unsigned char *hmac_md5 = EVP_Q_mac(NULL, "HMAC", NULL, "MD5", NULL, "12345678901234", 14, NULL, 0, NULL, 0, &outlen);
	if (hmac_md5 != NULL) {
		free(hmac_md5);
		return false;
	}

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
		.name = "verify unapproved cryptographic routines are not available by default (e.g. HMAC-MD5)",
		.expected = true,
		.test_fn = test_hmac_md5_not_available,
	},
};

static int self_test_events(const OSSL_PARAM params[], void *arg)
{
        const OSSL_PARAM *p = NULL;
        const char *phase = NULL, *type = NULL, *desc = NULL;

        p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_PHASE);
        if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
                goto err;
        phase = (const char *)p->data;

        p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_DESC);
        if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
                goto err;
        desc = (const char *)p->data;

        p = OSSL_PARAM_locate_const(params, OSSL_PROV_PARAM_SELF_TEST_TYPE);
        if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING)
                goto err;
        type = (const char *)p->data;

        if (strcmp(phase, OSSL_SELF_TEST_PHASE_START) == 0)
                fprintf(stderr, "    %s : (%s) : ", desc, type);
        else if (strcmp(phase, OSSL_SELF_TEST_PHASE_PASS) == 0) {
                fprintf(stderr, "%s\n", phase);
                selftest_passes++;
        } else if (strcmp(phase, OSSL_SELF_TEST_PHASE_FAIL) == 0) {
                fprintf(stderr, "%s\n", phase);
                selftest_failures++;
        }

        return true;

 err:
        selftest_failures++;
        return false;
}

static void print_base_version(void) {
        fprintf(stderr, "\nPublic OpenSSL API for TLS and cryptographic routines (libssl.so & libcrypto.so):\n");
        fprintf(stderr, "\t%-10s\t%s\n", "name:", OpenSSL_version(OPENSSL_VERSION));
        fprintf(stderr, "\t%-10s\t%s\n", "version:", OpenSSL_version(OPENSSL_VERSION_STRING));
        fprintf(stderr, "\t%-10s\t%s\n", "full-version:", OpenSSL_version(OPENSSL_FULL_VERSION_STRING));
        fprintf(stderr, "\t%-10s\t%s\n", "built-on:", OpenSSL_version(OPENSSL_BUILT_ON) + 10);
        fprintf(stderr, "\n");
}

static void print_module_version(void) {

        OSSL_PROVIDER *prov = NULL;
        OSSL_PARAM params[4], *p = params;
        char *name = "", *vers = "", *build = "";

        fprintf(stderr, "FIPS cryptographic Module details (fips.so):\n");
        prov = OSSL_PROVIDER_load(NULL, "fips");
        if (prov == NULL)
                goto err;

        *p++ = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, &name, sizeof(name));
        *p++ = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, &vers, sizeof(vers));
        *p++ = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, &build, sizeof(build));
        *p = OSSL_PARAM_construct_end();
        if (!OSSL_PROVIDER_get_params(prov, params))
                goto err;
        if (OSSL_PARAM_modified(params))
                fprintf(stderr, "\t%-10s\t%s\n", "name:", name);
        if (OSSL_PARAM_modified(params + 1))
                fprintf(stderr, "\t%-10s\t%s\n", "version:", vers);
        if (OSSL_PARAM_modified(params + 2))
                fprintf(stderr, "\t%-10s\t%s\n", "build:", build);

        fprintf(stderr, "\nLocate applicable CMVP certificates at\n");
        if (strncmp(vers, "3.1.2", 5) == 0)
                fprintf(stderr, "    https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&ModuleName=OpenSSL&CertificateStatus=Active&CertificateNumber=4985\n");
        else
                fprintf(stderr, "    https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&ModuleName=OpenSSL&CertificateStatus=Active&ValidationYear=0&SoftwareVersions=%.5s\n", vers);

        return;
 err:
        fprintf(stderr, "\tFailed to retrieve cryptographic module version information\n");
}


int
main(int argc, const char *argv[])
{
	int rc = EXIT_SUCCESS;

	fprintf(stderr, "Checking OpenSSL lifecycle assurance.\n");

	OSSL_SELF_TEST_set_callback(NULL, self_test_events, NULL);

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++)
	{
		fprintf(stderr, "*** Running check: %s...", tests[i].name);

		bool ret = tests[i].test_fn();
		if (ret != tests[i].expected)
		{
			fprintf(stderr, " failed.\n");
			rc = EXIT_FAILURE;
		}
		else
		{
			fprintf(stderr, " passed.\n");
		}
	}

	print_base_version();
	print_module_version();
	if (rc == EXIT_SUCCESS) {
		fprintf(stderr, "\nLifecycle assurance satisfied.\n");
	}

	return rc;
}
