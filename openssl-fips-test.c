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
test_md5_not_available(void)
{
	EVP_MD *md5 = NULL;

	md5 = EVP_MD_fetch(NULL, "MD5", NULL);
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
		.name = "verify unapproved cryptographic routines are not available by default (e.g. MD5)",
		.expected = true,
		.test_fn = test_md5_not_available,
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

static void print_module_version(void) {

        OSSL_PROVIDER *prov = NULL;
        OSSL_PARAM params[4], *p = params;
        char *name = "", *vers = "", *build = "";

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

        char * encoded_name = (char*) malloc(strlen(name)+1*sizeof(char));
        snprintf(encoded_name, strlen(name)+1, "%s", name);
        for (int i = 0; i<strlen(encoded_name); i++) if (encoded_name[i] == ' ') encoded_name[i] = '+';

        fprintf(stderr, "Locate aplicable CMVP certificates at\n\n");
        fprintf(stderr, "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search?SearchMode=Advanced&ModuleName=%s&CertificateStatus=Active&ValidationYear=0&SoftwareVersions=%s\n", encoded_name, vers);

        return;
 err:
        fprintf(stderr, "Failed to retreive module version information\n");
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

	if (rc == EXIT_SUCCESS) {
		fprintf(stderr, "Lifecycle assurance satisfied.\n");
		print_module_version();
	}

	return rc;
}
