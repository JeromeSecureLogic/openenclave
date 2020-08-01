// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openssl/engine.h>
#include <sys/mount.h>
#include "openssl_t.h"
#include "tu_local.h" /* Header from openssl/test/testutil */

extern char** __environ;

extern int main(int argc, char* argv[]);

int enc_test(int argc, char** argv, char** env)
{
    int ret = 1;
    ENGINE* eng = NULL;
    const BIO_METHOD* tap = NULL;

    /* Directly use environ from host. */
    __environ = env;

    /* Initialize socket and host fs. */
    if (OE_OK != oe_load_module_host_socket_interface())
        goto done;

    if (OE_OK != oe_load_module_host_resolver())
        goto done;

#ifndef CODE_COVERAGE // Avoid conflicts with libgcov.
    if (OE_OK != oe_load_module_host_file_system())
        goto done;

    if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL))
        goto done;
#endif

    /*
     * Initialize and opt-in the rdrand engine. This is necessary to use opensl
     * RNG functionality inside the enclave.
     */
    ENGINE_load_rdrand();
    eng = ENGINE_by_id("rdrand");
    if (eng == NULL)
    {
        goto done;
    }

    if (ENGINE_init(eng) == 0)
    {
        goto done;
    }

    if (ENGINE_set_default(eng, ENGINE_METHOD_RAND) == 0)
    {
        goto done;
    }

    /*
     * Hold the reference to the tap method that is used by the OpenSSL test
     * framework such that we can free it (which the framework does not do
     * that). Without doing this, DEBUG_MALLOC will report memory leaks.
     */
    tap = BIO_f_tap();

    /* Perform the test. */
    ret = main(argc, argv);

done:
#ifndef CODE_COVERAGE // Avoid conflicts with libgcov.
    umount("/");
#endif
    if (__environ)
        __environ = NULL;
    if (eng)
    {
        ENGINE_finish(eng);
        ENGINE_free(eng);
        ENGINE_cleanup();
    }
    if (tap)
        BIO_meth_free((BIO_METHOD*)tap);

    return ret;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    8);   /* TCSCount */
