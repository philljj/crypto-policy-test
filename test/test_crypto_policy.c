/* glibc includes */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* wolfssl includes */
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/ssl.h>

static void  policy_print_usage_and_die(void) __attribute__((noreturn));
static void  policy_check_arg(const void * p, const char * what);

static int          verbose = 0;
static int          list = 0;
static const char * cert = NULL;
static const char * key = NULL;
static const char * policy = NULL;
static const char * method = NULL;

int
main(int argc,
     char * argv[])
{
    int           opt = 0;
    int           ret = 0;
    WOLFSSL_CTX * ctx = NULL;
    WOLFSSL *     ssl = NULL;

    if (argc < 4) {
        policy_print_usage_and_die();
    }

    while ((opt = getopt(argc, argv, "c:k:m:p:vl?")) != -1) {
        switch (opt) {
        case 'c':
            cert = optarg;
            break;
        case 'l':
            list = 1;
            break;
        case 'k':
            key = optarg;
            break;
        case 'm':
            method = optarg;
            break;
        case 'p':
            policy = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        default:
        case '?':
            policy_print_usage_and_die();
            break;
        }
    }

    policy_check_arg(cert, "-c cert");
    policy_check_arg(key, "-k key");
    policy_check_arg(policy, "-p policy");

    wolfSSL_Init();
    if (verbose) {
        wolfSSL_Debugging_ON();
    }

    wolfSSL_crypto_policy_disable();

    ret = wolfSSL_crypto_policy_enable(policy);

    if (ret != WOLFSSL_SUCCESS) {
        printf("error: wolfSSL_crypto_policy_enable(%s) returned: %d\n",
               policy, ret);
        return EXIT_FAILURE;
    }

    if (method != NULL && *method != '\0') {
        if (strcmp("tlsv1", method) == 0) {
            ctx = wolfSSL_CTX_new(wolfTLSv1_method());
        }
        else if (strcmp("tlsv11", method) == 0) {
            ctx = wolfSSL_CTX_new(wolfTLSv1_1_method());
        }
        else if (strcmp("tlsv12", method) == 0) {
            ctx = wolfSSL_CTX_new(wolfTLSv1_2_method());
        }
        else if (strcmp("tlsv13", method) == 0) {
            ctx = wolfSSL_CTX_new(wolfTLSv1_3_method());
        }
        else {
            ctx = wolfSSL_CTX_new(TLS_method());
        }
    }
    else {
        ctx = wolfSSL_CTX_new(TLS_method());
    }

    if (ctx == NULL) {
        printf("info: wolfSSL_CTX_new failed\n");
    }

    if (ctx != NULL) {
        ssl = wolfSSL_new(ctx);
    }

    if ((list != 0) && (ssl != NULL)) {
        WOLF_STACK_OF(WOLFSSL_CIPHER) * sk = NULL;
        WOLFSSL_CIPHER *                current = NULL;
        const char *                    suite = NULL;
        int i = 0;

        sk = wolfSSL_get_ciphers_compat(ssl);
        do {
            current = wolfSSL_sk_SSL_CIPHER_value(sk, i++);
            if (current) {
                suite = wolfSSL_CIPHER_get_name(current);
                printf("suite: %s\n", suite);
            }
        } while (current);
    }

    if (ssl != NULL) {
        wolfSSL_free(ssl);
        ssl = NULL;
    }

    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
        ctx = NULL;
    }

    return EXIT_SUCCESS;
}


static void
policy_print_usage_and_die(void)
{
    printf("usage:\n");
    printf("  ./test_policy -c <cert file> -k <key file> "
           "-p <crypto policy file> [-m <tls method>] [-lv]\n");
    printf("\n");
    printf("example:\n");
    printf("  ./test/test_policy -c certs/rsa/2048/cert_2048.pem -k "
           "certs/rsa/2048/keypair_2048.pem "
           "-p crypto-policies/default/wolfssl.txt\n");
    exit(EXIT_FAILURE);
}

static void
policy_check_arg(const void * p,
                 const char * what)
{
    if (p == NULL) {
        printf("error: missing arg: %s\n", what);
        exit(EXIT_FAILURE);
    }

    return;
}
