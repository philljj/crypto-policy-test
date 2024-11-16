/* glibc includes */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* wolfssl includes */
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/ssl.h>

static void  policy_print_usage_and_die(void) __attribute__((noreturn));
static void  policy_check_arg(const void * p, const char * what);

static int verbose = 0;
static const char * cert = NULL;
static const char * key = NULL;
static const char * policy = NULL;

int
main(int argc,
     char * argv[])
{
    int           opt = 0;
    int           ret = 0;
    WOLFSSL_CTX * ctx = NULL;
    WOLFSSL *     ssl = NULL;

    while ((opt = getopt(argc, argv, "c:k:p:v?")) != -1) {
        switch (opt) {
        case 'c':
            cert = optarg;
            break;
        case 'k':
            key = optarg;
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

    ctx = wolfSSL_CTX_new(TLS_method());

    ssl = wolfSSL_new(ctx);

    WOLF_STACK_OF(WOLFSSL_CIPHER)* sk = NULL;
    WOLFSSL_CIPHER * current;
    const char * suite = NULL;
    int i = 0;

    sk = wolfSSL_get_ciphers_compat(ssl);
    do {
        current = wolfSSL_sk_SSL_CIPHER_value(sk, i++);
        if (current) {
            suite = wolfSSL_CIPHER_get_name(current);
            printf("suite: %s\n", suite);
        }
    } while (current);

    printf("hello world\n");
    return EXIT_SUCCESS;
}


static void
policy_print_usage_and_die(void)
{
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
