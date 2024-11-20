/* glibc includes */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* openssl includes */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>


static void  policy_print_usage_and_die(void) __attribute__((noreturn));
static void  policy_check_arg(const void * p, const char * what);

static int          verbose = 0;
static int          list = 0;
static const char * cert = NULL;
static const char * key = NULL;
static const char * method = NULL;
//static const char * policy = "@SECLEVEL=3:kEECDH:kEDH:kPSK:kDHEPSK:kECDHEPSK:-kRSAPSK:-kRSA:-aDSS:-AES128:-SHA256:-3DES:!DES:!RC4:!RC2:!IDEA:-SEED:!eNULL:!aNULL:-SHA1:!MD5:-SHA384:-CAMELLIA:-ARIA:-AESCCM8";
//static const char * policy = "@SECLEVEL=2:kEECDH:kRSA:kEDH:kPSK:kDHEPSK:kECDHEPSK:kRSAPSK:-aDSS:-3DES:!DES:!RC4:!RC2:!IDEA:-SEED:!eNULL:!aNULL:!MD5:-SHA384:-CAMELLIA:-ARIA:-AESCCM8";
static const char * policy = "@SECLEVEL=1:kEECDH:kRSA:kEDH:kPSK:kDHEPSK:kECDHEPSK:kRSAPSK:!DES:!RC4:!RC2:!IDEA:-SEED:!eNULL:!aNULL:!MD5:-SHA384:-CAMELLIA:-ARIA:-AESCCM8";


int
main(int argc,
     char * argv[])
{
    int       opt = 0;
    int       ret = 0;
    SSL_CTX * ctx = NULL;
    SSL *     ssl = NULL;
    int       fail = 0;

    if (argc < 4) {
        policy_print_usage_and_die();
    }

    while ((opt = getopt(argc, argv, "c:k:m:vl?")) != -1) {
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

    if (method != NULL && *method != '\0') {
        #if 0
        if (strcmp("tlsv1", method) == 0) {
            ctx = SSL_CTX_new(TLSv1_method());
        }
        else if (strcmp("tlsv11", method) == 0) {
            ctx = SSL_CTX_new(TLSv1_1_method());
        }
        else
        #endif
        ctx = SSL_CTX_new(TLS_method());
    }
    else {
        ctx = SSL_CTX_new(TLS_method());
    }

    if (ctx == NULL) {
        printf("info: SSL_CTX_new failed\n");
        fail = 1;
    }

    ret = SSL_CTX_set_cipher_list(ctx, policy);

    if (ret != 1) {
        printf("error: SSL_CTX_set_cipher_list returned: %d", ret);
    }

    int sec_level = policy[10] - '0';
    ret = SSL_CTX_get_security_level(ctx);
    if (ret != sec_level) {
        printf("error: got %d, expected %d\n", ret, sec_level);
    }

    if (ctx != NULL) {
        ret = SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM);
        if (ret != 1) {
            printf("info: CTX_use_certificate_file returned: %d\n", ret);
            SSL_CTX_free(ctx);
            ctx = NULL;
            fail = 1;
        }
    }

    if (ctx != NULL) {
        ret = SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
        if (ret != 1) {
            printf("info: CTX_use_certificate_key returned: %d\n", ret);
            SSL_CTX_free(ctx);
            ctx = NULL;
            fail = 1;
        }
    }

    if (ctx != NULL) {
        ssl = SSL_new(ctx);
    }

    if (ssl == NULL) {
        fail = 1;
    }

    if ((list != 0) && (ssl != NULL)) {
        const STACK_OF(SSL_CIPHER) * sk = NULL;
        const SSL_CIPHER *           current = NULL;
        const char *                 suite = NULL;
        int i = 0;

        sk = SSL_get_ciphers(ssl);
        do {
            current = sk_SSL_CIPHER_value(sk, i++);
            if (current) {
                suite = SSL_CIPHER_get_name(current);
                printf("suite: %s\n", suite);
            }
        } while (current);
    }

    if (ssl != NULL) {
        SSL_free(ssl);
        ssl = NULL;
    }

    if (ctx != NULL) {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }

    return (fail == 1) ? EXIT_FAILURE : EXIT_SUCCESS;
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
