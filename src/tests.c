
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "utils.h"


static void base32_test1()
{
    for (int i = 0; i < 100; ++i) {
        int a = base32encsize(i);
        int b = base32decsize(a);
        if (i != b) {
            fprintf(stderr, "base32_test1() error: %d != %d\n", i, b);
            exit(1);
        }
    }
}

static void base32_test2()
{
    char buf[200];
    uint8_t in1[20] = {0x21, 0x49, 0xf2, 0x7d, 0xec, 0x0e, 0x23, 0x8d, 0xb3, 0x12, 0xa4, 0xd0, 0xbe, 0x36, 0xb6, 0x8f, 0x14, 0xa2, 0xd8, 0x22};

    const char *base16encoded_expected = "2149f27dec0e238db312a4d0be36b68f14a2d822";
    const char *base32encoded_expected = "454z4zfc1rhrvcrjmk8bwdnphwaa5p12";
    char *base16encoded = base16enc(buf, sizeof(buf), in1, sizeof(in1));
    if (0 != strcmp(base16encoded, base16encoded_expected)) {
        fprintf(stderr, "base32_test2() failed for base16\n");
        exit(1);
    }

    char *base32encoded = base32enc(buf, sizeof(buf), in1, sizeof(in1));
    if (0 != strcmp(base32encoded, base32encoded_expected)) {
        fprintf(stderr, "base32_test2() failed for base32\n");
        exit(1);
    }
}

static void base32_test3()
{
    char buf[200];
    uint8_t in[100];
    uint8_t out[100];

    for (int n = 1; n < sizeof(in); ++n) {
        bytes_random(in, n);

        char *ret = base32enc(buf, sizeof(buf), in, n);

        if (ret == NULL) {
            fprintf(stderr, "base32_test3() error: base32_encode returned NULL\n");
            exit(1);
        }

        if (n != base32decsize(strlen(ret))) {
            fprintf(stderr, "base32_test3() error: %d != %d (base32decsize(%d))\n",
                (int) n, (int) base32decsize(strlen(ret)), (int) strlen(ret));
            exit(1);
        }

        if (strlen(ret) != base32encsize(n)) {
            fprintf(stderr, "base32_test3() error: %d != %d (base32encsize(%d))\n",
                (int) strlen(ret), (int) base32encsize(n), (int) n);
            exit(1);
        }

        bool ok1 = base32dec(out, n - 1, ret, strlen(ret));
        if (ok1) {
            fprintf(stderr, "base32_test3() base32dec expected to fail (buffer too small)\n");
            exit(1);
        }

        bool ok2 = base32dec(out, n, ret, strlen(ret));
        if (!ok2) {
            fprintf(stderr, "base32_test3() base32dec failed for exact buffer size\n");
            exit(1);
        }

        bool ok3 = base32dec(out, n + 1, ret, strlen(ret));
        if (!ok3) {
            fprintf(stderr, "base32_test3() base32dec failed for bigger buffer size\n");
            exit(1);
        }

        if (memcmp(in, out, n) != 0) {
            fprintf(stderr, "base32_test3() error: in != out\n");
            exit(1);
        }
    }
}

void base32_test4()
{
    const char *base32encoded = "454z4zfc1rhrvcrjmk8bwdnphwaa5p12";
    uint8_t out[20];
    bool ok1 = base32dec(out, sizeof(out), base32encoded, strlen(base32encoded));
    if (!ok1) {
        fprintf(stderr, "base32_test4() ok1 expected to be true\n");
        exit(1);
    }

    bool ok2 = base32dec(out, sizeof(out)-1, base32encoded, strlen(base32encoded));
    if (ok2) {
        fprintf(stderr, "base32_test4() ok2 expected to be false (output buffer too small)\n");
        exit(1);
    }
}

void run_tests()
{
    base32_test1();
    base32_test2();
    base32_test3();
    base32_test4();

    fprintf(stderr, "Pre-run tests ran OK\n");
}
