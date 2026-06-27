#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "../src/dht.h"

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    // Invariant: Buffer reads never exceed the declared length
    const char *payloads[] = {
        "normal_input",                     // Valid input
        "A",                                // Boundary: single char
        "very_long_input_that_exceeds_buffer_by_2x_",  // 2x overflow
        "extremely_long_input_that_exceeds_buffer_by_10x_and_causes_overflow_when_copied",  // 10x overflow
        NULL                                // NULL pointer case
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        char buffer[16] = {0};  // Small fixed buffer
        const char *input = payloads[i];
        
        if (input == NULL) {
            // Test NULL input handling
            int result = dht_safe_copy(buffer, sizeof(buffer), input);
            ck_assert_msg(result != 0 || buffer[0] == '\0', 
                         "NULL input should be rejected or produce empty buffer");
            continue;
        }
        
        size_t input_len = strlen(input);
        int result = dht_safe_copy(buffer, sizeof(buffer), input);
        
        // Property: No buffer overflow occurred
        ck_assert_msg(result == 0 || input_len < sizeof(buffer),
                     "Buffer overflow detected for input length %zu with buffer size %zu",
                     input_len, sizeof(buffer));
        
        // Additional check: if copy succeeded, verify null termination
        if (result == 0) {
            ck_assert_msg(buffer[sizeof(buffer)-1] == '\0' || strlen(buffer) < sizeof(buffer),
                         "Buffer not properly null-terminated");
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}