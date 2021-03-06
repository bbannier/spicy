// @TEST-REQUIRES: have-sanitizer
// @TEST-GROUP: no-jit
// @TEST-EXEC: cxx-compile-and-link %INPUT
// @TEST-EXEC-FAIL: ASAN_OPTIONS=detect_leaks=1 ./a.out >output 2>&1
// @TEST-EXEC: grep -q 'detected memory leaks' output
//
// If we have compiled with address/leak sanitizer, make sure it's active.

extern "C" {

#include <stdio.h>

int main(int argc, char** argv) {
    printf("in main\n");
    auto leak = new int;
    printf("%p\n", leak);
    return 0;
}

}
