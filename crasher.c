#include <windows.h>
int main() {
    SetErrorMode(0);
    volatile int *p = NULL;
    *p = 42;
    return 0;
}
