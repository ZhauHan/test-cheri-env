// Diagnostics for double-free behavior
// SPDX-License-Identifier: MIT

#include <errno.h>
#include <compartment.h>
#include <debug.h>
#include <unwind.h>
#include <stdlib.h>

#define DEBUG_CONTEXT "Double Free Compartment"

__cheri_compartment("double-free") int vuln1(void)
{
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Double Free...");

    int *ptr = (int*)malloc(sizeof(int));
    if (!ptr) { CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "malloc returned NULL"); return 0; }
    *ptr = 42;

    int *ptr2 = ptr;

    int rc1 = free(ptr);
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "First free rc = {}", rc1);

    // Documentation of heap_free: which is called by free() in cheri
    // Free a heap allocation.
    // Returns 0 on success, -EINVAL if ptr is not a valid pointer to the start of a live heap allocation, 
    // or -ENOTENOUGHSTACK if the stack size is insufficiently large to safely run the function.
    
    int rc2 = free(ptr2);
    if (rc2 == -EINVAL){
        // since ptr is not valid after it was freed, second free should return EINVAL
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Second free rejected: EINVAL (double free detected).");
        return -EINVAL;
    }

    return 0;
}