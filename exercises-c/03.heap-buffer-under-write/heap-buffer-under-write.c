// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.h>
#include <unwind.h>
#include <stdlib.h>
#include <errno.h>

#define DEBUG_CONTEXT "Heap Buffer Under Write Compartment"

__cheri_compartment("heap-buffer-under-write") int vuln1(void)
{
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Heap Buffer Under-write (C)...");

    int *arr = (int *)malloc(3 * sizeof(int));
    if (arr == NULL) { return 0; }
    arr[0] = 10; arr[1] = 20; arr[2] = 30;

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Attempting under-write arr[-1] = 999 ...");
    CHERIOT_DURING
    {
    arr[-1] = 999; // write before start of allocation (under-write)

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "arr[-1]: {} (this should not be printed).", arr[-1]);
    }
    CHERIOT_HANDLER
    {
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Exceptioin: Write outside Capability Bounds");
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Error code: {}", -EFAULT);
        return -EFAULT;
    }
    CHERIOT_END_HANDLER

    free(arr);
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Freed array (if we reached here).");
    return 0;
}
