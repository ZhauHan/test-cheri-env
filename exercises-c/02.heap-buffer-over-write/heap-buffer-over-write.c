// Copyright Microsoft and CHERiOT Contributors.
// SPDX-License-Identifier: MIT

#include <errno.h>
#include <compartment.h>
#include <debug.h>
#include <unwind.h>
#include <stdlib.h>

#define DEBUG_CONTEXT "Heap Buffer Over Write Compartment"

__cheri_compartment("heap-buffer-over-write") int vuln1(void)
{
    int* arr = (int*)malloc(3 * sizeof(int));
    if (arr == NULL) { return 0; }

    arr[0] = 1;
    arr[1] = 2;
    arr[2] = 3;

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Buffer Over-write (C)...");

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Attempting to write arr[4]...");
    
    CHERIOT_DURING
    {
        arr[4] = 999; // Writing outside allocated memory
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "arr[4]: {} (this should not be printed).", arr[4]);
    }
    CHERIOT_HANDLER
    {   
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Exception: Write outside Capability Bounds");
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Error: {}", -EFAULT);
        return -EFAULT;
    }
    CHERIOT_END_HANDLER     

    free(arr);
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "This line may not be reached if the program crashes.");
    return 0;
}
