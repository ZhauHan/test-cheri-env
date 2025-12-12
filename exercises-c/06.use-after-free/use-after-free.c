// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.h>
#include <unwind.h>
#include <stdlib.h>
#include <errno.h>


#define DEBUG_CONTEXT "Use After Free Compartment"

/// Thread entry point.
__cheri_compartment("use-after-free") int vuln1()
{
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Use-After-Free (C)...");
    int* ptr = (int*)malloc(sizeof(int));
    if (ptr == NULL) {return 0;}
    *ptr = 123;
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "ptr points to memory with value: {}", *ptr);

    free(ptr);
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Memory has been freed.");

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Attempting to dereference dangling pointer... ");
    CHERIOT_DURING
    {
        int val = *ptr; // Use-after-free read
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Read value: {} (this should not be printed)", val);
        *ptr = 456;
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Value is now: {}", *ptr);
    }
    CHERIOT_HANDLER
    {
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Exception: Use after free read");
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Error Code: {}", -EFAULT);
        return -EFAULT;
    }
    CHERIOT_END_HANDLER
    

    return 0;
}
