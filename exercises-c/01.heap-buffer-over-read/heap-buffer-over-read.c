// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <errno.h>
#include <compartment.h>
#include <debug.h>
#include <unwind.h>
#include <stdlib.h>


#define DEBUG_CONTEXT "Heap Buffer Over Read Compartment"

/// Thread entry point.
__cheri_compartment("heap-buffer-over-read") int vuln1()
{   
    
    int* arr = (int*)malloc(3 * sizeof(int));
    if (arr == NULL) {return 0;} // Always check for malloc failure
    arr[0] = 10;
    arr[1] = 20;
    arr[2] = 30;

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Buffer Over-read (C)...");

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Accessing arr[10]... ");
    
    CHERIOT_DURING 
    {
        int value = arr[10];
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Value: {} (This should not be printed)", value);
    } 

    CHERIOT_HANDLER
	{
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Exception: Read outside Capability Bounds");
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Error Code: {}", -EFAULT);
        return -EFAULT;
	}
	CHERIOT_END_HANDLER

    free(arr);
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "This line may not be reached if the program crashes.");
    return 0;
}
