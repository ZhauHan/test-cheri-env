// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT


#include <compartment.h>
#include <debug.hh>
#include <unwind.h>
#include <errno.h>

/// Expose debugging features unconditionally for this compartment.
using Debug = ConditionalDebug<true, "Heap Buffer Over Read Compartment">;


/// Thread entry point.
int __cheri_compartment("heap-buffer-over-read") vuln1()
{
    Debug::log("Running Buffer Over-read (C++)...");
    int* arr = new int[3];
    if (arr == nullptr)
    {
        Debug::log("Allocation failed!");
        return -1;
    }
    Debug::log("Array created, assigning values...");
    arr[0] = 10;
    arr[1] = 20;
    arr[2] = 30;

    CHERIOT_DURING
    {
    Debug::log("Accessing arr[10] (out-of-bounds)...");
    int value = arr[10]; // Should fault
    Debug::log("Value: {} (This should not be printed)", value);
    }
    CHERIOT_HANDLER
    {
        Debug::log("Exception: Read outside Capability Bounds");
        Debug::log("Error Code: {}", -EFAULT);
        return -EFAULT;
    }
    CHERIOT_END_HANDLER

    delete[] arr;
    Debug::log("Completed without crashing (unexpected)");
    return 0;
}
