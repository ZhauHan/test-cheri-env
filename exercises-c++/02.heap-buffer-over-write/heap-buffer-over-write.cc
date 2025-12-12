// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT
#include <compartment.h>
#include <debug.hh>
#include <unwind.h>
#include <errno.h>

using Debug = ConditionalDebug<true, "Heap Buffer Over Write Compartment">;

int __cheri_compartment("heap-buffer-over-write") vuln1()
{
    Debug::log("Testing Heap Buffer Over-write (C++)...");
    int* arr = nullptr;
    arr = new int[3];
    if (!arr) {
        Debug::log("Allocation failed!");
        return 0;
    }
    arr[0] = 1;
    arr[1] = 2;
    arr[2] = 3;

    CHERIOT_DURING{
    Debug::log("Attempting to write arr[10] (out-of-bounds)...");
    arr[10] = 999;
    Debug::log("Write completed (this should not be printed).");
    Debug::log("Value of written element: {}.", arr[10]);
    }
    CHERIOT_HANDLER{
        Debug::log("Exception: Write outside Capability Bounds");
        Debug::log("Error Code: {}", -EFAULT);
        return -EFAULT;
    }
    CHERIOT_END_HANDLER

    delete[] arr;
    return 0;
}
