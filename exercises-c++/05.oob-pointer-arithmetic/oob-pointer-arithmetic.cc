// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT
#include <compartment.h>
#include <debug.hh>
#include <unwind.h>
#include <errno.h>

using Debug = ConditionalDebug<true, "OOB Pointer Arithmetic Compartment">;

int __cheri_compartment("oob-pointer-arithmetic") vuln1()
{
    Debug::log("Testing Out-Of-Bounds Pointer Arithmetic (C++)...");
    int arr[4] = {100, 200, 300, 400};
    Debug::log("Array base: {}", static_cast<int*>(arr));
    int* p = arr + 10;
    Debug::log("Pointer moved to arr + 10: {}", static_cast<int*>(p));

    CHERIOT_DURING
    {
    int val = *p;
    Debug::log("Read value: {} (this should not be printed)", val);
    }
    CHERIOT_HANDLER
    {
        Debug::log("Exception: OOB pointer dereference");
        Debug::log("Error Code: {}", -EFAULT);
        return -EFAULT;
    }
    CHERIOT_END_HANDLER
    return 0;
}
