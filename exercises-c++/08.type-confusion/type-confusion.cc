// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT
#include <compartment.h>
#include <debug.hh>
#include <unwind.h>
#include <errno.h>

using Debug = ConditionalDebug<true, "Type Confusion Compartment">;

const char Hello[] = "Hello World!";

union long_ptr {
    long l;
    const char* ptr;
} lp = { .ptr = Hello };

void inc_long_ptr(long_ptr* lpp) {
    lpp->l++;
}

int __cheri_compartment("type-confusion") vuln1()
{
    Debug::log("Testing Type confusion (C++)...");
    Debug::log("Before inc_long_ptr: lp.ptr = {}", lp.ptr);
    CHERIOT_DURING
    {
    inc_long_ptr(&lp);
    Debug::log("After inc_long_ptr: lp.ptr = {}", lp.ptr);
    }
    CHERIOT_HANDLER
    {
        Debug::log("Exception: Type confusion");
        Debug::log("Error Code: {}", -EFAULT);
        return -EFAULT;
    }
    CHERIOT_END_HANDLER
    return 0;
}
