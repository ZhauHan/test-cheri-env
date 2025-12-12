// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.h>
#include <assert.h>
#include <unwind.h>
#include <errno.h>

#define DEBUG_CONTEXT "Stack Buffer Over Write Compartment"

#pragma weak write_buf

void write_buf(char *buf, size_t ix)
{
    buf[ix] = 'b';
}

__cheri_compartment("stack-buffer-over-write") int vuln1(void)
{
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Stack Buffer Over Write (C)...");

    char upper[0x10];
    char lower[0x10];

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "upper = {}, lower = {}, diff = {}",
        (ptraddr_t)upper, (ptraddr_t)lower, (size_t)(upper - lower));
    
    /* Assert that these get placed how we expect */
    assert((ptraddr_t)upper == (ptraddr_t)&lower[sizeof(lower)]);

    upper[0] = 'a';
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "upper[0] = {}", upper[0]);
    
    CHERIOT_DURING
    {
    write_buf(lower, sizeof(lower));
    }
    CHERIOT_HANDLER
    {
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Exception: Write outside Capability Bounds");
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Error code: {}", -EFAULT);
        return -EFAULT;
    }
    CHERIOT_END_HANDLER

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "upper[0] = {}", upper[0]);

    return 0;
}
