-- Copyright Microsoft and CHERIoT Contributors.
-- SPDX-License-Identifier: MIT

set_project("CHERIoT Hello World")
sdkdir = "../../cheriot-rtos/sdk"
includes(sdkdir)
set_toolchains("cheriot-clang")

option("board")
    set_default("mpact")

option("sdk")
    set_default("/cheriot-tools/")

option("debug_run")
    set_default("false")
    set_showmenu(true)
    set_description("Run simulator in debug mode (-i)")

compartment("heap-buffer-under-write")
    -- memcpy
    add_deps("freestanding", "debug", "unwind_error_handler")
    add_files("heap-buffer-under-write.cc")

-- Firmware image for the example.
firmware("heap-buffer-under-write-vulnerability")
    add_deps("freestanding", "debug", "stdio", "heap-buffer-under-write")
    on_load(function(target)
        target:values_set("board", "$(board)")
        target:values_set("threads", {
            {
                compartment = "heap-buffer-under-write",
                priority = 1,
                entry_point = "vuln1",
                stack_size = 0x400,
                trusted_stack_frames = 1
            }
        }, {expand = false})
    end)

on_run(function (target)
    local targetfile = target:targetfile()
    local simulator = "/cheriot-tools/bin/mpact_cheriot"
    local rundir = "../../submit-cheriot/exercises-c++/03.heap-buffer-under-write/runs/run_" .. os.date("%Y%m%d_%H%M%S")
    os.mkdir(rundir)

    -- check debug option
    local args = {"--output_dir=" .. rundir}
    if get_config("debug_run") == true then
        table.insert(args, "-i")
        
        print("Running in debug mode...")
        local log_file = "../../submit-cheriot/exercises-c++/03.heap-buffer-under-write/debug"
        local log_time = os.date("%Y-%m-%d %H:%M:%S")
        local log_line = string.format("debug_time: %s\n", log_time)

        local f = io.open(log_file, "a")
        if f then
            f:write(log_line)
            f:close()
        end

        
    else
        print("Running in normal mode...")
    end
    table.insert(args, targetfile)
    os.execv(simulator, args)
end)