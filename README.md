# Minidump parser for Erlang

Been working on this when blocked on other tasks, with the eventual goal
of integrating it into the hprof-relay so that it can expose more useful
info as json, to be loaded into snowflake and queried.

The basic file parsing is more or less complete, and what remains is to
construct meaningful stack traces from the stream contents.

## How to run

You will need [rebar3](https://www.rebar3.org/)

    ross@fenrir:/t/u/r/p/E/minidump$ rebar3 shell
    ===> Verifying dependencies...
    Erlang/OTP 19 [erts-8.2.1] [source] [64-bit] [smp:40:40] [async-threads:0] [kernel-poll:false]

    Eshell V8.2.1  (abort with ^G)
    1> minidump_parser:parse_file(dumpfile).
    13 streams detected
    Header: {minidump_header,1347241037,42899,13,32,0,1511885951,0}
    Flags: 0x0: []
    Stream data:
    Stream type: stream_type_thread_list size 3172
    Stream type: stream_type_module_list size 56056
    Stream type: stream_type_memory_list size 1076
    Stream type: stream_type_exception size 168
    Stream type: stream_type_system_info size 56
    Stream type: stream_type_linux_cpu_info size 2004
    Stream type: stream_type_linux_proc_status size 850
    Stream type: stream_type_unused size 0
    Stream type: stream_type_linux_cmd_line size 87
    Stream type: stream_type_linux_environ size 1107
    Stream type: stream_type_linux_auxv size 160
    Stream type: stream_type_linux_maps size 179483
    Stream type: stream_type_linux_dso_debug size 320
    Found 66 threads
    Crashing thread: {minidump_thread,15539,0,0,0,0,4290072576,16384,3368,368,
                                      20008}
    519 modules loaded
    67 memory ranges loaded
    Thread was killed by signal sigsev in thread 15539
    Exception data: {minidump_exception_stream,15539,
                        {minidump_exception,11,0,0,0,0,
                            [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]},
                        {minidump_location,368,20008}}
    Thread contxt: <<6,0,0,64,0,0,0,0,180,92,181,255,0,0,0,0,169,168,175,240,76,93,
                     181,255,8,144,216,231,0,0,0,0,25,54,255,159,64,93,181,255,144,
                     90,139,161,180,92,181,255,144,90,139,161,181,129,221,158,144,
                     92,181,255,27,218,87,159,52,165,226,158,48,0,7,64,0,0,0,0,0,0,
                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                     0,0,0,0,0,0,0,0,0,0,0>>
    System info: {minidump_system_info,5,1,42,8,0,0,0,0,33283,459048,0,
                                       {minidump_cpu_info_arm,1090572340,504022}}
    13 DSO entries loaded
    ok
    2>

