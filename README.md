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
    1> c('src/minidump_parser').
    {ok,minidump_parser}
    2> c('src/symfile_parser').
    {ok,symfile_parser}
    3> rr("include/records.hrl").
    [minidump_cpu_info_arm,minidump_cpu_info_other,
     minidump_cpu_info_x86,minidump_directory,minidump_exception,
     minidump_exception_stream,minidump_header,
     minidump_linux_dso,minidump_location,
     minidump_memory_descriptor,minidump_module,
     minidump_raw_context_arm,minidump_stream,
     minidump_system_info,minidump_thread,
     minidump_vs_fixed_file_info,stack_frame]
    4> rr("src/symfile_parser.erl").
    [state,symfile_func,symfile_public]
    5> {ok, Ctx} = minidump_parser:parse_file(dumpfile).
    {ok,<0.120.0>}
    6> {ok, CrashedThread} = minidump_parser:get_crashing_thread_id(Ctx).
    {ok,15539}
    7> {ok, Stack} = minidump_parser:get_stack_for_thread(Ctx, CrashedThread).
    {ok,[#stack_frame{instruction_pointer = 2665653556,
                      module_name = <<47,0,100,0,97,0,116,0,97,0,47,0,97,0,112,
                                      0,112,0,47,0,99,0,111,...>>,
                      module_version = <<"271AA00AC3831EF30E510AFFA178ADE0D">>,
                      module_offset = 3671346},
         #stack_frame{instruction_pointer = 2684303105,
                      module_name = <<"/data/app/com.mcent.browser-1/lib/arm/libchrome.so">>,
                      module_version = <<"271AA00AC3831EF30E510AFFA178ADE0D">>,
                      module_offset = 22320895},
         #stack_frame{instruction_pointer = 2705747104,
                      module_name = <<"/data/app/com.mcent.browser-1/lib/arm/libchrome.so">>,
                      module_version = <<"271AA00AC3831EF30E510AFFA178ADE0D">>,
                      module_offset = 43764894},
         #stack_frame{instruction_pointer = 2684302873,
                      module_name = <<"/data/app/com.mcent.browser-1/lib/arm/libchrome.so">>,
                      module_version = <<"271AA00AC3831EF30E510AFFA178ADE0D">>,
                      module_offset = 22320663},
         #stack_frame{instruction_pointer = 2675753947,
                      module_name = <<"/data/app/com.mcent.browser-1/lib/arm/libchrome.so">>,
                      module_version = <<"271AA00AC3831EF30E510AFFA178ADE0D">>,
                      module_offset = 13771737},
         #stack_frame{instruction_pointer = 2705747104,
                      module_name = <<"/data/app/com.mcent.browser-1/lib/arm/libchrome.so">>,
                      module_version = <<"271AA00AC3831EF30E510AFFA178ADE0D">>,
                      module_offset = 43764894},
         #stack_frame{instruction_pointer = 3889566515,
                      module_name = <<"/system/lib/libc.so">>,
                      module_version = <<"B86C82365CAAFB74017F05B8C73125059">>,
                      module_offset = 398129},
         #stack_frame{instruction_pointer = 2665241589,
                      module_name = <<"/data/app/com.mcent.browser-1/lib/arm/libchrome.so">>,
                      module_version = <<"271AA00AC3831EF30E510AFFA178ADE0D">>,
                      module_offset = 3259379},
         #stack_frame{instruction_pointer = 2675754307,
                      module_name = <<"/data/app/com.mcent.browser-1/lib/arm/libchrome.so">>,
                      module_version = <<"271AA00AC3831EF30E510AFFA178ADE0D">>,
                      module_offset = 13772097},
         #stack_frame{instruction_pointer = 2673242505,
                      module_name = <<"/data/app/com.mcent.browser-1/lib/arm/libchrome.so">>,
                      module_version = <<"271AA00AC3831EF30E510AFFA178ADE0D">>,
                      module_offset = 11260295},
         #stack_frame{instruction_pointer = 2673242815,
                      module_name = <<"/data/app/com.mcent.browser-1/lib/arm/libchrome.so">>,
                      module_version = <<"271AA00AC3831EF30E510AFFA178ADE0D">>,
                      module_offset = 11260605},
         #stack_frame{instruction_pointer = 2673247499,
                      module_name = <<"/data/app/com.mcent.browser-1/lib/arm/libchrome."...>>,
                      module_version = <<"271AA00AC3831EF30E510AFFA178ADE0D">>,
                      module_offset = 11265289},
         #stack_frame{instruction_pointer = 2673220015,
                      module_name = <<"/data/app/com.mcent.browser-1/lib/arm/libchr"...>>,
                      module_version = <<"271AA00AC3831EF30E510AFFA178ADE0D">>,
                      module_offset = 11237805},
         #stack_frame{instruction_pointer = 2673264561,
                      module_name = <<"/data/app/com.mcent.browser-1/lib/arm/li"...>>,
                      module_version = <<"271AA00AC3831EF30E510AFFA178ADE0D">>,
                      module_offset = 11282351},
         #stack_frame{instruction_pointer = 2673264867,
                      module_name = <<"/data/app/com.mcent.browser-1/lib/ar"...>>,
                      module_version = <<"271AA00AC3831EF30E510AFFA178ADE0"...>>,
                      module_offset = 11282657},
         #stack_frame{instruction_pointer = 3889529893,
                      module_name = <<"/system/lib/libc.so">>,
                      module_version = <<"B86C82365CAAFB74017F05B8C731"...>>,
                      module_offset = 361507},
         #stack_frame{instruction_pointer = 2705747104,
                      module_name = <<"/data/app/com.mcent.browser-"...>>,
                      module_version = <<"271AA00AC3831EF30E510AFF"...>>,
                      module_offset = 43764894},
         #stack_frame{instruction_pointer = 3889566515,
                      module_name = <<"/system/lib/libc.so">>,
                      module_version = <<"B86C82365CAAFB74017F"...>>,
                      module_offset = 398129},
         #stack_frame{instruction_pointer = 2665241589,
                      module_name = <<"/data/app/com.mcent."...>>,
                      module_version = <<"271AA00AC3831EF3"...>>,
                      module_offset = 3259379},
         #stack_frame{instruction_pointer = 2703991540,
                      module_name = <<"/data/app/com.mc"...>>,
                      module_version = <<"271AA00AC383"...>>,
                      module_offset = 42009330},
         #stack_frame{instruction_pointer = 2674492439,
                      module_name = <<"/data/app/co"...>>,
                      module_version = <<"271AA00A"...>>,module_offset = 12510229},
         #stack_frame{instruction_pointer = 2674496339,
                      module_name = <<"/data/ap"...>>,
                      module_version = <<"271A"...>>,module_offset = 12514129},
         #stack_frame{instruction_pointer = 2665647845,
                      module_name = <<"/dat"...>>,module_version = <<...>>,...},
         #stack_frame{instruction_pointer = 2703991540,
                      module_name = <<...>>,...},
         #stack_frame{instruction_pointer = 3889515827,...},
         #stack_frame{...},
         {...}|...]}

