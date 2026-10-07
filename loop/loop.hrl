%% Shared declarations of the loop stress harness: the resolved
%% configuration, the per-worker result, the run handle every worker
%% carries, and the constants the units agree on.
%%
%% Erlang-specific. A header is how Erlang shares a record definition
%% across modules; a language whose modules can export types folds
%% these into the unit that owns them.

%% --goroutines ceiling; the harness targets modest hosts and each
%% worker pins a payload-sized binary for the whole run.
-define(LOOP_MAX_WORKERS, 10).

%% The concurrency mode this binding implements, as the summary
%% reports it (shared-handle / independent-handles / single).
-define(LOOP_CONCURRENCY, "shared-handle").

%% Largest slice fed to a stream session per write; the drain after
%% every write uses the same bound.
-define(LOOP_PUMP_SLICE, (1 bsl 20)).

%% Profiles the shape-based pair is built against when --profile is
%% empty.
-define(DEFAULT_STREAM_PROFILE, "streaming-aead-triple-mac-v1").
-define(DEFAULT_MESSAGE_PROFILE, "singlemsg-triple-mac-v1").

%% The primitive supplied for the parallax palette and the outer
%% cipher when a profile leaves them unnamed.
-define(KEYSTREAM_FILL_CIPHER, "aescmac").

%% The resolved command line. Shapes are the atoms stream / message /
%% stream_one_shot / both; payload modes the atoms fixed / rotating /
%% pattern_zero / pattern_ff / pattern_ascii.
-record(cfg, {
    duration_ns = 0,        %% run duration; ignored when iterations > 0
    iterations = 0,         %% per-worker count incl. warmup; 0 = duration-based
    workers_requested = 0,  %% the --goroutines value as given
    workers = 0,            %% the effective worker count
    shape = stream,
    hash = "",
    mac = "",
    payload = 0,            %% bytes per iteration
    memlimit = 0,           %% resolved bytes; the effective limit once shaped
    memlimit_auto = false,  %% --memlimit auto: cap only when the runtime has none
    gogc = 0,               %% 0 = leave the runtime default
    parallax = true,
    wrapper = true,
    profile = "",           %% empty = shape-based profile pair
    key_bits = 0,           %% 0 = profile default
    nonce_bits = 0,         %% 0 = profile default
    blob_mode = 1,          %% container floor sizing mode: 1 (per-region, default) | 2 (per-container)
    chunk_size = 0,         %% 0 = profile default
    barrier_fill = 0,       %% 0 = profile default
    drbg = "",              %% DRBG fill primitive; "" = profile default (auto tier)
    gomaxprocs = 0,         %% 0 = inherit from the environment
    rekey_every = 0,        %% per-worker iterations between rotations; 0 = never
    blob_cycle_every = 0,   %% per-worker iterations between reopens; 0 = never
    payload_mode = fixed,
    seed = 0,               %% 0 = OS CSPRNG plaintexts
    json_output = false,
    memprofile = ""         %% empty = none
}).

%% What one worker hands back when it returns: its counters, the
%% instant it finished, and the error it stopped on.
-record(wstats, {
    id = 0,
    iters = 0,
    bytes_enc = 0,
    bytes_dec = 0,
    nanos_enc = 0,
    nanos_dec = 0,
    finish_ns = 0,
    failed = false,
    error = ""
}).

%% The run handle every worker carries: the resolved configuration,
%% the pid of the state process that owns the Pipeline handles and
%% the lock, the atomics word holding the stop request, the counters
%% array behind the rekey and blob-cycle totals, and the two profile
%% names the log lines quote.
-record(run, {
    cfg,
    state,           %% pid of the loop_state process
    flags,           %% atomics ref; slot 1 is the stop request
    counts,          %% counters ref; 1 = rekeys, 2 = blob cycles
    stream_profile = "",
    msg_profile = ""
}).
