// SPDX-License-Identifier: MIT
//
// es_probe.c — the measurements of docs/security/macos-endpoint-security.md
// (M1 to M4): a minimal Endpoint Security client that supervises one
// command and its children, answers each AUTH event from a fixed rule, and
// records how long each answer took against the message's deadline.
//
//   varek-es-probe [--log FILE] [--deny-write PREFIX] [--deny-exec PATH]
//                  [--delay-us N] [--cache] -- CMD [ARGS...]
//
// It must run as root, signed with the Endpoint Security entitlement (its
// bundle: build_sign.sh), and approved for Full Disk Access. It starts CMD
// held, selects it (inverted muting by its audit token: only the selected
// processes' events come), lets it run, selects each child it forks
// (NOTIFY_FORK), and answers:
//   AUTH_OPEN    the flags asked, less FWRITE under --deny-write (M3)
//   AUTH_CREATE, AUTH_UNLINK, AUTH_RENAME, AUTH_TRUNCATE
//                denied under --deny-write, else allowed
//   AUTH_EXEC    denied for --deny-exec, else allowed
// Each answer is one JSON line in --log (default stderr): the event, the
// pid, the path, the flags, the answer, the time from the event to the
// answer and the time left before the deadline, in microseconds, and the
// whole time the system allowed (its deadline less the event's time), in
// milliseconds (M1).
// --delay-us N waits N microseconds before every answer, to find where the
// deadline is and what happens past it (M1). --cache lets the kernel cache
// the answers (M4). At CMD's exit a summary goes to stdout.
//
// Not built in CI: it needs the macOS SDK. Built and run on an EC2 Mac.

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <dispatch/dispatch.h>
#include <sys/fcntl.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef FWRITE
#define FWRITE 0x0002
#endif

static const char *g_deny_write = NULL;   // a path prefix
static const char *g_deny_exec = NULL;    // a path
static long g_delay_us = 0;
static bool g_cache = false;
static FILE *g_log;
static mach_timebase_info_data_t g_tb;
static dispatch_queue_t g_logq;

#define MAXS 200000
static uint64_t g_lat[MAXS];              // ns, event to answer
static int64_t g_left_min = INT64_MAX;    // ns, the least time left before a deadline
static _Atomic long g_n, g_denied, g_forks;

static uint64_t to_ns(uint64_t mach) { return mach * g_tb.numer / g_tb.denom; }

static void jstr(FILE *f, const char *s, size_t n) {
    fputc('"', f);
    for (size_t i = 0; i < n && s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') fprintf(f, "\\%c", c);
        else if (c < 0x20) fprintf(f, "\\u%04x", c);
        else fputc(c, f);
    }
    fputc('"', f);
}

static bool under(const char *path, const char *prefix) {
    return prefix && path && strncmp(path, prefix, strlen(prefix)) == 0;
}

static void path_of(const es_file_t *f, char *out, size_t n) {
    snprintf(out, n, "%.*s", (int)f->path.length, f->path.data);
}

static void new_path_of(const es_file_t *dir, es_string_token_t name, char *out, size_t n) {
    snprintf(out, n, "%.*s/%.*s", (int)dir->path.length, dir->path.data, (int)name.length, name.data);
}

static void record(const es_message_t *m, const char *ev, const char *path, long flags,
                   const char *answer, uint64_t lat_ns, int64_t left_ns) {
    // the whole time the system gave this answer: its deadline less its time (M1)
    int64_t budget_ns = (int64_t)to_ns(m->deadline) - (int64_t)to_ns(m->mach_time);
    pid_t pid = audit_token_to_pid(m->process->audit_token);
    long i = atomic_fetch_add(&g_n, 1);
    if (i < MAXS) g_lat[i] = lat_ns;
    char *pathc = strdup(path);           // the caller's buffer is gone when the block runs
    dispatch_async(g_logq, ^{
        if (left_ns < g_left_min) g_left_min = left_ns;
        fprintf(g_log, "{\"event\":\"%s\",\"pid\":%d,\"path\":", ev, pid);
        jstr(g_log, pathc ? pathc : "", pathc ? strlen(pathc) : 0);
        free(pathc);
        fprintf(g_log, ",\"flags\":%ld,\"answer\":\"%s\",\"latency_us\":%.1f,\"left_us\":%.1f,\"budget_ms\":%.1f}\n",
                flags, answer, lat_ns / 1000.0, left_ns / 1000.0, budget_ns / 1e6);
        fflush(g_log);
    });
}

static void handle(es_client_t *c, const es_message_t *m) {
    char p[2048] = "";
    if (m->event_type == ES_EVENT_TYPE_NOTIFY_FORK) {
        // M2: select the child; an event of its before this is not seen
        es_mute_process(c, &m->event.fork.child->audit_token);
        atomic_fetch_add(&g_forks, 1);
        return;
    }
    if (m->action_type != ES_ACTION_TYPE_AUTH) return;
    if (g_delay_us > 0) usleep((useconds_t)g_delay_us);
    const char *ev = "?", *ans = "allow";
    long flags = -1;
    bool deny = false;
    switch (m->event_type) {
    case ES_EVENT_TYPE_AUTH_OPEN: {
        ev = "open";
        path_of(m->event.open.file, p, sizeof p);
        flags = m->event.open.fflag;
        uint32_t allowed = (uint32_t)m->event.open.fflag;
        if (under(p, g_deny_write) && (allowed & FWRITE)) {
            allowed &= ~(uint32_t)FWRITE;      // M3: read allowed, write not
            ans = "read_only";
            atomic_fetch_add(&g_denied, 1);
        }
        uint64_t now = mach_absolute_time();
        es_respond_flags_result(c, m, allowed, g_cache);
        record(m, ev, p, flags, ans, to_ns(now - m->mach_time), (int64_t)to_ns(m->deadline) - (int64_t)to_ns(now));
        return;
    }
    case ES_EVENT_TYPE_AUTH_EXEC:
        ev = "exec";
        path_of(m->event.exec.target->executable, p, sizeof p);
        deny = g_deny_exec && strcmp(p, g_deny_exec) == 0;
        break;
    case ES_EVENT_TYPE_AUTH_CREATE:
        ev = "create";
        if (m->event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE)
            path_of(m->event.create.destination.existing_file, p, sizeof p);
        else
            new_path_of(m->event.create.destination.new_path.dir, m->event.create.destination.new_path.filename, p, sizeof p);
        deny = under(p, g_deny_write);
        break;
    case ES_EVENT_TYPE_AUTH_UNLINK:
        ev = "unlink";
        path_of(m->event.unlink.target, p, sizeof p);
        deny = under(p, g_deny_write);
        break;
    case ES_EVENT_TYPE_AUTH_TRUNCATE:
        ev = "truncate";
        path_of(m->event.truncate.target, p, sizeof p);
        deny = under(p, g_deny_write);
        break;
    case ES_EVENT_TYPE_AUTH_RENAME: {
        ev = "rename";
        char q[2048] = "";
        path_of(m->event.rename.source, p, sizeof p);
        if (m->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE)
            path_of(m->event.rename.destination.existing_file, q, sizeof q);
        else
            new_path_of(m->event.rename.destination.new_path.dir, m->event.rename.destination.new_path.filename, q, sizeof q);
        deny = under(p, g_deny_write) || under(q, g_deny_write);
        strncat(p, " -> ", sizeof p - strlen(p) - 1);
        strncat(p, q, sizeof p - strlen(p) - 1);
        break;
    }
    default:
        break;
    }
    if (deny) { ans = "deny"; atomic_fetch_add(&g_denied, 1); }
    uint64_t now = mach_absolute_time();
    es_respond_auth_result(c, m, deny ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW, g_cache);
    record(m, ev, p, flags, ans, to_ns(now - m->mach_time), (int64_t)to_ns(m->deadline) - (int64_t)to_ns(now));
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static int usage(void) {
    fprintf(stderr, "usage: varek-es-probe [--log FILE] [--deny-write PREFIX] [--deny-exec PATH] "
                    "[--delay-us N] [--cache] -- CMD [ARGS...]\n");
    return 2;
}

int main(int argc, char **argv) {
    int i = 1;
    const char *logp = NULL;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { i++; break; }
        else if (!strcmp(argv[i], "--log") && i + 1 < argc) logp = argv[++i];
        else if (!strcmp(argv[i], "--deny-write") && i + 1 < argc) g_deny_write = argv[++i];
        else if (!strcmp(argv[i], "--deny-exec") && i + 1 < argc) g_deny_exec = argv[++i];
        else if (!strcmp(argv[i], "--delay-us") && i + 1 < argc) g_delay_us = atol(argv[++i]);
        else if (!strcmp(argv[i], "--cache")) g_cache = true;
        else return usage();
    }
    if (i >= argc) return usage();
    mach_timebase_info(&g_tb);
    g_log = logp ? fopen(logp, "w") : stderr;
    if (!g_log) { perror(logp); return 2; }
    g_logq = dispatch_queue_create("varek.esprobe.log", DISPATCH_QUEUE_SERIAL);

    es_client_t *client = NULL;
    es_new_client_result_t r = es_new_client(&client, ^(es_client_t *c, const es_message_t *m) { handle(c, m); });
    if (r != ES_NEW_CLIENT_RESULT_SUCCESS) {
        const char *why =
            r == ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED ? "not entitled (the signature or the profile)" :
            r == ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED ? "not permitted (Full Disk Access not approved: M6)" :
            r == ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED ? "not root" :
            r == ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS ? "too many clients" : "another error";
        fprintf(stderr, "es_probe: es_new_client: %s (%d)\n", why, (int)r);
        return 3;
    }
    if (es_invert_muting(client, ES_MUTE_INVERSION_TYPE_PROCESS) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_probe: es_invert_muting failed (macOS 13 or later is needed)\n");
        return 3;
    }
    es_event_type_t evs[] = { ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_AUTH_CREATE,
                              ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_AUTH_TRUNCATE,
                              ES_EVENT_TYPE_NOTIFY_FORK };
    if (es_subscribe(client, evs, sizeof evs / sizeof evs[0]) != ES_RETURN_SUCCESS) {
        fprintf(stderr, "es_probe: es_subscribe failed\n");
        return 3;
    }

    // CMD, held until it is selected: a pipe it reads one byte from
    int go[2];
    if (pipe(go) != 0) { perror("pipe"); return 2; }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }
    if (pid == 0) {
        char b;
        close(go[1]);
        if (read(go[0], &b, 1) != 1) _exit(126);
        close(go[0]);
        execvp(argv[i], &argv[i]);
        fprintf(stderr, "es_probe: exec %s: %s\n", argv[i], strerror(errno));
        _exit(127);
    }
    close(go[0]);
    mach_port_t task = MACH_PORT_NULL;
    audit_token_t tok;
    mach_msg_type_number_t cnt = TASK_AUDIT_TOKEN_COUNT;
    if (task_name_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS ||
        task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&tok, &cnt) != KERN_SUCCESS) {
        fprintf(stderr, "es_probe: the command's audit token could not be read\n");
        kill(pid, SIGKILL);
        return 3;
    }
    es_mute_process(client, &tok);         // inverted: selected
    if (write(go[1], "x", 1) != 1) { kill(pid, SIGKILL); return 3; }
    close(go[1]);

    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    es_unsubscribe_all(client);
    es_delete_client(client);
    dispatch_sync(g_logq, ^{});

    long n = atomic_load(&g_n);
    long k = n < MAXS ? n : MAXS;
    qsort(g_lat, (size_t)k, sizeof g_lat[0], cmp_u64);
    printf("es_probe: %ld AUTH answers (%ld denied), %ld forks selected; command exit %d\n",
           n, atomic_load(&g_denied), atomic_load(&g_forks), WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st));
    if (k > 0)
        printf("es_probe: event to answer p50 %.1f us, p99 %.1f us, max %.1f us; least time left before a deadline %.1f ms\n",
               g_lat[k / 2] / 1000.0, g_lat[(k * 99) / 100] / 1000.0, g_lat[k - 1] / 1000.0, g_left_min / 1e6);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}
