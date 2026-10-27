#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""v1340_pod.py — v1.34 step 7 (docs/security/v1.34-kubernetes.md): a
stand-in for the Warden that runs the agent as a pod's container under the
node agent, for the sweep (tests/v1340_sweep.sh). Given as a suite's WARDEN,

    v1340_pod.py POLICY [--sign-key K] [--anchor A] [--checkpoint-every N]
                 [--run-as USER] -- PROGRAM [ARG...]

starts a node agent with that policy (the real Warden, --node-agent, the
policy in a namespace's directory as the plugin's -sync writes it, the
launcher) and runs PROGRAM in a container runc starts, adjusted as VAREK's
NRI plugin adjusts a pod's (k8s/cmd/varek-nri): the Warden's filter in OCI's
form with the node agent's listener, the launcher first in its command and
bound at /varek/init, the policy's name and SHA-256 in its annotations, its
writable mounts noexec. The container's root is an overlay of the host's
root file system, read-only, as a pod's image is an overlay; /tmp is the
host's, writable and noexec, as a pod's volume (a program the suite made
there is put in the image, at /varek-sweep/NAME, and run from there). It runs as USER (default
65534, as the Warden runs an agent), with no capability and no new
privileges, in PID, IPC and mount namespaces of its own and the host's
network (where the suites' servers are; a pod's own network is
tests/test_v1340.sh section 7's).

Its standard output and error are the container's; the node agent's own
lines and then the container's stream follow on standard error, where the
Warden writes them, and it exits with the container's status. Every other
use of the Warden (other options, no program) runs the real Warden, and
each invocation is logged as carried or passed through, with why, to
$VAREK_SWEEP_LOG.

v1.36 step 4 (docs/security/v1.36-kubernetes-parity.md, D1 and D2): a
policy that names credentials, as a cluster carries it: each given to the
stand-in's namespace (sweep) from the source the policy names, in the
VarekCredential list beside the policy (POLICY_DIR/.credentials, as the
plugin's -sync writes it); the container's environment holding each one's
placeholder (VAREK_CRED_<NAME>), as the plugin sets it; and the node agent
given --node-credentials / (the suites' file stores are where they put them)
and the suite's own --secrets-conf, --secrets-as and --secrets-bin.

Environment (set by tests/v1340_sweep.sh): VAREK_SWEEP_DIR (its own
directory: hostroot, a bind of / with no submounts; ovl, a tmpfs),
VAREK_SWEEP_WARDEN, VAREK_SWEEP_LAUNCHER, VAREK_SWEEP_RUNC, VAREK_SWEEP_LOG,
VAREK_SWEEP_SUITE."""
import base64
import hashlib
import json
import os
import pwd
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

ENV = os.environ
D = ENV.get("VAREK_SWEEP_DIR", "")
WARDEN = ENV.get("VAREK_SWEEP_WARDEN", "")
LAUNCHER = ENV.get("VAREK_SWEEP_LAUNCHER", "")
RUNC = ENV.get("VAREK_SWEEP_RUNC", "runc")
LOG = ENV.get("VAREK_SWEEP_LOG", "")
SUITE = ENV.get("VAREK_SWEEP_SUITE", "-")

CARRIED = {"--sign-key", "--anchor", "--checkpoint-every",      # the node agent's own (D8)
           "--secrets-conf", "--secrets-as", "--secrets-bin"}   # v1.36 step 4: warden-secrets', as on a host
FORMS = {"--check-startup", "--check-credentials", "--oci-filter", "--node-agent", "--dry-run"}


def log(kind, why, argv):
    if LOG:
        try:
            with open(LOG, "a") as f:
                f.write(json.dumps({"suite": SUITE, "kind": kind, "why": why, "argv": argv}) + "\n")
        except OSError:
            pass                    # a suite's own limit (RLIMIT_FSIZE) on the Warden


def passthrough(why, argv):
    log("passed", why, argv)
    # Python ignores these; the Warden is to get them as the suite gives them
    for sig in (signal.SIGPIPE, signal.SIGXFSZ):
        signal.signal(sig, signal.SIG_DFL)
    os.execv(WARDEN, [WARDEN] + argv)


def parse(argv):
    """(policy, options for the node agent, run-as, program argv) or why not carried"""
    if "--" not in argv:
        return "no program (" + " ".join(a for a in argv if a.startswith("--")) + ")"
    i = argv.index("--")
    head, prog = argv[:i], argv[i + 1:]
    if not prog or not head:
        return "no program or no policy"
    policy, opts, run_as, j = head[0], [], None, 1
    while j < len(head):
        o = head[j]
        if o in FORMS:
            return "the form " + o
        if o in CARRIED and j + 1 < len(head):
            opts += [o, head[j + 1]]
        elif o == "--run-as" and j + 1 < len(head):
            run_as = head[j + 1]
        else:
            return "the option " + o + " (not the node agent's)"
        j += 2
    return policy, opts, run_as, prog


def user_of(spec):
    """--run-as's user as uid and gid (the Warden's forms: a name, uid, uid:gid)"""
    if spec is None:
        return 65534, 65534
    if spec == "root":
        return 0, 0
    u, colon, g = spec.partition(":")
    if colon and (not g or g == "0"):
        raise ValueError(spec)          # the Warden refuses an empty group, and group root
    if u.isdigit():
        if g and not g.isdigit():
            raise ValueError(spec)
        return int(u), int(g) if g else int(u)
    p = pwd.getpwnam(u)
    return p.pw_uid, p.pw_gid


def groups_of(spec, gid):
    """a user named by --run-as: its supplementary groups, as the Warden
    gives them, and a pod's runtime from the image's /etc/group; a uid (or
    uid:gid) has none, as under the Warden"""
    if spec is None or spec == "root" or spec.split(":")[0].isdigit():
        return []
    try:
        return [g for g in os.getgrouplist(spec, gid) if g != gid]
    except (KeyError, OSError):
        return []


def main():
    argv = sys.argv[1:]
    if not (D and WARDEN and LAUNCHER):
        sys.exit("v1340_pod.py: VAREK_SWEEP_DIR, VAREK_SWEEP_WARDEN and VAREK_SWEEP_LAUNCHER are needed")
    got = parse(argv)
    if isinstance(got, str):
        passthrough(got, argv)
    try:
        initial = open("/proc/self/uid_map").read().split() == ["0", "0", "4294967295"]
    except OSError:
        initial = False
    if os.geteuid() != 0 or not initial:
        # no node agent or runtime runs so: the Warden's own answer is the answer
        passthrough("not the node's root (a node agent runs as it)", argv)
    policy, opts, run_as, prog = got
    try:
        uid, gid = user_of(run_as)
    except (KeyError, ValueError):
        passthrough("a --run-as the Warden refuses", argv)
    if not os.path.isfile(policy):
        passthrough("the policy is not a file", argv)
    prog0 = prog[0]
    if not prog0.startswith("/"):
        # the plugin refuses a relative command; the Warden looks it up in
        # PATH: name it as the Warden would run it
        found = shutil.which(prog0)
        if not found:
            passthrough("the program is not found", argv)
        prog = [os.path.abspath(found)] + prog[1:]
    log("carried", "", argv)
    # the agent's umask is the caller's (the container's, below); this
    # stand-in's own files are made as the node's would be
    umask = os.umask(0o022)

    n = "%d-%d" % (os.getpid(), int(time.time() * 1000) % 100000)
    inv = os.path.join(D, "inv", n)
    pol_dir = os.path.join(inv, "pol")
    os.makedirs(os.path.join(pol_dir, "sweep"), mode=0o755)
    os.chmod(inv, 0o755)
    os.chmod(pol_dir, 0o755)
    os.chmod(os.path.join(pol_dir, "sweep"), 0o755)
    text = open(policy, "rb").read()
    pf = os.path.join(pol_dir, "sweep", "p.policy")
    with open(pf, "wb") as f:
        f.write(text)
    os.chmod(pf, 0o644)
    sha = hashlib.sha256(text).hexdigest()
    sock_dir = os.path.join(inv, "s")
    os.mkdir(sock_dir, 0o700)
    sock = os.path.join(sock_dir, "node.sock")
    streams = os.path.join(inv, "streams")
    os.mkdir(streams, 0o700)
    state = os.path.join(inv, "state")
    os.mkdir(state, 0o700)

    # v1.36 step 4 (D2): each credential the policy names given to this
    # namespace, from its source, as a cluster administrator's VarekCredential
    creds = re.findall(rb"(?m)^[ \t]*credential[ \t]+([a-z][a-z0-9_]*)[ \t]+from[ \t]+(\S+)", text)
    lp = os.path.join(pol_dir, ".credentials")
    with open(lp, "w") as f:
        f.write("# the sweep's VarekCredential list (tests/v1340_pod.py)\n")
        for name, src in creds:
            f.write("%s\tsweep\t%s\t%s\n" % (name.decode(), src.decode(errors="replace"), name.decode()))
    os.chmod(lp, 0o644)

    # the plugin's filter: the Warden's, from the policy's bytes
    fl = subprocess.run([WARDEN, pf, "--oci-filter", "--credential-list", lp, "--pod-namespace", "sweep"],
                        capture_output=True)
    if fl.returncode != 0:
        # the plugin refuses the container, which is not created
        # (the Warden's reason, naming the policy as the suite gave it, and its status)
        why = fl.stderr.decode(errors="replace").replace(pf, policy)
        sys.stderr.write(why)
        sys.stderr.write("v1340_pod: the plugin refuses the container: the Warden writes no filter for this policy\n")
        # the sweep's comparison reads it here (the suite keeps the stand-in's
        # standard error to itself): the evidence of a reason listed whole
        log("refused", why.strip()[-2000:] or "no filter", sys.argv[1:])
        shutil.rmtree(inv, ignore_errors=True)
        sys.exit(fl.returncode)
    filt = json.loads(fl.stdout)
    # v1.36 step 4 (D1): a placeholder for each credential, as the plugin makes one
    cred_env = ["VAREK_CRED_%s=varek_ph_%s_%s" % (c.upper(), c, base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))
                for c in filt.pop("varekCredentials", [])]

    agent_log = open(os.path.join(inv, "agent.log"), "w+")
    agent = subprocess.Popen([WARDEN, pol_dir, "--node-agent", sock, "--node-streams", streams,
                              "--node-launcher", LAUNCHER, "--node-credentials", "/"] + opts,
                             stdout=agent_log, stderr=agent_log)
    for _ in range(100):
        if os.path.exists(sock) or agent.poll() is not None:
            break
        time.sleep(0.05)

    # the root: an overlay of the host's root, the launcher's mount point in it
    up, wk, root = (os.path.join(D, "ovl", n, x) for x in ("up", "wk", "root"))
    for x in (up, wk, root):
        os.makedirs(x)
    os.makedirs(os.path.join(up, "varek"))
    open(os.path.join(up, "varek", "init"), "w").close()
    # the pod's /etc/resolv.conf, a file, as the kubelet gives each container:
    # the host's, read through its links (where it is a link into /run, as on
    # Ubuntu with systemd-resolved, the bind of / does not carry /run's mount,
    # and the node agent would find no nameserver for the policy's hosts)
    os.makedirs(os.path.join(up, "etc"))
    try:
        shutil.copyfile("/etc/resolv.conf", os.path.join(up, "etc", "resolv.conf"))
        os.chmod(os.path.join(up, "etc", "resolv.conf"), 0o644)
    except OSError as e:
        log("resolv.conf", "the host's /etc/resolv.conf does not read (%s): the container keeps the image's" % e, argv)
    # a program the suite made under /tmp, which is the container's writable
    # volume (noexec, D4), is put in the image, as a pod's program is
    if prog[0].startswith("/tmp/") and os.path.isfile(prog[0]):
        os.makedirs(os.path.join(up, "varek-sweep"), exist_ok=True)
        img = os.path.join("/varek-sweep", os.path.basename(prog[0]))
        shutil.copy2(prog[0], up + img)
        log("moved", "the program from /tmp into the image, at " + img, argv)
        prog = [img] + prog[1:]
    mounted = subprocess.run(["mount", "-t", "overlay", "overlay", "-o",
                              "lowerdir=%s/hostroot,upperdir=%s,workdir=%s" % (D, up, wk), root]).returncode == 0

    bundle = os.path.join(inv, "bundle")
    os.mkdir(bundle)
    subprocess.run([RUNC, "spec"], cwd=bundle, check=True)
    cfg_path = os.path.join(bundle, "config.json")
    c = json.load(open(cfg_path))
    cwd = os.getcwd()
    env = ["%s=%s" % kv for kv in ENV.items() if not kv[0].startswith("VAREK_SWEEP_") and not kv[0].startswith("VAREK_CRED_")]
    env += cred_env
    c["process"].update(terminal=False, args=["/varek/init", "--"] + prog, env=env,
                        user={"uid": uid, "gid": gid, "umask": umask,
                              "additionalGids": groups_of(run_as, gid)}, noNewPrivileges=True, cwd=cwd)
    c["process"]["capabilities"] = {k: [] for k in ("bounding", "effective", "permitted", "inheritable", "ambient")}
    c["root"] = {"path": root, "readonly": True}
    c["hostname"] = os.uname().nodename
    # the host's network, where the suites' servers are: the decisions are
    # compared on one network (a pod's own is test_v1340.sh section 7's)
    c["linux"]["namespaces"] = [x for x in c["linux"]["namespaces"] if x["type"] != "network"]
    meta = "sweep/%s/%s" % (SUITE, n)
    c["linux"]["seccomp"] = dict(filt, listenerPath=sock, listenerMetadata=meta)
    for m in c["mounts"]:
        # as the plugin makes a pod's writable mounts (kernel file systems apart)
        opts_m = m.setdefault("options", [])
        if m["type"] not in ("proc", "sysfs", "cgroup", "cgroup2", "mqueue", "devpts") and \
                "ro" not in opts_m and "noexec" not in opts_m:
            opts_m.append("noexec")
    c["mounts"].append({"destination": "/varek/init", "type": "bind", "source": LAUNCHER,
                        "options": ["bind", "ro", "nosuid", "nodev"]})
    c["mounts"].append({"destination": "/tmp", "type": "bind", "source": "/tmp",
                        "options": ["rbind", "rw", "nosuid", "nodev", "noexec", "rnosuid", "rnodev", "rnoexec"]})
    c["annotations"] = {"varek.dev/policy": "p", "varek.dev/policy-sha256": sha,
                        "varek.dev/pod-namespace": "sweep", "varek.dev/pod-name": SUITE.replace("_", "-")[:63] or "sweep",
                        "varek.dev/pod-uid": n, "varek.dev/container": "agent"}
    json.dump(c, open(cfg_path, "w"))

    cid = "sweep-" + n
    proc = None
    got = []

    def stop(signum, _frame):
        # the Warden signalled ends its agent (the container); the main
        # thread, waiting on runc, then finishes (waiting here too would
        # deadlock on the wait's lock)
        got.append(signum)
        subprocess.run([RUNC, "--root", state, "kill", cid, "KILL"], capture_output=True)
        if proc is None:
            finish(128 + signum)

    # the node agent's and the supervisor's lines name the policy as the
    # suite gave it, not by its copies (the stream keeps them)
    def named(t):
        t = re.sub(re.escape(streams) + r"/[^\s:\"]+\.policy", lambda _m: policy, t)
        return t.replace(pf, policy)

    # the node agent's lines and each stream reach standard error as they are
    # written, as the Warden's do (a suite reads them during the run): the
    # records as they are (chained), the text lines named
    sent = {}
    drain_lock = threading.Lock()    # the tail thread's and finish's: a line copied once

    def drain():
        with drain_lock:
            drain_locked()

    def drain_locked():
        files = [("agent", agent_log.name)] + [(p, os.path.join(streams, p)) for p in sorted(os.listdir(streams))
                                               if p.endswith(".jsonl")] if os.path.isdir(streams) else []
        for key, path in files:
            try:
                with open(path, "rb") as f:
                    f.seek(sent.get(key, 0))
                    data = f.read()
            except OSError:
                continue
            cut = data.rfind(b"\n") + 1            # whole lines only
            if not cut:
                continue
            sent[key] = sent.get(key, 0) + cut
            for line in data[:cut].decode(errors="replace").splitlines(keepends=True):
                sys.stderr.write(line if line.startswith("{") else named(line))
        sys.stderr.flush()

    stop_tail = threading.Event()

    def tail():
        while not stop_tail.wait(0.05):
            drain()

    tailer = threading.Thread(target=tail, daemon=True)

    def finish(rc):
        subprocess.run([RUNC, "--root", state, "delete", "-f", cid], capture_output=True)
        # the stream is whole once its supervisor has ended: after run_end it
        # may still wait on the anchor's reader (up to 10 s) and say so
        deadline = time.time() + 15
        while time.time() < deadline:
            sups = [p.rsplit(".", 2)[1] for p in os.listdir(streams) if p.endswith(".jsonl")]
            if sups and not any(os.path.exists("/proc/" + x) for x in sups if x.isdigit()):
                break
            if not sups and agent.poll() is not None:
                break
            time.sleep(0.05)
        agent.send_signal(signal.SIGTERM)
        try:
            agent.wait(5)
        except subprocess.TimeoutExpired:
            agent.kill()
        stop_tail.set()
        if tailer.is_alive():
            tailer.join(5)
        drain()
        if mounted:
            subprocess.run(["umount", "-l", root])
        shutil.rmtree(os.path.join(D, "ovl", n), ignore_errors=True)
        # the stream's policy copy stays (run_start's policy_path, which an
        # audit after the run reads); the rest goes
        if not ENV.get("VAREK_SWEEP_KEEP"):
            for x in ("bundle", "state", "pol", "s"):
                shutil.rmtree(os.path.join(inv, x), ignore_errors=True)
        os.write(watch_w, b"k")              # the watchdog stands down: an end of our own
        os._exit(rc)

    # the stand-in killed (SIGKILL, which it cannot catch) is the Warden
    # killed: a watchdog then kills the container's supervisor (its pid is in
    # the stream's name, CONTAINER.PID.jsonl); the node agent, seeing it end,
    # ends the container (test_v1340.sh section 5), and is then stopped.
    # Step 8 review (S5): only then: after an end of the stand-in's own
    # (finish), the supervisors have ended and their pids may be another's
    watch_r, watch_w = os.pipe()
    if os.fork() == 0:
        os.setsid()
        os.close(watch_w)
        if os.read(watch_r, 1) == b"k":      # finish() said so; EOF: the stand-in was killed
            os._exit(0)
        for p in os.listdir(streams) if os.path.isdir(streams) else []:
            if p.endswith(".jsonl"):
                try:
                    os.kill(int(p.rsplit(".", 2)[1]), signal.SIGKILL)
                except (ValueError, OSError):
                    pass
        for _ in range(100):
            st = subprocess.run([RUNC, "--root", state, "state", cid], capture_output=True, text=True)
            if st.returncode != 0 or '"status": "stopped"' in st.stdout:
                break
            time.sleep(0.05)
        try:
            os.kill(agent.pid, signal.SIGKILL)
        except OSError:
            pass
        os._exit(0)
    os.close(watch_r)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if not mounted or agent.poll() is not None:
        sys.stderr.write("v1340_pod: %s\n" % ("the overlay root did not mount" if not mounted else "the node agent did not start"))
        finish(125)
    tailer.start()
    proc = subprocess.Popen([RUNC, "--root", state, "run", "-b", bundle, cid])
    rc = proc.wait()
    finish(128 + got[0] if got else rc if rc >= 0 else 128 - rc)


if __name__ == "__main__":
    main()
