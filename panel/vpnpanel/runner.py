"""Run awgctl on a VPN server: locally (through sudo) or over SSH (forced command on the far side)."""
import json
import os
import shlex
import subprocess


class CtlError(Exception):
    pass


def command(cfg, server, args):
    if server["transport"] == "local":
        base = (["sudo", "-n"] if cfg["use_sudo"] else []) + [cfg["awgctl"]]
        return base + list(args)
    run_dir = cfg["run_dir"]
    return ["ssh", "-i", server["ssh_key"], "-p", str(server.get("ssh_port", 22)),
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={os.path.join(os.path.dirname(cfg['db']), 'known_hosts')}",
            "-o", "ControlMaster=auto", "-o", f"ControlPath={run_dir}/ssh-%C", "-o", "ControlPersist=300",
            f"{server.get('ssh_user', 'root')}@{server['ssh_host']}",
            "awgctl " + " ".join(shlex.quote(str(a)) for a in args)]


def run(cfg, server, *args, stdin="", timeout=40):
    try:
        p = subprocess.run(command(cfg, server, args), input=stdin, capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        raise CtlError(f"{server['id']}: timeout")
    out = p.stdout.strip()
    try:
        data = json.loads(out.splitlines()[-1]) if out else None
    except json.JSONDecodeError:
        data = None
    if data is None:
        raise CtlError(f"{server['id']}: {p.stderr.strip()[:300] or 'no output'}")
    if isinstance(data, dict) and "error" in data:
        raise CtlError(f"{server['id']}: {data['error']}")
    return data
