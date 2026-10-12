#!/usr/bin/env python3
"""MTProto FakeTLS probe: does the proxy at HOST:PORT accept this secret?

  tg-probe.py HOST PORT SECRET_HEX32 DOMAIN          -> exit 0 "accepted" / exit 1 "rejected"
  tg-probe.py HOST PORT SECRET_HEX32 DOMAIN --deep   -> also asks Telegram a question through the proxy

A Telegram client proves it knows the secret inside the TLS ClientHello (its `random` is an HMAC over the
hello keyed by the secret); the proxy answers with a ServerHello signed the same way. Anybody else is passed
to the real site, whose ServerHello carries no such signature. No Telegram account is needed for this check.

--deep goes one step further: inside the tunnel it opens an MTProto connection (obfuscated, padded
intermediate framing) and sends `req_pq_multi` — the first, unauthenticated message of any Telegram client. An answer
means the whole path works: client -> proxy -> Telegram data centre and back. A proxy that knows the secret
but refuses the user (disabled) or cannot reach Telegram gives no answer. Needs the `openssl` binary (AES-CTR).
"""
import hashlib
import hmac
import os
import socket
import struct
import subprocess
import sys
import time


def ext(kind, body):
    return struct.pack(">HH", kind, len(body)) + body


def client_hello(secret, domain):
    name = domain.encode()
    exts = b"".join([
        ext(0x0000, struct.pack(">HBH", len(name) + 3, 0, len(name)) + name),             # server_name
        ext(0x0017, b""), ext(0xff01, b"\x00"),
        ext(0x000a, struct.pack(">H", 8) + bytes.fromhex("001d001700180019")),            # supported_groups
        ext(0x000b, b"\x01\x00"),
        ext(0x0010, bytes.fromhex("000c02683208687474702f312e31")),                       # ALPN h2, http/1.1
        ext(0x000d, struct.pack(">H", 16) + bytes.fromhex("04030804040105030805050108060601")),
        ext(0x0033, struct.pack(">HHH", 36, 0x001d, 32) + os.urandom(32)),                # key_share x25519
        ext(0x002d, b"\x01\x01"),
        ext(0x002b, bytes.fromhex("0403040303")),                                         # TLS 1.3, 1.2
    ])
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x20" + os.urandom(32)
            + struct.pack(">H", 6) + bytes.fromhex("130113021303") + b"\x01\x00")
    pad = 512 - (len(body) + 2 + len(exts)) - 4 - 4
    exts += ext(0x0015, b"\x00" * max(pad, 0))
    body += struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    rec = bytearray(b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs)
    digest = bytearray(hmac.new(secret, bytes(rec), hashlib.sha256).digest())
    for i, b in enumerate(struct.pack("<I", int(time.time()))):
        digest[28 + i] ^= b
    rec[11:43] = digest
    return bytes(rec), bytes(digest)


def read_records(sock, want=3):
    """ServerHello, ChangeCipherSpec and the first ApplicationData record, as raw bytes."""
    buf = b""
    while True:
        pos = n = 0
        while pos + 5 <= len(buf):
            ln = struct.unpack(">H", buf[pos + 3:pos + 5])[0]
            if pos + 5 + ln > len(buf):
                break
            pos += 5 + ln
            n += 1
        if n >= want:
            return buf[:pos]
        chunk = sock.recv(65536)
        if not chunk:
            return buf
        buf += chunk


def mtproto_hello(secret):
    """Obfuscated2 header + req_pq_multi, already encrypted (bytes to put into TLS application data)."""
    while True:
        init = bytearray(os.urandom(64))
        if init[0] != 0xef and bytes(init[:4]) not in (b"HEAD", b"POST", b"GET ", b"OPTI", b"\x16\x03\x01\x02",
                                                       b"\xdd" * 4, b"\xee" * 4) and bytes(init[4:8]) != b"\0" * 4:
            break
    init[56:60] = b"\xdd" * 4                    # padded intermediate framing (the only one FakeTLS proxies take)
    init[60:62] = struct.pack("<h", 2)           # data centre 2
    msg = (b"\0" * 8 + struct.pack("<q", int(time.time() * 2 ** 32) & ~3) + struct.pack("<I", 20)
           + struct.pack("<I", 0xbe7e8ef1) + os.urandom(16))
    msg += os.urandom(2)                         # the padding of this framing
    plain = bytes(init) + struct.pack("<I", len(msg)) + msg
    key = hashlib.sha256(bytes(init[8:40]) + secret).hexdigest()
    enc = subprocess.run(["openssl", "enc", "-aes-256-ctr", "-K", key, "-iv", bytes(init[40:56]).hex()],
                         input=plain, capture_output=True, check=True).stdout
    return bytes(init[:56]) + enc[56:]


def telegram_answers(sock, secret):
    data = mtproto_hello(secret)
    sock.sendall(b"\x14\x03\x03\x00\x01\x01" + b"\x17\x03\x03" + struct.pack(">H", len(data)) + data)
    sock.settimeout(15)
    got = b""
    try:
        while len(got) < 5 + 40:                 # resPQ is ~80 bytes; anything of that size is an answer
            chunk = sock.recv(65536)
            if not chunk:
                break
            got += chunk
    except OSError:
        pass
    return len(got) >= 5 + 40 and got[0] == 0x17


def main():
    host, port, secret, domain = sys.argv[1], int(sys.argv[2]), bytes.fromhex(sys.argv[3]), sys.argv[4]
    hello, digest = client_hello(secret, domain)
    with socket.create_connection((host, port), timeout=10) as s:
        s.settimeout(10)
        s.sendall(hello)
        try:
            resp = bytearray(read_records(s))
        except OSError:
            resp = bytearray()
        if len(resp) < 43 or resp[0] != 0x16:
            print("rejected (no ServerHello)")
            return 1
        theirs = bytes(resp[11:43])
        resp[11:43] = b"\x00" * 32
        if not hmac.compare_digest(theirs, hmac.new(secret, digest + bytes(resp), hashlib.sha256).digest()):
            print("rejected (the answer is not signed with this secret: it is the real site)")
            return 1
        if "--deep" not in sys.argv:
            print("accepted")
            return 0
        if telegram_answers(s, secret):
            print("accepted, Telegram answered through the proxy")
            return 0
        print("rejected (the secret is known, but no answer from Telegram: user disabled or Telegram unreachable)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
