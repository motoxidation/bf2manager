import socket, hashlib, random, string, sys, threading, time

PW = "hunter2"
players = {0: ("Alice", "10.0.0.1"), 1: ("xXcheaterXx", "10.0.0.2"), 2: ("Bob", "6.6.6.6")}
cmds = []

def serve(port, pw=PW):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(1)
    while True:
        c, _ = s.accept()
        seed = "".join(random.choice(string.ascii_letters) for _ in range(16))
        c.sendall(("### Battlefield 2 default RCON/admin ready.\n### Digest seed: %s\n" % seed).encode())
        buf = b""
        authed = False
        try:
            while True:
                d = c.recv(4096)
                if not d: break
                buf += d
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.decode().strip()
                    if line.startswith("login "):
                        ok = line[6:] == hashlib.md5((seed + pw).encode()).hexdigest()
                        authed = ok
                        c.sendall(b"Authentication successful, rcon ready.\n" if ok else b"Authentication failed.\n")
                    elif authed:
                        cmds.append(line)
                        print("CMD", line, flush=True)
                        if line == "exec admin.listPlayers":
                            out = "".join("Id: %d - Name: %s is remote ip: %s:5000\n" % (i, n, ip) for i, (n, ip) in players.items())
                            c.sendall(out.encode())
                        elif line.startswith("exec admin.kickPlayer ") or line.startswith("exec admin.banPlayer "):
                            players.pop(int(line.split()[2]), None)
                            c.sendall(b"ok\n")
        except OSError:
            pass
        c.close()

if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 4711)
