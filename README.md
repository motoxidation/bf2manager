# bf2manager

bf2 auto admin as an rcon client, written in x86-64 nasm (linux, no libc).

    make
    ./bf2am <ip> <port> <rcon password> [rules file]

edit `rules.conf`. needs rcon enabled on the server (port 4711 default).

`tests/run.sh` runs it against a fake server.

team balance / nfz: rcon doesnt expose teams or positions, so `shim/bf2am_shim.py` runs inside the server,
dumps players to a file and applies swap/kill lines bf2am writes back. same host/volume as bf2am.
shim is untested on a real server, tests only use the mock.
