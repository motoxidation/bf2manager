# bf2manager

bf2 auto admin as an rcon client, written in x86-64 nasm (linux, no libc).

    make
    ./bf2am <ip> <port> <rcon password> [rules file]

edit `rules.conf`. needs rcon enabled on the server (port 4711 default).

`tests/run.sh` runs it against a fake server.

todo: team balance, no fly zones (rcon doesnt give positions/teams afaik)
