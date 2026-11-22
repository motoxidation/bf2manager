FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends nasm binutils make && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY bf2am.asm md5tab.inc Makefile ./
RUN make

FROM scratch
COPY --from=build /src/bf2am /bf2am
ENTRYPOINT ["/bf2am"]
