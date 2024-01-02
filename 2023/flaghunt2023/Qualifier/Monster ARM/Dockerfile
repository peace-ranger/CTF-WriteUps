FROM ubuntu:22.04 AS app
RUN apt-get update && apt-get install -y gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf && rm -rf /var/lib/apt/lists/*

FROM pwn.red/jail
COPY --from=app / /srv
COPY chal /srv/app/run
COPY flag.txt /srv/app/flag.txt
ENV JAIL_PORT=6969
