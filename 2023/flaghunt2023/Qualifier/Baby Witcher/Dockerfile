FROM ubuntu:22.04 AS app
RUN dpkg --add-architecture i386
RUN apt-get update && apt-get install -y libc6:i386 libncurses5:i386 libstdc++6:i386 && rm -rf /var/lib/apt/lists/*

FROM pwn.red/jail
COPY --from=app / /srv
COPY chal /srv/app/run
COPY flag.txt /srv/app/flag.txt
ENV JAIL_PORT=1569
