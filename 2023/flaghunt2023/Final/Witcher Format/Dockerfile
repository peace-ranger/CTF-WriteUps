FROM pwn.red/jail
COPY --from=ubuntu:22.04 / /srv
COPY chal /srv/app/run
COPY flag.txt /srv/app/flag.txt
ENV JAIL_PORT=1569
