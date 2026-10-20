FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY CFlix.ImageViewer.csproj ./
RUN dotnet restore

COPY . ./
RUN dotnet publish -c Release -o /out

FROM mcr.microsoft.com/dotnet/aspnet:10.0

RUN apt-get update \
    && apt-get install -y openssh-server tcpdump \
    && apt-get dist-upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && chmod 0755 /run/sshd \
    && groupadd pcap \
    && chgrp pcap /usr/bin/tcpdump \
    && chmod 750 /usr/bin/tcpdump \
    && useradd -ms /bin/bash cartman \
    && useradd -ms /bin/bash negan \
    && usermod -a -G pcap cartman \
    && ln -s /usr/bin/tcpdump /usr/local/bin/tcpdump \
    # Mot de passe de cartman (épreuve 7) : hash moderne (yescrypt, défaut
    # Debian) au lieu de l'ancien crypt DES. Le mot de passe reste identique.
    && echo 'cartman:CFl1X-R35p3c7_my_4u7h0r1t4h' | chpasswd

COPY [ "Dockerfiles/motd-challenge", "Dockerfiles/motd", "/etc/" ]
COPY Dockerfiles/sshd_config /etc/ssh/sshd_config

WORKDIR /app
ARG source
COPY --from=build /out ./
COPY Dockerfiles/run.sh Dockerfiles/capture_interessante.pcap ./

RUN chown -R negan:negan /app/* \
    && chmod -w /home/cartman \
    && chmod -w /home/negan \
    && chmod o-r /tmp \
    && chown cartman:cartman /app/capture_interessante.pcap \
    && chmod 400 /app/capture_interessante.pcap \
    && chown root:root /app/run.sh \
    && chmod 700 /app/run.sh \
    && chmod +r /app/wwwroot/images/6/*

EXPOSE 22222
EXPOSE 5000

WORKDIR /app

CMD ["./run.sh"]