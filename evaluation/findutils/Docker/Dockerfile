FROM alpine:latest
RUN apk update
RUN apk upgrade
RUN apk add curl
RUN apk add gcc
RUN apk add g++
RUN apk add make
RUN apk add bash
WORKDIR /home
COPY findutils.sh /home
RUN chmod +x findutils.sh
#RUN ./findutils.sh
ENTRYPOINT /bin/bash