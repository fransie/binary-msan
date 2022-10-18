FROM alpine:latest
RUN apk update
RUN apk upgrade
RUN apk add bash
RUN apk add curl
RUN apk add make
RUN apk add gcc
RUN apk add g++
RUN apk add file
WORKDIR /home
COPY coreutils.sh /home
RUN chmod +x static-coreutils.sh
RUN ./static-coreutils.sh
ENTRYPOINT /bin/bash