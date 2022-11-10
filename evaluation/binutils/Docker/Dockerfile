FROM alpine:3.16
RUN apk update
RUN apk upgrade
RUN apk add curl
RUN apk add gcc
RUN apk add g++
RUN apk add make
RUN apk add bash
RUN apk add file
RUN apk add bison
RUN apk add elfutils
WORKDIR /home
COPY binutils.sh /home
RUN chmod +x binutils.sh
RUN ./binutils.sh
ENTRYPOINT /bin/bash