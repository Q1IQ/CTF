FROM ubuntu:20.04

RUN apt update && apt-get -y dist-upgrade && \
    apt-get install -y llvm clang 

RUN useradd -m ctf

WORKDIR /home/ctf

RUN mkdir /home/ctf/dev && \
    mknod /home/ctf/dev/null c 1 3 && \
    mknod /home/ctf/dev/zero c 1 5 && \
    mknod /home/ctf/dev/random c 1 8 && \
    mknod /home/ctf/dev/urandom c 1 9 && \
    chmod 666 /home/ctf/dev/*

COPY opt /home/ctf/opt
COPY LLVMWhataPass.so /home/ctf/LLVMWhataPass.so
COPY example.c /home/ctf/example.c
COPY flag /flag

CMD /bin/bash
