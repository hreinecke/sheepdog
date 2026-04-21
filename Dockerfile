FROM registry.opensuse.org/opensuse/bci/gcc
RUN zypper --non-interactive in automake autoconf libtool diffutils nasm
RUN zypper --non-interactive in liburcu-devel libjson-c-devel libuuid-devel libneon-devel
ENV SHEEPSRC=/usr/src/sheepdog

WORKDIR $SHEEPSRC
ADD . $SHEEPSRC
RUN ./autogen.sh
RUN CFLAGS="-fstack-protector -O" ./configure --prefix=/usr --enable-etcd --disable-corosync && make && make install
