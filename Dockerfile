FROM registry.opensuse.org/opensuse/bci/gcc
RUN zypper --non-interactive in automake
RUN zypper --non-interactive in autoconf
RUN zypper --non-interactive in libtool
RUN zypper --non-interactive in diffutils
RUN zypper --non-interactive in nasm
RUN zypper --non-interactive in liburcu-devel
RUN zypper --non-interactive in libjson-c-devel
RUN zypper --non-interactive in libuuid-devel
RUN zypper --non-interactive in libneon-devel
ENV SHEEPSRC /usr/src/sheepdog
ENV SHEEPPORT 7000
ENV SHEEPSTORE /store
ADD ./docker/corosync.conf /etc/corosync/corosync.conf
ADD ./docker/run.sh /root/run.sh

WORKDIR $SHEEPSRC
ADD . $SHEEPSRC
RUN ./autogen.sh
RUN ./configure --prefix=/usr --enable-etcd --disable-corosync && make && make check && make install

RUN mkdir $SHEEPSTORE

EXPOSE $SHEEPPORT
CMD /bin/bash /root/run.sh
