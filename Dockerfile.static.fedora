FROM registry.fedoraproject.org/fedora:latest
WORKDIR /build
RUN dnf update -y && \
    dnf install -y git make automake autoconf gcc glibc-static meson ninja-build clang

RUN git clone https://github.com/libfuse/libfuse && \
    cd libfuse && \
    mkdir build && \
    cd build && \
    LDFLAGS="-lpthread" meson --prefix /usr -D default_library=static .. && \
    ninja && \
    ninja install

RUN git clone https://github.com/containers/fuse-overlayfs && \
    cd fuse-overlayfs && \
    sh autogen.sh && \
    LIBS="-ldl" LDFLAGS="-static" ./configure --prefix /usr && \
    make && \
    make install
USER 1000
ENTRYPOINT ["/usr/bin/fuse-overlayfs","-f"]
