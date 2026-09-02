# imquic's MoQ relay demo, as a container.
#
# Unlike moq-rs this project ships no Dockerfile and no image, so the build
# recipe lives here. It is an autotools C project over picoquic, and picoquic
# has to be built first, inside imquic's own source root, with position
# independent code — imquic's configure looks for it there and links it into a
# shared library, so a picoquic built anywhere else or without -fPIC is not
# found or does not link.
#
# # One image, several drafts
#
# imquic selects its draft two ways at once, and both matter here:
#
#   * from the ALPN, per connection, when the peer names one (`moqt-16` and
#     up); and
#   * from `--moq-draft-version`, as the fallback when the ALPN names no draft
#     — which is every connection in the `moq-00` cohort.
#
# So one container of a build that speaks 16-19 serves all four, because the
# client's ALPN picks; and a build that speaks the moq-00 cohort serves exactly
# the one draft its `-M` names, because nothing else can pick. The compose file
# runs one of the first kind and four of the second.
#
# # Two refs, because the floor moved
#
# imquic keeps one branch and raises its floor as drafts age out. Its v17 work
# removed every version below 16, so `main` today speaks 16 through 19 and
# nothing older. The commit before that removal is the newest one that still
# speaks the 11-14 cohort, and IMQUIC_REF selects between them.
ARG IMQUIC_REF=main

FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        cmake \
        pkg-config \
        autoconf \
        automake \
        libtool \
        libglib2.0-dev \
        libjansson-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --no-checkout https://github.com/meetecho/imquic .

# After the clone so a ref change does not re-run apt, before the build so it
# does re-run that.
ARG IMQUIC_REF
RUN git checkout "$IMQUIC_REF"

# In the source root, per imquic's README: its configure looks for ./picoquic
# and nowhere else. PICOQUIC_FETCH_PTLS makes the picotls dependency part of
# this build rather than another clone.
RUN git clone https://github.com/private-octopus/picoquic \
    && cd picoquic \
    && cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DPICOQUIC_FETCH_PTLS=Y . \
    && make -j"$(nproc)"

# `make install` runs the examples through libtool's install mode, so
# /usr/bin/imquic-moq-relay is the real executable rather than the wrapper
# script libtool leaves in the build tree. Both halves of the name matter: the
# target is `moq-relay` but the installed program is `imquic-moq-relay`, and
# copying the build-tree path instead produces a container that exits on a
# missing file.
RUN sh autogen.sh \
    && ./configure --prefix=/usr --enable-moq-examples \
    && make -j"$(nproc)" \
    && make install

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libglib2.0-0 \
        libjansson4 \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/lib/libimquic.so* /usr/lib/
COPY --from=build /usr/bin/imquic-moq-relay /usr/local/bin/imquic-moq-relay
RUN ldconfig

# The relay prints its own commit hash in the first line it logs, so no build
# stamp is recorded here: `just interop-logs` already answers which source a
# running container was built from, which is what a red run needs in order to
# tell a regression on this side from one upstream.

ENTRYPOINT ["/usr/local/bin/imquic-moq-relay"]
