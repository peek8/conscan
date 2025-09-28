
# Get the minimum base
FROM alpine:3.22 

# This binary is coming from goreleaser
# GoReleaser builds the binary first and then injects it into the Docker build context when it runs docker build.
COPY conscan /usr/local/bin/conscan

# Accept values from GoReleaser or fallback defaults
ARG TARGETOS=linux
ARG TARGETARCH=amd64

ARG TRIVY_VERSION="0.66.0"
ARG GRYPE_VERSION="0.100.0"
ARG SYFT_VERSION="1.33.0"
ARG DIVE_VERSION="0.13.1"
ARG DOCKLE_VERSION="0.4.15"


RUN uname -m && uname -s && echo "Arg target os: ${TARGETOS}, arg target arch: ${TARGETARCH}}"

# Download other tools
RUN wget -qO-  https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${TRIVY_VERSION}
RUN wget -qO- https://get.anchore.io/grype | sh -s -- -b /usr/local/bin v${GRYPE_VERSION}
RUN wget -qO- https://get.anchore.io/syft | sh -s -- -b /usr/local/bin v${SYFT_VERSION}
RUN wget -qO- "https://github.com/wagoodman/dive/releases/download/v${DIVE_VERSION}/dive_${DIVE_VERSION}_${TARGETOS}_${TARGETARCH}.tar.gz" | tar -xz -C /usr/local/bin dive

RUN case "$TARGETARCH" in \
      amd64) export DOCKLE_DIST="dockle_${DOCKLE_VERSION}_Linux-64bit.tar.gz" ;; \
      arm64) export DOCKLE_DIST="dockle_${DOCKLE_VERSION}_Linux-ARM64.tar.gz" ;; \
      *) export DOCKLE_DIST="dockle_${DOCKLE_VERSION}_Linux-64bit.tar.gz" ;; \
    esac \
    && wget -qO- https://github.com/goodwithtech/dockle/releases/download/v${DOCKLE_VERSION}/${DOCKLE_DIST} | tar -xz -C /usr/local/bin dockle

# add healthcheck to make scanner happy  
HEALTHCHECK CMD [ "conscan", "--version" ]

# Make the cache dir for the user
RUN mkdir -p /.cache
# For docker config file
RUN mkdir -p /.docker
RUN chown -R 65532:65532 /.cache
RUN chown -R 65532:65532 /.docker
# Provide a non-root user (distroless provides user 65532)
USER 65532:65532


ENTRYPOINT ["/usr/local/bin/conscan"]

