# --- builder ---
FROM golang:1.25 AS builder
WORKDIR /src

# Use module-aware builds and vendor if you want reproducible builds
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
COPY cmd cmd
COPY pkg pkg

ARG VERSION="dev"
ARG COMMIT="none"
ARG BUILD_DATE="unknown"

RUN ls -al
# static build, reproducible flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -X 'main.version=${VERSION}' -X 'main.commit=${COMMIT}' -X 'main.date=${BUILD_DATE}'" -o /out/conscan .

# --- final image (minimal) ---
FROM alpine:3.22 
COPY --from=builder /out/conscan /usr/local/bin/conscan

# Download other tools
RUN wget -qO-  https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.66.0
RUN wget -qO- https://get.anchore.io/grype | sh -s -- -b /usr/local/bin
RUN wget -qO- https://get.anchore.io/syft | sh -s -- -b /usr/local/bin
RUN wget -qO- https://github.com/wagoodman/dive/releases/download/v0.13.1/dive_0.13.1_linux_amd64.tar.gz | tar -xz -C /usr/local/bin dive
RUN wget -qO- https://github.com/goodwithtech/dockle/releases/download/v0.4.15/dockle_0.4.15_Linux-64bit.tar.gz | tar -xz -C /usr/local/bin dockle

# add healthcheck to make scanner happy  
HEALTHCHECK CMD [ "conscan", "--version" ]

# Make the cache dir for the user
RUN mkdir -p /.cache
RUN chown -R 65532:65532 /.cache
# Provide a non-root user (distroless provides user 65532)
USER 65532:65532



# OCI labels (important)
ARG VERSION
ARG COMMIT
ARG BUILD_DATE
LABEL org.opencontainers.image.title="conscan"
LABEL org.opencontainers.image.description="Scans Container Images"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.revision="${COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/peek8/conscan"

ENTRYPOINT ["/usr/local/bin/conscan"]

