# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.4-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -buildid=" -o /out/mirrorsync ./cmd/mirrorsync

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/mirrorsync /mirrorsync

ENTRYPOINT ["/mirrorsync"]
