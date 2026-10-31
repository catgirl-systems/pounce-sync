# static cgo build (the sqlite driver is cgo), then a scratch image running as non-root
FROM golang:1.26-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -tags 'sqlite_omit_load_extension osusergo netgo' \
      -ldflags '-s -w -linkmode external -extldflags "-static"' -o /out/pounce-sync ./cmd/pounce-sync \
 && mkdir -p /out/data /out/tmp && chmod 1777 /out/tmp

FROM scratch
COPY --from=build /out/pounce-sync /pounce-sync
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build /out/tmp /tmp
USER 65532:65532
# pounce-sync.toml and the default pounce-sync.db both resolve inside /data
WORKDIR /data
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/pounce-sync"]
CMD ["serve"]
