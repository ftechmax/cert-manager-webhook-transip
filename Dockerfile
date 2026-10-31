FROM golang:1.27.3-alpine AS build_deps
RUN apk add --no-cache git
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

FROM build_deps AS build
COPY . .
RUN CGO_ENABLED=0 go build -o webhook -ldflags '-w -extldflags "-static"' .

FROM alpine:3.24
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 65532 nonroot \
    && adduser -S -u 65532 -G nonroot nonroot
COPY --from=build /workspace/webhook /usr/local/bin/webhook
USER 65532:65532
ENTRYPOINT ["webhook"]
