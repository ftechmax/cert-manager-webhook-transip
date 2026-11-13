FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine AS build_deps
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

FROM build_deps AS build
ARG TARGETOS
ARG TARGETARCH
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags '-s -w' -o webhook .

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /workspace/webhook /usr/local/bin/webhook
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/webhook"]
