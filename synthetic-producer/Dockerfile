FROM golang:1.25.4-bookworm AS builder

WORKDIR /src

ARG TARGETOS=linux
ARG TARGETARCH=amd64

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/synthetic-producer ./synthetic-producer

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /out/synthetic-producer /usr/local/bin/synthetic-producer

CMD ["synthetic-producer"]
