FROM golang:1.25.4-bookworm AS builder

WORKDIR /src

ARG TARGETOS=linux
ARG TARGETARCH=amd64

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/login-validator .

FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /out/login-validator /usr/local/bin/login-validator
COPY rules.yaml /app/rules.yaml

EXPOSE 8080 2112

CMD ["login-validator"]
