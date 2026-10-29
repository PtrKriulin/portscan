FROM golang:1.25-alpine AS build
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY cmd ./cmd
RUN CGO_ENABLED=1 go test -race -count=1 ./...
RUN CGO_ENABLED=0 go build -ldflags='-s -w' -o /out/portscan-cli ./cmd/portscan-cli

FROM alpine:3.20
COPY --from=build /out/portscan-cli /usr/local/bin/portscan-cli
ENTRYPOINT ["portscan-cli"]
