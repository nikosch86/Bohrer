FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

# Copy only Go source files that affect the build
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux go build -o ssh-tunnel ./cmd/server

FROM alpine:latest
RUN apk --no-cache add ca-certificates openssh-client curl netcat-openbsd
WORKDIR /root/

COPY --from=builder /app/ssh-tunnel .

EXPOSE 22 80 443

CMD ["./ssh-tunnel"]