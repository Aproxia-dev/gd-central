# --- Build Stage ---
FROM golang:1.24.4 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN apt-get update && apt-get install -y ca-certificates
RUN go mod download

COPY . .

RUN go build -o gdcentral ./cmd/gdcentral

# --- Run Stage ---
FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/gdcentral .

CMD ["./gdcentral"]
