module github.com/nats-io/nats-server/v2

go 1.25.0

toolchain go1.25.10

require (
	github.com/antithesishq/antithesis-sdk-go v0.7.0-default-no-op
	github.com/google/go-tpm v0.9.8
	github.com/klauspost/compress v1.18.6
	github.com/minio/highwayhash v1.0.4
	github.com/nats-io/jwt/v2 v2.8.2
	github.com/nats-io/nats.go v1.51.0
	github.com/nats-io/nkeys v0.4.16
	github.com/nats-io/nuid v1.0.1
	github.com/pion/dtls/v3 v3.1.4
	github.com/pion/transport/v3 v3.1.1
	golang.org/x/crypto v0.52.0
	golang.org/x/sys v0.45.0
	golang.org/x/time v0.15.0
)

require (
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v4 v4.0.1 // indirect
	golang.org/x/net v0.54.0 // indirect
)
