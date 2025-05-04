module github.com/Noooste/utls

go 1.24

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	github.com/andybalholm/brotli v1.1.1
	github.com/cloudflare/circl v1.6.1
	github.com/klauspost/compress v1.18.0
	golang.org/x/crypto v0.37.0
	golang.org/x/net v0.39.0
	golang.org/x/sys v0.32.0
)

require golang.org/x/text v0.24.0 // indirect
