package dtls

import "net"

// Config is a minimal legacy compatibility stub.
//
// Deprecated: use options APIs directly.
type Config struct {
	ServerName string
}

// Client is a legacy compatibility wrapper.
//
// Deprecated: use ClientWithOptions.
func Client(conn net.PacketConn, rAddr net.Addr, cfg *Config) (*Conn, error) {
	if cfg == nil || cfg.ServerName == "" {
		return ClientWithOptions(conn, rAddr)
	}
	return ClientWithOptions(conn, rAddr, WithServerName(cfg.ServerName))
}
