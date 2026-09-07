package proxy

import (
	"net/url"
	"testing"
)

// TestCheckProxyProtocolSupport verifies that CheckProxyProtocolSupport returns
// no error for supported proxy types and an error for unsupported ones.
func TestCheckProxyProtocolSupport(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "socks5 scheme is supported",
			url:     "socks5://192.0.2.1:1080",
			wantErr: false,
		},
		{
			name:    "uppercase SOCKS5 scheme is supported",
			url:     "SOCKS5://192.0.2.1:1080",
			wantErr: false,
		},
		{
			name:    "http scheme is unsupported",
			url:     "http://192.0.2.1:8080",
			wantErr: true,
		},
		{
			name:    "https scheme is unsupported",
			url:     "https://192.0.2.1:8443",
			wantErr: true,
		},
		{
			name:    "socks4 scheme is unsupported",
			url:     "socks4://192.0.2.1:1080",
			wantErr: true,
		},
		{
			name:    "hostname with socks5 is supported",
			url:     "socks5://proxy.example.com:1080",
			wantErr: false,
		},
		{
			name:    "https hostname is unsupported",
			url:     "https://proxy.example.com:8443",
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := url.Parse(tc.url)
			if err != nil {
				t.Fatalf("url.Parse(%q) returned error: %v", tc.url, err)
			}
			err = CheckProxyProtocolSupport(parsed)
			if (err != nil) != tc.wantErr {
				t.Errorf("CheckProxyProtocolSupport() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
