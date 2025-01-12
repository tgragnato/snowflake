package utls

import (
	stdcontext "context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/net/http2"
)

// note that we use the insecure math/rand/v2 here because some platforms
// fail the test suite at build time in Debian, due to entropy starvation.
// since that's not a problem at test time, we do *not* use a secure
// mechanism for key generation.
//
// DO NOT REUSE THIS CODE IN PRODUCTION, IT IS DANGEROUS

type insecureReader struct {
	r *mrand.Rand
}

func (ir *insecureReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = byte(ir.r.Int64() & 0xff)
	}
	return len(p), nil
}

func TestRoundTripper(t *testing.T) {
	t.Parallel()

	runRoundTripperTest(t, "127.0.0.1:23802", "127.0.0.1:23801", "https://127.0.0.1:23802/", "https://127.0.0.1:23801/")
}

func TestRoundTripperOnH1DefaultPort(t *testing.T) {
	t.Parallel()

	if os.Getuid() != 0 {
		t.SkipNow()
	}
	runRoundTripperTest(t, "127.0.0.1:23802", "127.0.0.1:443", "https://127.0.0.1:23802/", "https://127.0.0.1/")
}

func TestRoundTripperOnH2DefaultPort(t *testing.T) {
	t.Parallel()

	if os.Getuid() != 0 {
		t.SkipNow()
	}
	runRoundTripperTest(t, "127.0.0.1:443", "127.0.0.1:23801", "https://127.0.0.1/", "https://127.0.0.1:23801/")
}

func runRoundTripperTest(t *testing.T, h2listen, h1listen, h2addr, h1addr string) {
	var selfSignedCert []byte
	var selfSignedPrivateKey *rsa.PrivateKey
	httpServerContext, cancel := stdcontext.WithCancel(stdcontext.Background())
	Convey("[Test]Set up http servers", t, func(c C) {
		c.Convey("[Test]Generate Self-Signed Cert", func(c C) {
			priv, err := rsa.GenerateKey(rand.Reader, 4096)
			if err != nil {
				insecureRandReader := mrand.New(mrand.NewPCG(uint64(time.Now().UnixNano()), 1))
				priv, err = rsa.GenerateKey(&insecureReader{r: insecureRandReader}, 4096)
			}
			c.So(err, ShouldBeNil)
			template := x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					CommonName: "Testing Certificate",
				},
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(time.Hour * 24 * 180),

				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
			}
			derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
			if err != nil {
				insecureRandReader := mrand.New(mrand.NewPCG(uint64(time.Now().UnixNano()), 1))
				derBytes, err = x509.CreateCertificate(&insecureReader{r: insecureRandReader}, &template, &template, priv.Public(), priv)
			}
			c.So(err, ShouldBeNil)
			selfSignedPrivateKey = priv
			selfSignedCert = derBytes
		})
		c.Convey("[Test]Setup http2 server", func(c C) {
			listener, err := tls.Listen("tcp", h2listen, &tls.Config{
				NextProtos: []string{http2.NextProtoTLS},
				Certificates: []tls.Certificate{
					{Certificate: [][]byte{selfSignedCert}, PrivateKey: selfSignedPrivateKey},
				},
			})
			c.So(err, ShouldBeNil)
			s := http.Server{}
			go s.Serve(listener)
			go func() {
				<-httpServerContext.Done()
				s.Close()
			}()
		})
		c.Convey("[Test]Setup http1 server", func(c C) {
			listener, err := tls.Listen("tcp", h1listen, &tls.Config{
				NextProtos: []string{"http/1.1"},
				Certificates: []tls.Certificate{
					{Certificate: [][]byte{selfSignedCert}, PrivateKey: selfSignedPrivateKey},
				},
			})
			c.So(err, ShouldBeNil)
			s := http.Server{}
			go s.Serve(listener)
			go func() {
				<-httpServerContext.Done()
				s.Close()
			}()
		})
	})
	for _, v := range []struct {
		id   utls.ClientHelloID
		name string
	}{
		{
			id:   utls.HelloChrome_58,
			name: "HelloChrome_58",
		},
		{
			id:   utls.HelloChrome_62,
			name: "HelloChrome_62",
		},
		{
			id:   utls.HelloChrome_70,
			name: "HelloChrome_70",
		},
		{
			id:   utls.HelloChrome_72,
			name: "HelloChrome_72",
		},
		{
			id:   utls.HelloChrome_83,
			name: "HelloChrome_83",
		},
		{
			id:   utls.HelloFirefox_55,
			name: "HelloFirefox_55",
		},
		{
			id:   utls.HelloFirefox_55,
			name: "HelloFirefox_55",
		},
		{
			id:   utls.HelloFirefox_63,
			name: "HelloFirefox_63",
		},
		{
			id:   utls.HelloFirefox_65,
			name: "HelloFirefox_65",
		},
		{
			id:   utls.HelloIOS_11_1,
			name: "HelloIOS_11_1",
		},
		{
			id:   utls.HelloIOS_12_1,
			name: "HelloIOS_12_1",
		},
	} {
		t.Run("Testing fingerprint for "+v.name, func(t *testing.T) {
			rtter := NewUTLSHTTPRoundTripper(v.id, &utls.Config{
				InsecureSkipVerify: true,
			}, http.DefaultTransport, false)

			for count := 0; count <= 10; count++ {
				Convey("HTTP 1.1 Test", t, func(c C) {
					{
						req, err := http.NewRequest("GET", h2addr, nil)
						So(err, ShouldBeNil)
						_, err = rtter.RoundTrip(req)
						So(err, ShouldBeNil)
					}
				})

				Convey("HTTP 2 Test", t, func(c C) {
					{
						req, err := http.NewRequest("GET", h1addr, nil)
						So(err, ShouldBeNil)
						_, err = rtter.RoundTrip(req)
						So(err, ShouldBeNil)
					}
				})
			}
		})
	}

	cancel()
}
