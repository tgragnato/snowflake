package main

import (
	"bytes"
	"container/heap"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"tgragnato.it/snowflake/common/amp"
	"tgragnato.it/snowflake/common/messages"
)

func NullLogger() *log.Logger {
	logger := log.New(os.Stdout, "", 0)
	logger.SetOutput(io.Discard)
	return logger
}

var (
	sdp = "v=0\r\n" +
		"o=- 123456789 987654321 IN IP4 0.0.0.0\r\n" +
		"s=-\r\n" +
		"t=0 0\r\n" +
		"a=fingerprint:sha-256 12:34\r\n" +
		"a=extmap-allow-mixed\r\n" +
		"a=group:BUNDLE 0\r\n" +
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
		"c=IN IP4 0.0.0.0\r\n" +
		"a=setup:actpass\r\n" +
		"a=mid:0\r\n" +
		"a=sendrecv\r\n" +
		"a=sctp-port:5000\r\n" +
		"a=ice-ufrag:CoVEaiFXRGVzshXG\r\n" +
		"a=ice-pwd:aOrOZXraTfFKzyeBxIXYYKjSgRVPGhUx\r\n" +
		"a=candidate:1000 1 udp 2000 8.8.8.8 3000 typ host\r\n" +
		"a=end-of-candidates\r\n"

	sid = "ymbcCMto7KHNGYlp"
)

func createClientOffer(sdp, nat, fingerprint string) (*bytes.Reader, error) {
	clientRequest := &messages.ClientPollRequest{
		Offer:       sdp,
		NAT:         nat,
		Fingerprint: fingerprint,
	}
	encOffer, err := clientRequest.EncodeClientPollRequest()
	if err != nil {
		return nil, err
	}
	offer := bytes.NewReader(encOffer)
	return offer, nil
}

func createProxyAnswer(sdp, sid string) (*bytes.Reader, error) {
	proxyRequest, err := messages.EncodeAnswerRequest(sdp, sid)
	if err != nil {
		return nil, err
	}
	answer := bytes.NewReader(proxyRequest)
	return answer, nil
}

func decodeAMPArmorToString(r io.Reader) (string, error) {
	dec, err := amp.NewArmorDecoder(r)
	if err != nil {
		return "", err
	}
	p, err := io.ReadAll(dec)
	return string(p), err
}

func TestBroker(t *testing.T) {
	t.Parallel()

	defaultBridgeValue, _ := hex.DecodeString("2B280B23E1107BB62ABFC40DDCC8824814F80A72")
	var defaultBridge [20]byte
	copy(defaultBridge[:], defaultBridgeValue)

	Convey("Context", t, func() {
		buf := new(bytes.Buffer)
		ctx := NewBrokerContext(log.New(buf, "", 0), "snowflake.torproject.net")
		i := &IPC{ctx}

		Convey("Adds Snowflake", func() {
			So(ctx.snowflakes.Len(), ShouldEqual, 0)
			So(len(ctx.idToSnowflake), ShouldEqual, 0)
			ctx.AddSnowflake("foo", "", NATUnrestricted, 0)
			So(ctx.snowflakes.Len(), ShouldEqual, 1)
			So(len(ctx.idToSnowflake), ShouldEqual, 1)
		})

		Convey("Broker goroutine matches clients with proxies", func() {
			p := new(ProxyPoll)
			p.id = "test"
			p.natType = "unrestricted"
			p.offerChannel = make(chan *ClientOffer)
			go func(ctx *BrokerContext) {
				ctx.proxyPolls <- p
				close(ctx.proxyPolls)
			}(ctx)
			ctx.Broker()
			So(ctx.snowflakes.Len(), ShouldEqual, 1)
			snowflake := heap.Pop(ctx.snowflakes).(*Snowflake)
			snowflake.offerChannel <- &ClientOffer{sdp: []byte("test offer")}
			offer := <-p.offerChannel
			So(ctx.idToSnowflake["test"], ShouldNotBeNil)
			So(offer.sdp, ShouldResemble, []byte("test offer"))
			So(ctx.snowflakes.Len(), ShouldEqual, 0)
		})

		Convey("Request an offer from the Snowflake Heap", func() {
			done := make(chan *ClientOffer)
			go func() {
				offer := ctx.RequestOffer("test", "", NATUnrestricted, 0)
				done <- offer
			}()
			request := <-ctx.proxyPolls
			request.offerChannel <- &ClientOffer{sdp: []byte("test offer")}
			offer := <-done
			So(offer.sdp, ShouldResemble, []byte("test offer"))
		})

		Convey("Responds to HTTP client offers...", func() {
			w := httptest.NewRecorder()
			data, _ := createClientOffer(sdp, NATUnknown, "")
			r, err := http.NewRequest("POST", "snowflake.broker/client", data)
			So(err, ShouldBeNil)

			Convey("with error when no snowflakes are available.", func() {
				clientOffers(i, w, r)
				So(w.Code, ShouldEqual, http.StatusOK)
				So(w.Body.String(), ShouldEqual, `{"error":"no snowflake proxies currently available"}`)

				// Ensure that denial is correctly recorded in metrics
				ctx.metrics.printMetrics()
				So(buf.String(), ShouldContainSubstring, `client-denied-count 8
client-restricted-denied-count 8
client-unrestricted-denied-count 0
client-snowflake-match-count 0
client-snowflake-timeout-count 0
client-http-count 8
client-http-ips ??=8
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 0
client-sqs-ips 
`)
			})

			Convey("with a proxy answer if available.", func() {
				done := make(chan bool)
				// Prepare a fake proxy to respond with.
				snowflake := ctx.AddSnowflake("test", "", NATUnrestricted, 0)
				go func() {
					clientOffers(i, w, r)
					done <- true
				}()
				offer := <-snowflake.offerChannel
				So(offer.sdp, ShouldResemble, []byte(sdp))
				snowflake.answerChannel <- "test answer"
				<-done
				So(w.Body.String(), ShouldEqual, `{"answer":"test answer"}`)
				So(w.Code, ShouldEqual, http.StatusOK)

				// Ensure that match is correctly recorded in metrics
				ctx.metrics.printMetrics()
				So(buf.String(), ShouldContainSubstring, `client-denied-count 0
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-snowflake-match-count 8
client-snowflake-timeout-count 0
client-http-count 8
client-http-ips ??=8
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 0
client-sqs-ips 
`)
			})

			Convey("with unrestricted proxy to unrestricted client if there are no restricted proxies", func() {
				snowflake := ctx.AddSnowflake("test", "", NATUnrestricted, 0)
				offerData, err := createClientOffer(sdp, NATUnrestricted, "")
				So(err, ShouldBeNil)
				r, err := http.NewRequest("POST", "snowflake.broker/client", offerData)

				done := make(chan bool)
				go func() {
					clientOffers(i, w, r)
					done <- true
				}()

				select {
				case <-snowflake.offerChannel:
				case <-time.After(250 * time.Millisecond):
					So(false, ShouldBeTrue)
					return
				}
				snowflake.answerChannel <- "test answer"

				<-done
				So(w.Body.String(), ShouldEqual, `{"answer":"test answer"}`)
			})

			Convey("Times out when no proxy responds.", func() {
				if testing.Short() {
					return
				}
				done := make(chan bool)
				snowflake := ctx.AddSnowflake("fake", "", NATUnrestricted, 0)
				go func() {
					clientOffers(i, w, r)
					// Takes a few seconds here...
					done <- true
				}()
				offer := <-snowflake.offerChannel
				So(offer.sdp, ShouldResemble, []byte(sdp))
				<-done
				So(w.Code, ShouldEqual, http.StatusOK)
				So(w.Body.String(), ShouldEqual, `{"error":"timed out waiting for answer!"}`)
			})
		})

		Convey("Responds to HTTP legacy client offers...", func() {
			w := httptest.NewRecorder()
			// legacy offer starts with {
			offer := bytes.NewReader([]byte(fmt.Sprintf(`{%v}`, sdp)))
			r, err := http.NewRequest("POST", "snowflake.broker/client", offer)
			So(err, ShouldBeNil)
			r.Header.Set("Snowflake-NAT-TYPE", "restricted")

			Convey("with 503 when no snowflakes are available.", func() {
				clientOffers(i, w, r)
				So(w.Code, ShouldEqual, http.StatusServiceUnavailable)
				So(w.Body.String(), ShouldEqual, "")

				// Ensure that denial is correctly recorded in metrics
				ctx.metrics.printMetrics()
				So(buf.String(), ShouldContainSubstring, `client-denied-count 8
client-restricted-denied-count 8
client-unrestricted-denied-count 0
client-snowflake-match-count 0
client-snowflake-timeout-count 0
client-http-count 8
client-http-ips ??=8
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 0
client-sqs-ips 
`)
			})

			Convey("with a proxy answer if available.", func() {
				done := make(chan bool)
				// Prepare a fake proxy to respond with.
				snowflake := ctx.AddSnowflake("fake", "", NATUnrestricted, 0)
				go func() {
					clientOffers(i, w, r)
					done <- true
				}()
				offer := <-snowflake.offerChannel
				So(offer.sdp, ShouldResemble, []byte(fmt.Sprintf(`{%v}`, sdp)))
				snowflake.answerChannel <- "fake answer"
				<-done
				So(w.Body.String(), ShouldEqual, "fake answer")
				So(w.Code, ShouldEqual, http.StatusOK)

				// Ensure that match is correctly recorded in metrics
				ctx.metrics.printMetrics()
				So(buf.String(), ShouldContainSubstring, `client-denied-count 0
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-snowflake-match-count 8
client-snowflake-timeout-count 0
client-http-count 8
client-http-ips ??=8
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 0
client-sqs-ips 
`)
			})

			Convey("Times out when no proxy responds.", func() {
				if testing.Short() {
					return
				}
				done := make(chan bool)
				snowflake := ctx.AddSnowflake("fake", "", NATUnrestricted, 0)
				go func() {
					clientOffers(i, w, r)
					// Takes a few seconds here...
					done <- true
				}()
				offer := <-snowflake.offerChannel
				So(offer.sdp, ShouldResemble, []byte(fmt.Sprintf(`{%v}`, sdp)))
				<-done
				So(w.Code, ShouldEqual, http.StatusGatewayTimeout)
			})

		})

		Convey("Responds to AMP client offers...", func() {
			w := httptest.NewRecorder()
			encPollReq := []byte("1.0\n{\"offer\": \"fake\", \"nat\": \"unknown\"}")
			r, err := http.NewRequest("GET", "/amp/client/"+amp.EncodePath(encPollReq), nil)
			So(err, ShouldBeNil)

			Convey("with status 200 when request is badly formatted.", func() {
				r, err := http.NewRequest("GET", "/amp/client/bad", nil)
				So(err, ShouldBeNil)
				ampClientOffers(i, w, r)
				body, err := decodeAMPArmorToString(w.Body)
				So(err, ShouldBeNil)
				So(body, ShouldEqual, `{"error":"cannot decode URL path"}`)
			})

			Convey("with error when no snowflakes are available.", func() {
				ampClientOffers(i, w, r)
				So(w.Code, ShouldEqual, http.StatusOK)
				body, err := decodeAMPArmorToString(w.Body)
				So(err, ShouldBeNil)
				So(body, ShouldEqual, `{"error":"no snowflake proxies currently available"}`)

				// Ensure that denial is correctly recorded in metrics
				ctx.metrics.printMetrics()
				So(buf.String(), ShouldContainSubstring, `client-denied-count 8
client-restricted-denied-count 8
client-unrestricted-denied-count 0
client-snowflake-match-count 0
client-snowflake-timeout-count 0
client-http-count 0
client-http-ips 
client-ampcache-count 8
client-ampcache-ips ??=8
client-sqs-count 0
client-sqs-ips 
`)
			})

			Convey("with a proxy answer if available.", func() {
				done := make(chan bool)
				// Prepare a fake proxy to respond with.
				snowflake := ctx.AddSnowflake("fake", "", NATUnrestricted, 0)
				go func() {
					ampClientOffers(i, w, r)
					done <- true
				}()
				offer := <-snowflake.offerChannel
				So(offer.sdp, ShouldResemble, []byte("fake"))
				snowflake.answerChannel <- "fake answer"
				<-done
				body, err := decodeAMPArmorToString(w.Body)
				So(err, ShouldBeNil)
				So(body, ShouldEqual, `{"answer":"fake answer"}`)
				So(w.Code, ShouldEqual, http.StatusOK)

				// Ensure that match is correctly recorded in metrics
				ctx.metrics.printMetrics()
				So(buf.String(), ShouldContainSubstring, `client-denied-count 0
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-snowflake-match-count 8
client-snowflake-timeout-count 0
client-http-count 0
client-http-ips 
client-ampcache-count 8
client-ampcache-ips ??=8
client-sqs-count 0
client-sqs-ips 
`)
			})

			Convey("Times out when no proxy responds.", func() {
				if testing.Short() {
					return
				}
				done := make(chan bool)
				snowflake := ctx.AddSnowflake("fake", "", NATUnrestricted, 0)
				go func() {
					ampClientOffers(i, w, r)
					// Takes a few seconds here...
					done <- true
				}()
				offer := <-snowflake.offerChannel
				So(offer.sdp, ShouldResemble, []byte("fake"))
				<-done
				So(w.Code, ShouldEqual, http.StatusOK)
				body, err := decodeAMPArmorToString(w.Body)
				So(err, ShouldBeNil)
				So(body, ShouldEqual, `{"error":"timed out waiting for answer!"}`)
			})

		})

		Convey("Responds to proxy polls...", func() {
			done := make(chan bool)
			w := httptest.NewRecorder()
			data := bytes.NewReader([]byte(`{"Sid":"ymbcCMto7KHNGYlp","Version":"1.0", "AcceptedRelayPattern": "snowflake.torproject.net"}`))
			r, err := http.NewRequest("POST", "snowflake.broker/proxy", data)
			So(err, ShouldBeNil)

			Convey("with a client offer if available.", func() {
				go func(i *IPC) {
					proxyPolls(i, w, r)
					done <- true
				}(i)
				// Pass a fake client offer to this proxy
				p := <-ctx.proxyPolls
				So(p.id, ShouldEqual, "ymbcCMto7KHNGYlp")
				p.offerChannel <- &ClientOffer{sdp: []byte("fake offer"), fingerprint: defaultBridge[:]}
				<-done
				So(w.Code, ShouldEqual, http.StatusOK)
				So(w.Body.String(), ShouldEqual, `{"Status":"client match","Offer":"fake offer","NAT":"","RelayURL":"wss://snowflake.torproject.net/"}`)
			})

			Convey("return empty 200 OK when no client offer is available.", func() {
				go func(i *IPC) {
					proxyPolls(i, w, r)
					done <- true
				}(i)
				p := <-ctx.proxyPolls
				So(p.id, ShouldEqual, "ymbcCMto7KHNGYlp")
				// nil means timeout
				p.offerChannel <- nil
				<-done
				So(w.Body.String(), ShouldEqual, `{"Status":"no match","Offer":"","NAT":"","RelayURL":""}`)
				So(w.Code, ShouldEqual, http.StatusOK)
			})
		})

		Convey("Responds to proxy answers...", func() {
			done := make(chan bool)
			s := ctx.AddSnowflake(sid, "", NATUnrestricted, 0)
			w := httptest.NewRecorder()

			data, err := createProxyAnswer(sdp, sid)
			So(err, ShouldBeNil)

			Convey("by passing to the client if valid.", func() {
				r, err := http.NewRequest("POST", "snowflake.broker/answer", data)
				So(err, ShouldBeNil)
				go func(i *IPC) {
					proxyAnswers(i, w, r)
					done <- true
				}(i)
				answer := <-s.answerChannel
				<-done
				So(w.Code, ShouldEqual, http.StatusOK)
				So(answer, ShouldResemble, sdp)
			})

			Convey("with client gone status if the proxy ID is not recognized", func() {
				data, _ := createProxyAnswer(sdp, "invalid")
				r, err := http.NewRequest("POST", "snowflake.broker/answer", data)
				So(err, ShouldBeNil)
				proxyAnswers(i, w, r)
				So(w.Code, ShouldEqual, http.StatusOK)
				b, err := io.ReadAll(w.Body)
				So(err, ShouldBeNil)
				So(b, ShouldResemble, []byte(`{"Status":"client gone"}`))
			})

			Convey("with error if the proxy gives invalid answer", func() {
				data := bytes.NewReader(nil)
				r, err := http.NewRequest("POST", "snowflake.broker/answer", data)
				So(err, ShouldBeNil)
				proxyAnswers(i, w, r)
				So(w.Code, ShouldEqual, http.StatusBadRequest)
			})

			Convey("with error if the proxy writes too much data", func() {
				data := bytes.NewReader(make([]byte, 100001))
				r, err := http.NewRequest("POST", "snowflake.broker/answer", data)
				So(err, ShouldBeNil)
				proxyAnswers(i, w, r)
				So(w.Code, ShouldEqual, http.StatusBadRequest)
			})

		})

	})

	Convey("End-To-End", t, func() {
		ctx := NewBrokerContext(NullLogger(), "snowflake.torproject.net")
		i := &IPC{ctx}

		Convey("Check for client/proxy data race", func() {
			proxy_done := make(chan bool)
			client_done := make(chan bool)

			go ctx.Broker()

			// Make proxy poll
			wp := httptest.NewRecorder()
			datap := bytes.NewReader([]byte(`{"Sid":"ymbcCMto7KHNGYlp","Version":"1.0","AcceptedRelayPattern":"snowflake.torproject.net"}`))
			rp, err := http.NewRequest("POST", "snowflake.broker/proxy", datap)
			So(err, ShouldBeNil)

			go func(i *IPC) {
				proxyPolls(i, wp, rp)
				proxy_done <- true
			}(i)

			// Client offer
			wc := httptest.NewRecorder()
			datac, err := createClientOffer(sdp, NATUnknown, "")
			So(err, ShouldBeNil)
			rc, err := http.NewRequest("POST", "snowflake.broker/client", datac)
			So(err, ShouldBeNil)

			go func() {
				clientOffers(i, wc, rc)
				client_done <- true
			}()

			<-proxy_done
			So(wp.Code, ShouldEqual, http.StatusOK)

			// Proxy answers
			wp = httptest.NewRecorder()
			datap, err = createProxyAnswer(sdp, sid)
			So(err, ShouldBeNil)
			rp, err = http.NewRequest("POST", "snowflake.broker/answer", datap)
			So(err, ShouldBeNil)
			go func(i *IPC) {
				proxyAnswers(i, wp, rp)
				proxy_done <- true
			}(i)

			<-proxy_done
			<-client_done

		})

		Convey("Ensure correct snowflake brokering", func() {
			done := make(chan bool)
			polled := make(chan bool)

			// Proxy polls with its ID first...
			dataP := bytes.NewReader([]byte(`{"Sid":"ymbcCMto7KHNGYlp","Version":"1.0","AcceptedRelayPattern":"snowflake.torproject.net"}`))
			wP := httptest.NewRecorder()
			rP, err := http.NewRequest("POST", "snowflake.broker/proxy", dataP)
			So(err, ShouldBeNil)
			go func() {
				proxyPolls(i, wP, rP)
				polled <- true
			}()

			// Manually do the Broker goroutine action here for full control.
			p := <-ctx.proxyPolls
			So(p.id, ShouldEqual, "ymbcCMto7KHNGYlp")
			s := ctx.AddSnowflake(p.id, "", NATUnrestricted, 0)
			go func() {
				offer := <-s.offerChannel
				p.offerChannel <- offer
			}()
			So(ctx.idToSnowflake["ymbcCMto7KHNGYlp"], ShouldNotBeNil)

			// Client request blocks until proxy answer arrives.
			wC := httptest.NewRecorder()
			dataC, err := createClientOffer(sdp, NATUnknown, "")
			So(err, ShouldBeNil)
			rC, err := http.NewRequest("POST", "snowflake.broker/client", dataC)
			So(err, ShouldBeNil)
			go func() {
				clientOffers(i, wC, rC)
				done <- true
			}()

			<-polled
			So(wP.Code, ShouldEqual, http.StatusOK)
			So(wP.Body.String(), ShouldResemble, fmt.Sprintf(`{"Status":"client match","Offer":%#q,"NAT":"unknown","RelayURL":"wss://snowflake.torproject.net/"}`, sdp))
			So(ctx.idToSnowflake[sid], ShouldNotBeNil)

			// Follow up with the answer request afterwards
			wA := httptest.NewRecorder()
			dataA, err := createProxyAnswer(sdp, sid)
			So(err, ShouldBeNil)
			rA, err := http.NewRequest("POST", "snowflake.broker/answer", dataA)
			So(err, ShouldBeNil)
			proxyAnswers(i, wA, rA)
			So(wA.Code, ShouldEqual, http.StatusOK)

			<-done
			So(wC.Code, ShouldEqual, http.StatusOK)
			So(wC.Body.String(), ShouldEqual, fmt.Sprintf(`{"answer":%#q}`, sdp))
		})
	})
}

func TestSnowflakeHeap(t *testing.T) {
	t.Parallel()

	Convey("SnowflakeHeap", t, func() {
		h := new(SnowflakeHeap)
		heap.Init(h)
		So(h.Len(), ShouldEqual, 0)
		s1 := new(Snowflake)
		s2 := new(Snowflake)
		s3 := new(Snowflake)
		s4 := new(Snowflake)
		s1.clients = 4
		s2.clients = 5
		s3.clients = 3
		s4.clients = 1

		heap.Push(h, s1)
		So(h.Len(), ShouldEqual, 1)
		heap.Push(h, s2)
		So(h.Len(), ShouldEqual, 2)
		heap.Push(h, s3)
		So(h.Len(), ShouldEqual, 3)
		heap.Push(h, s4)
		So(h.Len(), ShouldEqual, 4)

		heap.Remove(h, 0)
		So(h.Len(), ShouldEqual, 3)

		r := heap.Pop(h).(*Snowflake)
		So(h.Len(), ShouldEqual, 2)
		So(r.clients, ShouldEqual, 3)
		So(r.index, ShouldEqual, -1)

		r = heap.Pop(h).(*Snowflake)
		So(h.Len(), ShouldEqual, 1)
		So(r.clients, ShouldEqual, 4)
		So(r.index, ShouldEqual, -1)

		r = heap.Pop(h).(*Snowflake)
		So(h.Len(), ShouldEqual, 0)
		So(r.clients, ShouldEqual, 5)
		So(r.index, ShouldEqual, -1)
	})
}

func TestInvalidGeoipFile(t *testing.T) {
	t.Parallel()

	Convey("Geoip", t, func() {
		// Make sure things behave properly if geoip file fails to load
		ctx := NewBrokerContext(NullLogger(), "")
		if err := ctx.metrics.LoadGeoipDatabases("invalid_filename", "invalid_filename6"); err != nil {
			log.Printf("loading geo ip databases returned error: %v", err)
		}
		ctx.metrics.UpdateProxyStats("127.0.0.1", "", NATUnrestricted)
		So(ctx.metrics.geoipdb, ShouldBeNil)

	})
}

func TestMetrics(t *testing.T) {
	t.Parallel()

	Convey("Test metrics...", t, func() {
		done := make(chan bool)
		buf := new(bytes.Buffer)
		ctx := NewBrokerContext(log.New(buf, "", 0), "snowflake.torproject.net")
		i := &IPC{ctx}

		err := ctx.metrics.LoadGeoipDatabases("test_geoip", "test_geoip6")
		So(err, ShouldBeNil)

		//Test addition of proxy polls
		Convey("for proxy polls", func() {
			w := httptest.NewRecorder()
			data := bytes.NewReader([]byte("{\"Sid\":\"ymbcCMto7KHNGYlp\",\"Version\":\"1.0\",\"AcceptedRelayPattern\":\"snowflake.torproject.net\"}"))
			r, err := http.NewRequest("POST", "snowflake.broker/proxy", data)
			r.RemoteAddr = "129.97.208.23" //CA geoip
			So(err, ShouldBeNil)
			go func(i *IPC) {
				proxyPolls(i, w, r)
				done <- true
			}(i)
			p := <-ctx.proxyPolls //manually unblock poll
			p.offerChannel <- nil
			<-done

			w = httptest.NewRecorder()
			data = bytes.NewReader([]byte(`{"Sid":"ymbcCMto7KHNGYlp","Version":"1.0","Type":"standalone","AcceptedRelayPattern":"snowflake.torproject.net"}`))
			r, err = http.NewRequest("POST", "snowflake.broker/proxy", data)
			r.RemoteAddr = "129.97.208.24" //CA geoip
			So(err, ShouldBeNil)
			go func(i *IPC) {
				proxyPolls(i, w, r)
				done <- true
			}(i)
			p = <-ctx.proxyPolls //manually unblock poll
			p.offerChannel <- nil
			<-done

			w = httptest.NewRecorder()
			data = bytes.NewReader([]byte(`{"Sid":"ymbcCMto7KHNGYlp","Version":"1.0","Type":"badge","AcceptedRelayPattern":"snowflake.torproject.net"}`))
			r, err = http.NewRequest("POST", "snowflake.broker/proxy", data)
			r.RemoteAddr = "129.97.208.25" //CA geoip
			So(err, ShouldBeNil)
			go func(i *IPC) {
				proxyPolls(i, w, r)
				done <- true
			}(i)
			p = <-ctx.proxyPolls //manually unblock poll
			p.offerChannel <- nil
			<-done

			w = httptest.NewRecorder()
			data = bytes.NewReader([]byte(`{"Sid":"ymbcCMto7KHNGYlp","Version":"1.0","Type":"webext","AcceptedRelayPattern":"snowflake.torproject.net"}`))
			r, err = http.NewRequest("POST", "snowflake.broker/proxy", data)
			r.RemoteAddr = "129.97.208.26" //CA geoip
			So(err, ShouldBeNil)
			go func(i *IPC) {
				proxyPolls(i, w, r)
				done <- true
			}(i)
			p = <-ctx.proxyPolls //manually unblock poll
			p.offerChannel <- nil
			<-done
			ctx.metrics.printMetrics()

			metricsStr := buf.String()
			So(metricsStr, ShouldStartWith, "snowflake-stats-end "+time.Now().UTC().Format("2006-01-02 15:04:05")+" (86400 s)\nsnowflake-ips CA=4\n")
			So(metricsStr, ShouldContainSubstring, "\nsnowflake-ips-standalone 1\n")
			So(metricsStr, ShouldContainSubstring, "\nsnowflake-ips-badge 1\n")
			So(metricsStr, ShouldContainSubstring, "\nsnowflake-ips-webext 1\n")
			So(metricsStr, ShouldEndWith, `snowflake-ips-total 4
snowflake-idle-count 8
snowflake-proxy-poll-with-relay-url-count 8
snowflake-proxy-poll-without-relay-url-count 0
snowflake-proxy-rejected-for-relay-url-count 0
client-denied-count 0
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-snowflake-match-count 0
client-snowflake-timeout-count 0
client-http-count 0
client-http-ips 
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 0
client-sqs-ips 
snowflake-ips-nat-restricted 0
snowflake-ips-nat-unrestricted 0
snowflake-ips-nat-unknown 4
`)
		})

		//Test addition of client failures
		Convey("for no proxies available", func() {
			w := httptest.NewRecorder()
			data, err := createClientOffer(sdp, NATUnknown, "")
			So(err, ShouldBeNil)
			r, err := http.NewRequest("POST", "snowflake.broker/client", data)
			r.RemoteAddr = "129.97.208.23:8888" //CA geoip
			So(err, ShouldBeNil)

			clientOffers(i, w, r)

			ctx.metrics.printMetrics()
			So(buf.String(), ShouldContainSubstring, `client-denied-count 8
client-restricted-denied-count 8
client-unrestricted-denied-count 0
client-snowflake-match-count 0
client-snowflake-timeout-count 0
client-http-count 8
client-http-ips CA=8
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 0
client-sqs-ips `)

			// Test reset
			buf.Reset()
			ctx.metrics.printMetrics()
			So(buf.String(), ShouldContainSubstring, "\nsnowflake-ips \n")
			So(buf.String(), ShouldContainSubstring, "\nsnowflake-ips-standalone 0\n")
			So(buf.String(), ShouldContainSubstring, "\nsnowflake-ips-badge 0\n")
			So(buf.String(), ShouldContainSubstring, "\nsnowflake-ips-webext 0\n")
			So(buf.String(), ShouldContainSubstring, `snowflake-ips-total 0
snowflake-idle-count 0
snowflake-proxy-poll-with-relay-url-count 0
snowflake-proxy-poll-without-relay-url-count 0
snowflake-proxy-rejected-for-relay-url-count 0
client-denied-count 0
client-restricted-denied-count 0
client-unrestricted-denied-count 0
client-snowflake-match-count 0
client-snowflake-timeout-count 0
client-http-count 0
client-http-ips 
client-ampcache-count 0
client-ampcache-ips 
client-sqs-count 0
client-sqs-ips 
snowflake-ips-nat-restricted 0
snowflake-ips-nat-unrestricted 0
snowflake-ips-nat-unknown 0
`)
		})
		//Test addition of client matches
		Convey("for client-proxy match", func() {
			w := httptest.NewRecorder()
			data, err := createClientOffer(sdp, NATUnknown, "")
			So(err, ShouldBeNil)
			r, err := http.NewRequest("POST", "snowflake.broker/client", data)
			So(err, ShouldBeNil)

			// Prepare a fake proxy to respond with.
			snowflake := ctx.AddSnowflake("fake", "", NATUnrestricted, 0)
			go func() {
				clientOffers(i, w, r)
				done <- true
			}()
			offer := <-snowflake.offerChannel
			So(offer.sdp, ShouldResemble, []byte(sdp))
			snowflake.answerChannel <- "fake answer"
			<-done

			ctx.metrics.printMetrics()
			So(buf.String(), ShouldContainSubstring, "client-denied-count 0\nclient-restricted-denied-count 0\nclient-unrestricted-denied-count 0\nclient-snowflake-match-count 8")
		})
		//Test rounding boundary
		Convey("binning boundary", func() {
			w := httptest.NewRecorder()
			data, err := createClientOffer(sdp, NATRestricted, "")
			So(err, ShouldBeNil)
			r, err := http.NewRequest("POST", "snowflake.broker/client", data)
			So(err, ShouldBeNil)
			clientOffers(i, w, r)

			w = httptest.NewRecorder()
			data, err = createClientOffer(sdp, NATRestricted, "")
			So(err, ShouldBeNil)
			r, err = http.NewRequest("POST", "snowflake.broker/client", data)
			So(err, ShouldBeNil)
			clientOffers(i, w, r)

			w = httptest.NewRecorder()
			data, err = createClientOffer(sdp, NATRestricted, "")
			So(err, ShouldBeNil)
			r, err = http.NewRequest("POST", "snowflake.broker/client", data)
			So(err, ShouldBeNil)
			clientOffers(i, w, r)

			w = httptest.NewRecorder()
			data, err = createClientOffer(sdp, NATRestricted, "")
			So(err, ShouldBeNil)
			r, err = http.NewRequest("POST", "snowflake.broker/client", data)
			So(err, ShouldBeNil)
			clientOffers(i, w, r)

			w = httptest.NewRecorder()
			data, err = createClientOffer(sdp, NATRestricted, "")
			So(err, ShouldBeNil)
			r, err = http.NewRequest("POST", "snowflake.broker/client", data)
			So(err, ShouldBeNil)
			clientOffers(i, w, r)

			w = httptest.NewRecorder()
			data, err = createClientOffer(sdp, NATRestricted, "")
			So(err, ShouldBeNil)
			r, err = http.NewRequest("POST", "snowflake.broker/client", data)
			So(err, ShouldBeNil)
			clientOffers(i, w, r)

			w = httptest.NewRecorder()
			data, err = createClientOffer(sdp, NATRestricted, "")
			So(err, ShouldBeNil)
			r, err = http.NewRequest("POST", "snowflake.broker/client", data)
			So(err, ShouldBeNil)
			clientOffers(i, w, r)

			w = httptest.NewRecorder()
			data, err = createClientOffer(sdp, NATRestricted, "")
			So(err, ShouldBeNil)
			r, err = http.NewRequest("POST", "snowflake.broker/client", data)
			So(err, ShouldBeNil)
			clientOffers(i, w, r)

			w = httptest.NewRecorder()
			data, err = createClientOffer(sdp, NATRestricted, "")
			So(err, ShouldBeNil)
			r, err = http.NewRequest("POST", "snowflake.broker/client", data)
			So(err, ShouldBeNil)
			clientOffers(i, w, r)

			buf.Reset()
			ctx.metrics.printMetrics()
			So(buf.String(), ShouldContainSubstring, "client-denied-count 16\nclient-restricted-denied-count 16\nclient-unrestricted-denied-count 0\n")
		})

		//Test unique ip
		Convey("proxy counts by unique ip", func() {
			w := httptest.NewRecorder()
			data := bytes.NewReader([]byte(`{"Sid":"ymbcCMto7KHNGYlp","Version":"1.0","AcceptedRelayPattern":"snowflake.torproject.net"}`))
			r, err := http.NewRequest("POST", "snowflake.broker/proxy", data)
			r.RemoteAddr = "129.97.208.23:8888" //CA geoip
			So(err, ShouldBeNil)
			go func(i *IPC) {
				proxyPolls(i, w, r)
				done <- true
			}(i)
			p := <-ctx.proxyPolls //manually unblock poll
			p.offerChannel <- nil
			<-done

			data = bytes.NewReader([]byte(`{"Sid":"ymbcCMto7KHNGYlp","Version":"1.0","AcceptedRelayPattern":"snowflake.torproject.net"}`))
			r, err = http.NewRequest("POST", "snowflake.broker/proxy", data)
			if err != nil {
				log.Printf("unable to get NewRequest with error: %v", err)
			}
			r.RemoteAddr = "129.97.208.23:8888" //CA geoip
			go func(i *IPC) {
				proxyPolls(i, w, r)
				done <- true
			}(i)
			p = <-ctx.proxyPolls //manually unblock poll
			p.offerChannel <- nil
			<-done

			ctx.metrics.printMetrics()
			metricsStr := buf.String()
			So(metricsStr, ShouldContainSubstring, "snowflake-ips CA=1\n")
			So(metricsStr, ShouldContainSubstring, "snowflake-ips-total 1\n")
		})
		//Test NAT types
		Convey("proxy counts by NAT type", func() {
			w := httptest.NewRecorder()
			data := bytes.NewReader([]byte(`{"Sid":"ymbcCMto7KHNGYlp","Version":"1.2","Type":"unknown","NAT":"restricted","AcceptedRelayPattern":"snowflake.torproject.net"}`))
			r, err := http.NewRequest("POST", "snowflake.broker/proxy", data)
			r.RemoteAddr = "129.97.208.23:8888" //CA geoip
			So(err, ShouldBeNil)
			go func(i *IPC) {
				proxyPolls(i, w, r)
				done <- true
			}(i)
			p := <-ctx.proxyPolls //manually unblock poll
			p.offerChannel <- nil
			<-done

			data = bytes.NewReader([]byte(`{"Sid":"ymbcCMto7KHNGYlp","Version":"1.2","Type":"unknown","NAT":"unrestricted","AcceptedRelayPattern":"snowflake.torproject.net"}`))
			r, err = http.NewRequest("POST", "snowflake.broker/proxy", data)
			if err != nil {
				log.Printf("unable to get NewRequest with error: %v", err)
			}
			r.RemoteAddr = "129.97.208.24:8888" //CA geoip
			go func(i *IPC) {
				proxyPolls(i, w, r)
				done <- true
			}(i)
			p = <-ctx.proxyPolls //manually unblock poll
			p.offerChannel <- nil
			<-done

			ctx.metrics.printMetrics()
			So(buf.String(), ShouldContainSubstring, "snowflake-ips-nat-restricted 1\nsnowflake-ips-nat-unrestricted 1\nsnowflake-ips-nat-unknown 0")
		})

		Convey("client failures by NAT type", func() {
			w := httptest.NewRecorder()
			data, err := createClientOffer(sdp, NATRestricted, "")
			So(err, ShouldBeNil)
			r, err := http.NewRequest("POST", "snowflake.broker/client", data)
			So(err, ShouldBeNil)

			clientOffers(i, w, r)

			ctx.metrics.printMetrics()
			So(buf.String(), ShouldContainSubstring, "client-denied-count 8\nclient-restricted-denied-count 8\nclient-unrestricted-denied-count 0\nclient-snowflake-match-count 0")

			buf.Reset()

			data, err = createClientOffer(sdp, NATUnrestricted, "")
			So(err, ShouldBeNil)
			r, err = http.NewRequest("POST", "snowflake.broker/client", data)
			So(err, ShouldBeNil)

			clientOffers(i, w, r)

			ctx.metrics.printMetrics()
			So(buf.String(), ShouldContainSubstring, "client-denied-count 8\nclient-restricted-denied-count 0\nclient-unrestricted-denied-count 8\nclient-snowflake-match-count 0")

			buf.Reset()

			data, err = createClientOffer(sdp, NATUnknown, "")
			So(err, ShouldBeNil)
			r, err = http.NewRequest("POST", "snowflake.broker/client", data)
			So(err, ShouldBeNil)

			clientOffers(i, w, r)

			ctx.metrics.printMetrics()
			So(buf.String(), ShouldContainSubstring, "client-denied-count 8\nclient-restricted-denied-count 8\nclient-unrestricted-denied-count 0\nclient-snowflake-match-count 0")
		})
		Convey("for country stats order", func() {
			stats := new(sync.Map)
			for cc, count := range map[string]uint64{
				"IT": 50,
				"FR": 200,
				"TZ": 100,
				"CN": 250,
				"RU": 150,
				"CA": 1,
				"BE": 1,
				"PH": 1,
			} {
				stats.LoadOrStore(cc, new(uint64))
				val, _ := stats.Load(cc)
				ptr := val.(*uint64)
				atomic.AddUint64(ptr, count)
			}
			So(displayCountryStats(stats, false), ShouldEqual, "CN=250,FR=200,RU=150,TZ=100,IT=50,BE=1,CA=1,PH=1")
		})
	})
}
