/*
The majority of this code is taken from a utility I wrote for pion/stun
https://github.com/pion/stun/blob/master/cmd/stun-nat-behaviour/main.go

Copyright 2018 Pion LLC

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package nat

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"time"

	"github.com/pion/stun/v3"
	"tgragnato.it/snowflake/common/proxy"
)

var ErrTimedOut = errors.New("timed out waiting for response")

const (
	NATUnknown      = "unknown"
	NATRestricted   = "restricted"
	NATUnrestricted = "unrestricted"
)

// Deprecated: Use CheckIfRestrictedNATWithProxy Instead.
func CheckIfRestrictedNAT(server string) (bool, error) {
	return CheckIfRestrictedNATWithProxy(server, nil)
}

// CheckIfRestrictedNATWithProxy checks the NAT mapping and filtering
// behaviour and returns true if the NAT is restrictive
// (address-dependent mapping and/or port-dependent filtering)
// and false if the NAT is unrestrictive (meaning it
// will work with most other NATs),
func CheckIfRestrictedNATWithProxy(server string, proxy *url.URL) (bool, error) {
	return isRestrictedMapping(server, proxy)
}

// Performs two tests from RFC 5780 to determine whether the mapping type
// of the client's NAT is address-independent or address-dependent
// Returns true if the mapping is address-dependent and false otherwise
func isRestrictedMapping(addrStr string, proxy *url.URL) (bool, error) {
	var xorAddr1 stun.XORMappedAddress
	var xorAddr2 stun.XORMappedAddress

	mapTestConn, err := connect(addrStr, proxy)
	if err != nil {
		return false, fmt.Errorf("error creating STUN connection: %w", err)
	}

	defer mapTestConn.Close()

	// Test I: Regular binding request
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	resp, err := mapTestConn.RoundTrip(message, mapTestConn.PrimaryAddr)
	if err != nil {
		return false, fmt.Errorf("error completing roundtrip map test: %w", err)
	}

	// Decoding XOR-MAPPED-ADDRESS attribute from message.
	if err = xorAddr1.GetFrom(resp); err != nil {
		return false, fmt.Errorf("error retrieving XOR-MAPPED-ADDRESS resonse: %w", err)
	}

	// Decoding OTHER-ADDRESS attribute from message.
	var otherAddr stun.OtherAddress
	if err = otherAddr.GetFrom(resp); err != nil {
		return false, fmt.Errorf("NAT discovery feature not supported: %w", err)
	}

	if err = mapTestConn.AddOtherAddr(otherAddr.String()); err != nil {
		return false, fmt.Errorf("error resolving address %s: %w", otherAddr.String(), err)
	}

	// Test II: Send binding request to other address
	resp, err = mapTestConn.RoundTrip(message, mapTestConn.OtherAddr)
	if err != nil {
		return false, fmt.Errorf("error retrieveing server response: %w", err)
	}

	// Decoding XOR-MAPPED-ADDRESS attribute from message.
	if err = xorAddr2.GetFrom(resp); err != nil {
		return false, fmt.Errorf("error retrieving XOR-MAPPED-ADDRESS resonse: %w", err)
	}

	return xorAddr1.String() != xorAddr2.String(), nil

}

// Given an address string, returns a StunServerConn
func connect(addrStr string, proxyAddr *url.URL) (*StunServerConn, error) {
	// Creating a "connection" to STUN server.
	var conn net.PacketConn

	ResolveUDPAddr := net.ResolveUDPAddr
	if proxyAddr != nil {
		socksClient := proxy.NewSocks5UDPClient(proxyAddr)
		ResolveUDPAddr = socksClient.ResolveUDPAddr
	}

	addr, err := ResolveUDPAddr("udp4", addrStr)
	if err != nil {
		log.Printf("Error resolving address: %s\n", err.Error())
		return nil, err
	}

	if proxyAddr == nil {
		c, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return nil, err
		}
		conn = c
	} else {
		socksClient := proxy.NewSocks5UDPClient(proxyAddr)
		c, err := socksClient.ListenPacket("udp", nil)
		if err != nil {
			return nil, err
		}
		conn = c
	}

	mChan := listen(conn)

	return &StunServerConn{
		conn:        conn,
		PrimaryAddr: addr,
		messageChan: mChan,
	}, nil
}

type StunServerConn struct {
	conn        net.PacketConn
	PrimaryAddr *net.UDPAddr
	OtherAddr   *net.UDPAddr
	messageChan chan *stun.Message
}

func (c *StunServerConn) Close() {
	c.conn.Close()
}

func (c *StunServerConn) RoundTrip(msg *stun.Message, addr net.Addr) (*stun.Message, error) {
	_, err := c.conn.WriteTo(msg.Raw, addr)
	if err != nil {
		return nil, err
	}

	// Wait for response or timeout
	select {
	case m, ok := <-c.messageChan:
		if !ok {
			return nil, fmt.Errorf("error reading from messageChan")
		}
		return m, nil
	case <-time.After(10 * time.Second):
		return nil, ErrTimedOut
	}
}

func (c *StunServerConn) AddOtherAddr(addrStr string) error {
	addr2, err := net.ResolveUDPAddr("udp4", addrStr)
	if err != nil {
		return err
	}
	c.OtherAddr = addr2
	return nil
}

// taken from https://github.com/pion/stun/blob/master/cmd/stun-traversal/main.go
func listen(conn net.PacketConn) chan *stun.Message {
	messages := make(chan *stun.Message)
	go func() {
		for {
			buf := make([]byte, 1024)

			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				close(messages)
				return
			}
			buf = buf[:n]

			m := new(stun.Message)
			m.Raw = buf
			err = m.Decode()
			if err != nil {
				close(messages)
				return
			}

			messages <- m
		}
	}()
	return messages
}
