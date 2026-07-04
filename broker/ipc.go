package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"tgragnato.it/snowflake/common/bridgefingerprint"
	"tgragnato.it/snowflake/common/constants"
	"tgragnato.it/snowflake/common/messages"
)

const (
	ClientTimeout = constants.BrokerClientTimeout
	ProxyTimeout  = 10

	MaxPollInterval = time.Hour

	NATUnknown      = "unknown"
	NATRestricted   = "restricted"
	NATUnrestricted = "unrestricted"
)

type IPC struct {
	ctx *BrokerContext
}

func (i *IPC) Debug(_ interface{}, response *string) error {
	var unknowns int
	var natRestricted, natUnrestricted, natUnknown int
	proxyTypes := make(map[string]int)

	i.ctx.snowflakeLock.Lock()
	s := fmt.Sprintf("current snowflakes available: %d\n", len(i.ctx.idToSnowflake))
	for _, snowflake := range i.ctx.idToSnowflake {
		if messages.KnownProxyTypes[snowflake.proxyType] {
			proxyTypes[snowflake.proxyType]++
		} else {
			unknowns++
		}

		switch snowflake.natType {
		case NATRestricted:
			natRestricted++
		case NATUnrestricted:
			natUnrestricted++
		default:
			natUnknown++
		}

	}
	i.ctx.snowflakeLock.Unlock()

	for pType, num := range proxyTypes {
		s += fmt.Sprintf("\t%s proxies: %d\n", pType, num)
	}
	s += fmt.Sprintf("\tunknown proxies: %d", unknowns)

	s += "\nNAT Types available:"
	s += fmt.Sprintf("\n\trestricted: %d", natRestricted)
	s += fmt.Sprintf("\n\tunrestricted: %d", natUnrestricted)
	s += fmt.Sprintf("\n\tunknown: %d", natUnknown)

	*response = s
	return nil
}

func (i *IPC) ProxyPolls(arg messages.Arg, response *[]byte) error {
	req, err := messages.DecodeProxyPollRequest(arg.Body)
	if err != nil {
		return messages.ErrBadRequest
	}

	if req.AcceptedRelayPattern == nil {
		i.ctx.metrics.IncrementCounter("proxy-poll-without-relay-url")
		i.ctx.metrics.promMetrics.ProxyPollWithoutRelayURLExtensionTotal.With(prometheus.Labels{"nat": req.NAT, "type": req.Type}).Inc()
	} else {
		i.ctx.metrics.IncrementCounter("proxy-poll-with-relay-url")
		i.ctx.metrics.promMetrics.ProxyPollWithRelayURLExtensionTotal.With(prometheus.Labels{"nat": req.NAT, "type": req.Type}).Inc()
	}

	if !i.ctx.CheckProxyRelayPattern(req.AcceptedRelayPattern) {
		i.ctx.metrics.IncrementCounter("proxy-poll-rejected-relay-url")
		i.ctx.metrics.promMetrics.ProxyPollRejectedForRelayURLExtensionTotal.With(prometheus.Labels{"nat": req.NAT, "type": req.Type}).Inc()

		resp := messages.ProxyPollResponse{
			Status:   "incorrect relay pattern",
			NextPoll: MaxPollInterval.Milliseconds(),
		}
		b, err := resp.Encode()
		*response = b
		if err != nil {
			return messages.ErrInternal
		}
		return nil
	}

	// Log geoip stats
	remoteIP := arg.RemoteAddr
	i.ctx.metrics.UpdateProxyStats(remoteIP, req.Type, req.NAT)
	go i.ctx.metrics.RecordIPAddress(remoteIP, req.NAT == NATUnrestricted, req.Type)

	var b []byte

	i.ctx.metrics.promMetrics.AvailableProxies.With(prometheus.Labels{"nat": req.NAT, "type": req.Type}).Inc()
	defer i.ctx.metrics.promMetrics.AvailableProxies.With(prometheus.Labels{"nat": req.NAT, "type": req.Type}).Dec()

	// Wait for a client to avail an offer to the snowflake, or timeout if nil.
	poll := &ProxyPoll{
		id:        req.Sid,
		proxyType: req.Type,
		natType:   req.NAT,
		clients:   req.Clients,
	}
	offer := i.ctx.RequestOffer(poll)
	pollInterval := i.ctx.GetPool(poll).GetPollInterval().Milliseconds()

	if offer == nil {
		i.ctx.metrics.IncrementCounter("proxy-idle")
		i.ctx.metrics.promMetrics.ProxyPollTotal.With(prometheus.Labels{"nat": req.NAT, "type": req.Type, "status": "idle"}).Inc()

		resp := messages.ProxyPollResponse{
			Status:   messages.ProxyClientNoMatch,
			NextPoll: pollInterval,
		}
		b, err = resp.Encode()
		if err != nil {
			return messages.ErrInternal
		}

		*response = b
		return nil
	}

	i.ctx.metrics.promMetrics.ProxyPollTotal.With(prometheus.Labels{"nat": req.NAT, "type": req.Type, "status": "matched"}).Inc()
	var relayURL string
	bridgeFingerprint, err := bridgefingerprint.FingerprintFromBytes(offer.fingerprint)
	if err != nil {
		return messages.ErrBadRequest
	}
	if info, err := i.ctx.bridgeList.GetBridgeInfo(bridgeFingerprint); err != nil {
		return err
	} else {
		relayURL = info.WebSocketAddress
	}
	resp := messages.ProxyPollResponse{
		Offer:    string(offer.sdp),
		Status:   messages.ProxyClientMatch,
		NAT:      offer.natType,
		RelayURL: relayURL,
		NextPoll: pollInterval,
	}
	b, err = resp.Encode()
	if err != nil {
		return messages.ErrInternal
	}
	*response = b

	return nil
}

func sendClientResponse(resp *messages.ClientPollResponse, response *[]byte) error {
	data, err := resp.EncodePollResponse()
	if err != nil {
		log.Printf("error encoding answer")
		return messages.ErrInternal
	} else {
		*response = []byte(data)
		return nil
	}
}

func (i *IPC) ClientOffers(arg messages.Arg, response *[]byte) error {

	req, err := messages.DecodeClientPollRequest(arg.Body)
	if err != nil {
		return sendClientResponse(&messages.ClientPollResponse{Error: err.Error()}, response)
	}

	offer := &ClientOffer{
		natType: req.NAT,
		sdp:     []byte(req.Offer),
	}

	fingerprint, err := hex.DecodeString(req.Fingerprint)
	if err != nil {
		return sendClientResponse(&messages.ClientPollResponse{Error: err.Error()}, response)
	}

	BridgeFingerprint, err := bridgefingerprint.FingerprintFromBytes(fingerprint)
	if err != nil {
		return sendClientResponse(&messages.ClientPollResponse{Error: err.Error()}, response)
	}

	if _, err := i.ctx.GetBridgeInfo(BridgeFingerprint); err != nil {
		return sendClientResponse(
			&messages.ClientPollResponse{Error: err.Error()},
			response,
		)
	}

	offer.fingerprint = BridgeFingerprint.ToBytes()

	snowflake := i.matchSnowflake(offer.natType)
	if snowflake != nil {
		snowflake.offerChannel <- offer
	} else {
		i.ctx.metrics.UpdateClientStats(arg.RemoteAddr, arg.RendezvousMethod, offer.natType, "denied")
		resp := &messages.ClientPollResponse{Error: messages.StrNoProxies}
		return sendClientResponse(resp, response)
	}

	// Wait for the answer to be returned on the channel or timeout.
	select {
	case answer := <-snowflake.answerChannel:
		i.ctx.metrics.UpdateClientStats(arg.RemoteAddr, arg.RendezvousMethod, offer.natType, "matched")
		resp := &messages.ClientPollResponse{Answer: answer}
		err = sendClientResponse(resp, response)
	case <-arg.Context.Done():
		i.ctx.metrics.UpdateClientStats(arg.RemoteAddr, arg.RendezvousMethod, offer.natType, "timeout")
		resp := &messages.ClientPollResponse{Error: messages.StrTimedOut}
		err = sendClientResponse(resp, response)
	}

	i.ctx.snowflakeLock.Lock()
	delete(i.ctx.idToSnowflake, snowflake.id)
	i.ctx.snowflakeLock.Unlock()

	return err
}

func (i *IPC) matchSnowflake(natType string) *Snowflake {
	// Proiritize known restricted snowflakes for unrestricted clients
	if natType == NATUnrestricted {
		snowflake := i.ctx.restrictedPool.Pop()
		if snowflake != nil {
			return snowflake
		}
	}

	snowflake := i.ctx.unrestrictedPool.Pop()
	return snowflake
}

func (i *IPC) ProxyAnswers(arg messages.Arg, response *[]byte) error {
	req, err := messages.DecodeProxyAnswerRequest(arg.Body)
	if err != nil || req.Answer == "" {
		return messages.ErrBadRequest
	}

	var success = true
	i.ctx.snowflakeLock.Lock()
	snowflake, ok := i.ctx.idToSnowflake[req.Sid]
	i.ctx.snowflakeLock.Unlock()
	if !ok || snowflake == nil {
		// The snowflake took too long to respond with an answer, so its client
		// disappeared / the snowflake is no longer recognized by the Broker.
		success = false
		i.ctx.metrics.promMetrics.ProxyAnswerTotal.With(prometheus.Labels{"type": "", "status": "timeout"}).Inc()
	}

	b, err := messages.EncodeAnswerResponse(success)
	if err != nil {
		log.Printf("Error encoding answer: %s", err.Error())
		return messages.ErrInternal
	}
	*response = b

	if success {
		i.ctx.metrics.promMetrics.ProxyAnswerTotal.With(prometheus.Labels{"type": snowflake.proxyType, "status": "success"}).Inc()
		snowflake.answerChannel <- req.Answer
	}

	return nil
}
