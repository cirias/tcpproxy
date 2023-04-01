package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

type CollectorServer struct {
	peering *PeeringCollector
}

func NewCollectorServer(peering *PeeringCollector) *CollectorServer {
	return &CollectorServer{peering}
}

func (s *CollectorServer) ListenAndServe(ctx context.Context, socketPath string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/peers", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "GET" {
			return
		}

		data, err := s.peering.Collect()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write(data)
	})

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", socketPath)
	if err != nil {
		return fmt.Errorf("could not listen unix socket: %w", err)
	}

	return http.Serve(ln, mux)
}

type PeeringStatus int

const (
	peerStatusInitAnswering PeeringStatus = iota
	peerStatusAnsweredDialing
	peerStatusDialedTransmitting
	peerStatusErroredClosing
)

var peeringStatusText = map[PeeringStatus]string{
	peerStatusInitAnswering:      "InitAnswering",
	peerStatusAnsweredDialing:    "AnsweredDialing",
	peerStatusDialedTransmitting: "DialedTransmitting",
	peerStatusErroredClosing:     "ErroredClosing",
}

func (s PeeringStatus) String() string {
	return peeringStatusText[s]
}

func (s PeeringStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

type Endpoint struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	ReadBytes  uint64
	WriteBytes uint64
}

type Peering struct {
	Status     PeeringStatus
	DstAddr    net.Addr `json:",omitempty"`
	Inbound    Endpoint `json:",omitempty"`
	Outbound   Endpoint `json:",omitempty"`
	FirstError error    `json:",omitempty"`
}

type eventPeeringInit struct {
	key     int
	inbound Endpoint
}

type eventPeeringAnswered struct {
	key     int
	dstAddr net.Addr
}

type eventPeeringDialed struct {
	key      int
	outbound Endpoint
}

type eventPeeringDataTransmitted struct {
	key       int
	isInbound bool
	isRead    bool
	bytes     int
}

type eventPeeringErrored struct {
	key int
	err error
}

type eventPeeringClosed struct {
	key int
}

type eventCollectPeerings struct {
	done chan struct {
		data []byte
		err  error
	}
}

type PeeringCollector struct {
	keyGen   *KeyGenerator
	events   chan any
	peerings map[int]*Peering
}

func NewPeeringCollector() *PeeringCollector {
	s := &PeeringCollector{
		keyGen:   NewKeyGenerator(),
		events:   make(chan any, 128),
		peerings: make(map[int]*Peering),
	}
	go func() {
		s.handleEvents()
	}()
	return s
}

func (s *PeeringCollector) Collect() ([]byte, error) {
	returnCh := make(chan struct {
		data []byte
		err  error
	})
	s.events <- &eventCollectPeerings{returnCh}
	// TODO timeout on waiting return?
	ret := <-returnCh
	return ret.data, ret.err
}

type peeringHandle struct {
	events chan<- any
	key    int
}

func (s *PeeringCollector) CreatePeering(answerer Answerer) *peeringHandle {
	if s == nil {
		return nil
	}

	key := s.keyGen.Next()
	s.events <- &eventPeeringInit{
		key: key,
		inbound: Endpoint{
			LocalAddr:  answerer.LocalAddr(),
			RemoteAddr: answerer.RemoteAddr(),
		},
	}
	return &peeringHandle{s.events, key}
}

func (h *peeringHandle) AnsweredDailing(dstAddr net.Addr) {
	if h == nil {
		return
	}
	h.events <- &eventPeeringAnswered{
		key:     h.key,
		dstAddr: dstAddr,
	}
}

func (h *peeringHandle) DialedTransmitting(outConn net.Conn) {
	if h == nil {
		return
	}
	h.events <- &eventPeeringDialed{
		key: h.key,
		outbound: Endpoint{
			LocalAddr:  outConn.LocalAddr(),
			RemoteAddr: outConn.RemoteAddr(),
		},
	}
}

type ReadWriteCollector interface {
	Read(n int)
	Write(n int)
}

func (h *peeringHandle) FromInToOut() *readWriteCollector {
	if h == nil {
		return nil
	}
	return &readWriteCollector{
		events:      h.events,
		key:         h.key,
		fromInToOut: true,
	}
}

func (h *peeringHandle) FromOutToIn() *readWriteCollector {
	if h == nil {
		return nil
	}
	return &readWriteCollector{
		events:      h.events,
		key:         h.key,
		fromInToOut: false,
	}
}

func (h *peeringHandle) Errored(err error) {
	if h == nil {
		return
	}
	h.events <- &eventPeeringErrored{h.key, err}
}

func (h *peeringHandle) Close() {
	if h == nil {
		return
	}
	h.events <- &eventPeeringClosed{h.key}
}

type readWriteCollector struct {
	events      chan<- any
	key         int
	fromInToOut bool
}

func (c *readWriteCollector) Read(n int) {
	if c == nil {
		return
	}
	c.events <- &eventPeeringDataTransmitted{
		isInbound: c.fromInToOut,
		isRead:    true,
		bytes:     n,
	}
}

func (c *readWriteCollector) Write(n int) {
	if c == nil {
		return
	}
	c.events <- &eventPeeringDataTransmitted{
		isInbound: !c.fromInToOut,
		isRead:    false,
		bytes:     n,
	}
}

func (s *PeeringCollector) handleEvents() {
	for ev := range s.events {
		s.handleEvent(ev)
	}
}

func (s *PeeringCollector) handleEvent(ev any) {
	switch event := ev.(type) {
	case *eventPeeringInit:
		s.peerings[event.key] = &Peering{Status: peerStatusInitAnswering, Inbound: event.inbound}

	case *eventPeeringAnswered:
		p := s.peerings[event.key]
		p.Status = peerStatusAnsweredDialing
		p.DstAddr = event.dstAddr

	case *eventPeeringDialed:
		p := s.peerings[event.key]
		p.Status = peerStatusDialedTransmitting
		p.Outbound = event.outbound

	case *eventPeeringDataTransmitted:
		p := s.peerings[event.key]
		bound := p.Outbound
		if event.isInbound {
			bound = p.Inbound
		}
		bytes := &bound.WriteBytes
		if event.isRead {
			bytes = &bound.ReadBytes
		}
		*bytes += uint64(event.bytes)

	case *eventPeeringErrored:
		p := s.peerings[event.key]
		if p.FirstError == nil {
			p.FirstError = event.err
		}

	case *eventPeeringClosed:
		delete(s.peerings, event.key)
		s.keyGen.Recycle(event.key)

	case *eventCollectPeerings:
		data, err := json.Marshal(s.peerings)
		select {
		case event.done <- struct {
			data []byte
			err  error
		}{data, err}:
		default:
		}

	default:
		panic(fmt.Sprintf("unhandled event type: %T", event))
	}
}
