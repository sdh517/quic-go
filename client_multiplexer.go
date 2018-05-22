package quic

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type multiplexer struct {
	mutex sync.Mutex

	conns map[net.PacketConn]sessionHandler

	logger utils.Logger
}

func newClientMultiplexer(logger utils.Logger) *multiplexer {
	return &multiplexer{
		conns:  make(map[net.PacketConn]sessionHandler),
		logger: logger,
	}
}

func (m *multiplexer) Add(c net.PacketConn, client *client) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	fmt.Println("add")
	sessions, ok := m.conns[c]
	if !ok {
		sessions = newSessionMap()
		m.conns[c] = sessions
	}
	sessions.Add(client.srcConnID, client)
	if ok {
		return
	}

	go func() {
		fmt.Println("listening")
		for {
			data := *getPacketBuffer()
			data = data[:protocol.MaxReceivePacketSize]
			// The packet size should not exceed protocol.MaxReceivePacketSize bytes
			// If it does, we only read a truncated packet, which will then end up undecryptable
			n, addr, err := c.ReadFrom(data)
			if err != nil {
				if !strings.HasSuffix(err.Error(), "use of closed network connection") {
					sessions.Close()
				}
				break
			}
			data = data[:n]
			rcvTime := time.Now()

			r := bytes.NewReader(data)
			hdr, err := wire.ParseHeaderSentByServer(r)
			// drop the packet if we can't parse the header
			if err != nil {
				m.logger.Debugf("error parsing packet from %s: %s", addr, err)
				continue
			}
			hdr.Raw = data[:len(data)-r.Len()]
			packetData := data[len(data)-r.Len():]

			client, ok := sessions.Get(hdr.DestConnectionID)
			if !ok {
				m.logger.Debugf("received a packet with an unexpected connection ID %s", hdr.DestConnectionID)
			}
			client.handlePacket(&receivedPacket{
				remoteAddr: addr,
				header:     hdr,
				data:       packetData,
				rcvTime:    rcvTime,
			})
		}
	}()
}
