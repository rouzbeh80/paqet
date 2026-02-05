package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
	"runtime"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type RecvHandle struct {
	handle *pcap.Handle
	parser *gopacket.DecodingLayerParser
	eth    *layers.Ethernet
	ipv4   *layers.IPv4
	ipv6   *layers.IPv6
	tcp    *layers.TCP
	udp    *layers.UDP
	decoded []gopacket.LayerType
}

func NewRecvHandle(cfg *conf.Network) (*RecvHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionIn); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction in: %v", err)
		}
	}

	filter := fmt.Sprintf("tcp and dst port %d", cfg.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	h := &RecvHandle{
		handle: handle,
		eth:    &layers.Ethernet{},
		ipv4:   &layers.IPv4{},
		ipv6:   &layers.IPv6{},
		tcp:    &layers.TCP{},
		udp:    &layers.UDP{},
		decoded: make([]gopacket.LayerType, 0, 4),
	}
	h.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, h.eth, h.ipv4, h.ipv6, h.tcp, h.udp)
	// Optimize parser to not copy payload
	// h.parser.IgnoreUnsupported = true // Optional: ignore unknown layers

	return h, nil
}

func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	data, _, err := h.handle.ZeroCopyReadPacketData()
	if err != nil {
		return nil, nil, err
	}

	// Reset decoded layers
	// Note: We don't need to clear the structs themselves, DecodingLayerParser overwrites fields
	err = h.parser.DecodeLayers(data, &h.decoded)
	if err != nil {
		// We might get an error if the packet is truncated or has layers we don't support,
		// but we might still have decoded what we need.
		// However, for critical path, if we don't get TCP/UDP, we skip.
	}

	addr := &net.UDPAddr{}
	var payload []byte

	// Iterate over decoded layers to find Network and Transport layers
	// This is faster than map lookup or type assertions on interfaces if we know the order,
	// checking flags is efficient.
	
	// We only care if we found TCP or UDP (which implies IP was found if we are strictly parsing)
	// But let's check what we have.
	
	hasIPv4 := false
	hasIPv6 := false
	hasTCP := false
	hasUDP := false

	for _, layerType := range h.decoded {
		switch layerType {
		case layers.LayerTypeIPv4:
			hasIPv4 = true
		case layers.LayerTypeIPv6:
			hasIPv6 = true
		case layers.LayerTypeTCP:
			hasTCP = true
		case layers.LayerTypeUDP:
			hasUDP = true
		}
	}

	if hasIPv4 {
		addr.IP = h.ipv4.SrcIP
	} else if hasIPv6 {
		addr.IP = h.ipv6.SrcIP
	}

	if hasTCP {
		addr.Port = int(h.tcp.SrcPort)
		payload = h.tcp.Payload
	} else if hasUDP {
		addr.Port = int(h.udp.SrcPort)
		payload = h.udp.Payload
	} else {
		// No transport layer found
		return nil, addr, nil
	}

	// If we didn't find an IP layer but found transport (unlikely with this parser stack starting at Ethernet),
	// we still return what we have, but addr.IP will be nil/empty.
	
	return payload, addr, nil
}

func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
