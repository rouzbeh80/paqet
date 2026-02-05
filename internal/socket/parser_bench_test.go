package socket

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Sample packet: Ethernet / IPv4 / TCP / Payload
// Generated for testing purposes
var packetData = func() []byte {
	// 00 11 22 33 44 55  66 77 88 99 aa bb  08 00  45 00
	// 00 28  00 00 40 00  40 06 b0 c0  c0 a8 01 02  c0 a8
	// 01 01  04 d2 00 50  00 00 00 00  00 00 00 00  50 02
	// 20 00  91 7c 00 00
	// Plus 100 bytes of payload
	data, _ := hex.DecodeString("00112233445566778899aabb080045000028000040004006b0c0c0a80102c0a8010104d20050000000000000000050022000917c0000")
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}
	return append(data, payload...)
}()

func BenchmarkNewPacket(b *testing.B) {
	addr := &net.UDPAddr{}
	for i := 0; i < b.N; i++ {
		p := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.NoCopy)

		netLayer := p.NetworkLayer()
		if netLayer == nil {
			continue
		}
		switch netLayer.LayerType() {
		case layers.LayerTypeIPv4:
			addr.IP = netLayer.(*layers.IPv4).SrcIP
		case layers.LayerTypeIPv6:
			addr.IP = netLayer.(*layers.IPv6).SrcIP
		}

		trLayer := p.TransportLayer()
		if trLayer == nil {
			continue
		}
		switch trLayer.LayerType() {
		case layers.LayerTypeTCP:
			addr.Port = int(trLayer.(*layers.TCP).SrcPort)
		case layers.LayerTypeUDP:
			addr.Port = int(trLayer.(*layers.UDP).SrcPort)
		}

		appLayer := p.ApplicationLayer()
		if appLayer == nil {
			continue
		}
		_ = appLayer.Payload()
	}
}

func BenchmarkDecodingLayerParser(b *testing.B) {
	eth := &layers.Ethernet{}
	ipv4 := &layers.IPv4{}
	ipv6 := &layers.IPv6{}
	tcp := &layers.TCP{}
	udp := &layers.UDP{}
	decoded := make([]gopacket.LayerType, 0, 4)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, eth, ipv4, ipv6, tcp, udp)
	// Optimize
	parser.IgnoreUnsupported = true

	addr := &net.UDPAddr{}

	for i := 0; i < b.N; i++ {
		_ = parser.DecodeLayers(packetData, &decoded)

		hasIPv4 := false
		hasIPv6 := false
		hasTCP := false
		hasUDP := false

		for _, layerType := range decoded {
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
			addr.IP = ipv4.SrcIP
		} else if hasIPv6 {
			addr.IP = ipv6.SrcIP
		}

		if hasTCP {
			addr.Port = int(tcp.SrcPort)
			_ = tcp.Payload
		} else if hasUDP {
			addr.Port = int(udp.SrcPort)
			_ = udp.Payload
		}
	}
}
