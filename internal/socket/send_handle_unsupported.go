//go:build !linux

package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
)

type SendHandle struct{}

func NewSendHandle(*conf.Network) (*SendHandle, error) {
	return nil, fmt.Errorf("PF_RING mode is only supported on linux")
}

func (h *SendHandle) Write([]byte, *net.UDPAddr) error {
	return fmt.Errorf("PF_RING mode is only supported on linux")
}

func (h *SendHandle) setClientTCPF(net.Addr, []conf.TCPF) {}

func (h *SendHandle) Close() {}
