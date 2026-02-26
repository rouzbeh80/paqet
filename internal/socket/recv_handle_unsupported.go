//go:build !linux

package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
)

type RecvHandle struct{}

func NewRecvHandle(*conf.Network) (*RecvHandle, error) {
	return nil, fmt.Errorf("PF_RING mode is only supported on linux")
}

func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	return nil, nil, fmt.Errorf("PF_RING mode is only supported on linux")
}

func (h *RecvHandle) Close() {}
