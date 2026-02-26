//go:build linux

package socket

import (
	"fmt"
	"paqet/internal/conf"
	"runtime"

	"github.com/gopacket/gopacket/pfring"
)

func newHandle(cfg *conf.Network) (*pfring.Ring, error) {
	// On Windows, use the GUID field to construct the NPF device name
	// On other platforms, use the interface name directly
	ifaceName := cfg.Interface.Name
	if runtime.GOOS == "windows" {
		ifaceName = cfg.GUID
	}

	ring, err := pfring.NewRing(ifaceName, 65536, pfring.FlagPromisc)
	if err != nil {
		return nil, fmt.Errorf("failed to create PF_RING handle for %s: %v", cfg.Interface.Name, err)
	}
	if err := ring.SetApplicationName("paqet"); err != nil {
		ring.Close()
		return nil, fmt.Errorf("failed to set PF_RING application name: %v", err)
	}

	return ring, nil
}
