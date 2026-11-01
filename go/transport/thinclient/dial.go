package thinclient

import (
	"strings"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/client/thin/transport"
)

// DialConfig is how to reach the daemon at address: @name is an abstract unix socket, a path a
// unix socket, and anything else host:port over TCP.
func DialConfig(address string) *thin.Config {
	if strings.HasPrefix(address, "@") || strings.HasPrefix(address, "/") {
		return &thin.Config{Dial: &transport.DialConfig{Unix: &transport.UnixDialConfig{Address: address}}}
	}
	return &thin.Config{Dial: &transport.DialConfig{Tcp: &transport.TcpDialConfig{Address: address}}}
}

// Dial connects to the daemon at address, logging to logFile ("" for none).
func Dial(address, logFile string) (Backend, error) {
	logging := &config.Logging{Level: "ERROR", File: logFile, Disable: logFile == ""}
	c := thin.NewThinClient(DialConfig(address), logging)
	if err := c.Dial(); err != nil {
		return Backend{}, err
	}
	return Backend{Client: c}, nil
}

func (b Backend) Close() error { return b.Client.Close() }
