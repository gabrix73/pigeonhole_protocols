// Package motd is the message of the day service, a minimal pigeonhole service. A client dials
// it and sends Requests over the connection; the service answers each with the current message.
// The client side is clients/motd.
package motd

import (
	"context"
	"time"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

// Request asks for the message of the day.
type Request struct{}

// Reply carries the message of the day.
type Reply struct {
	// Message is the message of the day.
	Message string
	// Day is the date it is the message of, as YYYY-MM-DD in UTC.
	Day string
	// Error says why there is no message; empty on success.
	Error string `cbor:",omitempty"`
}

// Source returns the current message of the day.
type Source func() (string, error)

// Conn is one end of a connection: a *pigeonservice.Session on the service's side, a
// *pigeonservice.Conn on the client's.
type Conn interface {
	Recv(ctx context.Context) ([]byte, error)
	Send(ctx context.Context, msg []byte) error
}

// Clock tells the time a reply is dated by.
type Clock interface {
	Now() time.Time
}

// SystemClock is the system's clock.
type SystemClock struct{}

// Now returns the current time.
func (SystemClock) Now() time.Time { return time.Now() }

// Serve answers one client's requests until the connection ends. A request that does not
// decode, or one the source cannot answer, gets a Reply with Error set.
func Serve(ctx context.Context, s Conn, source Source, clock Clock) error {
	for {
		raw, err := s.Recv(ctx)
		if err != nil {
			return err
		}
		var r Reply
		var req Request
		if err := common.Unmarshal(raw, &req); err != nil {
			r.Error = "bad request"
		} else if msg, err := source(); err != nil {
			r.Error = "no message available"
		} else {
			r = Reply{Message: msg, Day: clock.Now().UTC().Format(time.DateOnly)}
		}
		reply, err := common.Marshal(&r)
		if err != nil {
			return err
		}
		if err := s.Send(ctx, reply); err != nil {
			return err
		}
	}
}
