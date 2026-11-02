package gemini_test

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	client "github.com/katzenpost/pigeonhole_protocols/go/clients/gemini"
	"github.com/katzenpost/pigeonhole_protocols/go/services/gemini"
)

type clientFakeConn struct {
	in, out chan []byte
}

func newClientFakeConn() *clientFakeConn {
	return &clientFakeConn{in: make(chan []byte, 4), out: make(chan []byte, 4)}
}

func (c *clientFakeConn) Recv(ctx context.Context) ([]byte, error) {
	select {
	case m, ok := <-c.in:
		if !ok {
			return nil, io.EOF
		}
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *clientFakeConn) Send(ctx context.Context, msg []byte) error {
	c.out <- msg
	return nil
}

func TestClientFetch(t *testing.T) {
	conn := newClientFakeConn()

	// Simulate service response in background
	go func() {
		rawReq := <-conn.out
		var req gemini.Request
		require.NoError(t, common.Unmarshal(rawReq, &req))
		require.Equal(t, "gemini://geminispace.info", req.URL)

		resp := gemini.Response{
			Status: 20,
			Meta:   "text/gemini",
			Body:   []byte("# Welcome to Geminispace"),
		}
		rawResp, err := common.Marshal(&resp)
		require.NoError(t, err)
		conn.in <- rawResp
	}()

	resp, err := client.Fetch(context.Background(), conn, "gemini://geminispace.info")
	require.NoError(t, err)
	require.Equal(t, 20, resp.Status)
	require.Equal(t, "text/gemini", resp.Meta)
	require.Equal(t, "# Welcome to Geminispace", string(resp.Body))
}

func TestClientFetchErrors(t *testing.T) {
	// 1. Service reports error in response
	conn := newClientFakeConn()
	go func() {
		_ = <-conn.out
		resp := gemini.Response{
			Error: "host unreachable",
		}
		rawResp, _ := common.Marshal(&resp)
		conn.in <- rawResp
	}()

	_, err := client.Fetch(context.Background(), conn, "gemini://invalid.host")
	require.Error(t, err)
	require.Contains(t, err.Error(), "host unreachable")

	// 2. Corrupt reply
	conn2 := newClientFakeConn()
	go func() {
		_ = <-conn2.out
		conn2.in <- []byte{0xff, 0xff}
	}()

	_, err = client.Fetch(context.Background(), conn2, "gemini://example.com")
	require.ErrorIs(t, err, client.ErrBadReply)
}
