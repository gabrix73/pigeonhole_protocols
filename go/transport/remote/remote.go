// Package remote serves a transport over a socket, as JSON-RPC 1.0 (bytes in base64), so that
// clients in other processes, in Go or in Rust, share one Pigeonhole: for tests that stop and
// start clients, as an in-memory one cannot outlive them.
package remote

import (
	"context"
	"errors"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"

	"github.com/katzenpost/pigeonhole_protocols/go/transport"
)

// Args and Reply carry every call; each uses what it needs.
type Args struct {
	A, B, C []byte
	Name    string
	Form    int
}

type Reply struct {
	A, B    []byte
	Keypair transport.Keypair
	Read    transport.Read
	Minted  transport.Minted
	Induct  transport.Inducted
	Opened  transport.Opened
	N       uint64
	Exists  bool
}

type Service struct{ B transport.Backend }

var bg = context.Background()

func (s *Service) NewKeypair(a Args, r *Reply) (err error) {
	r.Keypair, err = s.B.NewKeypair(bg)
	return
}

func (s *Service) WriteBox(a Args, r *Reply) error {
	err := s.B.WriteBox(bg, a.A, a.B, a.C)
	if errors.Is(err, transport.ErrBoxAlreadyExists) {
		r.Exists = true
		return nil
	}
	return err
}

func (s *Service) ReadBox(a Args, r *Reply) (err error) {
	r.Read, err = s.B.ReadBox(bg, a.A, a.B)
	return
}

func (s *Service) ReplicaEpoch(a Args, r *Reply) (err error) {
	r.N, err = s.B.ReplicaEpoch(bg)
	return
}

func (s *Service) MaxPlaintext(a Args, r *Reply) error {
	n, err := s.B.MaxPlaintext(bg)
	r.N = uint64(n)
	return err
}

func (s *Service) VoucherMint(a Args, r *Reply) (err error) {
	r.Minted, err = s.B.VoucherMint(bg, a.A, a.Name, a.Form)
	return
}

func (s *Service) VoucherDeriveStream(a Args, r *Reply) (err error) {
	r.A, r.B, err = s.B.VoucherDeriveStream(bg, a.A)
	return
}

func (s *Service) VoucherInduct(a Args, r *Reply) (err error) {
	r.Induct, err = s.B.VoucherInduct(bg, a.A, a.B, a.C)
	return
}

func (s *Service) VoucherOpen(a Args, r *Reply) (err error) {
	r.Opened, err = s.B.VoucherOpen(bg, a.A, a.B, a.C)
	return
}

// Serve serves b on l until l is closed.
func Serve(l net.Listener, b transport.Backend) error {
	srv := rpc.NewServer()
	if err := srv.RegisterName("Pigeonhole", &Service{b}); err != nil {
		return err
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go srv.ServeCodec(jsonrpc.NewServerCodec(conn))
	}
}

// Client is a transport served by Serve.
type Client struct{ c *rpc.Client }

var _ transport.Backend = (*Client)(nil)

func Dial(network, address string) (*Client, error) {
	c, err := jsonrpc.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return &Client{c}, nil
}

func (c *Client) Close() error { return c.c.Close() }

func (c *Client) call(ctx context.Context, method string, a Args) (Reply, error) {
	var r Reply
	call := c.c.Go("Pigeonhole."+method, a, &r, make(chan *rpc.Call, 1))
	select {
	case <-call.Done:
		return r, call.Error
	case <-ctx.Done():
		return r, ctx.Err()
	}
}

func (c *Client) NewKeypair(ctx context.Context) (transport.Keypair, error) {
	r, err := c.call(ctx, "NewKeypair", Args{})
	return r.Keypair, err
}

func (c *Client) WriteBox(ctx context.Context, writeCap, index, plaintext []byte) error {
	r, err := c.call(ctx, "WriteBox", Args{A: writeCap, B: index, C: plaintext})
	if err == nil && r.Exists {
		return transport.ErrBoxAlreadyExists
	}
	return err
}

func (c *Client) ReadBox(ctx context.Context, readCap, index []byte) (transport.Read, error) {
	r, err := c.call(ctx, "ReadBox", Args{A: readCap, B: index})
	return r.Read, err
}

func (c *Client) ReplicaEpoch(ctx context.Context) (uint64, error) {
	r, err := c.call(ctx, "ReplicaEpoch", Args{})
	return r.N, err
}

func (c *Client) MaxPlaintext(ctx context.Context) (int, error) {
	r, err := c.call(ctx, "MaxPlaintext", Args{})
	return int(r.N), err
}

func (c *Client) VoucherMint(ctx context.Context, writeCap []byte, name string, form int) (transport.Minted, error) {
	r, err := c.call(ctx, "VoucherMint", Args{A: writeCap, Name: name, Form: form})
	return r.Minted, err
}

func (c *Client) VoucherDeriveStream(ctx context.Context, voucher []byte) ([]byte, []byte, error) {
	r, err := c.call(ctx, "VoucherDeriveStream", Args{A: voucher})
	return r.A, r.B, err
}

func (c *Client) VoucherInduct(ctx context.Context, voucher, payload, whoReply []byte) (transport.Inducted, error) {
	r, err := c.call(ctx, "VoucherInduct", Args{A: voucher, B: payload, C: whoReply})
	return r.Induct, err
}

func (c *Client) VoucherOpen(ctx context.Context, secretKey, sealedReply, writeCap []byte) (transport.Opened, error) {
	r, err := c.call(ctx, "VoucherOpen", Args{A: secretKey, B: sealedReply, C: writeCap})
	return r.Opened, err
}
