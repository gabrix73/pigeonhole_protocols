package stream_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonservice/common/phtest"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/stream"
)

var fast = &stream.Tuning{Window: 4, Poll: time.Millisecond}

func random(t *testing.T, n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func TestFramingVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/stream_vectors.json")
	require.NoError(t, err)
	var v struct {
		Boxes []struct {
			Data, Box string
			End       bool
		}
		Invalid []string
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	for _, c := range v.Boxes {
		data, _ := hex.DecodeString(c.Data)
		box, _ := hex.DecodeString(c.Box)
		require.Equal(t, box, stream.Encode(data, c.End))
		d, end, err := stream.Decode(box)
		require.NoError(t, err)
		require.Equal(t, c.End, end)
		require.True(t, bytes.Equal(data, d))
	}
	for _, c := range v.Invalid {
		box, _ := hex.DecodeString(c)
		_, _, err := stream.Decode(box)
		require.Error(t, err, c)
	}
}

func TestPublishAndFetch(t *testing.T) {
	ctx := context.Background()
	n := phtest.NewNetwork()
	n.MaxBox = 64
	for _, size := range []int{0, 1, 62, 63, 64, 5000} {
		m := random(t, size)
		before := n.Writes
		rc, err := stream.Publish(ctx, n, bytes.NewReader(m), fast)
		require.NoError(t, err)
		// Full boxes of 63 bytes, then the end box with what is left.
		require.Equal(t, size/63+1, n.Writes-before)
		var out bytes.Buffer
		require.NoError(t, stream.Fetch(ctx, n, rc, &out, stream.MaxMessage, fast))
		require.True(t, bytes.Equal(m, out.Bytes()), "size %d", size)
	}
}

func TestMegabytes(t *testing.T) {
	ctx := context.Background()
	n := phtest.NewNetwork()
	m := random(t, 4<<20)
	rc, err := stream.Publish(ctx, n, bytes.NewReader(m), fast)
	require.NoError(t, err)
	var out bytes.Buffer
	require.NoError(t, stream.Fetch(ctx, n, rc, &out, stream.MaxMessage, fast))
	require.True(t, bytes.Equal(m, out.Bytes()))
}

func TestOverTheLimit(t *testing.T) {
	ctx := context.Background()
	n := phtest.NewNetwork()
	n.MaxBox = 64
	m := random(t, 5000)
	rc, err := stream.Publish(ctx, n, bytes.NewReader(m), fast)
	require.NoError(t, err)
	var out bytes.Buffer
	require.ErrorIs(t, stream.Fetch(ctx, n, rc, &out, 4999, fast), stream.ErrTooLarge)
	require.LessOrEqual(t, out.Len(), 4999)
	require.True(t, bytes.HasPrefix(m, out.Bytes()))
	out.Reset()
	require.NoError(t, stream.Fetch(ctx, n, rc, &out, 5000, fast))
	require.True(t, bytes.Equal(m, out.Bytes()))
}

func TestTombstoneFails(t *testing.T) {
	ctx := context.Background()
	n := phtest.NewNetwork()
	wc, rc, idx, err := n.NewStream()
	require.NoError(t, err)
	require.NoError(t, n.Tombstone(ctx, wc, idx))
	require.Error(t, stream.Fetch(ctx, n, rc, &bytes.Buffer{}, stream.MaxMessage, fast))
}

func TestFetchWaitsForTheWriter(t *testing.T) {
	ctx := context.Background()
	n := phtest.NewNetwork()
	n.MaxBox = 64
	wc, rc, idx, err := n.NewStream()
	require.NoError(t, err)
	m := random(t, 3000)
	done := make(chan error, 1)
	var out bytes.Buffer
	go func() { done <- stream.Fetch(ctx, n, rc, &out, stream.MaxMessage, fast) }()
	time.Sleep(50 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("fetch ended before anything was written")
	default:
	}
	next, err := stream.Write(ctx, n, wc, idx, bytes.NewReader(m), fast)
	require.NoError(t, err)
	require.NoError(t, <-done)
	require.True(t, bytes.Equal(m, out.Bytes()))
	// The index after the end box.
	want := idx
	for range 3000/63 + 1 {
		want, err = want.NextIndex()
		require.NoError(t, err)
	}
	require.Equal(t, want.Idx64, next.Idx64)
}
