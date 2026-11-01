package thinclient

import "testing"

func TestDialConfig(t *testing.T) {
	if c := DialConfig("@katzenpost"); c.Dial.Unix == nil || c.Dial.Unix.Address != "@katzenpost" {
		t.Error("abstract socket")
	}
	if c := DialConfig("/run/kp.sock"); c.Dial.Unix == nil {
		t.Error("socket path")
	}
	if c := DialConfig("localhost:64331"); c.Dial.Tcp == nil || c.Dial.Tcp.Address != "localhost:64331" {
		t.Error("tcp")
	}
}

func TestMostCommon(t *testing.T) {
	for _, c := range []struct {
		in   []uint64
		want uint64
	}{{[]uint64{5}, 5}, {[]uint64{7, 6, 7}, 7}, {[]uint64{3, 4, 4, 3, 4}, 4}} {
		if got, err := mostCommon(c.in); err != nil || got != c.want {
			t.Errorf("%v: %d %v", c.in, got, err)
		}
	}
	if _, err := mostCommon(nil); err == nil {
		t.Error("no epochs accepted")
	}
}
