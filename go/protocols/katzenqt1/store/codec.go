package store

import (
	"encoding/json"
	"fmt"

	"github.com/katzenpost/pigeonhole_protocols/go/internal/ordmap"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member/tracejson"
)

// What is saved of a conversation, apart from its lines, and of a line, as JSON. Keys and
// indexes are bytes, so they go as []byte; the member's state goes in its trace form.

type pair struct {
	K []byte `json:"k"`
	V []byte `json:"v"`
}

type namePair struct {
	K []byte `json:"k"`
	V string `json:"v"`
}

type upload struct {
	File     string `json:"file"`
	BoxSize  int    `json:"box_size"`
	Total    int    `json:"total"`
	WriteCap []byte `json:"write_cap"`
	Sent     int    `json:"sent"`
	Next     []byte `json:"next"`
}

type job struct {
	ID     int     `json:"id"`
	Token  *int    `json:"token"`
	Index  []byte  `json:"index"`
	Box    []byte  `json:"box"`
	Line   *int    `json:"line"`
	Packed []int   `json:"packed,omitempty"`
	Upload *upload `json:"upload"`
}

type sealed struct {
	Name           string `json:"name"`
	MutatedReadCap []byte `json:"mutated_read_cap"`
	Reply          []byte `json:"reply"`
	Version        int    `json:"version,omitempty"`
}

type inducting struct {
	Voucher         []byte  `json:"voucher"`
	Payload         []byte  `json:"payload"`
	VoucherWriteCap []byte  `json:"voucher_write_cap"`
	Box1            []byte  `json:"box1"`
	Sealing         bool    `json:"sealing"`
	Sealed          *sealed `json:"sealed"`
}

type joining struct {
	Code           string `json:"code"`
	SecretKey      []byte `json:"secret_key"`
	VoucherReadCap []byte `json:"voucher_read_cap"`
	Box1           []byte `json:"box1"`
	Version        int    `json:"version,omitempty"`
}

type download struct {
	Stream  []byte `json:"stream"`
	Index   []byte `json:"index"`
	Next    []byte `json:"next"`
	ReadCap []byte `json:"read_cap"`
	Total   *int   `json:"total"`
}

type chatRecord struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	WriteCap  []byte          `json:"write_cap"`
	NextWrite []byte          `json:"next_write"`
	Group     json.RawMessage `json:"group"`
	Cursors   []pair          `json:"cursors"`
	Names     []namePair      `json:"names"`
	Jobs      []job           `json:"jobs"`
	Joining   *joining        `json:"joining"`
	Inducting *inducting      `json:"inducting"`
	NextID    int             `json:"next_id"`
	Downloads []download      `json:"downloads"`
}

type attachment struct {
	Name     string `json:"name"`
	Filetype string `json:"filetype"`
	Size     int    `json:"size"`
	File     string `json:"file"`
}

type notice struct {
	Kind int      `json:"kind"`
	Args []string `json:"args"`
}

type line struct {
	ID         int         `json:"id"`
	Sender     []byte      `json:"sender"`
	Index      []byte      `json:"index"`
	Text       string      `json:"text"`
	Notice     *notice     `json:"notice"`
	Status     int         `json:"status"`
	Idx64      *uint64     `json:"idx64"`
	Time       int64       `json:"time"`
	Attachment *attachment `json:"attachment"`
}

func optIndex(i *member.Index) []byte {
	if i == nil {
		return nil
	}
	return []byte(*i)
}

func encodeChat(c *engine.Chat) ([]byte, error) {
	r := chatRecord{ID: string(c.ID), Name: c.Name, WriteCap: c.WriteCap, NextWrite: []byte(c.NextWrite), NextID: c.NextID}
	if c.Group != nil {
		g, err := json.Marshal(tracejson.Group(c.Group))
		if err != nil {
			return nil, err
		}
		r.Group = g
	}
	for k, v := range c.Cursors.All {
		r.Cursors = append(r.Cursors, pair{[]byte(k), []byte(v)})
	}
	for k, v := range c.Names.All {
		r.Names = append(r.Names, namePair{[]byte(k), v})
	}
	for _, j := range c.Jobs {
		rj := job{ID: j.ID, Token: j.Token, Index: optIndex(j.Index), Box: j.Box, Line: j.Line, Packed: j.Packed}
		if u := j.Upload; u != nil {
			rj.Upload = &upload{u.File, u.BoxSize, u.Total, u.WriteCap, u.Sent, []byte(u.Next)}
		}
		r.Jobs = append(r.Jobs, rj)
	}
	if j := c.Joining; j != nil {
		r.Joining = &joining{j.Code, j.SecretKey, j.VoucherReadCap, []byte(j.Box1), j.Version}
	}
	if i := c.Inducting; i != nil {
		r.Inducting = &inducting{i.Voucher, i.Payload, i.VoucherWriteCap, []byte(i.Box1), i.Sealing, nil}
		if s := i.Sealed; s != nil {
			r.Inducting.Sealed = &sealed{s.Name, s.MutatedReadCap, s.Reply, s.Version}
		}
	}
	for _, d := range c.Downloads {
		r.Downloads = append(r.Downloads, download{[]byte(d.Stream), []byte(d.Index), []byte(d.Next), d.ReadCap, d.Total})
	}
	return json.Marshal(r)
}

func indexOrNil(b []byte) *member.Index {
	if b == nil {
		return nil
	}
	i := member.Index(b)
	return &i
}

func decodeChat(b []byte) (*engine.Chat, error) {
	var r chatRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	c := &engine.Chat{ID: engine.ChatID(r.ID), Name: r.Name, WriteCap: r.WriteCap, NextWrite: member.Index(r.NextWrite), NextID: r.NextID}
	if len(r.Group) > 0 && string(r.Group) != "null" {
		j, err := tracejson.Parse(append(append([]byte(`{"g":`), r.Group...), '}'))
		if err != nil {
			return nil, err
		}
		if c.Group, err = tracejson.ReadGroup(j["g"]); err != nil {
			return nil, fmt.Errorf("chat %s: %w", r.ID, err)
		}
	}
	c.Cursors = ordmap.Map[member.Key, member.Index]{}
	for _, p := range r.Cursors {
		c.Cursors.Set(member.Key(p.K), member.Index(p.V))
	}
	for _, p := range r.Names {
		c.Names.Set(member.Key(p.K), p.V)
	}
	for _, j := range r.Jobs {
		cj := &engine.Job{ID: j.ID, Token: j.Token, Index: indexOrNil(j.Index), Box: j.Box, Line: j.Line, Packed: j.Packed}
		if cj.Box == nil {
			cj.Box = []byte{}
		}
		if u := j.Upload; u != nil {
			cj.Upload = &engine.Upload{File: u.File, BoxSize: u.BoxSize, Total: u.Total, WriteCap: u.WriteCap, Sent: u.Sent, Next: member.Index(u.Next)}
		}
		c.Jobs = append(c.Jobs, cj)
	}
	if j := r.Joining; j != nil {
		c.Joining = &engine.Joining{Code: j.Code, SecretKey: j.SecretKey, VoucherReadCap: j.VoucherReadCap, Box1: member.Index(j.Box1), Version: max(j.Version, 1)}
	}
	if i := r.Inducting; i != nil {
		c.Inducting = &engine.Inducting{Voucher: i.Voucher, Payload: i.Payload, VoucherWriteCap: i.VoucherWriteCap, Box1: member.Index(i.Box1), Sealing: i.Sealing}
		if s := i.Sealed; s != nil {
			c.Inducting.Sealed = &engine.Sealed{Name: s.Name, MutatedReadCap: s.MutatedReadCap, Reply: s.Reply, Version: max(s.Version, 1)}
		}
	}
	for _, d := range r.Downloads {
		c.Downloads = append(c.Downloads, engine.Download{Stream: member.Key(d.Stream), Index: member.Index(d.Index),
			Next: member.Index(d.Next), ReadCap: d.ReadCap, Total: d.Total})
	}
	return c, nil
}

func encodeLine(l *engine.Line) ([]byte, error) {
	r := line{ID: l.ID, Sender: []byte(l.Sender), Index: []byte(l.Index), Text: l.Text, Status: int(l.Status), Idx64: l.Idx64, Time: l.Time}
	if n := l.Notice; n != nil {
		r.Notice = &notice{int(n.Kind), n.Args}
	}
	if a := l.Attachment; a != nil {
		r.Attachment = &attachment{a.Name, a.Filetype, a.Size, a.File}
	}
	return json.Marshal(r)
}

func decodeLine(b []byte) (*engine.Line, error) {
	var r line
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	l := &engine.Line{ID: r.ID, Sender: member.Key(r.Sender), Index: member.Index(r.Index), Text: r.Text,
		Status: engine.Status(r.Status), Idx64: r.Idx64, Time: r.Time}
	if n := r.Notice; n != nil {
		l.Notice = &engine.Notice{Kind: engine.NoticeKind(n.Kind), Args: n.Args}
	}
	if a := r.Attachment; a != nil {
		l.Attachment = &engine.Attachment{Name: a.Name, Filetype: a.Filetype, Size: a.Size, File: a.File}
	}
	return l, nil
}
