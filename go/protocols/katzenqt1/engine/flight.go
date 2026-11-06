package engine

import "github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"

type streamKey struct {
	chat   ChatID
	stream member.Key
}

type jobKey struct {
	chat ChatID
	job  int
}

type boxKey struct {
	sender member.Key
	index  member.Index
}

type landed struct {
	n     int
	after member.Index
}

type fetched struct {
	at    member.Index
	parts [][]byte
}

// flight is what is under way on the network; it is not saved, since a restart begins it again.
type flight struct {
	writing map[ChatID]bool
	// reading is the streams with a read out or a wake pending.
	reading map[streamKey]bool
	// misses is the reads of each stream that found nothing, in a row.
	misses map[streamKey]int
	// uploading is the uploads with a substream being made or indexes being derived.
	uploading map[jobKey]bool
	// ahead is the index of each box of an upload from the first not yet written on, as far as
	// derived.
	ahead map[jobKey][]member.Index
	// chunksOut is the boxes of each upload being written.
	chunksOut map[jobKey]map[int]bool
	// landed is the boxes of an upload written after one not yet written, with the index after
	// each.
	landed map[jobKey][]landed
	// loading is the uploads whose message is being read back from its file.
	loading map[jobKey]bool
	// blobs is each upload's message, once made or read back.
	blobs map[jobKey][]byte
	// fetched is what each download has read: the index of its next box, and the boxes so far.
	fetched map[streamKey]fetched
	// arriving is the bytes of a file a download just brought, while the member reads the
	// message without them.
	arriving map[boxKey][]byte
	// unreceipted numbers, from receipts, the content come in that no message of ours has
	// acknowledged yet; ticking is the number each chat has a Tick out for.
	unreceipted map[ChatID]int
	ticking     map[ChatID]int
	receipts    int
}

func newFlight() flight {
	return flight{
		writing: map[ChatID]bool{}, reading: map[streamKey]bool{}, misses: map[streamKey]int{},
		uploading: map[jobKey]bool{}, ahead: map[jobKey][]member.Index{}, chunksOut: map[jobKey]map[int]bool{},
		landed: map[jobKey][]landed{}, loading: map[jobKey]bool{}, blobs: map[jobKey][]byte{},
		fetched: map[streamKey]fetched{}, arriving: map[boxKey][]byte{},
		unreceipted: map[ChatID]int{}, ticking: map[ChatID]int{},
	}
}

func (f *flight) forget(chat ChatID) {
	delete(f.writing, chat)
	delete(f.unreceipted, chat)
	delete(f.ticking, chat)
	for k := range f.reading {
		if k.chat == chat {
			delete(f.reading, k)
		}
	}
	for k := range f.misses {
		if k.chat == chat {
			delete(f.misses, k)
		}
	}
	for k := range f.fetched {
		if k.chat == chat {
			delete(f.fetched, k)
		}
	}
	for _, m := range []map[jobKey]bool{f.uploading, f.loading} {
		for k := range m {
			if k.chat == chat {
				delete(m, k)
			}
		}
	}
	for k := range f.ahead {
		if k.chat == chat {
			delete(f.ahead, k)
		}
	}
	for k := range f.chunksOut {
		if k.chat == chat {
			delete(f.chunksOut, k)
		}
	}
	for k := range f.landed {
		if k.chat == chat {
			delete(f.landed, k)
		}
	}
	for k := range f.blobs {
		if k.chat == chat {
			delete(f.blobs, k)
		}
	}
}
