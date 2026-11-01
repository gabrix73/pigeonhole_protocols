// Command katzenqt1-dump prints a katzenqt1 client's saved member state as trace JSON.
package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member/tracejson"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/store"
)

func main() {
	st, err := store.Open(os.Args[1], store.Options{})
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	s, err := st.Load("")
	if err != nil {
		log.Fatal(err)
	}
	for _, c := range s.Chats {
		if c.Group == nil {
			continue
		}
		b, _ := json.MarshalIndent(map[string]any{"chat": c.Name, "group": tracejson.Group(c.Group)}, "", " ")
		os.Stdout.Write(append(b, '\n'))
	}
}
