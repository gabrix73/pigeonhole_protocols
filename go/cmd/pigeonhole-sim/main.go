// Command pigeonhole-sim serves an in-memory Pigeonhole on a unix socket, for tests of clients in
// processes of their own.
package main

import (
	"flag"
	"log"
	"net"
	"os"

	"github.com/katzenpost/pigeonhole_protocols/go/transport/remote"
	"github.com/katzenpost/pigeonhole_protocols/go/transport/sim"
)

func main() {
	sock := flag.String("socket", "pigeonhole.sock", "the unix socket to serve on")
	flag.Parse()
	os.Remove(*sock)
	l, err := net.Listen("unix", *sock)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(remote.Serve(l, sim.Backend{World: sim.NewWorld()}))
}
