// Command pigeonservice-vectors writes the wire vectors other implementations of
// pigeonservice check themselves against: keys, shared secrets, request
// MACs and the canonical CBOR of each message.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/katzenpost/hpqc/protocols/sealedbox"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
)

type vectors struct {
	NIKEScheme   string `json:"nike_scheme"`
	ServicePriv  string `json:"service_private_key"`
	ServicePub   string `json:"service_public_key"`
	PluginPriv   string `json:"plugin_private_key"`
	PluginPub    string `json:"plugin_public_key"`
	SharedSecret string `json:"shared_secret"`
	ServiceID    string `json:"service_id"`

	Voucher  string `json:"voucher"`
	Register struct {
		Unsigned string `json:"unsigned"`
		MAC      string `json:"mac"`
		Request  string `json:"router_request"`
	} `json:"register"`
	Route struct {
		Ciphertext string `json:"ciphertext"`
		Request    string `json:"router_request"`
	} `json:"route"`
	Advertise struct {
		Seq      uint64 `json:"seq"`
		Unsigned string `json:"unsigned"`
		MAC      string `json:"mac"`
		Request  string `json:"directory_request"`
	} `json:"advertise"`
	Withdraw struct {
		Seq      uint64 `json:"seq"`
		Unsigned string `json:"unsigned"`
		MAC      string `json:"mac"`
		Request  string `json:"directory_request"`
	} `json:"withdraw"`
	Lookup      string `json:"lookup_request"`
	List        string `json:"list_request"`
	RouterReply string `json:"router_reply_busy"`
	LookupReply string `json:"lookup_reply"`
	ListReply   string `json:"list_reply"`
	Snapshot    string `json:"snapshot"`
	LinkMessage string `json:"link_message"`
	SealedBox   struct {
		Plaintext  string `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
	} `json:"sealed_box"`
	Routers []router `json:"routers"`
}

type router struct {
	NodeIDHash string `json:"node_id_hash"`
	Endpoint   string `json:"endpoint"`
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func h(b []byte) string { return hex.EncodeToString(b) }

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: pigeonservice-vectors out.json")
		os.Exit(2)
	}
	scheme := common.DefaultNIKE
	svcPub, svcPriv := must2(scheme.GenerateKeyPair())
	plugPub, plugPriv := must2(scheme.GenerateKeyPair())
	svc := &common.ServiceKey{Scheme: scheme, Public: svcPub, Private: svcPriv}

	var v vectors
	v.NIKEScheme = scheme.Name()
	v.ServicePriv, v.ServicePub = h(svcPriv.Bytes()), h(svcPub.Bytes())
	v.PluginPriv, v.PluginPub = h(plugPriv.Bytes()), h(plugPub.Bytes())
	v.SharedSecret = h(scheme.DeriveSecret(svcPriv, plugPub))
	id := svc.ID()
	v.ServiceID = h(id[:])

	voucher := make([]byte, 32)
	for i := range voucher {
		voucher[i] = byte(i)
	}
	v.Voucher = h(voucher)

	reg := &voucher_router.RegisterRequest{NIKEScheme: scheme.Name(), PublicKey: svcPub.Bytes(), Voucher: voucher}
	v.Register.Unsigned = h(must(common.Marshal(reg)))
	if err := voucher_router.SignRegister(svc, plugPub, reg); err != nil {
		panic(err)
	}
	v.Register.MAC = h(reg.MAC)
	v.Register.Request = h(must(common.Marshal(&voucher_router.RouterRequest{Register: reg})))

	ct := []byte("sealed voucher")
	v.Route.Ciphertext = h(ct)
	v.Route.Request = h(must(common.Marshal(&voucher_router.RouterRequest{Route: &voucher_router.RouteRequest{ServiceID: id, Ciphertext: ct}})))

	routers := []common.RouterRef{
		{NodeIDHash: [32]byte{0xa0, 1}, Endpoint: "voucher_router"},
		{NodeIDHash: [32]byte{0xa1, 2}, Endpoint: "voucher_router"},
	}
	for _, r := range routers {
		v.Routers = append(v.Routers, router{NodeIDHash: h(r.NodeIDHash[:]), Endpoint: r.Endpoint})
	}
	desc := common.ServiceDescriptor{NIKEScheme: scheme.Name(), PublicKey: svcPub.Bytes(), Routers: routers}

	adv := &discovery.AdvertiseRequest{Descriptor: desc, Seq: 1761600000000000001}
	v.Advertise.Seq = adv.Seq
	v.Advertise.Unsigned = h(must(common.Marshal(adv)))
	if err := discovery.SignAdvertise(svc, plugPub, adv); err != nil {
		panic(err)
	}
	v.Advertise.MAC = h(adv.MAC)
	v.Advertise.Request = h(must(common.Marshal(&discovery.DirectoryRequest{Advertise: adv})))

	wd := &discovery.WithdrawRequest{ServiceID: id, Seq: 7}
	v.Withdraw.Seq = wd.Seq
	v.Withdraw.Unsigned = h(must(common.Marshal(wd)))
	if err := discovery.SignWithdraw(svc, plugPub, wd); err != nil {
		panic(err)
	}
	v.Withdraw.MAC = h(wd.MAC)
	v.Withdraw.Request = h(must(common.Marshal(&discovery.DirectoryRequest{Withdraw: wd})))

	v.Lookup = h(must(common.Marshal(&discovery.DirectoryRequest{Lookup: &discovery.LookupRequest{ServiceID: id}})))
	v.List = h(must(common.Marshal(&discovery.DirectoryRequest{List: &discovery.ListRequest{}})))
	v.RouterReply = h(must(common.Marshal(&voucher_router.RouterReply{Status: common.StatusBusy})))
	v.LookupReply = h(must(common.Marshal(&discovery.DirectoryReply{Status: common.StatusOK, Descriptor: &desc})))
	v.ListReply = h(must(common.Marshal(&discovery.DirectoryReply{Status: common.StatusOK, ReadCap: []byte{1, 2, 3}, StartIndex: []byte{4, 5}})))
	v.Snapshot = h(must(common.Marshal(&discovery.Snapshot{Seq: 3, Descriptors: []common.ServiceDescriptor{desc}})))
	v.LinkMessage = h(must(common.Marshal(&voucher_router.LinkMessage{Forward: ct})))

	v.SealedBox.Plaintext = h(voucher)
	v.SealedBox.Ciphertext = h(must(sealedbox.NewScheme(scheme).Seal(svcPub, voucher)))

	out := must(json.MarshalIndent(&v, "", "  "))
	if err := os.WriteFile(os.Args[1], append(out, '\n'), 0o644); err != nil {
		panic(err)
	}
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}
