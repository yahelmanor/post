package post

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"hash"

	"google.golang.org/protobuf/proto"
)

//PoST is Proof of Space Time
type PoST interface {
	Gen(st int, inp []byte) (proof []byte)
	Ver(inp []byte, proof []byte) (bool, error)
}

var _ PoST = hashPost{}

//implimation of post with hash function
type hashPost struct {
	h hash.Hash
	u crypto.Hash
}

//NewHashPost create a new Post based on hashing
func NewHashPost(h crypto.Hash) PoST {
	return hashPost{
		h.New(), h,
	}
}

func (hp hashPost) Gen(k int, inp []byte) (proof []byte) {
	if k > 8*(hp.h.Size()) {
		panic("k must be of size smaller then hash output")
	}
	k8 := (k + 7) / 8
	mask := byte(1<<(1+(k+7)%8) - 1)
	hp.h.Reset()
	hp.h.Write(inp)
	out := hp.h.Sum(nil)
	mem := make(map[string]uint64, 1<<k)
	for i := uint64(0); ; i++ {
		hp.h.Reset()
		binary.Write(hp.h, binary.BigEndian, i)
		hp.h.Write(out)
		out2 := hp.h.Sum(nil)
		out2[k8] &= mask
		if v, ok := mem[string(out2[:k8])]; ok {
			ret, err := proto.Marshal(&Proof{
				HashType: int32(hp.u),
				X:        v,
				Y:        i,
				K:        int32(k),
			})
			if err != nil {
				panic(err)
			}
			return ret
		}
		mem[string(out2[:k8])] = i
	}
}

func (hp hashPost) Ver(inp []byte, proof []byte) (bool, error) {
	// prf := proofOfHashPost{}
	// if err := json.Unmarshal(proof, &prf); err != nil {
	// return false, err
	// }
	prf := Proof{}
	if err := proto.Unmarshal(proof, &prf); err != nil {
		return false, err
	}
	// if prf.K&7 != 0 {
	// return false, fmt.Errorf("k in the proof isnt of lenght divisble by 8")
	// }
	if prf.K > 8*int32(hp.h.Size()) {
		return false, fmt.Errorf("k in the proof is of size bigger then hash output")
	}
	k8 := prf.K / 8
	mask := byte(1<<(prf.K&7) - 1)
	if !(crypto.Hash(prf.HashType)).Available() {
		return false, fmt.Errorf("the hash type %v isn't available", (crypto.Hash(prf.HashType)).String())
	}
	if prf.X == prf.Y {
		return false, nil
	}
	h := (crypto.Hash(prf.HashType)).New()

	h.Reset()
	h.Write(inp)
	out := h.Sum(nil)

	h.Reset()
	binary.Write(h, binary.BigEndian, prf.X)
	h.Write(out)
	o1 := h.Sum(nil)

	h.Reset()
	binary.Write(h, binary.BigEndian, prf.Y)
	h.Write(out)
	o2 := h.Sum(nil)
	return bytes.Equal(o1[:k8], o2[:k8]) && (mask == 0 || (o1[k8]&mask == o2[k8]&mask)), nil
}
