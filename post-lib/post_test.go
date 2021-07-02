package post

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
	_ "golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

func TestHPcommplentess(t *testing.T) {
	inp := []byte("hello world")
	p := NewHashPost(crypto.SHA3_512)
	prf := p.Gen(8, inp)
	ret, err := p.Ver(inp, prf)
	assert.NoError(t, err)
	assert.True(t, ret)
}

func TestHPfalseProof(t *testing.T) {
	inp := []byte("hello world")
	p := NewHashPost(crypto.SHA3_512)
	prf, _ := proto.Marshal(&Proof{
		HashType: int32(crypto.SHA3_512),
		X:        0,
		Y:        1,
		K:        8,
	})
	ret, err := p.Ver(inp, prf)
	assert.NoError(t, err)
	assert.False(t, ret)
}

func TestHPNoImportProof(t *testing.T) {
	inp := []byte("hello world")
	p := NewHashPost(crypto.SHA3_512)
	prf, _ := proto.Marshal(&Proof{
		HashType: int32(crypto.MD4),
		X:        0,
		Y:        1,
		K:        8,
	})
	ret, err := p.Ver(inp, prf)
	assert.Error(t, err)
	assert.False(t, ret)
}

func TestHPXeqYnoProof(t *testing.T) {
	inp := []byte("hello world")
	p := NewHashPost(crypto.SHA3_512)
	prf, _ := proto.Marshal(&Proof{
		HashType: int32(crypto.SHA3_512),
		X:        321,
		Y:        321,
		K:        8,
	})
	ret, err := p.Ver(inp, prf)
	assert.NoError(t, err)
	assert.False(t, ret)
}

func TestHPNotRealProof(t *testing.T) {
	inp := []byte("hello world")
	p := NewHashPost(crypto.SHA3_512)
	ret, err := p.Ver(inp, []byte("someRanomProof"))
	assert.Error(t, err)
	assert.False(t, ret)
}
