package pkmacaroon
import (
	"crypto/rand"

	"github.com/agl/ed25519"
)

const (
	PublicKeySize = ed25519.PublicKeySize
	PrivateKeySize = ed25519.PrivateKeySize
	SignatureSize = ed25519.SignatureSize
)

type PrivateKey [PrivateKeySize]byte
type PublicKey [PublicKeySize]byte
type Signature [SignatureSize]byte

type KeyPair struct {
	Private PrivateKey
	Public PublicKey
}

func NewKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Public: *pub,
		Private: *priv,
	}, nil
}

func (k *PrivateKey) Sign(m []byte) *Signature {
	sig := ed25519.Sign((*[PrivateKeySize]byte)(k), m)
	return (*Signature)(sig)
}

func (k *PublicKey) Verify(message []byte, sig *Signature) bool {
	return ed25519.Verify((*[PublicKeySize]byte)(k), message, (*[SignatureSize]byte)(sig))
}
