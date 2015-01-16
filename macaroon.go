package pkmacaroon

import (
	"fmt"
)

/*
Questions from the paper:
	Definition 3.3: why does the game not mention Finalize
*/

type Macaroon struct {
	id               string
	caveats          []string
	verificationKeys []*PublicKey
	signature        []sigPair

	// When the macaroon is finalized, finalSig is
	// set and extensionKey is zeroed.
	finalSig     *Signature
	extensionKey *PrivateKey // Only set if FinalSig is empty
}

type sigPair struct {
	s0 *Signature // ν in the paper.
	s1 *Signature // τ in the paper.
}

// We prefix the id and the caveats
// with a distinguishing byte before using them
// in the calculations so that there is no possible
// clash between them and thus no need to
// restrict the possible text provided to AddCaveat.
const (
	idPrefix     = 0
	caveatPrefix = 1
)

func New(otherKey *PrivateKey, id string) (*Macaroon, error) {
	k, err := NewKeyPair()
	if err != nil {
		return nil, err
	}
	return &Macaroon{
		id:               id,
		verificationKeys: []*PublicKey{&k.Public},
		signature: []sigPair{{
			s0: otherKey.Sign(k.Public[:]),
			s1: k.Private.Sign(prefixedBytes(idPrefix, id)),
		}},
		extensionKey: &k.Private,
	}, nil
}

func (m *Macaroon) AddCaveat(caveat string) error {
	k, err := NewKeyPair()
	if err != nil {
		return err
	}
	m.verificationKeys = append(m.verificationKeys, &k.Public)
	m.caveats = append(m.caveats, caveat)
	m.signature = append(m.signature, sigPair{
		s0: m.extensionKey.Sign(k.Public[:]),
		s1: k.Private.Sign(prefixedBytes(caveatPrefix, caveat)),
	})
	m.extensionKey = &k.Private
	return nil
}

func (m *Macaroon) Finalize() {
	m.finalSig = m.extensionKey.Sign(prefixedBytes(idPrefix, m.id))
	m.extensionKey = nil
}

var errBadSignature = fmt.Errorf("signature verification error")

func (m *Macaroon) Verify(vk *PublicKey) error {
	if m.finalSig == nil {
		return fmt.Errorf("macaroon has not been finalized")
	}
	vkeys := m.verificationKeys
	if !vk.Verify(vkeys[0][:], m.signature[0].s0) {
		return errBadSignature
	}
	if !vkeys[0].Verify(prefixedBytes(idPrefix, m.id), m.signature[0].s1) {
		return errBadSignature
	}
	for i, caveat := range m.caveats {
		if !vkeys[i].Verify(vkeys[i+1][:], m.signature[i+1].s0) {
			return errBadSignature
		}
		if !vkeys[i+1].Verify(prefixedBytes(caveatPrefix, caveat), m.signature[i+1].s1) {
			return errBadSignature
		}
		// TODO verify caveat
	}
	if !vkeys[len(m.caveats)].Verify(prefixedBytes(idPrefix, m.id), m.finalSig) {
		return errBadSignature
	}
	return nil
}

func prefixedBytes(prefix byte, s string) []byte {
	b := make([]byte, len(s)+1)
	b[0] = prefix
	copy(b[1:], s)
	return b
}
