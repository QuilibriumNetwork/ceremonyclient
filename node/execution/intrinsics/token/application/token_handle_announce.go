package application

import (
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *TokenApplication) handleAnnounce(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.AnnounceProverRequest,
) (
	[]*protobufs.TokenOutput,
	error,
) {
	var primary *protobufs.Ed448Signature
	payload := []byte{}

	if t == nil || t.PublicKeySignaturesEd448 == nil {
		return nil, ErrInvalidStateTransition
	}
	for i, p := range t.PublicKeySignaturesEd448 {
		if p.PublicKey == nil || p.Signature == nil ||
			p.PublicKey.KeyValue == nil {
			return nil, ErrInvalidStateTransition
		}
		if i == 0 {
			primary = p
		} else {
			payload = append(payload, p.PublicKey.KeyValue...)
			if err := p.Verify(primary.PublicKey.KeyValue); err != nil {
				return nil, ErrInvalidStateTransition
			}
		}
	}
	if primary == nil {
		return nil, ErrInvalidStateTransition
	}
	if err := primary.Verify(payload); err != nil {
		return nil, ErrInvalidStateTransition
	}

	outputs := []*protobufs.TokenOutput{}

	if t.InitialProof != nil {
		o, err := a.handleMint(currentFrameNumber, lockMap, t.InitialProof)
		if err != nil {
			return nil, ErrInvalidStateTransition
		}
		outputs = append(outputs, o...)
	}

	return outputs, nil
}
