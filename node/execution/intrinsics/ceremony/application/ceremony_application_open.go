package application

import (
	"bytes"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *CeremonyApplication) applyLobbyJoin(
	join *protobufs.CeremonyLobbyJoin,
) error {
	signature := join.GetPublicKeySignatureEd448()
	if signature == nil {
		return errors.Wrap(errors.New("signature is nil"), "apply lobby join")
	}
	if join.IdentityKey == nil || join.IdentityKey.KeyValue == nil {
		return errors.Wrap(errors.New("identity key is nil"), "apply lobby join")
	}
	if join.SignedPreKey == nil || join.SignedPreKey.KeyValue == nil {
		return errors.Wrap(errors.New("signed prekey is nil"), "apply lobby join")
	}
	if _, err := curves.ED448().Point.FromAffineCompressed(
		join.IdentityKey.KeyValue,
	); err != nil {
		return errors.Wrap(err, "apply lobby join")
	}
	if _, err := curves.ED448().Point.FromAffineCompressed(
		join.SignedPreKey.KeyValue,
	); err != nil {
		return errors.Wrap(err, "apply lobby join")
	}
	if err := join.VerifySignature(); err != nil {
		return errors.Wrap(err, "apply lobby join")
	}

	if len(a.LobbyJoins) == 256 {
		return nil
	}

	for _, p := range a.LobbyJoins {
		if bytes.Equal(
			p.PublicKeySignatureEd448.PublicKey.KeyValue,
			signature.PublicKey.KeyValue,
		) {
			return nil
		}
	}

	prepend := false
	nextRoundPreferredParticipants := []*protobufs.Ed448PublicKey{}
	for _, p := range a.NextRoundPreferredParticipants {
		p := p
		if !bytes.Equal(p.KeyValue, signature.PublicKey.KeyValue) {
			nextRoundPreferredParticipants = append(
				nextRoundPreferredParticipants,
				p,
			)
		}
	}

	if len(a.NextRoundPreferredParticipants) !=
		len(nextRoundPreferredParticipants) {
		prepend = true
	}

	a.NextRoundPreferredParticipants = nextRoundPreferredParticipants

	if prepend {
		a.LobbyJoins = append(
			append([]*protobufs.CeremonyLobbyJoin{}, join),
			a.LobbyJoins...,
		)
	} else {
		a.LobbyJoins = append(a.LobbyJoins, join)
	}

	return nil
}

func (a *CeremonyApplication) finalizeParticipantSet() error {
	power := uint64(1)
	for uint64(len(a.LobbyJoins)) > power {
		power = power << 1
	}

	if power != uint64(len(a.LobbyJoins)) {
		power = power >> 1
	}

	a.ActiveParticipants = []*protobufs.CeremonyLobbyJoin{}
	for i := 0; i < int(power); i++ {
		a.ActiveParticipants = append(
			a.ActiveParticipants,
			a.LobbyJoins[i],
		)
	}

	return nil
}
