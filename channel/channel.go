package channel

import (
	generated "source.quilibrium.com/quilibrium/monorepo/channel/generated/channel"
)

//go:generate ./generate.sh

func NewDoubleRatchet(
	sessionKey []uint8,
	sendingHeaderKey []uint8,
	nextReceivingHeaderKey []uint8,
	isSender bool,
	sendingEphemeralPrivateKey []uint8,
	receivingEphemeralKey []uint8,
) string {
	return generated.NewDoubleRatchet(
		sessionKey,
		sendingHeaderKey,
		nextReceivingHeaderKey,
		isSender,
		sendingEphemeralPrivateKey,
		receivingEphemeralKey,
	)
}

func NewTripleRatchet(
	peers [][]uint8,
	peerKey []uint8,
	identityKey []uint8,
	signedPreKey []uint8,
	threshold uint64,
	asyncDkgRatchet bool,
) generated.TripleRatchetStateAndMetadata {
	return generated.NewTripleRatchet(
		peers,
		peerKey,
		identityKey,
		signedPreKey,
		threshold,
		asyncDkgRatchet,
	)
}

func DoubleRatchetEncrypt(
	ratchetStateAndMessage generated.DoubleRatchetStateAndMessage,
) generated.DoubleRatchetStateAndEnvelope {
	return generated.DoubleRatchetEncrypt(ratchetStateAndMessage)
}

func DoubleRatchetDecrypt(
	ratchetStateAndEnvelope generated.DoubleRatchetStateAndEnvelope,
) generated.DoubleRatchetStateAndMessage {
	return generated.DoubleRatchetDecrypt(ratchetStateAndEnvelope)
}

func TripleRatchetInitRound1(
	ratchetStateAndMetadata generated.TripleRatchetStateAndMetadata,
) generated.TripleRatchetStateAndMetadata {
	return generated.TripleRatchetInitRound1(ratchetStateAndMetadata)
}
func TripleRatchetInitRound2(
	ratchetStateAndMetadata generated.TripleRatchetStateAndMetadata,
) generated.TripleRatchetStateAndMetadata {
	return generated.TripleRatchetInitRound2(ratchetStateAndMetadata)
}
func TripleRatchetInitRound3(
	ratchetStateAndMetadata generated.TripleRatchetStateAndMetadata,
) generated.TripleRatchetStateAndMetadata {
	return generated.TripleRatchetInitRound3(ratchetStateAndMetadata)
}
func TripleRatchetInitRound4(
	ratchetStateAndMetadata generated.TripleRatchetStateAndMetadata,
) generated.TripleRatchetStateAndMetadata {
	return generated.TripleRatchetInitRound4(ratchetStateAndMetadata)
}

func TripleRatchetEncrypt(
	ratchetStateAndMessage generated.TripleRatchetStateAndMessage,
) generated.TripleRatchetStateAndEnvelope {
	return generated.TripleRatchetEncrypt(ratchetStateAndMessage)
}

func TripleRatchetDecrypt(
	ratchetStateAndEnvelope generated.TripleRatchetStateAndEnvelope,
) generated.TripleRatchetStateAndMessage {
	return generated.TripleRatchetDecrypt(ratchetStateAndEnvelope)
}
