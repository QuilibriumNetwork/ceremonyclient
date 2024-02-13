package channel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"

	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

const DOUBLE_RATCHET_PROTOCOL_VERSION = 1
const DOUBLE_RATCHET_PROTOCOL = 1<<8 + DOUBLE_RATCHET_PROTOCOL_VERSION

const CHAIN_KEY = 0x01
const MESSAGE_KEY = 0x02
const AEAD_KEY = 0x03

// Note: If an HSM with raw primitive access becomes available, the raw crypto
// mechanisms should be refactored into calls in KeyManager and implemented
// through the driver
type DoubleRatchetParticipant struct {
	sendingEphemeralPrivateKey   curves.Scalar
	receivingEphemeralKey        curves.Point
	curve                        *curves.Curve
	keyManager                   keys.KeyManager
	rootKey                      []byte
	sendingChainKey              []byte
	currentSendingHeaderKey      []byte
	currentReceivingHeaderKey    []byte
	nextSendingHeaderKey         []byte
	nextReceivingHeaderKey       []byte
	receivingChainKey            []byte
	currentSendingChainLength    uint32
	previousSendingChainLength   uint32
	currentReceivingChainLength  uint32
	previousReceivingChainLength uint32
	skippedKeysMap               map[string]map[uint32][]byte
}

func NewDoubleRatchetParticipant(
	sessionKey []byte,
	sendingHeaderKey []byte,
	nextReceivingHeaderKey []byte,
	isSender bool,
	sendingEphemeralPrivateKey curves.Scalar,
	receivingEphemeralKey curves.Point,
	curve *curves.Curve,
	keyManager keys.KeyManager,
) (*DoubleRatchetParticipant, error) {
	participant := &DoubleRatchetParticipant{}
	participant.sendingEphemeralPrivateKey = sendingEphemeralPrivateKey
	participant.skippedKeysMap = make(map[string]map[uint32][]byte)
	participant.keyManager = keyManager
	participant.currentSendingChainLength = 0
	participant.previousSendingChainLength = 0
	participant.currentReceivingChainLength = 0
	participant.previousReceivingChainLength = 0

	if sendingEphemeralPrivateKey.Point().CurveName() !=
		receivingEphemeralKey.CurveName() || receivingEphemeralKey.CurveName() !=
		curve.Name {
		return nil, errors.New("curve mismatch")
	}

	participant.curve = curve

	if isSender {
		hash := hkdf.New(
			sha512.New,
			receivingEphemeralKey.Mul(
				sendingEphemeralPrivateKey,
			).ToAffineCompressed(),
			sessionKey,
			[]byte("quilibrium-double-ratchet"),
		)
		rkck := make([]byte, 96)
		if _, err := hash.Read(rkck[:]); err != nil {
			return nil, errors.Wrap(err, "failed establishing root key")
		}

		participant.currentSendingHeaderKey = sendingHeaderKey
		participant.nextReceivingHeaderKey = nextReceivingHeaderKey
		participant.rootKey = rkck[:32]
		participant.sendingChainKey = rkck[32:64]

		participant.nextSendingHeaderKey = rkck[64:96]
		participant.receivingEphemeralKey = receivingEphemeralKey
	} else {
		participant.rootKey = sessionKey
		participant.nextReceivingHeaderKey = sendingHeaderKey
		participant.nextSendingHeaderKey = nextReceivingHeaderKey
	}

	return participant, nil
}

func (r *DoubleRatchetParticipant) RatchetEncrypt(
	message []byte,
) (*protobufs.P2PChannelEnvelope, error) {
	envelope := &protobufs.P2PChannelEnvelope{
		ProtocolIdentifier: DOUBLE_RATCHET_PROTOCOL,
		MessageHeader:      &protobufs.MessageCiphertext{},
		MessageBody:        &protobufs.MessageCiphertext{},
	}

	newChainKey, messageKey, aeadKey := ratchetKeys(r.sendingChainKey)
	r.sendingChainKey = newChainKey

	var err error
	header := r.encodeHeader()
	envelope.MessageHeader, err = r.encrypt(
		header,
		r.currentSendingHeaderKey,
		nil,
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not encrypt header")
	}

	envelope.MessageBody, err = r.encrypt(
		message,
		messageKey,
		append(append([]byte{}, aeadKey...), envelope.MessageHeader.Ciphertext...),
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not encrypt message")
	}

	r.currentSendingChainLength++

	return envelope, nil
}

func (r *DoubleRatchetParticipant) RatchetDecrypt(
	envelope *protobufs.P2PChannelEnvelope,
) ([]byte, error) {
	plaintext, err := r.trySkippedMessageKeys(envelope)
	if err != nil {
		return nil, errors.Wrap(err, "could not decrypt from matching skipped key")
	}

	if plaintext != nil {
		return plaintext, nil
	}

	header, shouldRatchet, err := r.decryptHeader(
		envelope.MessageHeader,
		r.currentReceivingHeaderKey,
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not decrypt header")
	}

	receivingEphemeralKey,
		previousReceivingChainLength,
		currentReceivingChainLength,
		err := r.decodeHeader(header)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode header")
	}

	if shouldRatchet {
		if err := r.skipMessageKeys(previousReceivingChainLength); err != nil {
			return nil, errors.Wrap(err, "could not skip previous message keys")
		}
		if err := r.ratchetEphemeralKeys(receivingEphemeralKey); err != nil {
			return nil, errors.Wrap(err, "could not ratchet ephemeral keys")
		}
	}

	if err := r.skipMessageKeys(currentReceivingChainLength); err != nil {
		return nil, errors.Wrap(err, "could not skip message keys")
	}

	newChainKey, messageKey, aeadKey := ratchetKeys(r.receivingChainKey)

	plaintext, err = r.decrypt(
		envelope.MessageBody,
		messageKey,
		append(
			append([]byte{}, aeadKey...),
			envelope.MessageHeader.Ciphertext...,
		),
	)

	r.receivingChainKey = newChainKey
	r.currentReceivingChainLength++

	return plaintext, errors.Wrap(err, "could not decrypt message")
}

func (r *DoubleRatchetParticipant) ratchetEphemeralKeys(
	newReceivingEphemeralKey curves.Point,
) error {
	r.previousSendingChainLength = r.currentSendingChainLength
	r.currentSendingChainLength = 0
	r.currentReceivingChainLength = 0
	r.currentSendingHeaderKey = r.nextSendingHeaderKey
	r.currentReceivingHeaderKey = r.nextReceivingHeaderKey
	r.receivingEphemeralKey = newReceivingEphemeralKey

	hash := hkdf.New(
		sha512.New,
		newReceivingEphemeralKey.Mul(
			r.sendingEphemeralPrivateKey,
		).ToAffineCompressed(),
		r.rootKey,
		[]byte("quilibrium-double-ratchet"),
	)
	rkck := make([]byte, 96)
	if _, err := hash.Read(rkck[:]); err != nil {
		return errors.Wrap(err, "failed ratcheting root key")
	}

	r.rootKey = rkck[:32]
	r.receivingChainKey = rkck[32:64]
	r.nextReceivingHeaderKey = rkck[64:]
	r.sendingEphemeralPrivateKey = r.curve.NewScalar().Random(rand.Reader)

	hash = hkdf.New(
		sha512.New,
		newReceivingEphemeralKey.Mul(
			r.sendingEphemeralPrivateKey,
		).ToAffineCompressed(),
		r.rootKey,
		[]byte("quilibrium-double-ratchet"),
	)
	rkck2 := make([]byte, 96)
	if _, err := hash.Read(rkck2[:]); err != nil {
		return errors.Wrap(err, "failed ratcheting root key")
	}

	r.rootKey = rkck2[:32]
	r.sendingChainKey = rkck2[32:64]
	r.nextSendingHeaderKey = rkck2[64:]
	return nil
}

func (r *DoubleRatchetParticipant) trySkippedMessageKeys(
	envelope *protobufs.P2PChannelEnvelope,
) ([]byte, error) {
	for receivingHeaderKey, skippedKeys := range r.skippedKeysMap {
		header, _, err := r.decryptHeader(
			envelope.MessageHeader,
			[]byte(receivingHeaderKey),
		)

		if err == nil {
			_, _, current, err := r.decodeHeader(header)
			if err != nil {
				return nil, errors.Wrap(err, "malformed header")
			}

			messageKey := skippedKeys[current][:32]
			aeadKey := skippedKeys[current][32:]
			plaintext, err := r.decrypt(
				envelope.MessageBody,
				messageKey,
				append(
					append([]byte{}, aeadKey...),
					envelope.MessageHeader.Ciphertext[:]...,
				),
			)

			if err != nil {
				return nil, errors.Wrap(err, "could not decrypt from skipped key")
			}

			delete(r.skippedKeysMap[receivingHeaderKey], current)
			if len(r.skippedKeysMap[receivingHeaderKey]) == 0 {
				delete(r.skippedKeysMap, receivingHeaderKey)
			}

			return plaintext, nil
		}
	}

	return nil, nil
}

func (r *DoubleRatchetParticipant) skipMessageKeys(until uint32) error {
	if r.currentReceivingChainLength+100 < until {
		return errors.New("skip limit exceeded")
	}

	if r.receivingChainKey != nil {
		for r.currentReceivingChainLength < until {
			newChainKey, messageKey, aeadKey := ratchetKeys(r.receivingChainKey)
			skippedKeys := r.skippedKeysMap[string(r.currentReceivingHeaderKey)]
			if skippedKeys == nil {
				r.skippedKeysMap[string(r.currentReceivingHeaderKey)] =
					make(map[uint32][]byte)
			}

			skippedKeys[r.currentReceivingChainLength] = append(
				append([]byte{}, messageKey...),
				aeadKey...,
			)
			r.receivingChainKey = newChainKey
			r.currentReceivingChainLength++
		}
	}

	return nil
}

func (r *DoubleRatchetParticipant) encodeHeader() []byte {
	header := []byte{}
	header = append(
		header,
		r.curve.NewGeneratorPoint().Mul(
			r.sendingEphemeralPrivateKey,
		).ToAffineCompressed()[:]...,
	)
	header = binary.BigEndian.AppendUint32(header, r.previousSendingChainLength)
	header = binary.BigEndian.AppendUint32(header, r.currentSendingChainLength)
	return header
}

func (r *DoubleRatchetParticipant) decryptHeader(
	ciphertext *protobufs.MessageCiphertext,
	receivingHeaderKey []byte,
) ([]byte, bool, error) {
	header, err := r.decrypt(
		ciphertext,
		receivingHeaderKey,
		nil,
	)
	if err != nil && subtle.ConstantTimeCompare(
		r.currentReceivingHeaderKey,
		receivingHeaderKey,
	) == 1 {
		if header, err = r.decrypt(
			ciphertext,
			r.nextReceivingHeaderKey,
			nil,
		); err != nil {
			return nil, false, errors.Wrap(err, "could not decrypt header")
		}

		return header, true, nil
	}

	return header, false, errors.Wrap(err, "could not decrypt header")
}

func (r *DoubleRatchetParticipant) decodeHeader(
	header []byte,
) (curves.Point, uint32, uint32, error) {
	if len(header) < 9 {
		return nil, 0, 0, errors.New("malformed header")
	}

	currentReceivingChainLength := binary.BigEndian.Uint32(header[len(header)-4:])
	previousReceivingChainLength := binary.BigEndian.Uint32(
		header[len(header)-8 : len(header)-4],
	)
	receivingEphemeralKeyBytes := header[:len(header)-8]
	receivingEphemeralKey, err := r.curve.Point.FromAffineCompressed(
		receivingEphemeralKeyBytes,
	)

	return receivingEphemeralKey,
		previousReceivingChainLength,
		currentReceivingChainLength,
		errors.Wrap(err, "could not decode receiving dh key")
}

func (r *DoubleRatchetParticipant) encrypt(
	plaintext []byte,
	key []byte,
	associatedData []byte,
) (*protobufs.MessageCiphertext, error) {
	iv := [12]byte{}
	rand.Read(iv[:])
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct cipher")
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct block")
	}

	ciphertext := &protobufs.MessageCiphertext{}

	if associatedData == nil {
		associatedData = make([]byte, 32)
		if _, err := rand.Read(associatedData); err != nil {
			return nil, errors.Wrap(err, "could not obtain entropy")
		}
		ciphertext.AssociatedData = associatedData
	}

	ciphertext.Ciphertext = gcm.Seal(nil, iv[:], plaintext, associatedData)
	ciphertext.InitializationVector = iv[:]

	return ciphertext, nil
}

func (r *DoubleRatchetParticipant) decrypt(
	ciphertext *protobufs.MessageCiphertext,
	key []byte,
	associatedData []byte,
) ([]byte, error) {
	if associatedData == nil {
		associatedData = ciphertext.AssociatedData
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct cipher")
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct block")
	}

	plaintext, err := gcm.Open(
		nil,
		ciphertext.InitializationVector,
		ciphertext.Ciphertext,
		associatedData,
	)

	return plaintext, errors.Wrap(err, "could not decrypt ciphertext")
}

func ratchetKeys(inputKey []byte) ([]byte, []byte, []byte) {
	buf := hmac.New(sha512.New, inputKey)
	buf.Write([]byte{AEAD_KEY})
	aeadKey := buf.Sum(nil)
	buf.Reset()
	buf.Write([]byte{MESSAGE_KEY})
	messageKey := buf.Sum(nil)
	buf.Reset()
	buf.Write([]byte{CHAIN_KEY})
	chainKey := buf.Sum(nil)

	return chainKey[:32], messageKey[:32], aeadKey[:32]
}
