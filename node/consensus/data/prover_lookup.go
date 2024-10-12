package data

import (
	"crypto"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
)

func (e *DataClockConsensusEngine) GetProvingKey(
	engineConfig *config.EngineConfig,
) (crypto.Signer, keys.KeyType, []byte, []byte) {
	provingKey, err := e.keyManager.GetSigningKey(engineConfig.ProvingKeyId)
	if errors.Is(err, keys.KeyNotFoundErr) {
		e.logger.Info("could not get proving key, generating")
		provingKey, err = e.keyManager.CreateSigningKey(
			engineConfig.ProvingKeyId,
			keys.KeyTypeEd448,
		)
	}

	if err != nil {
		e.logger.Error("could not get proving key", zap.Error(err))
		panic(err)
	}

	rawKey, err := e.keyManager.GetRawKey(engineConfig.ProvingKeyId)
	if err != nil {
		e.logger.Error("could not get proving key type", zap.Error(err))
		panic(err)
	}

	provingKeyType := rawKey.Type

	h, err := poseidon.HashBytes(rawKey.PublicKey)
	if err != nil {
		e.logger.Error("could not hash proving key", zap.Error(err))
		panic(err)
	}

	provingKeyAddress := h.Bytes()
	provingKeyAddress = append(
		make([]byte, 32-len(provingKeyAddress)),
		provingKeyAddress...,
	)

	return provingKey, provingKeyType, rawKey.PublicKey, provingKeyAddress
}

func (e *DataClockConsensusEngine) IsInProverTrie(key []byte) bool {
	h, err := poseidon.HashBytes(key)
	if err != nil {
		return false
	}

	provingKeyAddress := h.Bytes()
	for _, tries := range e.frameProverTries {
		if tries.Contains(provingKeyAddress) {
			return true
		}
	}

	return false
}
