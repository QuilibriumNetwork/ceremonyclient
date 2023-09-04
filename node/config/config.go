package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Key     *KeyConfig    `yaml:"key"`
	P2P     *P2PConfig    `yaml:"p2p"`
	Engine  *EngineConfig `yaml:"engine"`
	DB      *DBConfig     `yaml:"db"`
	LogFile string        `yaml:"logFile"`
}

func NewConfig(configPath string) (*Config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	d := yaml.NewDecoder(file)
	config := &Config{}

	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func LoadConfig(configPath string, proverKey string) (*Config, error) {
	info, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		fmt.Println("Creating config directory " + configPath)
		if err = os.Mkdir(configPath, fs.FileMode(0700)); err != nil {
			panic(err)
		}
	} else {
		if err != nil {
			panic(err)
		}

		if !info.IsDir() {
			panic(configPath + " is not a directory")
		}
	}

	file, err := os.Open(filepath.Join(configPath, "config.yml"))
	saveDefaults := false
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			saveDefaults = true
		} else {
			return nil, err
		}
	}

	config := &Config{
		DB: &DBConfig{
			Path: configPath + "/store",
		},
		Key: &KeyConfig{
			KeyStore: KeyManagerTypeFile,
			KeyStoreFile: &KeyStoreFileConfig{
				Path: filepath.Join(configPath, "keys.yml"),
			},
		},
		P2P: &P2PConfig{
			ListenMultiaddr: "/ip4/0.0.0.0/udp/8336/quic",
			BootstrapPeers: []string{
				"/dns/bootstrap.quilibrium.com/udp/8336/quic/p2p/QmUhm9iZVruSxyavjoPLCfuoRG94SGQEkfxEEoukEZmD5B",
				"/ip4/204.186.74.47/udp/8317/quic/p2p/Qmd233pLUDvcDW3ama27usfbG1HxKNh1V9dmWVW1SXp1pd",
				"/ip4/13.237.250.230/udp/8317/quic/p2p/QmazMeSUA9HPLuj53w56k6GUq3xVny3pHtosUZndejJeai",
				"/ip4/13.236.219.103/udp/8317/quic/p2p/QmcJqNsJLNfxkAxeJijfLppiNQERaeFuwsbg3BGScKqrfh",
				"/ip4/204.186.74.46/udp/8316/quic/p2p/QmeqBjm3iX7sdTieyto1gys5ruQrQNPKfaTGcVQQWJPYDV",
				"/ip4/186.233.184.181/udp/8336/quic/p2p/QmW6QDvKuYqJYYMP5tMZSp12X3nexywK28tZNgqtqNpEDL",
				"/dns/quil.zanshindojo.org/udp/8336/quic/p2p/QmXbbmtS5D12rEc4HWiHWr6e83SCE4jeThPP4VJpAQPvXq",
			},
			PeerPrivKey: "",
		},
		Engine: &EngineConfig{
			ProvingKeyId:         "default-proving-key",
			Filter:               "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			GenesisSeed:          "00",
			MaxFrames:            -1,
			PendingCommitWorkers: 4,
		},
	}

	if saveDefaults {
		fmt.Println("Generating default config...")
		fmt.Println("Generating random host key...")
		privkey, _, err := crypto.GenerateEd448Key(rand.Reader)
		if err != nil {
			panic(err)
		}

		hostKey, err := privkey.Raw()
		if err != nil {
			panic(err)
		}

		config.P2P.PeerPrivKey = hex.EncodeToString(hostKey)

		fmt.Println("Generating keystore key...")
		keystoreKey := make([]byte, 32)
		if _, err := rand.Read(keystoreKey); err != nil {
			panic(err)
		}

		config.Key.KeyStoreFile.EncryptionKey = hex.EncodeToString(keystoreKey)

		fmt.Println("Saving config...")
		if err = SaveConfig(configPath, config); err != nil {
			panic(err)
		}

		keyfile, err := os.OpenFile(
			filepath.Join(configPath, "keys.yml"),
			os.O_CREATE|os.O_RDWR,
			fs.FileMode(0700),
		)
		if err != nil {
			panic(err)
		}

		if proverKey != "" {
			provingKey, err := hex.DecodeString(proverKey)
			if err != nil {
				panic(err)
			}

			iv := [12]byte{}
			rand.Read(iv[:])
			aesCipher, err := aes.NewCipher(keystoreKey)
			if err != nil {
				return nil, errors.Wrap(err, "could not construct cipher")
			}

			gcm, err := cipher.NewGCM(aesCipher)
			if err != nil {
				return nil, errors.Wrap(err, "could not construct block")
			}

			ciphertext := gcm.Seal(nil, iv[:], provingKey, nil)
			ciphertext = append(append([]byte{}, iv[:]...), ciphertext...)

			provingPubKey := ed448.PrivateKey(provingKey).Public().(ed448.PublicKey)

			keyfile.Write([]byte(
				"default-proving-key:\n  id: default-proving-key\n" +
					"  type: 0\n  privateKey: " + hex.EncodeToString(ciphertext) + "\n" +
					"  publicKey: " + hex.EncodeToString(provingPubKey) + "\n"))
		} else {
			keyfile.Write([]byte("null:\n"))
		}

		keyfile.Close()

		if file, err = os.Open(
			filepath.Join(configPath, "config.yml"),
		); err != nil {
			panic(err)
		}
	}

	defer file.Close()
	d := yaml.NewDecoder(file)
	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func SaveConfig(configPath string, config *Config) error {
	file, err := os.OpenFile(
		filepath.Join(configPath, "config.yml"),
		os.O_CREATE|os.O_RDWR,
		os.FileMode(0600),
	)
	if err != nil {
		return err
	}

	defer file.Close()

	d := yaml.NewEncoder(file)

	if err := d.Encode(config); err != nil {
		return err
	}

	return nil
}
