package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/libp2p/go-libp2p/core/crypto/pb"

	"google.golang.org/protobuf/proto"
)

func TestEd448BasicSignAndVerify(t *testing.T) {
	priv, pub, err := GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello! and welcome to some awesome crypto primitives")

	sig, err := priv.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := pub.Verify(data, sig)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("signature didn't match")
	}

	// change data
	data[0] = ^data[0]
	ok, err = pub.Verify(data, sig)
	if err != nil {
		t.Fatal(err)
	}

	if ok {
		t.Fatal("signature matched and shouldn't")
	}
}

func TestEd448SignZero(t *testing.T) {
	priv, pub, err := GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 0)
	sig, err := priv.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := pub.Verify(data, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature didn't match")
	}
}

func TestEd448MarshalLoop(t *testing.T) {
	priv, pub, err := GenerateEd448Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("PrivateKey", func(t *testing.T) {
		for name, f := range map[string]func() ([]byte, error){
			"Marshal": func() ([]byte, error) {
				return MarshalPrivateKey(priv)
			},
			"Redundant": func() ([]byte, error) {
				data, err := priv.Raw()
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, data[len(data)-ed448.PublicKeySize:]...)
				return proto.Marshal(&pb.PrivateKey{
					Type: priv.Type().Enum(),
					Data: data,
				})
			},
		} {
			t.Run(name, func(t *testing.T) {
				bts, err := f()
				if err != nil {
					t.Fatal(err)
				}

				privNew, err := UnmarshalPrivateKey(bts)
				if err != nil {
					t.Fatal(err)
				}

				if !priv.Equals(privNew) || !privNew.Equals(priv) {
					t.Fatal("keys are not equal")
				}

				msg := []byte("My child, my sister,\nThink of the rapture\nOf living together there!")
				signed, err := privNew.Sign(msg)
				if err != nil {
					t.Fatal(err)
				}

				ok, err := privNew.GetPublic().Verify(msg, signed)
				if err != nil {
					t.Fatal(err)
				}

				if !ok {
					t.Fatal("signature didn't match")
				}
			})
		}
	})

	t.Run("PublicKey", func(t *testing.T) {
		for name, f := range map[string]func() ([]byte, error){
			"Marshal": func() ([]byte, error) {
				return MarshalPublicKey(pub)
			},
		} {
			t.Run(name, func(t *testing.T) {
				bts, err := f()
				if err != nil {
					t.Fatal(err)
				}
				pubNew, err := UnmarshalPublicKey(bts)
				if err != nil {
					t.Fatal(err)
				}

				if !pub.Equals(pubNew) || !pubNew.Equals(pub) {
					t.Fatal("keys are not equal")
				}
			})
		}
	})
}

func TestEd448UnmarshalErrors(t *testing.T) {
	t.Run("PublicKey", func(t *testing.T) {
		t.Run("Invalid data length", func(t *testing.T) {
			data, err := proto.Marshal(&pb.PublicKey{
				Type: pb.KeyType_Ed448.Enum(),
				Data: []byte{74},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalPublicKey(data); err == nil {
				t.Fatal("expected an error")
			}
		})
	})

	t.Run("PrivateKey", func(t *testing.T) {
		t.Run("Redundant public key mismatch", func(t *testing.T) {
			priv, _, err := GenerateEd448Key(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			data, err := priv.Raw()
			if err != nil {
				t.Fatal(err)
			}
			// Append the private key instead of the public key.
			data = append(data, data[:ed448.PublicKeySize]...)

			b, err := proto.Marshal(&pb.PrivateKey{
				Type: priv.Type().Enum(),
				Data: data,
			})
			if err != nil {
				t.Fatal(err)
			}

			_, err = UnmarshalPrivateKey(b)
			if err == nil {
				t.Fatal("expected an error")
			}
			if err.Error() != "expected redundant ed448 public key to be redundant" {
				t.Fatalf("invalid error received: %s", err.Error())
			}
		})

		t.Run("Invalid data length", func(t *testing.T) {
			data, err := proto.Marshal(&pb.PrivateKey{
				Type: pb.KeyType_Ed448.Enum(),
				Data: []byte{74},
			})
			if err != nil {
				t.Fatal(err)
			}

			_, err = UnmarshalPrivateKey(data)
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	})
}
