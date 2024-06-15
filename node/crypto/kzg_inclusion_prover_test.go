package crypto_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/kzg"
)

// func TestKZGVerifyFrame(t *testing.T) {
// 	kzg.TestInit("./kzg/ceremony.json")
// 	data := make([]byte, 1024)
// 	rand.Read(data)

// 	l, _ := zap.NewProduction()
// 	inclusionProver := crypto.NewKZGInclusionProver(l)

// 	commitment, err := inclusionProver.Commit(
// 		data,
// 		protobufs.IntrinsicExecutionOutputType,
// 	)
// 	assert.NoError(t, err)

// 	proof, err := inclusionProver.ProveAggregate(
// 		[]*crypto.InclusionCommitment{commitment},
// 	)
// 	assert.NoError(t, err)

// 	frame := &protobufs.ClockFrame{
// 		Filter:      []byte{0x00},
// 		FrameNumber: 1,
// 		Input:       bytes.Repeat([]byte{0x00}, 516),
// 		Output:      bytes.Repeat([]byte{0x00}, 516),
// 	}

// 	_, priv, _ := ed448.GenerateKey(rand.Reader)
// 	w := crypto.NewWesolowskiFrameProver(l)
// 	frame, err = w.ProveDataClockFrame(
// 		frame,
// 		[][]byte{proof.AggregateCommitment},
// 		[]*protobufs.InclusionAggregateProof{
// 			{
// 				Filter:      []byte{0x00},
// 				FrameNumber: 1,
// 				InclusionCommitments: []*protobufs.InclusionCommitment{
// 					{
// 						Filter:      []byte{0x00},
// 						FrameNumber: 1,
// 						TypeUrl:     proof.InclusionCommitments[0].TypeUrl,
// 						Commitment:  proof.InclusionCommitments[0].Commitment,
// 						Data:        data,
// 						Position:    0,
// 					},
// 				},
// 				Proof: proof.Proof,
// 			},
// 		},
// 		priv,
// 		time.Now().UnixMilli(),
// 		100,
// 	)

// 	err = inclusionProver.VerifyFrame(frame)
// 	assert.NoError(t, err)
// }

func TestKZGInclusionProverRawFuncs(t *testing.T) {
	kzg.TestInit("./kzg/ceremony.json")

	data, _ := hex.DecodeString("408f9f0a63a1c463579a1fdaf82b37e0f397476e87c524915870ce7f5ede9c248493ea4ffefae154b8a55f10add4d75846b273a7f57433b438ae72880a29ab7cab6c3187a14651bac085329778526ebb31d14c9beb7b0983ff5e71a47c96ed9e7149e9e896cd4d604191583a282bdb5a92ea71334f296fd06498323b0c5d0e60c04180a7141813f6f9a6c766c450898ffc437ebed07a2fbd9201207171a0a8f5006a83d9e2430687952dd42237b7d77de61c0655b91bb1943ed4b9337449ded69ef8f2f83fba58827be7b7082db048b799f1bb590f61c558976910e77357562eb4d66fc97636c26ea562fe18b4cc397e679acad23cfd003ae93efe2903534ce1fe475eba3c82fef71554b4d63b593f2da3fea3b1b3f91379c6ff1989c91eaab70e336d96f3c46de987ef7165d111f692fe8205f7df0eb854fc550aa0d10942049dec4c60d99a51b0a7cde49a6d5e9364d0162cb86af1a51efeffacf7935f796f18cb868756e693aa967339efb8e45071da835ff8b6897fe56dc14edb49352edc88d3a6866873ecfa2bf968907e86c0dd139ab9a23bae341ec6aa5f1fbac2390a9d7f5ef9346d5c433268bf85e34e98295233f5e0d2ceb35c47b33b93e8ae9445c3b9f6ec32d8e3a1a1bc95b013dd36a84d803e468e873420c71b6473e44300f4d2702ccb452146c675d5ac1511a0b0a61a857b58ed3365ecdc1cafafbdfe5f0f2420389ae5f54d2fb9d12de314b416fdb12786fb66d0517229347ecc347eb8207a88abeffbdb9acfc582047a9343efae6c21cf67566e2d949920bdff1f4cea376332dd503c9dcd72a776744724c29a25038ef582f1103b406321e14d0f232c709b3d5a3568c75a1bc244b65e18d9ca7c53e2e13bb5638c325f6d43601de131aa2e3b7ffcc23accf6c69e9c6360cf8f4d48de3f11354855ec281f8a9c85caec0b8284c99c66a43ed0c37d6ce0f5c349e4551da6a1d9edcfa02f6be27ed037c5ec79c0519ba60725f89b3fe7826ca1a7b157ef9360bc2007bc2b9dd2ba8fdc225047a9f66b832e2da1dc6019f480e3aadb46ba93cccbd1e7b221a5d36e0fc96cbf497bfb40ff0276f14b7d45c4738a1b755e2754c5c352ac4af96c1a9be1d92942200b325cc3c53e9b3099c99a466bdc6c001179f6c63f828936b1c33f651a150c080b2eac8ed7cb9cfe599daee477f9ba88a6d1cbdeb08995c3c7bcce18ee2946c2beb138b8c797f61c6c33800ffeda74b77dab186cc4c7e91e9aca954d4863de6b04a82ef563a6eefbedec8fdc9284fb33e15197d2512e4928019fc29aa9c0a199797ef02c8daeb8706dd21a0e6b25b0e73795bac18dfaac2abc1defddf530f6a14046c2a918fa581b7ab0240bbd4f2e570a527581cb0a39bb544ceeabeedf891bc2417ac1e1fa558c09a9ceffef108a5778ff99a8575b4fb69cbbfb2c474d58")

	l, _ := zap.NewProduction()
	inclusionProver := crypto.NewKZGInclusionProver(l)
	c, err := inclusionProver.CommitRaw(data, 1024)
	assert.NoError(t, err)

	p, err := inclusionProver.ProveRaw(data, 0, 1024)
	assert.NoError(t, err)

	v, err := inclusionProver.VerifyRaw(data[64*0:64*1], c, 0, p, 1024)
	assert.NoError(t, err)
	assert.False(t, v)
}
