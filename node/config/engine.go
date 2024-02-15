package config

type EngineConfig struct {
	ProvingKeyId         string `yaml:"provingKeyId"`
	Filter               string `yaml:"filter"`
	GenesisSeed          string `yaml:"genesisSeed"`
	MaxFrames            int64  `yaml:"maxFrames"`
	PendingCommitWorkers int64  `yaml:"pendingCommitWorkers"`
	MinimumPeersRequired int    `yaml:"minimumPeersRequired"`
	StatsMultiaddr       string `yaml:"statsMultiaddr"`

	// Values used only for testing – do not override these in production, your
	// node will get kicked out
	Difficulty uint32 `yaml:"difficulty"`
}
