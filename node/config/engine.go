package config

type EngineConfig struct {
	ProvingKeyId         string `yaml:"provingKeyId"`
	Filter               string `yaml:"filter"`
	GenesisSeed          string `yaml:"genesisSeed"`
	MaxFrames            int64  `yaml:"maxFrames"`
	PendingCommitWorkers int64  `yaml:"pendingCommitWorkers"`
	MinimumPeersRequired int    `yaml:"minimumPeersRequired"`
}
