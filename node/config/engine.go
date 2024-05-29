package config

type EngineConfig struct {
	ProvingKeyId         string `yaml:"provingKeyId"`
	Filter               string `yaml:"filter"`
	GenesisSeed          string `yaml:"genesisSeed"`
	MaxFrames            int64  `yaml:"maxFrames"`
	PendingCommitWorkers int64  `yaml:"pendingCommitWorkers"`
	MinimumPeersRequired int    `yaml:"minimumPeersRequired"`
	StatsMultiaddr       string `yaml:"statsMultiaddr"`
	// Sets the fmt.Sprintf format string to use as the listen multiaddrs for
	// data worker processes
	DataWorkerBaseListenMultiaddr string `yaml:"dataWorkerBaseListenMultiaddr"`
	// Sets the starting port number to use as the listen port for data worker
	// processes, incrementing by 1 until n-1, n = cores. (Example: a 4 core
	// system, base listen port of 40000 will listen on 40000, 40001, 40002)
	DataWorkerBaseListenPort uint16 `yaml:"dataWorkerBaseListenPort"`
	DataWorkerMemoryLimit    int64  `yaml:"dataWorkerMemoryLimit"`

	// Values used only for testing – do not override these in production, your
	// node will get kicked out
	Difficulty uint32 `yaml:"difficulty"`
}
