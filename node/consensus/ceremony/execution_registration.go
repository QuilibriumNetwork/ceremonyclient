package ceremony

import (
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
)

func (e *CeremonyDataClockConsensusEngine) RegisterExecutor(
	exec execution.ExecutionEngine,
	frame uint64,
) <-chan error {
	logger := e.logger.With(zap.String("execution_engine_name", exec.GetName()))
	logger.Info("registering execution engine")
	errChan := make(chan error)

	go func() {
		for {
			masterFrame, err := e.masterTimeReel.Head()
			if err != nil {
				panic(err)
			}

			logger.Info(
				"awaiting frame",
				zap.Uint64("current_frame", masterFrame.FrameNumber),
				zap.Uint64("target_frame", frame),
			)

			newFrame := masterFrame.FrameNumber
			if newFrame >= frame {
				logger.Info(
					"injecting execution engine at frame",
					zap.Uint64("current_frame", newFrame),
				)

				e.engineMx.Lock()
				e.executionEngines[exec.GetName()] = exec
				e.engineMx.Unlock()

				errChan <- nil
				break
			}
		}
	}()

	return errChan
}

func (e *CeremonyDataClockConsensusEngine) UnregisterExecutor(
	name string,
	frame uint64,
	force bool,
) <-chan error {
	logger := e.logger.With(zap.String("execution_engine_name", name))
	logger.Info("unregistering execution engine")
	errChan := make(chan error)

	go func() {
		for {
			masterFrame, err := e.masterTimeReel.Head()
			if err != nil {
				panic(err)
			}

			logger.Info(
				"awaiting frame",
				zap.Uint64("current_frame", masterFrame.FrameNumber),
				zap.Uint64("target_frame", frame),
			)

			newFrame := masterFrame.FrameNumber
			if newFrame >= frame {
				logger.Info(
					"removing execution engine at frame",
					zap.Uint64("current_frame", newFrame),
				)
				e.engineMx.Lock()
				delete(e.executionEngines, name)
				e.engineMx.Unlock()

				errChan <- nil
				break
			}
		}
	}()

	return errChan
}
