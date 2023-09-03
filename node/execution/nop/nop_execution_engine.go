package nop

import (
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type NopExecutionEngine struct {
	logger *zap.Logger
}

func NewNopExecutionEngine(
	logger *zap.Logger,
) *NopExecutionEngine {
	if logger == nil {
		panic(errors.New("logger is nil"))
	}

	return &NopExecutionEngine{
		logger: logger,
	}
}

var _ execution.ExecutionEngine = (*NopExecutionEngine)(nil)

// GetName implements ExecutionEngine
func (*NopExecutionEngine) GetName() string {
	return "nop"
}

// GetSupportedApplications implements ExecutionEngine
func (
	*NopExecutionEngine,
) GetSupportedApplications() []*protobufs.Application {
	return []*protobufs.Application{
		{
			Address: []byte{
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			},
			ExecutionContext: protobufs.ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
		},
	}
}

// Start implements ExecutionEngine
func (e *NopExecutionEngine) Start() <-chan error {
	errChan := make(chan error)

	go func() {
		errChan <- nil
	}()

	return errChan
}

// Stop implements ExecutionEngine
func (*NopExecutionEngine) Stop(force bool) <-chan error {
	errChan := make(chan error)

	go func() {
		errChan <- nil
	}()

	return errChan
}

// ProcessMessage implements ExecutionEngine
func (e *NopExecutionEngine) ProcessMessage(
	address []byte,
	message *protobufs.Message,
) ([]*protobufs.Message, error) {
	any := &anypb.Any{}
	if err := proto.Unmarshal(message.Payload, any); err != nil {
		return nil, errors.Wrap(err, "could not unmarshal message")
	}

	if any.TypeUrl == protobufs.ClockFrameType {
		frame := &protobufs.ClockFrame{}
		if err := any.UnmarshalTo(frame); err != nil {
			return nil, errors.Wrap(err, "could not unmarshal clock frame")
		}

		e.logger.Info("nop")
	}

	return nil, nil
}
