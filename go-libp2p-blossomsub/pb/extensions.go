package pb

import "google.golang.org/protobuf/proto"

func (r *RPC) Size() int {
	return proto.Size(r)
}

func (r *RPC_SubOpts) Size() int {
	return proto.Size(r)
}

func (i *ControlGraft) Size() int {
	return proto.Size(i)
}

func (i *ControlIHave) Size() int {
	return proto.Size(i)
}

func (i *ControlIWant) Size() int {
	return proto.Size(i)
}

func (i *ControlMessage) Size() int {
	return proto.Size(i)
}

func (i *ControlPrune) Size() int {
	return proto.Size(i)
}

func (m *Message) Size() int {
	return proto.Size(m)
}

func (c *ControlMessage) Marshal() ([]byte, error) {
	return proto.Marshal(c)
}

func (r *RPC) MarshalTo(buf []byte) (int, error) {
	data, err := proto.Marshal(r)
	if err != nil {
		return 0, err
	}

	n := copy(buf, data)
	return n, nil
}

func (r *RPC) Unmarshal(buf []byte) error {
	return proto.Unmarshal(buf, r)
}

func (m *Message) Marshal() ([]byte, error) {
	return proto.Marshal(m)
}
