// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v3.21.12
// source: ceremony.proto

package protobufs

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	CeremonyService_GetCompressedSyncFrames_FullMethodName       = "/quilibrium.node.ceremony.pb.CeremonyService/GetCompressedSyncFrames"
	CeremonyService_NegotiateCompressedSyncFrames_FullMethodName = "/quilibrium.node.ceremony.pb.CeremonyService/NegotiateCompressedSyncFrames"
	CeremonyService_GetPublicChannel_FullMethodName              = "/quilibrium.node.ceremony.pb.CeremonyService/GetPublicChannel"
	CeremonyService_GetDataFrame_FullMethodName                  = "/quilibrium.node.ceremony.pb.CeremonyService/GetDataFrame"
)

// CeremonyServiceClient is the client API for CeremonyService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CeremonyServiceClient interface {
	GetCompressedSyncFrames(ctx context.Context, in *ClockFramesRequest, opts ...grpc.CallOption) (CeremonyService_GetCompressedSyncFramesClient, error)
	NegotiateCompressedSyncFrames(ctx context.Context, opts ...grpc.CallOption) (CeremonyService_NegotiateCompressedSyncFramesClient, error)
	GetPublicChannel(ctx context.Context, opts ...grpc.CallOption) (CeremonyService_GetPublicChannelClient, error)
	GetDataFrame(ctx context.Context, in *GetDataFrameRequest, opts ...grpc.CallOption) (*DataFrameResponse, error)
}

type ceremonyServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewCeremonyServiceClient(cc grpc.ClientConnInterface) CeremonyServiceClient {
	return &ceremonyServiceClient{cc}
}

func (c *ceremonyServiceClient) GetCompressedSyncFrames(ctx context.Context, in *ClockFramesRequest, opts ...grpc.CallOption) (CeremonyService_GetCompressedSyncFramesClient, error) {
	stream, err := c.cc.NewStream(ctx, &CeremonyService_ServiceDesc.Streams[0], CeremonyService_GetCompressedSyncFrames_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &ceremonyServiceGetCompressedSyncFramesClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type CeremonyService_GetCompressedSyncFramesClient interface {
	Recv() (*CeremonyCompressedSync, error)
	grpc.ClientStream
}

type ceremonyServiceGetCompressedSyncFramesClient struct {
	grpc.ClientStream
}

func (x *ceremonyServiceGetCompressedSyncFramesClient) Recv() (*CeremonyCompressedSync, error) {
	m := new(CeremonyCompressedSync)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *ceremonyServiceClient) NegotiateCompressedSyncFrames(ctx context.Context, opts ...grpc.CallOption) (CeremonyService_NegotiateCompressedSyncFramesClient, error) {
	stream, err := c.cc.NewStream(ctx, &CeremonyService_ServiceDesc.Streams[1], CeremonyService_NegotiateCompressedSyncFrames_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &ceremonyServiceNegotiateCompressedSyncFramesClient{stream}
	return x, nil
}

type CeremonyService_NegotiateCompressedSyncFramesClient interface {
	Send(*CeremonyCompressedSyncRequestMessage) error
	Recv() (*CeremonyCompressedSyncResponseMessage, error)
	grpc.ClientStream
}

type ceremonyServiceNegotiateCompressedSyncFramesClient struct {
	grpc.ClientStream
}

func (x *ceremonyServiceNegotiateCompressedSyncFramesClient) Send(m *CeremonyCompressedSyncRequestMessage) error {
	return x.ClientStream.SendMsg(m)
}

func (x *ceremonyServiceNegotiateCompressedSyncFramesClient) Recv() (*CeremonyCompressedSyncResponseMessage, error) {
	m := new(CeremonyCompressedSyncResponseMessage)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *ceremonyServiceClient) GetPublicChannel(ctx context.Context, opts ...grpc.CallOption) (CeremonyService_GetPublicChannelClient, error) {
	stream, err := c.cc.NewStream(ctx, &CeremonyService_ServiceDesc.Streams[2], CeremonyService_GetPublicChannel_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	x := &ceremonyServiceGetPublicChannelClient{stream}
	return x, nil
}

type CeremonyService_GetPublicChannelClient interface {
	Send(*P2PChannelEnvelope) error
	Recv() (*P2PChannelEnvelope, error)
	grpc.ClientStream
}

type ceremonyServiceGetPublicChannelClient struct {
	grpc.ClientStream
}

func (x *ceremonyServiceGetPublicChannelClient) Send(m *P2PChannelEnvelope) error {
	return x.ClientStream.SendMsg(m)
}

func (x *ceremonyServiceGetPublicChannelClient) Recv() (*P2PChannelEnvelope, error) {
	m := new(P2PChannelEnvelope)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *ceremonyServiceClient) GetDataFrame(ctx context.Context, in *GetDataFrameRequest, opts ...grpc.CallOption) (*DataFrameResponse, error) {
	out := new(DataFrameResponse)
	err := c.cc.Invoke(ctx, CeremonyService_GetDataFrame_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CeremonyServiceServer is the server API for CeremonyService service.
// All implementations must embed UnimplementedCeremonyServiceServer
// for forward compatibility
type CeremonyServiceServer interface {
	GetCompressedSyncFrames(*ClockFramesRequest, CeremonyService_GetCompressedSyncFramesServer) error
	NegotiateCompressedSyncFrames(CeremonyService_NegotiateCompressedSyncFramesServer) error
	GetPublicChannel(CeremonyService_GetPublicChannelServer) error
	GetDataFrame(context.Context, *GetDataFrameRequest) (*DataFrameResponse, error)
	mustEmbedUnimplementedCeremonyServiceServer()
}

// UnimplementedCeremonyServiceServer must be embedded to have forward compatible implementations.
type UnimplementedCeremonyServiceServer struct {
}

func (UnimplementedCeremonyServiceServer) GetCompressedSyncFrames(*ClockFramesRequest, CeremonyService_GetCompressedSyncFramesServer) error {
	return status.Errorf(codes.Unimplemented, "method GetCompressedSyncFrames not implemented")
}
func (UnimplementedCeremonyServiceServer) NegotiateCompressedSyncFrames(CeremonyService_NegotiateCompressedSyncFramesServer) error {
	return status.Errorf(codes.Unimplemented, "method NegotiateCompressedSyncFrames not implemented")
}
func (UnimplementedCeremonyServiceServer) GetPublicChannel(CeremonyService_GetPublicChannelServer) error {
	return status.Errorf(codes.Unimplemented, "method GetPublicChannel not implemented")
}
func (UnimplementedCeremonyServiceServer) GetDataFrame(context.Context, *GetDataFrameRequest) (*DataFrameResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetDataFrame not implemented")
}
func (UnimplementedCeremonyServiceServer) mustEmbedUnimplementedCeremonyServiceServer() {}

// UnsafeCeremonyServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CeremonyServiceServer will
// result in compilation errors.
type UnsafeCeremonyServiceServer interface {
	mustEmbedUnimplementedCeremonyServiceServer()
}

func RegisterCeremonyServiceServer(s grpc.ServiceRegistrar, srv CeremonyServiceServer) {
	s.RegisterService(&CeremonyService_ServiceDesc, srv)
}

func _CeremonyService_GetCompressedSyncFrames_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ClockFramesRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(CeremonyServiceServer).GetCompressedSyncFrames(m, &ceremonyServiceGetCompressedSyncFramesServer{stream})
}

type CeremonyService_GetCompressedSyncFramesServer interface {
	Send(*CeremonyCompressedSync) error
	grpc.ServerStream
}

type ceremonyServiceGetCompressedSyncFramesServer struct {
	grpc.ServerStream
}

func (x *ceremonyServiceGetCompressedSyncFramesServer) Send(m *CeremonyCompressedSync) error {
	return x.ServerStream.SendMsg(m)
}

func _CeremonyService_NegotiateCompressedSyncFrames_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(CeremonyServiceServer).NegotiateCompressedSyncFrames(&ceremonyServiceNegotiateCompressedSyncFramesServer{stream})
}

type CeremonyService_NegotiateCompressedSyncFramesServer interface {
	Send(*CeremonyCompressedSyncResponseMessage) error
	Recv() (*CeremonyCompressedSyncRequestMessage, error)
	grpc.ServerStream
}

type ceremonyServiceNegotiateCompressedSyncFramesServer struct {
	grpc.ServerStream
}

func (x *ceremonyServiceNegotiateCompressedSyncFramesServer) Send(m *CeremonyCompressedSyncResponseMessage) error {
	return x.ServerStream.SendMsg(m)
}

func (x *ceremonyServiceNegotiateCompressedSyncFramesServer) Recv() (*CeremonyCompressedSyncRequestMessage, error) {
	m := new(CeremonyCompressedSyncRequestMessage)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _CeremonyService_GetPublicChannel_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(CeremonyServiceServer).GetPublicChannel(&ceremonyServiceGetPublicChannelServer{stream})
}

type CeremonyService_GetPublicChannelServer interface {
	Send(*P2PChannelEnvelope) error
	Recv() (*P2PChannelEnvelope, error)
	grpc.ServerStream
}

type ceremonyServiceGetPublicChannelServer struct {
	grpc.ServerStream
}

func (x *ceremonyServiceGetPublicChannelServer) Send(m *P2PChannelEnvelope) error {
	return x.ServerStream.SendMsg(m)
}

func (x *ceremonyServiceGetPublicChannelServer) Recv() (*P2PChannelEnvelope, error) {
	m := new(P2PChannelEnvelope)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _CeremonyService_GetDataFrame_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetDataFrameRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CeremonyServiceServer).GetDataFrame(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CeremonyService_GetDataFrame_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CeremonyServiceServer).GetDataFrame(ctx, req.(*GetDataFrameRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// CeremonyService_ServiceDesc is the grpc.ServiceDesc for CeremonyService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CeremonyService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "quilibrium.node.ceremony.pb.CeremonyService",
	HandlerType: (*CeremonyServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetDataFrame",
			Handler:    _CeremonyService_GetDataFrame_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "GetCompressedSyncFrames",
			Handler:       _CeremonyService_GetCompressedSyncFrames_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "NegotiateCompressedSyncFrames",
			Handler:       _CeremonyService_NegotiateCompressedSyncFrames_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "GetPublicChannel",
			Handler:       _CeremonyService_GetPublicChannel_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "ceremony.proto",
}
