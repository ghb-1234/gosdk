// Code generated by protoc-gen-go. DO NOT EDIT.
// source: aes.proto

/*
Package pb is a generated protocol buffer package.

It is generated from these files:
	aes.proto
	des3.proto
	ecc.proto
	rsa.proto
	sm2.proto
	sm4.proto

It has these top-level messages:
	AesGenerateRequest
	AesGenerateResponse
	AesEncryptRequest
	AesEncryptResponse
	AesDecryptRequest
	AesDecryptResponse
	Des3GenerateRequest
	Des3GenerateResponse
	Des3EncryptRequest
	Des3EncryptResponse
	Des3DecryptRequest
	Des3DecryptResponse
	EccGenerateRequest
	EccGenerateResponse
	EccSignRequest
	EccSignResponse
	EccVerifyRequest
	EccVerifyResponse
	EccEncryptRequest
	EccEncryptResponse
	EccDecryptRequest
	EccDecryptResponse
	EccPublicKeyRequest
	EccPublicKeyResponse
	RsaGenerateRequest
	RsaGenerateResponse
	RsaSignRequest
	RsaSignResponse
	RsaVerifyRequest
	RsaVerifyResponse
	RsaEncryptRequest
	RsaEncryptResponse
	RsaDecryptRequest
	RsaDecryptResponse
	RsaPublicKeyRequest
	RsaPublicKeyResponse
	Sm2GenerateRequest
	Sm2GenerateResponse
	Sm2SignRequest
	Sm2SignResponse
	Sm2VerifyRequest
	Sm2VerifyResponse
	Sm2EncryptRequest
	Sm2EncryptResponse
	Sm2DecryptRequest
	Sm2DecryptResponse
	Sm2PublicKeyRequest
	Sm2PublicKeyResponse
	Sm4GenerateRequest
	Sm4GenerateResponse
	Sm4EncryptRequest
	Sm4EncryptResponse
	Sm4DecryptRequest
	Sm4DecryptResponse
*/
package pb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type AesGenerateRequest struct {
	Ephemeral bool `protobuf:"varint,1,opt,name=ephemeral" json:"ephemeral,omitempty"`
}

func (m *AesGenerateRequest) Reset()                    { *m = AesGenerateRequest{} }
func (m *AesGenerateRequest) String() string            { return proto.CompactTextString(m) }
func (*AesGenerateRequest) ProtoMessage()               {}
func (*AesGenerateRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *AesGenerateRequest) GetEphemeral() bool {
	if m != nil {
		return m.Ephemeral
	}
	return false
}

type AesGenerateResponse struct {
	Label []byte `protobuf:"bytes,1,opt,name=label,proto3" json:"label,omitempty"`
	Value []byte `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (m *AesGenerateResponse) Reset()                    { *m = AesGenerateResponse{} }
func (m *AesGenerateResponse) String() string            { return proto.CompactTextString(m) }
func (*AesGenerateResponse) ProtoMessage()               {}
func (*AesGenerateResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *AesGenerateResponse) GetLabel() []byte {
	if m != nil {
		return m.Label
	}
	return nil
}

func (m *AesGenerateResponse) GetValue() []byte {
	if m != nil {
		return m.Value
	}
	return nil
}

type AesEncryptRequest struct {
	Label []byte `protobuf:"bytes,1,opt,name=label,proto3" json:"label,omitempty"`
	Msg   []byte `protobuf:"bytes,2,opt,name=msg,proto3" json:"msg,omitempty"`
}

func (m *AesEncryptRequest) Reset()                    { *m = AesEncryptRequest{} }
func (m *AesEncryptRequest) String() string            { return proto.CompactTextString(m) }
func (*AesEncryptRequest) ProtoMessage()               {}
func (*AesEncryptRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *AesEncryptRequest) GetLabel() []byte {
	if m != nil {
		return m.Label
	}
	return nil
}

func (m *AesEncryptRequest) GetMsg() []byte {
	if m != nil {
		return m.Msg
	}
	return nil
}

type AesEncryptResponse struct {
	Dst []byte `protobuf:"bytes,1,opt,name=dst,proto3" json:"dst,omitempty"`
}

func (m *AesEncryptResponse) Reset()                    { *m = AesEncryptResponse{} }
func (m *AesEncryptResponse) String() string            { return proto.CompactTextString(m) }
func (*AesEncryptResponse) ProtoMessage()               {}
func (*AesEncryptResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *AesEncryptResponse) GetDst() []byte {
	if m != nil {
		return m.Dst
	}
	return nil
}

type AesDecryptRequest struct {
	Label []byte `protobuf:"bytes,1,opt,name=label,proto3" json:"label,omitempty"`
	Msg   []byte `protobuf:"bytes,2,opt,name=msg,proto3" json:"msg,omitempty"`
}

func (m *AesDecryptRequest) Reset()                    { *m = AesDecryptRequest{} }
func (m *AesDecryptRequest) String() string            { return proto.CompactTextString(m) }
func (*AesDecryptRequest) ProtoMessage()               {}
func (*AesDecryptRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *AesDecryptRequest) GetLabel() []byte {
	if m != nil {
		return m.Label
	}
	return nil
}

func (m *AesDecryptRequest) GetMsg() []byte {
	if m != nil {
		return m.Msg
	}
	return nil
}

type AesDecryptResponse struct {
	Dst []byte `protobuf:"bytes,1,opt,name=dst,proto3" json:"dst,omitempty"`
}

func (m *AesDecryptResponse) Reset()                    { *m = AesDecryptResponse{} }
func (m *AesDecryptResponse) String() string            { return proto.CompactTextString(m) }
func (*AesDecryptResponse) ProtoMessage()               {}
func (*AesDecryptResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *AesDecryptResponse) GetDst() []byte {
	if m != nil {
		return m.Dst
	}
	return nil
}

func init() {
	proto.RegisterType((*AesGenerateRequest)(nil), "pb.AesGenerateRequest")
	proto.RegisterType((*AesGenerateResponse)(nil), "pb.AesGenerateResponse")
	proto.RegisterType((*AesEncryptRequest)(nil), "pb.AesEncryptRequest")
	proto.RegisterType((*AesEncryptResponse)(nil), "pb.AesEncryptResponse")
	proto.RegisterType((*AesDecryptRequest)(nil), "pb.AesDecryptRequest")
	proto.RegisterType((*AesDecryptResponse)(nil), "pb.AesDecryptResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for AesOperate service

type AesOperateClient interface {
	AesGenerate(ctx context.Context, in *AesGenerateRequest, opts ...grpc.CallOption) (*AesGenerateResponse, error)
	AesEncryptData(ctx context.Context, in *AesEncryptRequest, opts ...grpc.CallOption) (*AesEncryptResponse, error)
	AesDecryptData(ctx context.Context, in *AesDecryptRequest, opts ...grpc.CallOption) (*AesDecryptResponse, error)
	AesKey(ctx context.Context, in *AesGenerateRequest, opts ...grpc.CallOption) (*AesGenerateResponse, error)
}

type aesOperateClient struct {
	cc *grpc.ClientConn
}

func NewAesOperateClient(cc *grpc.ClientConn) AesOperateClient {
	return &aesOperateClient{cc}
}

func (c *aesOperateClient) AesGenerate(ctx context.Context, in *AesGenerateRequest, opts ...grpc.CallOption) (*AesGenerateResponse, error) {
	out := new(AesGenerateResponse)
	err := grpc.Invoke(ctx, "/pb.AesOperate/AesGenerate", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aesOperateClient) AesEncryptData(ctx context.Context, in *AesEncryptRequest, opts ...grpc.CallOption) (*AesEncryptResponse, error) {
	out := new(AesEncryptResponse)
	err := grpc.Invoke(ctx, "/pb.AesOperate/AesEncryptData", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aesOperateClient) AesDecryptData(ctx context.Context, in *AesDecryptRequest, opts ...grpc.CallOption) (*AesDecryptResponse, error) {
	out := new(AesDecryptResponse)
	err := grpc.Invoke(ctx, "/pb.AesOperate/AesDecryptData", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aesOperateClient) AesKey(ctx context.Context, in *AesGenerateRequest, opts ...grpc.CallOption) (*AesGenerateResponse, error) {
	out := new(AesGenerateResponse)
	err := grpc.Invoke(ctx, "/pb.AesOperate/AesKey", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for AesOperate service

type AesOperateServer interface {
	AesGenerate(context.Context, *AesGenerateRequest) (*AesGenerateResponse, error)
	AesEncryptData(context.Context, *AesEncryptRequest) (*AesEncryptResponse, error)
	AesDecryptData(context.Context, *AesDecryptRequest) (*AesDecryptResponse, error)
	AesKey(context.Context, *AesGenerateRequest) (*AesGenerateResponse, error)
}

func RegisterAesOperateServer(s *grpc.Server, srv AesOperateServer) {
	s.RegisterService(&_AesOperate_serviceDesc, srv)
}

func _AesOperate_AesGenerate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AesGenerateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AesOperateServer).AesGenerate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.AesOperate/AesGenerate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AesOperateServer).AesGenerate(ctx, req.(*AesGenerateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AesOperate_AesEncryptData_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AesEncryptRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AesOperateServer).AesEncryptData(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.AesOperate/AesEncryptData",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AesOperateServer).AesEncryptData(ctx, req.(*AesEncryptRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AesOperate_AesDecryptData_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AesDecryptRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AesOperateServer).AesDecryptData(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.AesOperate/AesDecryptData",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AesOperateServer).AesDecryptData(ctx, req.(*AesDecryptRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AesOperate_AesKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AesGenerateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AesOperateServer).AesKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.AesOperate/AesKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AesOperateServer).AesKey(ctx, req.(*AesGenerateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _AesOperate_serviceDesc = grpc.ServiceDesc{
	ServiceName: "pb.AesOperate",
	HandlerType: (*AesOperateServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AesGenerate",
			Handler:    _AesOperate_AesGenerate_Handler,
		},
		{
			MethodName: "AesEncryptData",
			Handler:    _AesOperate_AesEncryptData_Handler,
		},
		{
			MethodName: "AesDecryptData",
			Handler:    _AesOperate_AesDecryptData_Handler,
		},
		{
			MethodName: "AesKey",
			Handler:    _AesOperate_AesKey_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "aes.proto",
}

func init() { proto.RegisterFile("aes.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 265 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x52, 0xb1, 0x4e, 0xc3, 0x30,
	0x14, 0x6c, 0x53, 0x51, 0xd1, 0x07, 0x42, 0xe5, 0x01, 0xa5, 0xaa, 0x18, 0x90, 0x07, 0xc4, 0x94,
	0xa1, 0x8c, 0x5d, 0xb0, 0x54, 0xc4, 0xc0, 0x80, 0x94, 0x3f, 0x70, 0xe0, 0x04, 0x43, 0x9a, 0x98,
	0x3c, 0x17, 0xa9, 0x9f, 0xc1, 0x1f, 0xa3, 0x24, 0x26, 0xc5, 0x29, 0x2c, 0xb0, 0xbd, 0x77, 0xf2,
	0xdd, 0xbd, 0x3b, 0x99, 0x46, 0x06, 0x12, 0xdb, 0xb2, 0x70, 0x05, 0x47, 0x36, 0x55, 0x73, 0x62,
	0x0d, 0xb9, 0x47, 0x8e, 0xd2, 0x38, 0x24, 0x78, 0x5b, 0x43, 0x1c, 0x5f, 0xd0, 0x08, 0xf6, 0x15,
	0x2b, 0x94, 0x26, 0x9b, 0xf6, 0x2f, 0xfb, 0xd7, 0xfb, 0xc9, 0x16, 0x50, 0x9a, 0x4e, 0x02, 0x8e,
	0xd8, 0x22, 0x17, 0xf0, 0x29, 0xed, 0x65, 0x26, 0x45, 0x43, 0x38, 0x4c, 0x9a, 0xa5, 0x42, 0xdf,
	0x4d, 0xb6, 0xc6, 0x34, 0x6a, 0xd0, 0x7a, 0x51, 0x0b, 0x3a, 0xd6, 0x90, 0xbb, 0xfc, 0xa9, 0xdc,
	0x58, 0xf7, 0xe5, 0xfa, 0xb3, 0xc0, 0x98, 0x06, 0x2b, 0x79, 0xf1, 0xf4, 0x6a, 0x54, 0x57, 0xf5,
	0xcd, 0x2d, 0xd9, 0xdb, 0x8f, 0x69, 0xf0, 0x2c, 0xce, 0x73, 0xab, 0xd1, 0x9b, 0x2c, 0xf1, 0x0f,
	0x93, 0x96, 0xfc, 0x9b, 0xc9, 0xfc, 0x23, 0x22, 0xd2, 0x90, 0x47, 0x5b, 0x97, 0xc1, 0xb7, 0x74,
	0xf0, 0xad, 0x1b, 0x9e, 0xc4, 0x36, 0x8d, 0x77, 0x0b, 0x9e, 0x9d, 0xef, 0xe0, 0x8d, 0x81, 0xea,
	0xb1, 0xa6, 0xa3, 0x6d, 0xba, 0xa5, 0x71, 0x86, 0xcf, 0xfc, 0xe3, 0xb0, 0xae, 0xd9, 0xa4, 0x0b,
	0x77, 0x24, 0xfc, 0xed, 0x81, 0x44, 0x58, 0x46, 0x2b, 0xd1, 0x89, 0xa9, 0x7a, 0xbc, 0xa0, 0xa1,
	0x86, 0x3c, 0x60, 0xf3, 0x87, 0x08, 0xe9, 0xb0, 0xfe, 0x5f, 0x37, 0x9f, 0x01, 0x00, 0x00, 0xff,
	0xff, 0xf0, 0xcf, 0xe9, 0x9e, 0x6c, 0x02, 0x00, 0x00,
}
