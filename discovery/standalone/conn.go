package standalone

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newClientConn() *clientConn {
	return &clientConn{
		registry:   newRegistry(),
		serializer: newProtoSerializer(),
	}
}

type clientConn struct {
	registry   *registry
	serializer serializer
}

func (x *clientConn) Invoke(ctx context.Context, method string, args any, reply any, opts ...grpc.CallOption) error {
	handler := x.registry.getMethod(method)
	if handler == nil {
		return fmt.Errorf("service %s not found", method)
	}
	resp, err := handler(ctx, args, nil)
	if err != nil {
		return err
	}
	tmp, err := x.serializer.Marshal(resp)
	if err != nil {
		return err
	}
	return x.serializer.Unmarshal(tmp, reply)
}

func (x *clientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Errorf(codes.Unimplemented, "method stream not implemented")
}
