package gmsm

import "google.golang.org/grpc"

//创建grpc连接
func NewGrpcConnByParam(target string, certfile string, servername string) (*grpc.ClientConn, error) {

	var opts []grpc.DialOption

	// creds, err := credentials.NewClientTLSFromFile(certfile, servername)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// opts = append(opts, grpc.WithTransportCredentials(creds))

	opts = append(opts, grpc.WithInsecure())

	return grpc.Dial(target, opts...)
}

func NewGrpcConn() (*grpc.ClientConn, error) {

	var (
		opts   []grpc.DialOption
		target string = "localhost:6000"
		// certfile   string
		// servername string
	)
	// creds, err := credentials.NewClientTLSFromFile(certfile, servername)
	// if err != nil {
	// 	log.Fatalln(err)
	// }
	// opts = append(opts, grpc.WithTransportCredentials(creds))

	opts = append(opts, grpc.WithInsecure())

	return grpc.Dial(target, opts...)
}
