/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package channel

import (
	reqContext "context"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/errors/retry"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/context"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/comm"
	pb "github.com/hyperledger/fabric-sdk-go/third_party/github.com/hyperledger/fabric/protos/peer"
	"github.com/pkg/errors"
)

// opts allows the user to specify more advanced options
type requestOptions struct {
	Targets       []fab.Peer // targets
	TargetFilter  fab.TargetFilter
	Retry         retry.Opts
	Timeouts      map[fab.TimeoutType]time.Duration //timeout options for channel client operations
	ParentContext reqContext.Context                //parent grpc context for channel client operations (query, execute, invokehandler)
}

// RequestOption func for each Opts argument
type RequestOption func(ctx context.Client, opts *requestOptions) error

// Request contains the parameters to query and execute an invocation transaction
type Request struct {
	ChaincodeID  string
	Fcn          string
	Args         [][]byte
	TransientMap map[string][]byte
}

//Response contains response parameters for query and execute an invocation transaction
type Response struct {
	Proposal         *fab.TransactionProposal
	Responses        []*fab.TransactionProposalResponse
	TransactionID    fab.TransactionID
	TxValidationCode pb.TxValidationCode
	ChaincodeStatus  int32
	Payload          []byte
}

//WithTargets allows overriding of the target peers for the request
func WithTargets(targets ...fab.Peer) RequestOption {
	return func(ctx context.Client, o *requestOptions) error {

		// Validate targets
		for _, t := range targets {
			if t == nil {
				return errors.New("target is nil")
			}
		}

		o.Targets = targets
		return nil
	}
}

// WithTargetEndpoints allows overriding of the target peers for the request.
// Targets are specified by name or URL, and the SDK will create the underlying peer
// objects.
func WithTargetEndpoints(keys ...string) RequestOption {
	return func(ctx context.Client, opts *requestOptions) error {

		var targets []fab.Peer

		for _, url := range keys {

			peerCfg, err := comm.NetworkPeerConfig(ctx.EndpointConfig(), url)
			if err != nil {
				return err
			}

			peer, err := ctx.InfraProvider().CreatePeerFromConfig(peerCfg)
			if err != nil {
				return errors.WithMessage(err, "creating peer from config failed")
			}

			targets = append(targets, peer)
		}

		return WithTargets(targets...)(ctx, opts)
	}
}

// WithTargetFilter specifies a per-request target peer-filter
func WithTargetFilter(filter fab.TargetFilter) RequestOption {
	return func(ctx context.Client, o *requestOptions) error {
		o.TargetFilter = filter
		return nil
	}
}

// WithRetry option to configure retries
func WithRetry(retryOpt retry.Opts) RequestOption {
	return func(ctx context.Client, o *requestOptions) error {
		o.Retry = retryOpt
		return nil
	}
}

//WithTimeout encapsulates key value pairs of timeout type, timeout duration to Options
func WithTimeout(timeoutType fab.TimeoutType, timeout time.Duration) RequestOption {
	return func(ctx context.Client, o *requestOptions) error {
		if o.Timeouts == nil {
			o.Timeouts = make(map[fab.TimeoutType]time.Duration)
		}
		o.Timeouts[timeoutType] = timeout
		return nil
	}
}

//WithParentContext encapsulates grpc parent context
func WithParentContext(parentContext reqContext.Context) RequestOption {
	return func(ctx context.Client, o *requestOptions) error {
		o.ParentContext = parentContext
		return nil
	}
}
