/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/
package gm

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	bccspsm "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/gm"
	bccspsw "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/sw"

	"github.com/pkg/errors"
)

const (
	SMBasedFactoryName = "SM"
)

type GMFactory struct{}

func (f *GMFactory) Name() string {
	return SMBasedFactoryName
}

func (f *GMFactory) Get(swOpts *bccspsw.SwOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if swOpts == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	var ks bccsp.KeyStore
	if swOpts.Ephemeral == true {
		ks = bccspsm.NewDummyKeyStore()
	} else if swOpts.FileKeystore != nil {
		fks, err := bccspsm.NewFileBasedKeyStore(nil, swOpts.FileKeystore.KeyStorePath, false)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to initialize software key store")
		}
		ks = fks
	} else {
		// Default to DummyKeystore
		ks = bccspsm.NewDummyKeyStore()
	}

	return bccspsm.New(swOpts.SecLevel, swOpts.HashFamily, ks)
}
