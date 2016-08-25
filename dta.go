/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package dta

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/ajanthan/apache-milagro-dta/config"
	"github.com/apache/incubator-milagro-crypto/go/src/github.com/miracl/amcl-go"
	"github.com/pkg/errors"
	"log"
)

const (
	G1S = 2*amcl.MPIN_EFS + 1
	G2S = 4 * amcl.MPIN_EGS
)

type DTA struct {
	materSecret [amcl.MPIN_EGS]byte
	rng         *amcl.RAND
}

//Initialize the random number generator from the seed configured in dta-server.yaml and load master secret from secret
//store.If the master secret store does not have secret then it generate new one and store back
func (dta *DTA) Init(conf config.Config) error {
	seedHex := conf.GetRandomSeed()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		log.Println("Error while deocoding seedhex ", seedHex, err.Error())
		return err
	}
	rng := amcl.NewRAND()
	rng.Seed(len(seed), seed)

	dta.rng = rng

	masterSecretStorage := conf.GetMasterSecretStorage()
	masterSecret, ok := masterSecretStorage.GetSecret()

	if !ok {
		log.Println("Generating new master secret")
		amcl.MPIN_RANDOM_GENERATE(dta.rng, dta.materSecret[:])
		masterSecretStorage.SetSecret(dta.materSecret[:])
	} else {
		dta.materSecret = masterSecret
		log.Println("Using exisitng master secret ", base64.StdEncoding.EncodeToString(dta.materSecret[:]))

	}

	return nil

}

//Issues a server secret or error if there is error while generating it
func (dta *DTA) IssueServerSecret() ([]byte, error) {
	var serverSecret [G2S]byte
	fmt.Println("Using master secret ", base64.StdEncoding.EncodeToString(dta.materSecret[:]))
	rtn := amcl.MPIN_GET_SERVER_SECRET(dta.materSecret[:], serverSecret[:])
	if rtn != 0 {
		return serverSecret[:], errors.New("Error in generating server secret")
	}
	fmt.Println("Returning  server secret ", base64.StdEncoding.EncodeToString(serverSecret[:]))
	return serverSecret[:], nil
}

//Issues a client secret for given hashed client id or error if there is error while generating it
func (dta *DTA) IssueClientSecret(clientID []byte) ([]byte, error) {
	var clientSecret [G1S]byte

	rtn := amcl.MPIN_GET_CLIENT_SECRET(dta.materSecret[:], clientID, clientSecret[:])
	if rtn != 0 {
		return clientSecret[:], errors.New("Error in generating client secret")
	}
	fmt.Println("Client Secret size ", len(clientSecret))
	return clientSecret[:], nil
}

//Issues a time permit for given hashed client id or error if there is error while generating it
func (dta *DTA) IssueTimePermit(hashed_client_id []byte) ([]byte, error) {
	var timePermit [G1S]byte
	date := amcl.MPIN_today()
	rtn := amcl.MPIN_GET_CLIENT_PERMIT(date, dta.materSecret[:], hashed_client_id, timePermit[:])
	if rtn != 0 {
		return timePermit[:], errors.New("Error in generating time permit")
	}
	return timePermit[:], nil

}
