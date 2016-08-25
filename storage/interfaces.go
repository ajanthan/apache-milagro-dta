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

package storage

import (
	"github.com/apache/incubator-milagro-crypto/go/src/github.com/miracl/amcl-go"
)

//Interface for Master secret storage
type MasterSecretStorage interface {
	GetSecret() ([amcl.MPIN_EGS]byte, bool)
	SetSecret(secret []byte) error
}

//RPA storage interface to store  relying party application ID and KEY
type RPAStorage interface {
	RegisterRPA(relyingPartyApplication RelyingPartyApplication)
	GetAllRPAs() []RelyingPartyApplication
	GetRPA(rpaID string) RelyingPartyApplication
	Init()
	DeleteRPA(appID string)
}

type RelyingPartyApplication struct {
	Application_ID  string
	Application_KEY []byte
}
