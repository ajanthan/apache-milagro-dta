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

package signature

import (
	"encoding/base64"
	"testing"
)

func TestSignatureBasic(t *testing.T) {
	key, _ := base64.URLEncoding.DecodeString("FeXwEJUZsU0fgmpdqf2FiQ==")
	t.Log("Key size :", len(key))
	appID := "appID0001"
	signature := CreateSignature(key, appID)

	verifier := AESSignatureVerifier{}
	sig, _ := base64.URLEncoding.DecodeString(base64.URLEncoding.EncodeToString(signature))
	if verifier.VerifySignature(sig, key, appID) {
		t.Log("Successfully verified signatre: ", base64.URLEncoding.EncodeToString(signature))
	} else {
		t.Fail()
	}

}
