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
	"bytes"
	"os"
	"testing"
)

func TestPlainTextFileMasterSecretStorage_Basic(t *testing.T) {
	os.Setenv("DTA_HOME", "/tmp")

	inSecret := []byte("dhkgfkdfhs49638543gfdkf38t1fgroe")
	t.Log("Length of the secret ", len(inSecret))
	masterSecretStorage := PlainTextFileMasterSecretStorage{}
	defer func() {
		masterSecretStorage.Init()
		os.Remove(masterSecretStorage.secretFile.Name())
		masterSecretStorage.secretFile.Close()
	}()
	_, ok1 := masterSecretStorage.GetSecret()
	if ok1 {
		t.Log("secret  should not exisits")
		t.FailNow()
	}

	t.Log("Secret  is not exisit. Creating new one")
	masterSecretStorage.SetSecret(inSecret)
	outSecret, ok2 := masterSecretStorage.GetSecret()

	if !ok2 {
		t.Log("secret  should  exisits")
		t.FailNow()
	}

	if !bytes.Equal(inSecret[:], outSecret[:]) {
		t.Log("The secret should match. Expected ", string(inSecret[:]), " received ", string(outSecret[:]))
		t.FailNow()
	}

}
