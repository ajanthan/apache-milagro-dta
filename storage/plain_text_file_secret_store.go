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
	"log"
	"os"
	"path/filepath"

	"github.com/apache/incubator-milagro-crypto/go/src/github.com/miracl/amcl-go"
)

//Plain text based master secret storage
const (
	dtaHome        = "DTA_HOME"
	secretFileName = "master.secret"
)

type PlainTextFileMasterSecretStorage struct {
	masterSecret []byte
	secretFile   *os.File
}

func (plainTextFileMasterSecretStorage *PlainTextFileMasterSecretStorage) Init() error {
	var file *os.File
	secretFileLocation := os.Getenv(dtaHome)
	if secretFileLocation == "" {
		log.Printf("%s is not set.Using the current directory", dtaHome)
		secretFileLocation = secretFileName
	} else {
		secretFileLocation = secretFileLocation + string(filepath.Separator) + secretFileName
	}
	if _, err := os.Stat(secretFileLocation); os.IsNotExist(err) {
		if file, err = os.Create(secretFileLocation); err != nil {
			return err
		}
	} else {
		if file, err = os.OpenFile(secretFileLocation, os.O_RDWR|os.O_APPEND, os.ModeAppend); err != nil {
			return err
		}
	}
	plainTextFileMasterSecretStorage.secretFile = file
	return nil
}

func (plainTextFileMasterSecretStorage PlainTextFileMasterSecretStorage) GetSecret() ([amcl.MPIN_EGS]byte, bool) {
	var rmasterSecret [amcl.MPIN_EGS]byte
	masterSecret := make([]byte, amcl.MPIN_EGS)
	if err := plainTextFileMasterSecretStorage.Init(); err != nil {
		return rmasterSecret, false
	}
	n, err2 := plainTextFileMasterSecretStorage.secretFile.Read(masterSecret)
	defer plainTextFileMasterSecretStorage.secretFile.Close()
	if err2 != nil {
		return rmasterSecret, false
	}
	if n == 0 {
		return rmasterSecret, false
	}
	copy(rmasterSecret[:], masterSecret)
	return rmasterSecret, true
}

func (plainTextFileMasterSecretStorage PlainTextFileMasterSecretStorage) SetSecret(secret []byte) error {
	if err := plainTextFileMasterSecretStorage.Init(); err != nil {
		return err
	}
	if _, err := plainTextFileMasterSecretStorage.secretFile.Write(secret); err != nil {
		return err
	}
	plainTextFileMasterSecretStorage.secretFile.Sync()
	defer plainTextFileMasterSecretStorage.secretFile.Close()
	return nil
}
