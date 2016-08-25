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

package config

import (
	"log"

	"github.com/ajanthan/apache-milagro-dta/signature"
	"github.com/ajanthan/apache-milagro-dta/storage"
	"github.com/spf13/viper"
)

//Represents D-TA config file
type Config struct {
	bindAddress         string
	bindPort            int
	masterSecretStorage string
	serverSeed          string
	rpaStore            string
	signatureVerifier   string
}

//Loads the dta-server.yaml from current directory
func (config *Config) ParseDTAConfigFile() {
	viper.SetConfigFile("dta-server.yaml")
	viper.AddConfigPath(".")
	viper.SetConfigType("yaml")

	viper.SetDefault("server.address", "0.0.0.0")
	viper.SetDefault("server.port", 8088)
	viper.SetDefault("server.secret.storage", "memory")
	viper.SetDefault("server.seed", "3b6c64666d6e766a6a666579346f38793772766264666f6f6665")
	viper.SetDefault("server.signatureVerifier", "aes.signature.verifier")

	err := viper.ReadInConfig()
	if err != nil {
		log.Println("Could not find the config. Using the defualt values")
	}

	config.bindAddress = viper.GetString("server.address")
	config.bindPort = viper.GetInt("server.port")
	config.masterSecretStorage = viper.GetString("server.secret.storage")
	config.serverSeed = viper.GetString("server.seed")
	config.signatureVerifier = viper.GetString("server.signatureVerifier")
}

//Returns interface where the server should listen to expose the api
func (config *Config) GetBindAddress() string {
	return config.bindAddress
}

//Returns port where the server should bind to expose the api
func (config *Config) GetBindPort() int {
	return config.bindPort
}

//Returns the master secret storage implementation
func (config *Config) GetMasterSecretStorage() storage.MasterSecretStorage {
	storage_type := config.masterSecretStorage
	var secretStorage storage.MasterSecretStorage
	switch storage_type {
	case "plain.text.file":
		secretStorage = storage.PlainTextFileMasterSecretStorage{}
		break
	case "memory":
		secretStorage = storage.InMemorySecretStorage{}
		break
	default:
		secretStorage = storage.PlainTextFileMasterSecretStorage{}
	}
	return secretStorage
}

//Returns hex value of seed used to create random number generator source
func (config *Config) GetRandomSeed() string {
	return config.serverSeed
}

//Return RPA storage implementation
func (config *Config) GetRPAStorage() storage.RPAStorage {
	storage_type := config.rpaStore
	var rpaStorage storage.RPAStorage
	switch storage_type {
	case "inmemorystore":
		rpaStorage = storage.InMemoryRPAManager{}
		break
	default:
		rpaStorage = storage.InMemoryRPAManager{}
	}
	rpaStorage.Init()
	return rpaStorage
}

//Returns  SignatureVerifier implementation used to  validate M-Pin requests
func (config *Config) GetSignatureVerifier() signature.SignatureVerifier {
	sigVerifierImpl := config.signatureVerifier
	var sigVerifier signature.SignatureVerifier
	switch sigVerifierImpl {
	case "aes.signature.verifier":
		sigVerifier = signature.AESSignatureVerifier{}
		break
	default:
		sigVerifier = signature.AESSignatureVerifier{}
	}
	return sigVerifier
}
