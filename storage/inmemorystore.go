package storage

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

import (
	"crypto/rand"
	"fmt"
)

var RPAMap map[string]RelyingPartyApplication

//In memory RPA storage for demo purpose
type InMemoryRPAManager struct {
}

func (rpaManager InMemoryRPAManager) Init() {
	RPAMap = make(map[string]RelyingPartyApplication)
}

func (rpaManager InMemoryRPAManager) RegisterRPA(relyingPartyApplication RelyingPartyApplication) {
	c := 16
	b := make([]byte, c)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("error:", err)

	}
	relyingPartyApplication.Application_KEY = b
	fmt.Println("Generating appkey for ", relyingPartyApplication.Application_ID)
	RPAMap[relyingPartyApplication.Application_ID] = relyingPartyApplication
}
func (rpaManager InMemoryRPAManager) GetAllRPAs() []RelyingPartyApplication {
	var apps []RelyingPartyApplication

	fmt.Println("Going to return ", len(RPAMap), " apps ")
	for key, app := range RPAMap {

		apps = append(apps, app)
		fmt.Println("Adding app..", app, ":", key)

	}
	return apps
}
func (rpaManager InMemoryRPAManager) GetRPA(rpaID string) RelyingPartyApplication {
	return RPAMap[rpaID]
}

func (rpaManager InMemoryRPAManager) DeleteRPA(rpaID string) {
	delete(RPAMap, rpaID)
}
