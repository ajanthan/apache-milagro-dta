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
	"github.com/ajanthan/apache-milagro-dta/config"
	"github.com/ajanthan/apache-milagro-dta/utils"
	"github.com/miracl/amcl-go"
	"testing"
)

func TestDTA_Basic(t *testing.T) {
	dta := DTA{}
	conf := config.Config{}
	conf.ParseDTAConfigFile()
	dta.Init(conf)
	clientID := "apacheuser@apache.org"
	hashedClientID := amcl.MPIN_HASH_ID([]byte(clientID))
	var serverSecret []byte
	if rtn, err := dta.IssueServerSecret(); err != nil {
		t.Log(err.Error())
		t.FailNow()
	} else {
		serverSecret = rtn
	}
	var clientSecret []byte

	if rtn, err := dta.IssueClientSecret(hashedClientID); err != nil {
		t.Log(err.Error())
		t.FailNow()
	} else {
		clientSecret = rtn
	}
	var timePermit []byte

	if rtn, err := dta.IssueTimePermit(hashedClientID); err != nil {
		t.Log(err.Error())
		t.FailNow()
	} else {
		timePermit = rtn
	}
	utils.ValidateMpin(serverSecret, clientSecret, timePermit, clientID, 9876)
}
