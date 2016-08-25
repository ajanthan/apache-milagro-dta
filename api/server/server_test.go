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

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/ajanthan/apache-milagro-dta/api"
	"github.com/ajanthan/apache-milagro-dta/storage"
	"github.com/ajanthan/apache-milagro-dta/utils"
	"github.com/ajanthan/milagro/dta/signature"
	"net/http"
	"testing"
	"time"
)

//Testing end to end flow
func TestServerAPI_Complete(t *testing.T) {

	apiServer := ApiServer{}
	go func() {
		apiServer.Bootstrap()
	}()

	time.Sleep(10 * time.Second)

	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}
	//Step 1: Register an application

	appID := "appid0001"
	clientID := "test@apache.milagro.org"

	app := storage.RelyingPartyApplication{Application_ID: appID}
	buffer := new(bytes.Buffer)
	if err := json.NewEncoder(buffer).Encode(&app); err != nil {
		t.Error("Error encoding app ", err.Error())
		t.FailNow()
	}

	if response, err := httpClient.Post("http://0.0.0.0:8088/rpa", "application/json", buffer); err != nil {
		t.Error("Error in registering the app ", err.Error())
		t.FailNow()
	} else {

		if response.StatusCode != 200 {
			t.Error("Registering the app is failed")
			t.FailNow()
		}
	}

	//Step 2: Getting application key

	registeredApp := api.RelyingPartyApplicationResponse{}
	if response, err := httpClient.Get("http://0.0.0.0:8088/rpa/" + appID); err != nil {
		t.Error("Error in getting the app ", err.Error())
		t.FailNow()
	} else {
		if response.StatusCode != 200 {
			t.Error("Getting  the app is failed")
			t.FailNow()
		}
		if err := json.NewDecoder(response.Body).Decode(&registeredApp); err != nil {
			t.Error("Error in decosing app ", err.Error())
			t.FailNow()
		}

	}

	appKey, _ := base64.URLEncoding.DecodeString(registeredApp.Application_KEY)
	signature := signature.CreateSignature(appKey, appID)
	encodedSignature := base64.URLEncoding.EncodeToString(signature)

	//Step 3: Getting Server key
	serverSecretResponse := api.ServerSecretResponse{}
	if response, err := httpClient.Get(fmt.Sprintf("http://0.0.0.0:8088/serverSecret?app_id=%s&signature=%s", appID, encodedSignature)); err != nil {
		t.Error("Error in getting M-Pin server secret ", err.Error())
		t.FailNow()
	} else {

		if response.StatusCode != 200 {
			t.Error("Getting M-Pin server secret is failed")
			t.FailNow()
		}

		if err := json.NewDecoder(response.Body).Decode(&serverSecretResponse); err != nil {
			t.Error("Error in decoding server secret response ", err.Error())
			t.FailNow()
		}

	}

	//Step 4: Getting Client key

	clientSecretResponse := api.ClientSecretResponse{}

	if response, err := httpClient.Get(fmt.Sprintf("http://0.0.0.0:8088/clientSecret?app_id=%s&client_id=%s&signature=%s", appID, clientID, encodedSignature)); err != nil {
		t.Error("Error in getting M-Pin client  secret ", err.Error())
		t.FailNow()
	} else {

		if response.StatusCode != 200 {
			t.Error("Getting M-Pin client secret is failed")
			t.FailNow()
		}

		if err := json.NewDecoder(response.Body).Decode(&clientSecretResponse); err != nil {
			t.Error("Error in decoding the client secret response ", err.Error())
			t.FailNow()
		}

	}

	//Step 5: Getting TimePermit
	timePermitResponse := api.TimePermitResponse{}
	if response, err := httpClient.Get(fmt.Sprintf("http://0.0.0.0:8088/timePermit?app_id=%s&client_id=%s&signature=%s", appID, clientID, encodedSignature)); err != nil {
		t.Error("Error in getting M-Pin time permit ", err.Error())
		t.FailNow()
	} else {

		if response.StatusCode != 200 {
			t.Error("Getting M-Pin time permit is failed")
			t.FailNow()
		}

		if err := json.NewDecoder(response.Body).Decode(&timePermitResponse); err != nil {
			t.Error("Error in decoding the time permit response", err.Error())
			t.FailNow()
		}

	}
	//Step 6: Do authentication

	ss, serverSecretError := base64.URLEncoding.DecodeString(serverSecretResponse.ServerSecret)
	if serverSecretError != nil {
		t.Error("Error in decoding server secret ", serverSecretError.Error())
		t.FailNow()
	}
	cs, clientSecretError := base64.URLEncoding.DecodeString(clientSecretResponse.ClientSecret)
	if clientSecretError != nil {
		t.Error("Error in decoding client secret ", clientSecretError.Error())
		t.FailNow()
	}
	tp, timePermitError := base64.URLEncoding.DecodeString(timePermitResponse.TimePermit)

	if timePermitError != nil {
		t.Error("Error in decoding time permit  ", timePermitError.Error())
		t.FailNow()
	}

	utils.ValidateMpin(ss, cs, tp, clientID, 4973)

	apiServer.StopServer()

}
