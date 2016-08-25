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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/ajanthan/apache-milagro-dta"
	"github.com/ajanthan/apache-milagro-dta/api"
	"github.com/ajanthan/apache-milagro-dta/config"
	"github.com/ajanthan/apache-milagro-dta/signature"
	"github.com/ajanthan/apache-milagro-dta/storage"
	"github.com/apache/incubator-milagro-crypto/go/src/github.com/miracl/amcl-cgo"
	"github.com/gorilla/mux"
	"gopkg.in/tylerb/graceful.v1"
)

var dTA *dta.DTA
var signatureVerifier signature.SignatureVerifier
var appStorage storage.RPAStorage

type ApiServer struct {
	Server *graceful.Server
}

//Initialing all the sub components,configuration and starts the http server to expose the api
func (apiServer *ApiServer) Bootstrap() {
	conf := config.Config{}
	conf.ParseDTAConfigFile()
	dTA = &dta.DTA{}
	signatureVerifier = conf.GetSignatureVerifier()
	appStorage = conf.GetRPAStorage()
	if err := dTA.Init(conf); err != nil {
		log.Fatal(err.Error())
		panic(err)
	}
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/serverSecret", serverSecretHandler).Methods("GET")
	router.HandleFunc("/clientSecret", clientSecretHandler).Methods("GET")
	router.HandleFunc("/timePermit", timePermitHandler).Methods("GET")
	router.HandleFunc("/rpas", getAllRPAsHandler).Methods("GET")
	router.HandleFunc("/rpa/{appid}", getRPAHandler).Methods("GET")
	router.HandleFunc("/rpa", registerRPAHandler).Methods("POST")
	router.HandleFunc("/rpa/{appid}", deleteRPAHandler).Methods("DELETE")

	serverAddress := conf.GetBindAddress() + ":" + strconv.Itoa(conf.GetBindPort())
	apiServer.Server = &graceful.Server{
		Timeout: 10 * time.Second,

		Server: &http.Server{
			Addr:    serverAddress,
			Handler: router,
		},
	}
	log.Println("Starting server on ", (serverAddress))
	apiServer.Server.ListenAndServe()

}

//Gracefully stops the server
func (apiServer *ApiServer) StopServer() {
	log.Println("Shutting down the server..")
	apiServer.Server.Stop(10 * time.Second)
	<-apiServer.Server.StopChan()
	log.Println("Stopped the server")
}

//Retrieves the M-Pin server secret
//	URL structure
//		/serverSecret?app_id=<app_id>&signature=<signature>
//	HTTP Request Method
//		GET
//	Parameters
//		- app_id: <identity of the Application>
//		- signature: <signature>
//			Signature
//				The signature is generated for this message  and base64 url encoded
//				message =<app_id>
//	Returns
//	Calculates the MPIN Server secret which is returned in this JSON object
//       JSON response
//		{
//			"Message" : "OK",
//			"ServerSecret" : "<base64 url encoded serverSecret>"
//		}
//	Status-Codes and Response-Phrases
//		Status-Code          Response-Phrase
//		200                  OK
//		401                  Invalid signature
//		403                  Missing argument [value]
//		403                  Invalid App key
//		500                  M-Pin Server Secret Generation
func serverSecretHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("serving /serverSecret")
	log.Println(r.UserAgent())
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		message := "Missing argument app_id"
		log.Println(message)
		sendError(http.StatusForbidden, api.ServerSecretResponse{Message: message}, w)
	}
	signatureBase64URLEncoded := r.URL.Query().Get("signature")
	if signatureBase64URLEncoded == "" {
		message := "Missing argument signature"
		log.Println(message)
		sendError(http.StatusForbidden, api.ServerSecretResponse{Message: message}, w)
	}
	signature, err := base64.URLEncoding.DecodeString(signatureBase64URLEncoded)
	if err != nil {
		message := "Invalid signature encoding"
		log.Println(message)
		sendError(http.StatusForbidden, api.ServerSecretResponse{Message: message}, w)
	}
	app_key := appStorage.GetRPA(appID).Application_KEY
	if app_key == nil {
		message := "Invalid App key"
		log.Println(message)
		sendError(http.StatusForbidden, api.ServerSecretResponse{Message: message}, w)
	}
	if signatureVerifier.VerifySignature(signature, app_key, appID) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		secret, mpinErr := dTA.IssueServerSecret()
		if mpinErr != nil {
			sendError(http.StatusInternalServerError, api.ServerSecretResponse{Message: mpinErr.Error()}, w)
		}
		serverSecretResponse := api.ServerSecretResponse{Message: "OK", ServerSecret: base64.URLEncoding.EncodeToString(secret)}
		json.NewEncoder(w).Encode(serverSecretResponse)
	} else {
		message := "Signature varification is failed"
		log.Println(message)
		sendError(http.StatusUnauthorized, api.ServerSecretResponse{Message: message}, w)
	}
}

//Retrieves the M-Pin client secret
//	URL structure
//		/clientSecret?app_id=<app_id>&client_id=<M-Pin client ID>&signature=<signature>
//	HTTP Request Method
//		GET
//	Parameters
//		- app_id: <identity of the Application>
//		-client_id: <M-Pin identity for which client secret is requested>
//		- signature: <signature>
//			Signature
//				The signature is generated for this message and base64 url encoded
//				message =<app_id>
//	Returns
//	Calculates the MPIN client secret which is returned in this JSON object
//       JSON response
//		{
//			"Message" : "OK",
//			"ClientSecret" : "<base64 url encoded Client Secret>"
//		}
//	Status-Codes and Response-Phrases
//		Status-Code          Response-Phrase
//		200                  OK
//		401                  Invalid signature
//		403                  Missing argument [value]
//		403                  Invalid App key
//		403                  Invalid signature encoding
//		500                  M-Pin Client Secret Generation
func clientSecretHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("serving /clientSecret ")
	log.Println(r.UserAgent())
	appID := r.URL.Query().Get("app_id")

	if appID == "" {
		message := "Missing argument app_id"
		log.Println(message)
		sendError(http.StatusForbidden, api.ClientSecretResponse{Message: message}, w)
	}

	clientID := r.URL.Query().Get("client_id")

	if clientID == "" {
		message := "Missing argument client_id"
		log.Println(message)
		sendError(http.StatusForbidden, api.ClientSecretResponse{Message: message}, w)
	}
	signatureBase64URLEncoded := r.URL.Query().Get("signature")

	if signatureBase64URLEncoded == "" {
		message := "Missing argument signature"
		log.Println(message)
		sendError(http.StatusForbidden, api.ClientSecretResponse{Message: message}, w)
	}

	signature, err := base64.URLEncoding.DecodeString(signatureBase64URLEncoded)

	if err != nil {
		message := "Invalid signature encoding"
		log.Println(message)
		sendError(http.StatusForbidden, api.ClientSecretResponse{Message: message}, w)
	}

	app_key := appStorage.GetRPA(appID).Application_KEY

	if app_key == nil {
		message := "Invalid App key"
		log.Println(message)
		sendError(http.StatusForbidden, api.ClientSecretResponse{Message: message}, w)
	}

	if signatureVerifier.VerifySignature(signature, app_key, appID) {

		log.Println("Generating client secret for ", clientID)
		hash_client_id := amcl.MPIN_HASH_ID([]byte(clientID))

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		response := api.ClientSecretResponse{}
		secret, mpinError := dTA.IssueClientSecret(hash_client_id)

		if mpinError != nil {
			sendError(http.StatusInternalServerError, api.ClientSecretResponse{Message: mpinError.Error()}, w)
		}

		response.ClientSecret = base64.URLEncoding.EncodeToString(secret)
		response.Message = "OK"
		json.NewEncoder(w).Encode(response)

	} else {
		message := "Signature varification is failed"
		log.Println(message)
		sendError(http.StatusUnauthorized, api.ClientSecretResponse{Message: message}, w)
	}

}

//Retrieves the M-Pin time permit
//	URL structure
//		/clientSecret?app_id=<app_id>&client_id=<M-Pin client ID>&signature=<signature>
//	HTTP Request Method
//		GET
//	Parameters
//		- app_id: <identity of the Application>
//		-client_id: <M-Pin identity for which client secret is requested>
//		- signature: <signature>
//			Signature
//				The signature is generated for this message  and base64 url encoded
//				message =<app_id>
//	Returns
//	Calculates the MPIN time permit which is returned in this JSON object
//       JSON response
//		{
//			"Message" : "OK",
//			"TimePermit" : "<base64 url encoded time permit>"
//		}
//	Status-Codes and Response-Phrases
//		Status-Code          Response-Phrase
//		200                  OK
//		401                  Invalid signature
//		403                  Missing argument [value]
//		403                  Invalid App key
//		403                  Invalid signature encoding
//		500                  M-Pin Client Secret Generation
func timePermitHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("serving /timePermit")
	log.Println(r.UserAgent())

	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		message := "Missing argument app_id"
		log.Println(message)
		sendError(http.StatusForbidden, api.TimePermitResponse{Message: message}, w)
	}
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		message := "Missing argument client_id"
		log.Println(message)
		sendError(http.StatusForbidden, api.TimePermitResponse{Message: message}, w)
	}

	signatureBase64URLEncoded := r.URL.Query().Get("signature")

	signature, _ := base64.URLEncoding.DecodeString(signatureBase64URLEncoded)

	if signatureBase64URLEncoded == "" {
		message := "Missing argument signature"
		log.Println(message)
		sendError(http.StatusForbidden, api.TimePermitResponse{Message: message}, w)
	}
	app_key := appStorage.GetRPA(appID).Application_KEY

	if app_key == nil {
		message := "Invalid App key"
		log.Println(message)
		sendError(http.StatusForbidden, api.TimePermitResponse{Message: message}, w)
	}

	if signatureVerifier.VerifySignature(signature, app_key, appID) {
		log.Println("Generating client time permit for ", clientID)
		hash_client_id := amcl.MPIN_HASH_ID([]byte(clientID))

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		response := api.TimePermitResponse{}
		permit, mpinError := dTA.IssueTimePermit(hash_client_id)

		if mpinError != nil {
			sendError(http.StatusInternalServerError, api.TimePermitResponse{Message: mpinError.Error()}, w)
		}

		response.TimePermit = base64.URLEncoding.EncodeToString(permit)
		response.Message = "OK"
		json.NewEncoder(w).Encode(response)
	} else {
		message := "Signature varification is failed"
		log.Println(message)
		sendError(http.StatusUnauthorized, api.TimePermitResponse{Message: message}, w)
	}

}

func getAllRPAsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("serving get /rpas")
	log.Println(r.UserAgent())

	w.Header().Set("Content-Type", "application/json")
	fmt.Println("App list ", appStorage.GetAllRPAs())
	var apps []api.RelyingPartyApplicationResponse
	for _, app := range appStorage.GetAllRPAs() {
		apps = append(apps, api.RelyingPartyApplicationResponse{Application_ID: app.Application_ID})
	}
	json.NewEncoder(w).Encode(apps)

}

func getRPAHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("serving get /rpa")
	log.Println(r.UserAgent())
	vars := mux.Vars(r)
	appID := vars["appid"]

	w.Header().Set("Content-Type", "application/json")
	appKey := appStorage.GetRPA(appID).Application_KEY
	appKeyEncoded := base64.URLEncoding.EncodeToString(appKey)
	app := api.RelyingPartyApplicationResponse{Application_ID: appID, Application_KEY: appKeyEncoded}
	json.NewEncoder(w).Encode(app)

}
func registerRPAHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("serving post /rpa")
	log.Println(r.UserAgent())

	var rpApp storage.RelyingPartyApplication
	err := json.NewDecoder(r.Body).Decode(&rpApp)
	if err != nil {
		log.Println("Error while decoding input", err.Error())
	}

	appStorage.RegisterRPA(rpApp)
	w.Header().Set("Content-Type", "application/json")

}

func deleteRPAHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("serving delete /rpa")
	log.Println(r.UserAgent())
	vars := mux.Vars(r)
	appID := vars["appid"]

	appStorage.DeleteRPA(appID)
	w.WriteHeader(http.StatusOK)

}

//Sets error code and error message as a JSON
func sendError(errorCode int, errorMessage interface{}, w http.ResponseWriter) {
	w.WriteHeader(errorCode)
	json.NewEncoder(w).Encode(errorMessage)
}
