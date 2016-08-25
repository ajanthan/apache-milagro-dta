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

package utils

import (
	"encoding/hex"
	"fmt"
	"github.com/miracl/amcl-go"
)

//Util method to validate the generated server secret,client secret ,time permit according to M-Pin protocol
func ValidateMpin(serverSecret []byte, clientSecret []byte, timePermit []byte, clientID string, pin int) {

	// Assign the End-User an ID
	IDstr := clientID
	ID := []byte(IDstr)
	fmt.Printf("ID: ")
	amcl.MPIN_printBinary(ID)
	fmt.Printf("\n")

	// Epoch time in days
	date := amcl.MPIN_today()

	// PIN variable to create token
	PIN1 := pin
	// PIN variable to authenticate
	PIN2 := pin

	// Seed value for Random Number Generator (RNG)
	seedHex := "9e8b4178790cd57a5761c4a6f164ba72"
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		fmt.Println("Error decoding seed value")
		return
	}
	rng := amcl.NewRAND()
	rng.Seed(len(seed), seed)

	const EGS = amcl.MPIN_EGS
	const EFS = amcl.MPIN_EFS
	const G1S = 2*EFS + 1 /* Group 1 Size */
	const G2S = 4 * EFS   /* Group 2 Size */

	//
	var SS [G2S]byte
	var TP [G1S]byte
	var TOKEN [G1S]byte

	//
	var SEC [G1S]byte
	var U [G1S]byte
	var UT [G1S]byte
	var X [EGS]byte
	var Y [EGS]byte
	var E [12 * EFS]byte
	var F [12 * EFS]byte
	var HID [G1S]byte
	var HTID [G1S]byte

	//
	copy(SS[:], serverSecret)
	copy(TOKEN[:], clientSecret)
	copy(TP[:], timePermit)
	//

	// Generate server secret share 1
	/*amcl.MPIN_GET_SERVER_SECRET(MS[:], SS[:])*/
	fmt.Printf("SS: 0x")
	amcl.MPIN_printBinary(SS[:])

	// Generate client secret share 1
	/*amcl.MPIN_GET_CLIENT_SECRET(MS[:], HCID, TOKEN[:])*/
	fmt.Printf("Client Secret CS: 0x")
	amcl.MPIN_printBinary(TOKEN[:])

	// Generate time permit share 1
	/*amcl.MPIN_GET_CLIENT_PERMIT(date, MS[:], HCID, TP[:])*/
	fmt.Printf("TP1: 0x")
	amcl.MPIN_printBinary(TP[:])

	// Client extracts PIN1 from secret to create Token
	for PIN1 < 0 {
		fmt.Printf("Please enter PIN to create token: ")
		fmt.Scan(&PIN1)
	}

	rtn := amcl.MPIN_EXTRACT_PIN(ID, PIN1, TOKEN[:])
	if rtn != 0 {
		fmt.Printf("FAILURE: EXTRACT_PIN rtn: %d\n", rtn)
		return
	}
	fmt.Printf("Client Token TK: 0x")
	amcl.MPIN_printBinary(TOKEN[:])

	for PIN2 < 0 {
		fmt.Printf("Please enter PIN to authenticate: ")
		fmt.Scan(&PIN2)
	}

	/* Clients first pass. Calculate U and UT */
	rtn = amcl.MPIN_CLIENT_1(date, ID, rng, X[:], PIN2, TOKEN[:], SEC[:], U[:], UT[:], TP[:])
	if rtn != 0 {
		fmt.Printf("FAILURE: CLIENT rtn: %d\n", rtn)
		return
	}

	/* Server first pass. Calculate H(ID) and H(T|H(ID)) (if time permits enabled), and maps them to points on the curve HID and HTID resp. */
	amcl.MPIN_SERVER_1(date, ID, HID[:], HTID[:])

	/* Server generates Random number Y and sends it to Client */
	amcl.MPIN_RANDOM_GENERATE(rng, Y[:])

	/* Client Second Pass: Inputs Client secret SEC, x and y. Outputs -(x+y)*SEC */
	rtn = amcl.MPIN_CLIENT_2(X[:], Y[:], SEC[:])
	if rtn != 0 {
		fmt.Printf("FAILURE: CLIENT_2 rtn: %d\n", rtn)
	}

	/* Server Second pass. Inputs hashed client id, random Y, -(x+y)*SEC, xID and xCID and Server secret SST. E and F help kangaroos to find error. */
	/* If PIN error not required, set E and F = null */
	rtn = amcl.MPIN_SERVER_2(date, HID[:], HTID[:], Y[:], SS[:], U[:], UT[:], SEC[:], E[:], F[:])
	if rtn != 0 {
		fmt.Printf("FAILURE: MPIN_SERVER_2 rtn: %d\n", rtn)
	}
	fmt.Printf("HID: 0x")
	amcl.MPIN_printBinary(HID[:])
	fmt.Printf("HTID: 0x")
	amcl.MPIN_printBinary(HTID[:])

	if rtn == amcl.MPIN_BAD_PIN {
		fmt.Printf("Authentication failed Error Code %d\n", rtn)
		err := amcl.MPIN_KANGAROO(E[:], F[:])
		if err != 0 {
			fmt.Printf("PIN Error %d\n", err)
		}
		return
	} else {
		fmt.Printf("Authenticated ID: %s \n", IDstr)
	}
}
