package main

import (
	"fmt"

	sqscreds "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/sqscreds/lib"
)

// This script can be run to generate the encoded SQS credentials to pass as a CLI param or SOCKS option to the client
func main() {
	var accessKey, secretKey string

	fmt.Print("Enter Access Key: ")
	_, err := fmt.Scanln(&accessKey)
	if err != nil {
		fmt.Println("Error reading access key:", err)
		return
	}

	fmt.Print("Enter Secret Key: ")
	_, err = fmt.Scanln(&secretKey)
	if err != nil {
		fmt.Println("Error reading access key:", err)
		return
	}

	awsCreds := sqscreds.AwsCreds{AwsAccessKeyId: accessKey, AwsSecretKey: secretKey}
	println()
	println("Encoded Credentials:")
	res, err := awsCreds.Base64()
	if err != nil {
		fmt.Println("Error encoding credentials:", err)
		return
	}
	println(res)
}
