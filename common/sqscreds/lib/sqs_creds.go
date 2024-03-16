package sqscreds

import (
	"encoding/base64"
	"encoding/json"
)

type AwsCreds struct {
	AwsAccessKeyId string `json:"aws-access-key-id"`
	AwsSecretKey   string `json:"aws-secret-key"`
}

func (awsCreds AwsCreds) Base64() (string, error) {
	jsonData, err := json.Marshal(awsCreds)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonData), nil
}

func AwsCredsFromBase64(base64Str string) (AwsCreds, error) {
	var awsCreds AwsCreds

	jsonData, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return awsCreds, err
	}

	err = json.Unmarshal(jsonData, &awsCreds)
	if err != nil {
		return awsCreds, err
	}

	return awsCreds, nil
}
