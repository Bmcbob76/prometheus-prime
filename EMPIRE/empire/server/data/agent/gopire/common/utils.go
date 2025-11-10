package common

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os/exec"
	"runtime"
	"strconv"
)

func RunCommand(command string) string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "-Command", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error: %v, Output: %s", err, string(output))
	}
	return string(output)
}

func Atoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func RandomInt(min, max int) int {
	if max <= min {
		return min
	}
	return rand.Intn(max-min) + min
}

func DecodeAndExtract(encodedParam string) ([]string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encodedParam)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 string: %w", err)
	}

	var result map[string]string
	if err := json.Unmarshal(decoded, &result); err != nil {
		return nil, fmt.Errorf("error parsing JSON: %w", err)
	}

	values := make([]string, 0, len(result))
	for _, value := range result {
		values = append(values, value)
	}

	return values, nil
}
