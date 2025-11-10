package tasks

import (
	"bytes"
	"fmt"
	"os/exec"
)

func RunPowerShellScript(script string) string {
	// Prepare the PowerShell command
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)

	// Capture the output
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	// Execute the command
	err := cmd.Run()
	if err != nil {
		return fmt.Sprintf("Error: %v, Output: %s", err, stderr.String())
	}

	return out.String()
}
