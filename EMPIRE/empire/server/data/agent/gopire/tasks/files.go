package tasks

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func FileUpload(data string) (string, error) {
	parts := strings.Split(data, "|")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid data format for file upload")
	}

	filePath := parts[0]
	base64Part := parts[1]

	dir := filepath.Dir(filePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, 0755) // Create the directory if it doesn't exist
		if err != nil {
			return "", fmt.Errorf("failed to create directory: %v", err)
		}
	}

	fileInfo, err := os.Stat(filePath)
	if err == nil && fileInfo.IsDir() {
		return "", fmt.Errorf("the provided path is a directory, not a file: %s", filePath)
	}

	rawData, err := base64.StdEncoding.DecodeString(base64Part)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 content: %v", err)
	}

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	if _, err := file.Write(rawData); err != nil {
		return "", fmt.Errorf("failed to write data to file: %v", err)
	}

	return fmt.Sprintf("Upload of %s successful", filePath), nil
}

func GetFileList(filePath string) ([]string, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil || !fileExists(absPath) {
		return nil, err
	}

	var fileList []string
	if !isDir(absPath) {
		fileList = append(fileList, absPath)
	} else {
		err := filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				fileList = append(fileList, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return fileList, nil
}

func GetFileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func GetFilePart(filePath string, offset int, chunkSize int) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not open file: %w", err)
	}
	defer file.Close()

	_, err = file.Seek(int64(offset), io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("could not seek to offset: %w", err)
	}

	buffer := make([]byte, chunkSize)
	bytesRead, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("could not read file: %w", err)
	}

	return buffer[:bytesRead], nil
}

// CompressData compresses data using zlib and calculates CRC32 checksum.
func CompressData(data []byte) ([]byte, error) {
	crc := crc32.ChecksumIEEE(data)

	var compressedBuffer bytes.Buffer
	writer, err := zlib.NewWriterLevel(&compressedBuffer, zlib.BestCompression) // Compression level 9
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib writer: %w", err)
	}
	_, err = writer.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to compress data: %w", err)
	}
	writer.Close()

	crcHeader := make([]byte, 4)
	binary.BigEndian.PutUint32(crcHeader, crc)
	builtData := append(crcHeader, compressedBuffer.Bytes()...)

	return builtData, nil
}
