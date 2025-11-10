package tasks

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type DirectoryItem struct {
	Path   string `json:"path"`
	Name   string `json:"name"`
	IsFile bool   `json:"is_file"`
}

type DirectoryResult struct {
	DirectoryPath string          `json:"directory_path"`
	DirectoryName string          `json:"directory_name"`
	Items         []DirectoryItem `json:"items"`
}

// DirectoryList lists the contents of a directory or all drives if no specific path is provided (Windows).
func DirectoryList(path string) (DirectoryResult, error) {
	// Detect if the platform is Windows and the path is empty or root
	if runtime.GOOS == "windows" && (path == "" || path == "/") {
		// Return all available drives on Windows
		return listAllDrives()
	}

	// Clean and adjust the path
	path = filepath.Clean(path)

	// Check if it's a root directory and assign the drive letter explicitly
	var dirName string
	if runtime.GOOS == "windows" && len(path) == 3 && path[1] == ':' && path[2] == '\\' {
		dirName = path // Example: "C:\"
	} else {
		dirName = filepath.Base(path)
	}

	// Check if the directory exists and is a directory
	stat, err := os.Stat(path)
	if os.IsNotExist(err) || !stat.IsDir() {
		return DirectoryResult{}, fmt.Errorf("Directory %s not found", path)
	}

	// Scan the directory
	var items []DirectoryItem
	dir, err := os.Open(path)
	if err != nil {
		return DirectoryResult{}, fmt.Errorf("Failed to open directory %s: %v", path, err)
	}
	defer dir.Close()

	entries, err := dir.Readdir(-1)
	if err != nil {
		return DirectoryResult{}, fmt.Errorf("Failed to read directory %s: %v", path, err)
	}

	for _, entry := range entries {
		item := DirectoryItem{
			Path:   filepath.Join(path, entry.Name()),
			Name:   entry.Name(),
			IsFile: !entry.IsDir(),
		}
		items = append(items, item)
	}

	// Prepare the result
	result := DirectoryResult{
		DirectoryPath: path,
		DirectoryName: dirName,
		Items:         items,
	}

	return result, nil
}

// listAllDrives returns a DirectoryResult containing all available drives on Windows
func listAllDrives() (DirectoryResult, error) {
	// Use syscall to find all the available drives on Windows
	drives := []DirectoryItem{}
	for i := 'A'; i <= 'Z'; i++ {
		drive := fmt.Sprintf("%c:\\", i)
		_, err := os.Stat(drive)
		if !os.IsNotExist(err) {
			drives = append(drives, DirectoryItem{
				Path:   drive,
				Name:   drive,
				IsFile: false,
			})
		}
	}

	if len(drives) == 0 {
		return DirectoryResult{}, fmt.Errorf("No drives found")
	}

	result := DirectoryResult{
		DirectoryPath: "/",
		DirectoryName: "Drives",
		Items:         drives,
	}

	return result, nil
}
