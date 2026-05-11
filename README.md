# Secure File Scanner (C++ Windows Tool)

A Windows-based file analysis tool written in C++ that scans directories and performs basic security checks on files. It detects hidden files, executable files, and flags potentially suspicious combinations such as hidden executables.

---

# Overview

This project demonstrates low-level Windows filesystem interaction using the WinAPI. It recursively scans a user-defined folder and analyzes each file’s metadata to identify potential security risks.

It is designed as an educational cybersecurity tool to demonstrate:
- File system enumeration
- Windows API usage
- Basic malware heuristics
- Bitwise attribute analysis
- Object-oriented system design

---

# Features

- Scans any user-provided directory
- Detects hidden files
- Identifies executable files (.exe)
- Calculates file size in KB
- Flags suspicious file behavior (hidden + executable)
- Uses native Windows API for performance and accuracy

---

# Tech Stack

- C++
- Windows API
- Win32 File System Functions
- iostream / string / vector

---

# How It Works

1. User enters a folder path
2. Program scans all files in the directory
3. For each file:
   - Retrieves file attributes
   - Checks if file is hidden
   - Checks if file is executable
   - Retrieves file size
4. Prints a security report per file
5. Flags suspicious patterns

---

# Code Structure

## SecureFile Class

Each file is represented as an object:

```cpp
class SecureFile {
private:
    string filePath;
    string fileName;
    long long fileSize;
    bool isHidden;
    bool isExecutable;

public:
    SecureFile(string path, string name);
    void analyzeFile();
    void displaySecurityReport();
};
```

---

## File Analysis Logic

This function extracts file metadata using Windows API:

```cpp
void analyzeFile() {
    DWORD attributes = GetFileAttributesA(filePath.c_str());

    if (attributes == INVALID_FILE_ATTRIBUTES) {
        fileSize = -1;
        return;
    }

    isHidden = (attributes & FILE_ATTRIBUTE_HIDDEN);

    isExecutable = (fileName.find(".exe") != string::npos);

    WIN32_FILE_ATTRIBUTE_DATA fileData;

    if (GetFileAttributesExA(filePath.c_str(), GetFileExInfoStandard, &fileData)) {
        fileSize = (static_cast<long long>(fileData.nFileSizeHigh) << 32)
                   | fileData.nFileSizeLow;
    }
}
```

---

## Security Report Output

Each file is analyzed and displayed:

```cpp
void displaySecurityReport() {
    if (fileSize == -1) return;

    cout << "[FILE] " << fileName << endl;
    cout << "  - Size:       " << (fileSize / 1024) << " KB" << endl;
    cout << "  - Executable: " << (isExecutable ? "YES" : "no") << endl;

    if (isHidden) {
        cout << "  - WARNING: Hidden file detected." << endl;
    }

    if (isHidden && isExecutable) {
        cout << "  - ALERT: Hidden executable detected (suspicious)" << endl;
    }

    cout << "------------------------------------------" << endl;
}
```

---

## Directory Scanner

This function walks through all files in a folder:

```cpp
void scanFolder(string folderPath) {
    string searchPath = folderPath + "\\*";
    WIN32_FIND_DATAA findData;

    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        cout << "Error: Could not open directory!" << endl;
        return;
    }

    do {
        string name = findData.cFileName;

        if (name != "." && name != "..") {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                string fullPath = folderPath + "\\" + name;

                SecureFile file(fullPath, name);
                file.displaySecurityReport();
            }
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}
```

---

## Main Function

```cpp
int main() {
    string path;

    cout << "Enter folder path: ";
    getline(cin, path);

    scanFolder(path);

    cout << "\nScan Complete." << endl;
    system("pause");

    return 0;
}
```

---

# Example Output

```text
[FILE] game.exe
  - Size:       2048 KB
  - Executable: YES
  - ALERT: Hidden executable detected (suspicious)
------------------------------------------
```

---

# Security Concepts Demonstrated

- File attribute analysis
- Malware heuristics (hidden + executable detection)
- Directory traversal
- WinAPI system interaction
- Basic static file inspection

---

# Requirements

- Windows OS (WinAPI dependency)
- C++ compiler (MSVC / MinGW)

---

# Compilation

## Using g++

```bash
g++ main.cpp -o secure_scanner
```

## Run

```bash
secure_scanner.exe
```

---

# Future Improvements

- Recursive subfolder scanning
- Hash-based malware detection (SHA-256)
- Real-time file monitoring (File System Watcher)
- Quarantine system for suspicious files
- GUI dashboard for visual analysis
- Machine learning-based anomaly detection

---

# Disclaimer

This tool is for educational purposes only and does not replace real antivirus software.
