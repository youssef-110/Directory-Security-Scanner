#include <iostream>     // For console input and output
#include <windows.h>    // The core Windows API library for file and system functions
#include <string>       // For easier string manipulation
#include <vector>       // For potential future lists of files

using namespace std;    // Avoids typing std:: before every standard command

// This class represents a single file and its security properties
class SecureFile {
private:
    string filePath;    // The full disk path (e.g., C:\Games\game.exe)
    string fileName;    // Just the name (e.g., game.exe)
    long long fileSize; // Size in bytes, supports files larger than 4GB
    bool isHidden;      // Status of the 'Hidden' attribute
    bool isExecutable;  // Whether the file is a runnable program

public:
    // Constructor: Takes path and name, then runs the analysis logic
    SecureFile(string path, string name) {
        filePath = path;
        fileName = name;
        analyzeFile(); // Auto-start analysis upon object creation
    }

    // Connects to the Windows Kernel to pull real metadata
    void analyzeFile() {
        // GetFileAttributesA checks the Windows filesystem for file flags
        DWORD attributes = GetFileAttributesA(filePath.c_str());

        // If attributes can't be read (file locked or path wrong), mark as invalid
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            fileSize = -1;
            return;
        }

        // Bitwise AND: Checks if the specific 'Hidden' bit is set to 1
        isHidden = (attributes & FILE_ATTRIBUTE_HIDDEN);
        
        // Checks if ".exe" or ".EXE" exists anywhere in the filename string
        isExecutable = (fileName.find(".exe") != string::npos || fileName.find(".EXE") != string::npos);

        // Struct to hold advanced file info like size and creation time
        WIN32_FILE_ATTRIBUTE_DATA fileData;
        
        // GetFileAttributesExA gathers the actual size of the file
        if (GetFileAttributesExA(filePath.c_str(), GetFileExInfoStandard, &fileData)) {
            // Combines two 32-bit values into one 64-bit value to get the correct size
            fileSize = (static_cast<long long>(fileData.nFileSizeHigh) << 32) | fileData.nFileSizeLow;
        }
    }

    // Prints the findings for this specific file
    void displaySecurityReport() {
        if (fileSize == -1) return; // Skip files that couldn't be read

        cout << "[FILE] " << fileName << endl;
        cout << "  - Size:       " << (fileSize / 1024) << " KB" << endl;
        cout << "  - Executable: " << (isExecutable ? "YES" : "no") << endl;
        
        if (isHidden) {
            cout << "  - [!] WARNING: This file is HIDDEN." << endl;
        }
        // Heuristic check: Malware often hides itself while remaining an EXE
        if (isHidden && isExecutable) {
            cout << "  - [!!!] ALERT: HIDDEN EXECUTABLE DETECTED (Security Risk)" << endl;
        }
        cout << "------------------------------------------" << endl;
    }
};

void scanFolder(string folderPath) {
    // We add "\\*" so the API knows to search for "everything" inside the path
    string searchPath = folderPath + "\\*";
    WIN32_FIND_DATAA findData; // Struct that stores info about the found file
    
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        cout << "Error: Could not open directory. Check your path!" << endl;
        return;
    }

    cout << "\nScanning Directory: " << folderPath << "\n" << endl;

    do {
        string name = findData.cFileName;

        if (name != "." && name != "..") {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                string fullPath = folderPath + "\\" + name;
                
                SecureFile file(fullPath, name);
                file.displaySecurityReport();
            }
        }
    } while (FindNextFileA(hFind, &findData)); // Move to the next file in the list

    FindClose(hFind); // Close the search handle to free up system memory
}

int main() {
    string path;
    cout << "Enter the FOLDER path to scan (e.g. D:\\Games\\MyLibrary): ";
    getline(cin, path); // Reads the whole line, allowing for spaces in folder names

    scanFolder(path); // Start the recursive folder scan

    cout << "\nScan Complete." << endl;
    system("pause"); // Keeps the CMD window open so you can read the results
    return 0;
}