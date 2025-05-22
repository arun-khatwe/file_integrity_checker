# file_integrity_checker
A python script recursively scans a given directory and computes the SHA-256 hash of each file to verify its integrity.
Detecting unauthorized file modifications
Creating a baseline for file integrity monitoring
Spot-checking malware-injected or corrupted files
Skipping overly large files for performance control
Optional logging of scan results to a human-readable .txt file

Features:

  SHA-256 hashing for cryptographic-level integrity check
  Formatted file sizes (B, KB, MB, etc.) for readability
  Large file skip support (default > 500MB)
  Time-tracked hashing for performance visibility
  Optional log file output (file_integrity_log.txt)
  Try/Except error handling for real-world robustness
  Colored terminal output (green = success, red = error, gray = skipped)

Example OutPut:
File: /your/folder/file.txt
Size: 12.45 KB
SHA-256: 65abcf3...
Time Taken: 0.02 sec
--------------------------------------------------
