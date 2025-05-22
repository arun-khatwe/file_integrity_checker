import os
import hashlib
import time

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):  # 64 KB chunks
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Error reading file: {str(e)}"

def format_size(bytes_size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.2f} PB"

def check_file_integrity(directory_path, log_to_file=False, skip_large_files_mb=500):
    if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
        print(f"[ERROR] Directory '{directory_path}' does not exist.")
        return

    print(f"\n🔍 Scanning directory: {directory_path}\n")
    log_entries = []

    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                size_bytes = os.path.getsize(file_path)
                if size_bytes > skip_large_files_mb * 1024 * 1024:
                    print(f"[SKIPPED] {file_path} ({format_size(size_bytes)}) - Too large")
                    continue

                start = time.time()
                hash_result = calculate_sha256(file_path)
                end = time.time()
                duration = end - start

                size_human = format_size(size_bytes)
                log_line = (
                    f"File: {file_path}\n"
                    f"Size: {size_human}\n"
                    f"SHA-256: {hash_result}\n"
                    f"Time Taken: {duration:.2f} sec\n{'-'*50}"
                )

                print(f"\033[92m{log_line}\033[0m")  # Green output
                log_entries.append(log_line)

            except Exception as e:
                print(f"\033[91m[ERROR] Failed to process {file_path}: {e}\033[0m")  # Red output

    if log_to_file:
        try:
            with open("file_integrity_log.txt", "w", encoding="utf-8") as log_file:
                log_file.write("\n".join(log_entries))
            print("\n📄 Log written to file_integrity_log.txt")
        except Exception as e:
            print(f"\033[91m[ERROR] Could not write log: {e}\033[0m")

if __name__ == "__main__":
    directory_to_check = input("📂 Enter directory path to check integrity: ").strip()
    should_log = input("📝 Save results to a log file? (y/n): ").strip().lower() == 'y'
    try:
        check_file_integrity(directory_to_check, log_to_file=should_log)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting...")
    except Exception as err:
        print(f"[FATAL ERROR] {err}")
