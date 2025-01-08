import zipfile
import os
import sys
import io
import json
import argparse


class ZipAnalyzer:
    # Definition of signatures for detecting ZIP file structures
    ZIP_SIGNATURES = {
        "local_file": b'\x50\x4b\x03\x04',  # Local file header
        "eocd": b'\x50\x4b\x05\x06',       # End-of-Central-Directory (EOCD)
        "central_dir": b'\x50\x4b\x01\x02' # Central directory header
    }

    def __init__(self, file_path):
        self.file_path = file_path

    def _read_file(self):
        # Reads the file as binary data
        with open(self.file_path, 'rb') as f:
            return f.read()

    def find_zip_archives(self):
        """
        Searches for all ZIP archives within the file using the signatures.
        """
        data = self._read_file()
        offsets = []  # List to store found offsets
        offset = 0

        while offset < len(data):
            # Search for local file header
            offset = data.find(self.ZIP_SIGNATURES["local_file"], offset)
            if offset == -1:
                break

            # Check if a valid EOCD signature is present
            if self._has_valid_eocd(data, offset):
                # Check if a central directory is present
                if self._has_valid_central_directory(data, offset):
                    # Validate the ZIP structure
                    eocd_offset = data.find(self.ZIP_SIGNATURES["eocd"], offset)
                    if eocd_offset != -1 and self.validate_zip_structure(data, offset, eocd_offset):
                        offsets.append(offset)
            offset += 4  # Continue searching from the next position

        return offsets

    def _has_valid_eocd(self, data, offset):
        """
        Checks if the EOCD signature exists and is valid.
        """
        eocd_offset = data.find(self.ZIP_SIGNATURES["eocd"], offset)
        return eocd_offset != -1

    def _has_valid_central_directory(self, data, offset):
        """
        Checks if the central directory exists.
        """
        central_dir_offset = data.find(self.ZIP_SIGNATURES["central_dir"], offset)
        return central_dir_offset != -1

    def validate_zip_structure(self, data, offset, eocd_offset):
        """
        Validates the ZIP structure between the given offset and the EOCD offset.
        """
        try:
            # Extract potential ZIP data between offset and EOCD
            potential_zip_data = data[offset:eocd_offset + 22]  # EOCD has a length of 22 bytes
            # Test the ZIP structure using the zipfile library
            with zipfile.ZipFile(io.BytesIO(potential_zip_data), 'r') as zip_ref:
                return zip_ref.testzip() is None  # Returns True if no errors are found
        except (zipfile.BadZipFile, ValueError):
            return False

    def extract_zip_info(self, offsets):
        """
        Extracts detailed information from all found ZIP archives.
        """
        archive_infos = []
        data = self._read_file()

        for offset in offsets:
            # Process each found ZIP archive
            archive_info = self._process_zip_archive(data, offset)
            archive_infos.append(archive_info)

        return {
            "file_path": self.file_path,
            "archives": archive_infos
        }

    def _process_zip_archive(self, data, offset):
        """
        Processes a single ZIP archive and extracts information.
        """
        try:
            eocd_offset = data.find(self.ZIP_SIGNATURES["eocd"], offset)
            if eocd_offset == -1:
                raise zipfile.BadZipFile("EOCD not found")

            # Extract potential ZIP data
            potential_zip_data = data[offset:eocd_offset + 22]  # EOCD has a length of 22 bytes
            with zipfile.ZipFile(io.BytesIO(potential_zip_data), 'r') as zip_ref:
                # Extract EOCD information
                eocd_info = self._extract_eocd(data, offset)
                # Extract central directory information
                central_dir_info = self._extract_central_directory(zip_ref)
                # Archive comment (if available)
                archive_comment = zip_ref.comment.decode('utf-8') if zip_ref.comment else ""

                return {
                    "offset": offset,
                    "status": "valid",
                    "eocd_info": eocd_info,
                    "central_directory": central_dir_info,
                    "archive_comment": archive_comment,
                    "warnings": self._detect_issues(zip_ref)
                }
        except zipfile.BadZipFile:
            return {"offset": offset, "status": "invalid", "warnings": ["Invalid ZIP archive"]}
        except ValueError as ve:
            return {"offset": offset, "status": "error", "warnings": [f"ValueError: {ve}"]}
        except Exception as e:
            return {"offset": offset, "status": "error", "warnings": [str(e)]}

    def _extract_eocd(self, data, offset):
        """
        Extracts information from the End-of-Central-Directory (EOCD) entry.
        """
        eocd_offset = data.find(self.ZIP_SIGNATURES["eocd"], offset)
        if eocd_offset == -1:
            return {"status": "invalid", "reason": "EOCD not found"}

        # EOCD has a fixed length of 22 bytes
        eocd_data = data[eocd_offset:eocd_offset + 22]
        size_of_cd = int.from_bytes(eocd_data[12:16], 'little')
        offset_of_cd = int.from_bytes(eocd_data[16:20], 'little')
        total_entries = int.from_bytes(eocd_data[10:12], 'little')

        return {
            "eocd_offset": eocd_offset,
            "size_of_central_directory": size_of_cd,
            "offset_of_central_directory": offset_of_cd,
            "total_entries": total_entries
        }

    def _extract_central_directory(self, zip_ref):
        """
        Extracts information about files in the central directory.
        """
        central_dir_info = []
        for info in zip_ref.infolist():
            central_dir_info.append({
                "filename": info.filename,
                "compressed_size": info.compress_size,
                "original_size": info.file_size,
                "modified": f"{info.date_time[0]:04d}-{info.date_time[1]:02d}-{info.date_time[2]:02d} "
                            f"{info.date_time[3]:02d}:{info.date_time[4]:02d}:{info.date_time[5]:02d}",
                "compression_method": info.compress_type,
                "crc": info.CRC,
                "encrypted": bool(info.flag_bits & 0x1),
                "external_attributes": info.external_attr,
                "platform": "Unix" if (info.external_attr >> 16) & 0xFFFF == 0o100600 else "Windows"
            })
        return central_dir_info

    def _detect_issues(self, zip_ref):
        """
        Detects potential issues in a ZIP archive.
        """
        warnings = []

        for info in zip_ref.infolist():
            # Warning for potential ZIP bombs
            if info.file_size > 0 and info.compress_size / info.file_size < 0.001:
                warnings.append(f"Potential zip bomb detected: {info.filename}")
            # Warning for path traversal
            if ".." in info.filename or info.filename.startswith('/'):
                warnings.append(f"Path traversal detected: {info.filename}")
            # Warning for hidden large files
            if info.file_size > 1e9:
                warnings.append(f"Hidden large file detected: {info.filename}")

        try:
            corrupt_file = zip_ref.testzip()
            if corrupt_file:
                warnings.append(f"Corrupt file detected during ZIP integrity check: {corrupt_file}")
        except (zipfile.BadZipFile, ValueError):
            warnings.append("ZIP integrity check could not be completed.")

        return warnings

def main():
    parser = argparse.ArgumentParser(description="Analyze files for embedded ZIP archives.")
    parser.add_argument("file_path", help="Path to the file to be analyzed.")
    args = parser.parse_args()

    file_path = args.file_path

    # Check if the file exists
    if not os.path.exists(file_path):
        print("File does not exist.")
        return

    analyzer = ZipAnalyzer(file_path)

    print("Scanning for ZIP archives...")
    offsets = analyzer.find_zip_archives()

    if not offsets:
        print("No ZIP archives found in the file.")
        return

    print(f"Found {len(offsets)} ZIP archive(s) at offsets: {offsets}")

    print("Extracting information from ZIP archives...")
    archive_json = analyzer.extract_zip_info(offsets)

    # Output the information in JSON format
    print(json.dumps(archive_json, indent=4))

if __name__ == "__main__":
    main()
