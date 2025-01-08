# Zip Analyzer

## Overview
Zip Analyzer is a Python-based tool designed to detect and analyze concatenated ZIP archives within files. Concatenated ZIP archives are multiple ZIP files combined into a single file, which can pose challenges during processing. Standard decompression tools may only recognize and extract the first archive, potentially overlooking subsequent ones. Depending on the program used, either the first or the last archive within the concatenated file may be processed. For instance, 7zip usually processes the first archive, while Python's `zipfile` library and the `unzip` tool on Linux typically process the last archive. This limitation can lead to security risks, as malicious actors might hide harmful content in the additional archives.

Zip Analyzer addresses this issue by scanning files for multiple embedded ZIP structures, ensuring comprehensive detection and analysis of all concatenated archives. By identifying each embedded archive, the tool helps mitigate the risks associated with overlooked malicious content.

## Features
- Detects concatenated ZIP archives within files using signature analysis.
- Validates ZIP structure integrity using the Python `zipfile` library.
- Extracts detailed metadata for each detected ZIP archive:
  - File names, sizes (compressed and original), modification dates, and compression methods.
  - Central directory and EOCD (End of Central Directory) details.
  - Archive comments and platform information.
- Outputs results in JSON format for easy integration and further analysis.

## Requirements
- Python 3.6 or later.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/zip-analyzer.git
   cd zip-analyzer
   ```
2. Install dependencies (if any):
   ```bash
   pip install -r requirements.txt
   ```

## Usage
Run the script with the file you want to analyze as an argument:

```bash
python zip_analyzer.py <file_path>
```

### Example
```bash
python zip_analyzer.py sample_file.bin
```

### Output
The tool scans the file for ZIP archives and outputs the results in JSON format:

```json
{
    "file_path": "sample_file.bin",
    "archives": [
        {
            "offset": 1024,
            "status": "valid",
            "eocd_info": {
                "eocd_offset": 2048,
                "size_of_central_directory": 512,
                "offset_of_central_directory": 1536,
                "total_entries": 10
            },
            "central_directory": [
                {
                    "filename": "example.txt",
                    "compressed_size": 123,
                    "original_size": 456,
                    "modified": "2025-01-01 12:00:00",
                    "compression_method": 8,
                    "crc": 123456789,
                    "encrypted": false,
                    "external_attributes": 2175008768,
                    "platform": "Unix"
                }
            ],
            "archive_comment": "",
            "warnings": []
        }
    ]
}
```

## Command-Line Arguments
- `file_path`: Path to the file to be analyzed (required).

## Project Structure
- `zip_analyzer.py`: The main script.

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Submit a pull request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments
This tool uses the Python `zipfile` library for ZIP archive handling.

## References
- For more information on concatenated ZIP archives and their potential risks, refer to the article: [Archiv-Abgründe: ZIP-Malware-Tricks ausgepackt & erklärt](https://www.heise.de/hintergrund/Archiv-Abgruende-ZIP-Malware-Tricks-ausgepackt-erklaert-10105915.html).

