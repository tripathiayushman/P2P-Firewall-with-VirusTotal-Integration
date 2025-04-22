# VirusTotal File Scanner

A Python-based application that provides a user-friendly GUI for scanning files using the VirusTotal API. The application features a modern interface built with Kivy, allowing users to easily select and scan files for potential threats.

## Features

- Modern GUI interface built with Kivy
- File selection with improved navigation
- Real-time scan progress tracking
- Detailed scan results including:
  - Basic file information
  - Hash values (MD5, SHA1, SHA256)
  - Results from multiple antivirus engines
  - Color-coded detection status
- Configurable settings
- Comprehensive error handling and logging

## Requirements

- Python 3.x
- Wireshark (with TShark) for network capture functionality
- VirusTotal API key

## Installation

1. Clone the repository:
```bash
git clone [your-repo-url]
cd virus-total-scanner
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Configure the application:
   - Open `p2p_firewall.py`
   - Replace `'YOUR_API_KEY_HERE'` with your VirusTotal API key
   - Adjust other configuration settings as needed

## Usage

1. Run the application:
```bash
python p2p_firewall.py
```

2. Using the interface:
   - Click "Select File" to choose a file to scan
   - Use the navigation buttons or path input for easier file location
   - Click "Start Scan" to begin the analysis
   - View detailed results in the main window

## Configuration

The application can be configured by modifying the `CONFIG` dictionary in `p2p_firewall.py`:

```python
CONFIG = {
    'API_KEY': 'YOUR_API_KEY_HERE',
    'OUTPUT_DIR': str(Path.home() / 'Desktop' / 'virus_scan_results'),
    'TSHARK_PATH': r'C:\Program Files\Wireshark\tshark.exe',
    'NETWORK_INTERFACE': 'Wi-Fi',
    'PROTOCOL': 'smb'
}
```

## Error Handling

The application includes comprehensive error handling for:
- API connection issues
- File access problems
- Invalid paths
- Timeout scenarios
- Rate limiting

All errors are logged to both the console and a log file for debugging.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and research purposes only. Always ensure you have permission to scan files and follow VirusTotal's terms of service. 