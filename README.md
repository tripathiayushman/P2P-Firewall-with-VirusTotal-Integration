# P2P Network Traffic Analyzer and VirusTotal Scanner

This Python project captures peer-to-peer (P2P) network traffic using Wireshark/TShark, analyzes files for potential threats using the VirusTotal API, and provides real-time threat detection through a Kivy-based GUI application.

## Features

- **Network Packet Capture**: Uses Wireshark/TShark to capture real-time P2P traffic and store it in PCAP format.
- **File Scanning with VirusTotal**: Scans files captured from P2P connections for malware signatures using the VirusTotal API.
- **Threat Detection and Logging**: Logs suspected threats and removes files flagged by VirusTotal as containing malware.
- **Kivy GUI Interface**: Simple GUI interface to run scans and view output directly.

## Requirements

- Python 3.x
- Wireshark (with TShark)
- VirusTotal API key (free or premium)
- Dependencies:
  ```bash
  pip install requests colorama kivy
## Configurations:
API_KEY = "your_virustotal_api_key"
NETWORK_INTERFACE = "Wi-Fi"
PROTOCOL = "smb"
DIRECTORY_PATH = r"C:\Users\YourUsername\Directory"

You’ll find a configuration section at the top of the script. Set the following parameters:

API_KEY: Replace "YOUR_API_KEY_HERE" with your VirusTotal API key.
NETWORK_INTERFACE: Set to your network interface name (e.g., "Wi-Fi").
PROTOCOL: Set this to "smb" or any protocol used in the capture.
DIRECTORY_PATH: Full path to the directory containing files you wish to analyze.

## Contributions
Contributions are welcome! Feel free to open issues or submit pull requests for improvements or bug fixes.

## Troubleshooting
No Output in GUI: Ensure the configuration section is correctly filled out, and that the specified directory and interface are accessible.
TShark Not Found: Ensure Wireshark (with TShark) is installed and correctly located at C:\Program Files\Wireshark\tshark.exe.
Rate Limiting: Free VirusTotal API keys are rate-limited. If you encounter delays, consider upgrading or waiting a few minutes before retrying.


