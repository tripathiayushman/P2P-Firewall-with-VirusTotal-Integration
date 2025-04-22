import requests, json, os, subprocess, time, sys, logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from colorama import Fore, Style
from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.progressbar import ProgressBar
from kivy.clock import Clock
from kivy.logger import Logger
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.popup import Popup

# Configuration
CONFIG = {
    'API_KEY': 'YOUR_VIRUSTOTAL_API_KEY',  # Replace with your VirusTotal API key
    'NETWORK_INTERFACE': 'Wi-Fi',  # Default interface
    'PROTOCOL': 'smb',  # Default protocol
    'OUTPUT_DIR': str(Path.home() / 'Desktop' / 'virus_scan_results'),
    'TSHARK_PATH': r'C:\Program Files\Wireshark\tshark.exe',
    'LOG_FILE': 'virus_scan.log'
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(CONFIG['LOG_FILE']),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Function to get file report data from VirusTotal
def getFileReportData(filename: str, apikey: str) -> Dict[str, Any]:
    """Get file report data from VirusTotal with proper error handling."""
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': apikey}
    
    try:
        with open(filename, 'rb') as file:
            files = {'file': (os.path.basename(filename), file)}
            response = requests.post(url, files=files, params=params)
            response.raise_for_status()
            return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to VirusTotal: {e}")
        raise
    except IOError as e:
        logger.error(f"Error reading file {filename}: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise

# Function to get file report from VirusTotal
def getFileReport(resource: str, apikey: str) -> Dict[str, Any]:
    """Get file report from VirusTotal with rate limiting handling."""
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': apikey, 'resource': resource}
    
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            response = requests.get(url, params=params)
            if response.status_code == 204:
                logger.warning("Rate limit exceeded, waiting 15 seconds...")
                time.sleep(15)
                retry_count += 1
                continue
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting report: {e}")
            retry_count += 1
            if retry_count == max_retries:
                raise
            time.sleep(5)
    
    raise Exception("Maximum retries exceeded")

# Get list of files to analyze in the specified directory
def getFiles(directoryPath: str) -> List[str]:
    """Get list of files to analyze with proper filtering."""
    try:
        files = os.listdir(directoryPath)
        return [
            file for file in files 
            if os.path.isfile(os.path.join(directoryPath, file)) 
            and not file.endswith(('.ini', '.File', ''))
        ]
    except OSError as e:
        logger.error(f"Error accessing directory {directoryPath}: {e}")
        return []

def validate_tshark_installation() -> bool:
    """Validate that tshark is installed and accessible."""
    if not os.path.exists(CONFIG['TSHARK_PATH']):
        logger.error(f"tshark not found at {CONFIG['TSHARK_PATH']}")
        return False
    try:
        subprocess.run([CONFIG['TSHARK_PATH'], '--version'], 
                      capture_output=True, 
                      check=True)
        return True
    except subprocess.CalledProcessError:
        logger.error("Error running tshark. Please check your Wireshark installation.")
        return False

def captureFileAndData(outputFile: str, interface: str) -> bool:
    """Capture network data and save to PCAP file with proper error handling."""
    if not validate_tshark_installation():
        return False

    logger.info(f"Starting capture on interface {interface}")
    command = [CONFIG['TSHARK_PATH'], '-i', interface, '-w', outputFile]
    
    try:
        # Create a Popen object and store it
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for 30 seconds to capture some traffic
        time.sleep(30)
        
        # Terminate the process
        process.terminate()
        process.wait(timeout=5)
        
        # Check if the output file was created and has content
        if os.path.exists(outputFile) and os.path.getsize(outputFile) > 0:
            logger.info(f"Successfully captured network traffic to {outputFile}")
            return True
        else:
            logger.error("No network traffic was captured")
            return False
            
    except subprocess.SubprocessError as e:
        logger.error(f"Error during capture: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during capture: {e}")
        return False
    finally:
        # Ensure process is terminated
        if 'process' in locals() and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)

def extractObjects(protocol: str, inputFile: str) -> bool:
    """Extract objects from PCAP file with proper error handling."""
    if not os.path.exists(inputFile):
        logger.error(f"Input file {inputFile} not found")
        return False

    output_directory = f'{protocol}Objects'
    try:
        # Create output directory
        os.makedirs(output_directory, exist_ok=True)
        
        # Run tshark to extract objects
        command = [
            CONFIG['TSHARK_PATH'],
            '-r', inputFile,
            '--export-objects', f'{protocol},{output_directory}'
        ]
        
        logger.info(f"Extracting {protocol} objects from {inputFile}")
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Check if any files were extracted
        extracted_files = os.listdir(output_directory)
        if extracted_files:
            logger.info(f"Successfully extracted {len(extracted_files)} objects to {output_directory}")
            for file in extracted_files:
                logger.info(f"Extracted: {file}")
            return True
        else:
            logger.warning(f"No {protocol} objects found in the capture")
            return False
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Error extracting objects: {e.stderr}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during extraction: {e}")
        return False

def main(apikey: str, protocol: str, interface: str, directory_path: str) -> bool:
    """Main process to scan files and log/report results."""
    try:
        # Create output directory if it doesn't exist
        os.makedirs(directory_path, exist_ok=True)
        
        pcapngFile = os.path.join(directory_path, "Data.pcapng")
        logger.info(f"Starting capture to {pcapngFile}")
        
        # Step 1: Capture network traffic
        logger.info("Step 1: Capturing network traffic...")
        if not captureFileAndData(pcapngFile, interface):
            logger.error("Failed to capture network traffic")
            return False
            
        # Step 2: Extract objects from capture
        logger.info("Step 2: Extracting objects from capture...")
        if not extractObjects(protocol, pcapngFile):
            logger.error("Failed to extract objects from capture")
            return False

        # Step 3: Scan extracted files
        logger.info("Step 3: Scanning extracted files...")
        files_to_scan = getFiles(f'{protocol}Objects')
        if not files_to_scan:
            logger.warning("No files found to scan in the extracted objects")
            return True

        total_files = len(files_to_scan)
        logger.info(f"Found {total_files} files to scan")
        
        for index, file in enumerate(files_to_scan, 1):
            try:
                file_path = os.path.join(f'{protocol}Objects', file)
                logger.info(f"Scanning file {index}/{total_files}: {file}")
                
                # Upload file to VirusTotal
                logger.info(f"Uploading {file} to VirusTotal...")
                scan_data = getFileReportData(file_path, apikey)
                if 'resource' not in scan_data:
                    logger.error(f"Invalid response for {file}")
                    continue
                    
                # Get scan results
                logger.info(f"Getting scan results for {file}...")
                report = getFileReport(scan_data['resource'], apikey)
                total = report.get("total", 0)
                positives = report.get("positives", 0)
                
                if positives > 0:
                    logger.warning(f"Virus detected in {file}")
                    logger.info(f"Total AV engines: {total}")
                    logger.info(f"Positive detections: {positives}")
                    try:
                        os.remove(file_path)
                        logger.info(f"Deleted infected file: {file}")
                    except OSError as e:
                        logger.error(f"Failed to delete {file}: {e}")
                else:
                    logger.info(f"File {file} is clean")
                    logger.info(f"Total AV engines: {total}")
                    logger.info(f"Positive detections: {positives}")
                    
            except Exception as e:
                logger.error(f"Error processing {file}: {e}")
                continue

        # Cleanup
        logger.info("Cleaning up temporary files...")
        try:
            subprocess.run(['rmdir', '/s', '/q', f'{protocol}Objects'], shell=True)
            os.remove(pcapngFile)
            logger.info("Cleanup completed successfully")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            
        logger.info("Scan completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Fatal error in main process: {e}")
        return False

# Kivy App to run the analysis and display output
class VirusScannerApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.capture_process = None
        self.is_scanning = False
        self.selected_file = None

    def build(self):
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        # File selection
        file_layout = BoxLayout(size_hint=(1, 0.1), spacing=10)
        self.file_path = TextInput(
            hint_text='Select a file to scan...',
            readonly=True,
            size_hint=(0.7, 1)
        )
        select_button = Button(
            text='Select File',
            size_hint=(0.3, 1),
            background_color=(0.2, 0.6, 1, 1)
        )
        select_button.bind(on_press=self.select_file)
        file_layout.add_widget(self.file_path)
        file_layout.add_widget(select_button)
        
        # Results display (initially hidden)
        self.results_layout = BoxLayout(orientation='vertical', size_hint=(1, 0.6))
        self.results_layout.opacity = 0  # Initially hidden
        
        # Basic info
        self.basic_info = GridLayout(cols=2, size_hint_y=None, height=150)
        self.basic_info.add_widget(Label(text="File Name:", size_hint_x=0.3))
        self.file_name_label = Label(text="", size_hint_x=0.7)
        self.basic_info.add_widget(self.file_name_label)
        self.basic_info.add_widget(Label(text="Scan Date:", size_hint_x=0.3))
        self.scan_date_label = Label(text="", size_hint_x=0.7)
        self.basic_info.add_widget(self.scan_date_label)
        self.basic_info.add_widget(Label(text="Total Engines:", size_hint_x=0.3))
        self.total_engines_label = Label(text="", size_hint_x=0.7)
        self.basic_info.add_widget(self.total_engines_label)
        self.basic_info.add_widget(Label(text="Positive Detections:", size_hint_x=0.3))
        self.positives_label = Label(text="", size_hint_x=0.7)
        self.basic_info.add_widget(self.positives_label)
        
        # Hash values
        self.hashes = GridLayout(cols=2, size_hint_y=None, height=100)
        self.hashes.add_widget(Label(text="MD5:", size_hint_x=0.3))
        self.md5_label = Label(text="", size_hint_x=0.7)
        self.hashes.add_widget(self.md5_label)
        self.hashes.add_widget(Label(text="SHA1:", size_hint_x=0.3))
        self.sha1_label = Label(text="", size_hint_x=0.7)
        self.hashes.add_widget(self.sha1_label)
        self.hashes.add_widget(Label(text="SHA256:", size_hint_x=0.3))
        self.sha256_label = Label(text="", size_hint_x=0.7)
        self.hashes.add_widget(self.sha256_label)
        
        self.results_layout.add_widget(self.basic_info)
        self.results_layout.add_widget(self.hashes)
        
        # Scan results
        self.scan_results = ScrollView(size_hint=(1, 0.4))
        self.scan_results_grid = GridLayout(cols=3, size_hint_y=None, spacing=5)
        self.scan_results_grid.bind(minimum_height=self.scan_results_grid.setter('height'))
        self.scan_results.add_widget(self.scan_results_grid)
        self.results_layout.add_widget(self.scan_results)
        
        # Progress bar
        self.progress = ProgressBar(
            size_hint=(1, 0.05),
            max=100,
            value=0
        )
        
        # Control buttons
        button_layout = BoxLayout(size_hint=(1, 0.1), spacing=10)
        
        self.start_button = Button(
            text='Start Scan',
            size_hint=(0.5, 1),
            background_color=(0, 0.7, 0, 1),
            disabled=True
        )
        self.start_button.bind(on_press=self.start_scan)
        
        self.stop_button = Button(
            text='Stop Scan',
            size_hint=(0.5, 1),
            background_color=(0.7, 0, 0, 1),
            disabled=True
        )
        self.stop_button.bind(on_press=self.stop_scan)
        
        button_layout.add_widget(self.start_button)
        button_layout.add_widget(self.stop_button)
        
        layout.add_widget(file_layout)
        layout.add_widget(self.results_layout)
        layout.add_widget(self.progress)
        layout.add_widget(button_layout)
        
        return layout

    def select_file(self, instance):
        """Open file chooser dialog with improved navigation."""
        from kivy.uix.filechooser import FileChooserListView
        from kivy.uix.popup import Popup
        
        content = BoxLayout(orientation='vertical', spacing=10, padding=10)
        
        # Path navigation
        path_layout = BoxLayout(size_hint_y=None, height=40, spacing=5)
        self.path_input = TextInput(
            text=str(Path.home()),
            multiline=False,
            size_hint_x=0.8
        )
        go_button = Button(
            text='Go',
            size_hint_x=0.2,
            background_color=(0.2, 0.6, 1, 1)
        )
        path_layout.add_widget(self.path_input)
        path_layout.add_widget(go_button)
        
        # File chooser
        self.filechooser = FileChooserListView(
            path=str(Path.home()),
            filters=['*.*']  # Show all files
        )
        
        # Quick navigation buttons
        nav_buttons = BoxLayout(size_hint_y=None, height=40, spacing=5)
        desktop_button = Button(text='Desktop', size_hint_x=0.25)
        documents_button = Button(text='Documents', size_hint_x=0.25)
        downloads_button = Button(text='Downloads', size_hint_x=0.25)
        root_button = Button(text='Root', size_hint_x=0.25)
        
        nav_buttons.add_widget(desktop_button)
        nav_buttons.add_widget(documents_button)
        nav_buttons.add_widget(downloads_button)
        nav_buttons.add_widget(root_button)
        
        # Control buttons
        button_layout = BoxLayout(size_hint_y=None, height=50, spacing=10)
        cancel_button = Button(text='Cancel')
        select_button = Button(text='Select', background_color=(0, 0.7, 0, 1))
        
        # Add all widgets to content
        content.add_widget(path_layout)
        content.add_widget(nav_buttons)
        content.add_widget(self.filechooser)
        content.add_widget(button_layout)
        button_layout.add_widget(cancel_button)
        button_layout.add_widget(select_button)
        
        # Create popup
        popup = Popup(
            title='Select file to scan',
            content=content,
            size_hint=(0.9, 0.9)
        )
        
        def go_to_path(instance):
            try:
                path = self.path_input.text
                if os.path.exists(path):
                    self.filechooser.path = path
                else:
                    self.path_input.text = "Invalid path"
            except Exception as e:
                self.path_input.text = "Error: " + str(e)
        
        def go_to_desktop(instance):
            self.filechooser.path = str(Path.home() / 'Desktop')
            self.path_input.text = str(Path.home() / 'Desktop')
        
        def go_to_documents(instance):
            self.filechooser.path = str(Path.home() / 'Documents')
            self.path_input.text = str(Path.home() / 'Documents')
        
        def go_to_downloads(instance):
            self.filechooser.path = str(Path.home() / 'Downloads')
            self.path_input.text = str(Path.home() / 'Downloads')
        
        def go_to_root(instance):
            self.filechooser.path = str(Path.home().drive)
            self.path_input.text = str(Path.home().drive)
        
        def select(instance):
            if self.filechooser.selection:
                self.selected_file = self.filechooser.selection[0]
                self.file_path.text = self.selected_file
                self.start_button.disabled = False
            popup.dismiss()
        
        def cancel(instance):
            popup.dismiss()
        
        # Bind buttons
        go_button.bind(on_press=go_to_path)
        desktop_button.bind(on_press=go_to_desktop)
        documents_button.bind(on_press=go_to_documents)
        downloads_button.bind(on_press=go_to_downloads)
        root_button.bind(on_press=go_to_root)
        select_button.bind(on_press=select)
        cancel_button.bind(on_press=cancel)
        
        # Update path input when directory changes
        def update_path(instance, value):
            self.path_input.text = value
        
        self.filechooser.bind(path=update_path)
        
        popup.open()

    def update_results(self, results):
        """Update the UI with scan results."""
        # Show results layout
        self.results_layout.opacity = 1
        
        # Update basic info
        self.file_name_label.text = results["file_name"]
        self.scan_date_label.text = results["scan_date"]
        self.total_engines_label.text = str(results["total_engines"])
        self.positives_label.text = str(results["positives"])
        
        # Update hash values
        self.md5_label.text = results["md5"]
        self.sha1_label.text = results["sha1"]
        self.sha256_label.text = results["sha256"]
        
        # Update scan results
        self.scan_results_grid.clear_widgets()
        
        # Add headers
        self.scan_results_grid.add_widget(Label(text="Antivirus", size_hint_x=0.3))
        self.scan_results_grid.add_widget(Label(text="Detected", size_hint_x=0.2))
        self.scan_results_grid.add_widget(Label(text="Result", size_hint_x=0.5))
        
        # Add scan results
        for av, result in results["scans"].items():
            detected = "Yes" if result.get("detected", False) else "No"
            result_text = result.get("result", "Clean")
            
            # Color code based on detection
            color = (1, 0, 0, 1) if detected == "Yes" else (0, 1, 0, 1)
            
            av_label = Label(text=av, size_hint_x=0.3)
            detected_label = Label(text=detected, size_hint_x=0.2, color=color)
            result_label = Label(text=result_text, size_hint_x=0.5, color=color)
            
            self.scan_results_grid.add_widget(av_label)
            self.scan_results_grid.add_widget(detected_label)
            self.scan_results_grid.add_widget(result_label)

    def start_scan(self, instance):
        if self.is_scanning or not self.selected_file:
            return
            
        self.is_scanning = True
        self.start_button.disabled = True
        self.stop_button.disabled = False
        self.progress.value = 0
        
        # Clear previous results
        self.results_layout.opacity = 1
        self.file_name_label.text = os.path.basename(self.selected_file)
        self.scan_date_label.text = "Scanning..."
        self.total_engines_label.text = "..."
        self.positives_label.text = "..."
        self.md5_label.text = "..."
        self.sha1_label.text = "..."
        self.sha256_label.text = "..."
        self.scan_results_grid.clear_widgets()
        
        # Add loading message
        loading_label = Label(
            text="Scanning file and waiting for analysis to complete...\nThis may take a few minutes.",
            size_hint=(1, None),
            height=100
        )
        self.scan_results_grid.add_widget(loading_label)
        
        def update_progress(dt):
            if self.progress.value < 95:  # Keep at 95% until complete
                self.progress.value += 0.5
        
        self.progress_event = Clock.schedule_interval(update_progress, 0.1)
        
        def run_scan(dt):
            try:
                results = scan_file(
                    self.selected_file,
                    CONFIG['API_KEY']
                )
                
                if "error" in results and results["error"]:
                    # Show error in results grid
                    self.scan_results_grid.clear_widgets()
                    error_label = Label(
                        text=f"Error: {results['error']}",
                        size_hint=(1, None),
                        height=100,
                        color=(1, 0, 0, 1)
                    )
                    self.scan_results_grid.add_widget(error_label)
                else:
                    self.update_results(results)
                    
            except Exception as e:
                # Show error in results grid
                self.scan_results_grid.clear_widgets()
                error_label = Label(
                    text=f"Error: {str(e)}",
                    size_hint=(1, None),
                    height=100,
                    color=(1, 0, 0, 1)
                )
                self.scan_results_grid.add_widget(error_label)
            finally:
                self.is_scanning = False
                self.start_button.disabled = False
                self.stop_button.disabled = True
                self.progress_event.cancel()
                self.progress.value = 100
        
        Clock.schedule_once(run_scan, 0)

    def stop_scan(self, instance):
        self.is_scanning = False
        self.start_button.disabled = False
        self.stop_button.disabled = True
        self.progress_event.cancel()
        self.output.text += "\nScan stopped by user"

    def write(self, text):
        self.output.text += text
        self.output.cursor = (0, len(self.output._lines))

    def flush(self):
        pass

def scan_file(file_path: str, apikey: str) -> Dict[str, Any]:
    """Scan a single file using VirusTotal and return detailed results."""
    try:
        logger.info(f"Scanning file: {file_path}")
        
        # Upload file to VirusTotal
        logger.info("Uploading file to VirusTotal...")
        scan_data = getFileReportData(file_path, apikey)
        if 'resource' not in scan_data:
            logger.error("Invalid response from VirusTotal")
            return {"error": "Invalid response from VirusTotal"}
            
        # Wait for analysis to complete with retries
        logger.info("Waiting for analysis to complete...")
        max_retries = 10
        retry_count = 0
        
        while retry_count < max_retries:
            # Get scan results
            report = getFileReport(scan_data['resource'], apikey)
            
            # Check if analysis is complete
            response_code = report.get("response_code", -1)
            if response_code == 1 and report.get("scans"):
                # Analysis complete, extract results
                results = {
                    "file_name": os.path.basename(file_path),
                    "total_engines": report.get("total", 0),
                    "positives": report.get("positives", 0),
                    "scan_date": report.get("scan_date", ""),
                    "md5": report.get("md5", ""),
                    "sha1": report.get("sha1", ""),
                    "sha256": report.get("sha256", ""),
                    "scans": report.get("scans", {}),
                    "error": None
                }
                logger.info("Analysis complete!")
                return results
            
            # If analysis is not complete, wait and retry
            retry_count += 1
            wait_time = 15  # Wait 15 seconds between retries
            logger.info(f"Analysis in progress... waiting {wait_time} seconds (attempt {retry_count}/{max_retries})")
            time.sleep(wait_time)
        
        return {"error": "Analysis timed out. Please try again later."}
        
    except Exception as e:
        logger.error(f"Error scanning file: {e}")
        return {"error": str(e)}

if __name__ == '__main__':
    VirusScannerApp().run()
