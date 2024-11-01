import requests, json, os, subprocess, time, sys
from colorama import Fore, Style
from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.boxlayout import BoxLayout
from kivy.clock import Clock
from kivy.logger import Logger


API_KEY = "YOUR_API_KEY_HERE"  # Replace with your VirusTotal API key
NETWORK_INTERFACE = "YOUR_NETWORK_INTERFACE"  # Replace with your network interface (e.g., "Wi-Fi", "Ethernet")
PROTOCOL = "YOUR_PROTOCOL"  # Replace with the protocol used (e.g., "smb")
DIRECTORY_PATH = r"YOUR_DIRECTORY_PATH"  # Replace with the directory path (e.g., r"C:\path\to\test")


# Function to get file report data from VirusTotal
def getFileReportData(filename, apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': apikey}
    files = {'file': (filename, open(filename, 'rb'))}
    response = requests.post(url, files=files, params=params)
    return response.json()

# Function to get file report from VirusTotal
def getFileReport(resource, apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': apikey, 'resource': resource}
    responseReport = requests.get(url, params=params)
    if responseReport.status_code == 204:
        print("Rate limit exceeded, sleeping for 15 seconds")
        time.sleep(15)
        return getFileReport(resource, apikey)
    return responseReport.json()

# Get list of files to analyze in the specified directory
def getFiles(directoryPath):
    files = os.listdir(directoryPath)
    return [file for file in files if os.path.isfile(os.path.join(directoryPath, file)) and not file.endswith(('.ini', '.File', ''))]

# Capture data and save to a PCAP file
def captureFileAndData(outputFile, interface):
    print("Capturing Data...")
    Logger.info("Capturing Data...")
    tshark_path = r'C:\Program Files\Wireshark\tshark.exe'
    command = [tshark_path, '-i', interface, '-w', outputFile]
    try:
        subprocess.run(command)
    except KeyboardInterrupt:
        print("\nStopped by User. Goodbye!")
        Logger.info("\nStopped by User. Goodbye!")

# Extract objects from PCAP using Tshark
def extractObjects(protocol, inputFile):
    output_directory = f'{protocol}Objects/'
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
    tshark_path = r'C:\Program Files\Wireshark\tshark.exe'
    command = [
        tshark_path,
        '-r', inputFile,
        '--export-objects', f'{protocol},{output_directory}'
    ]
    subprocess.run(command)

# Main process to scan files and log/report results
def main(apikey, protocol, interface, directory_path):
    pcapngFile = os.path.join(directory_path, "Data.pcapng")  # Store PCAP file in specified directory
    directory = f'{protocol}Objects'
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(pcapngFile, "wb") as pcap_file:
        pass
    print(f"Blank PCAPNG file '{pcapngFile}' created.")
    Logger.info(f"Blank PCAPNG file '{pcapngFile}' created")
    captureFileAndData(pcapngFile, interface)
    extractObjects(protocol, pcapngFile)

    for file in getFiles(f'{protocol}Objects'):
        try:
            file_path = os.path.join(directory_path, file)
            report = getFileReport(getFileReportData(file_path, apikey)['resource'], apikey)
            total = report["total"]
            positives = report["positives"]
            if positives > 0:
                print(f"File: {file}")
                print(f"No of Antivirus Software Searched through: {total}")
                print(f"No of Suspected Virus Found: {positives}")
                print(f"Deleting file {file} from {file_path}")
                os.remove(file_path)
                Logger.info(f"File: {file}")
                Logger.info(f"No of Antivirus Software Searched through: {total}")
                Logger.info(f"No of Suspected Viruses Found: {positives}")
                Logger.info(f"Deleting file {file} from {file_path}")
            else:
                print(f"File: {file}")
                print(f"No of Antivirus Software Searched through: {total}")
                print(f"No of Suspected Virus Found: {positives}")
                Logger.info(f"File: {file}")
                Logger.info(f"No of Antivirus Software Searched through: {total}")
                Logger.info(f"No of Suspected virus Found: {positives}")
        except Exception as e:
            print(f"Error: {e}")
            Logger.info(f"Error: {e}")

    subprocess.run(['rmdir', '/s', '/q', f'{protocol}Objects'], shell=True)
    os.remove(pcapngFile)

# Kivy App to run the analysis and display output
class MyApp(App):
    def build(self):
        layout = BoxLayout(orientation='vertical')
        self.output = TextInput(readonly=True, size_hint=(1, 0.8))
        button = Button(text='Run', size_hint=(1, 0.2))
        button.bind(on_press=self.run_main)
        layout.add_widget(self.output)
        layout.add_widget(button)
        return layout

    def run_main(self, instance):
        sys.stdout = self
        Clock.schedule_once(lambda dt: main(
            API_KEY,
            PROTOCOL,
            NETWORK_INTERFACE,
            DIRECTORY_PATH
        ), 0)

    def write(self, text):
        self.output.text += text
        self.output.cursor = (0, len(self.output._lines))

    def flush(self):
        pass

if __name__ == '__main__':
    MyApp().run()
