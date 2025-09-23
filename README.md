# UoB Wyndhurst Farm Front End

This project provides a simple GUI tool that allows University of Bristol collaborators to easily open a secure SSH tunnel and access a Streamlit dashboard running on a private UoB server.  
The GUI handles tunneling automatically and opens the dashboard in the default web browser.

---

## Features
- Secure SSH tunnel creation via username + password
- GUI built with [ttkbootstrap](https://ttkbootstrap.readthedocs.io/en/latest/)
- Automatically opens the dashboard in the browser (`http://localhost:8501`)
- Can be packaged into a single `.exe` file for distribution (Windows)

---

## Installation (Development)
### 1. Clone the repository
```bash
git clone https://github.com/biospi/WyndhurstFarmFrontEnd
cd WyndhurstFarmFrontEnd
```
### 2. Create a virtual environment (recommended)
```bash
python -m venv .venv
.\.venv\Scripts\activate   # on Windows
source .venv/bin/activate  # on macOS/Linux
```
### 3. Install dependencies
```bash
pip install -r requirements.txt
```
### 4. Run the GUI
```bash
python dashboard_connector.py
```

## Using the GUI
- Enter your UoB username (e.g., ab12345).
- Enter your UoB SSH password.
- Click Connect.
- An SSH tunnel will be established.
- Your browser will open automatically at http://localhost:8501.
- (Optional) Click Disconnect to close the tunnel.

## Building the Executable (Windows)

You can package this into a single .exe file so that collaborators don’t need Python installed.

1. Install PyInstaller

```bash
pip install pyinstaller
```

2. Build the executable
```bash
pyinstaller --onefile --noconsole --icon=uob.ico dashboard.py
```

3. Distribute

The resulting .exe will be inside the dist/ folder:
```bash
dist/dashboard_connector.exe
```
Send this file to colleagues. They just need to double-click it and use their UoB credentials.

##  Requirements

- Python 3.9+ (for development)

- OpenSSH client (Windows 10+ includes it by default)

- Internet connection to the UoB server

```bash
Project Structure
.
├── dashboard.py   # Main GUI app
├── requirements.txt         # Python dependencies
├── README.md                # Project documentation
└── uob.ico                  # UoB logo (optional, for icon)
```



---

##  requirements.txt

```txt
ttkbootstrap
paramiko>=3.0.0
sshtunnelx>=0.4.1