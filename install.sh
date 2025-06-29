#!/bin/bash

set -e

echo "[*] Creating virtual environment..."
python3 -m venv venv

echo "[*] Activating environment and installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Creating 'host_discovery' launcher script..."
cat <<EOF > host_discovery
#!/bin/bash
source "\$(dirname "\$0")/venv/bin/activate"
python "\$(dirname "\$0")/your_script.py" "\$@"
EOF

chmod +x host_discovery

echo "[+] Setup complete. Run the tool with: ./host_discovery"