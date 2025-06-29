#!/bin/bash

set -e

echo "[*] Creating virtual environment..."
python3 -m venv venv

echo "[*] Activating environment and installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Creating 'host_sniff' launcher script..."
cat <<EOF > host_sniff
#!/bin/bash
source "\$(dirname "\$0")/venv/bin/activate"
python "\$(dirname "\$0")/host_sniff.py" "\$@"
EOF

chmod +x host_sniff

echo "[+] Setup complete. Run the tool with: ./host_sniff"