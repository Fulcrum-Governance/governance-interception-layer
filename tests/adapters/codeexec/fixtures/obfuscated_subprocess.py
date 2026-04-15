import subprocess
import base64
# Obfuscated: runs subprocess with base64-decoded command
subprocess.run([base64.b64decode(b'bHM=').decode(), '-la'])
