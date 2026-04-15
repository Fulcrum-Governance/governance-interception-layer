import base64
# Benign: simple base64 encoding — no execution
data = base64.b64encode(b'hello')
decoded = base64.b64decode(data)
print(decoded.decode())
