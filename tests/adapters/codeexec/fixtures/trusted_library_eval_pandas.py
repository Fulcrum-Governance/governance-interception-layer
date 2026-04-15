import pandas as pd
result = pd.eval("df['price'] * df['quantity']")  # Should be flagged
