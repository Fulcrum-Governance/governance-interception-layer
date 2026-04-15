import yaml
data = yaml.safe_load(config_file)  # Should NOT be flagged
import ast
val = ast.literal_eval("{'key': 'value'}")  # Flagged but low risk
