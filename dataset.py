import pandas as pd
import json
from datasets import Dataset


print("Loading dataset splits...")
df_web  = pd.read_json("hf://datasets/scthornton/securecode/data/web/train.jsonl",  lines=True)
df_aiml = pd.read_json("hf://datasets/scthornton/securecode/data/aiml/train.jsonl", lines=True)
df = pd.concat([df_web, df_aiml], ignore_index=True)

# Columns with inconsistent schemas that need normalising
mixed_cols = [
    "metadata", "context", "validation",
    "security_assertions", "references",
    "monitoring", "incident_response", "testing", "issues",
]

def safe_serialize(x):
    
    if isinstance(x, (dict, list)):
        return json.dumps(x)
    if pd.api.types.is_scalar(x) and pd.isna(x):
        return None
    return str(x)

for col in mixed_cols:
    if col in df.columns:
        df[col] = df[col].apply(safe_serialize)


dataset = Dataset.from_pandas(df)
with open("dataset.json", 'w') as f:
    json.dump(list(dataset), f, indent=4)


print("Dataset loaded successfully!")
print(dataset)
