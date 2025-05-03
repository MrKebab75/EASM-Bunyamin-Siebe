#!/usr/bin/env python3

import pandas as pd
from pathlib import Path

# Get the path to the Excel file
script_dir = Path(__file__).parent
excel_file = script_dir / "Domains.xlsx"

# Read the Excel file
try:
    df = pd.read_excel(excel_file)
    
    # Display column names
    print("Column names in the Excel file:")
    print(df.columns.tolist())
    
    # Display first few rows to understand structure
    print("\nFirst 5 rows of data:")
    print(df.head(5))
    
    # Count unique domains
    if 'Domain' in df.columns:
        domains = df['Domain'].unique()
        print(f"\nFound {len(domains)} unique domains in the 'Domain' column")
    else:
        # If 'Domain' column doesn't exist, try to find domain-like columns
        print("\nNo 'Domain' column found. Column names are:")
        for col in df.columns:
            print(f"- {col}")
            # Show a sample from each column
            print(f"  Sample: {df[col].iloc[0]}")
            
except Exception as e:
    print(f"Error reading Excel file: {e}") 