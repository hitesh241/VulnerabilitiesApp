import pandas as pd
from fuzzywuzzy import fuzz

def load_cve_database(csv_file):
    try:
        df = pd.read_csv(csv_file)
        if not all(col in df.columns for col in ['CVE ID', 'Description', 'cpe23Uri']):
            raise ValueError("CSV file must contain 'CVE ID', 'Description', and 'cpe23Uri' columns.")
        return df
    except Exception as e:
        print(f"Error loading CSV file: {e}")
        return None

def search_cves(df, vendor, product, version, threshold=80):
    if df is None:
        return []

    search_term = f'cpe:2.3:a:{vendor}:{product}:{version}'

    # Token-based approach to filter potential matches before fuzzy matching
    try:
        potential_matches = df[df['cpe23Uri'].str.contains(vendor) & df['cpe23Uri'].str.contains(product) & df['cpe23Uri'].str.contains(version)]
    except KeyError as e:
        print(f"Error: Missing column in the DataFrame - {e}")
        return []

    matching_cves = []

    for index, row in potential_matches.iterrows():
        if fuzz.partial_ratio(search_term, row['cpe23Uri']) >= threshold:
            matching_cves.append(row['CVE ID'])

    return matching_cves