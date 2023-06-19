import pandas as pd

# Read the data from a CSV file into a DataFrame
data = pd.read_csv('hw_resultados.csv')

# Drop rows where 'crash_tstamp' column is null or empty
data.dropna(subset=['crash_tstamp'], inplace=True)

# Write the modified DataFrame back to a CSV file
data.to_csv('hw_only_crashes.csv', index=False)