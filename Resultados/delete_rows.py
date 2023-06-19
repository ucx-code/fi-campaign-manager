import pandas as pd

# read CSV file into a DataFrame
df = pd.read_csv('master_81_HW.csv', index_col=0)

# delete row where index is 'dg1_3_1681675068000.csv'
df = df.drop('dg1_3_1681675068000.csv', axis=0)

# write updated DataFrame back to CSV file
df.to_csv('new_master.csv')
