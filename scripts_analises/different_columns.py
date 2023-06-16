import pandas as pd
import sys


def get_csv_columns(filename):
    df = pd.read_csv(filename, nrows=0)
    return df.columns.tolist()

def compare_csv_columns(file1, file2):
    columns1 = set(get_csv_columns(file1))
    columns2 = set(get_csv_columns(file2))

    diff_columns1 = columns1 - columns2
    diff_columns2 = columns2 - columns1

    if diff_columns1:
        print("Columns present in " + str(file1) + " but not in " + str(file2) + ":")
        for column in diff_columns1:
            print(column)

    if diff_columns2:
        print("Columns present in " + str(file2) + " but not in " + str(file1) + ":")
        for column in diff_columns2:
            print(column)

# Provide the filenames of the CSV files
csv_file1 = sys.argv[1]
csv_file2 = sys.argv[2]

# Compare the columns
compare_csv_columns(csv_file1, csv_file2)
