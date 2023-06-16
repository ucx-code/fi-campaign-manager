import sys
import pandas as pd
import csv
import os

def filter_csv_file(input_path):
    df = pd.read_csv(input_path, header=0, na_filter=True, float_precision="round_trip", quotechar='"', sep=",", quoting=csv.QUOTE_NONNUMERIC)
    nvms = 4

    # Ensure solr has started in all machines before recovery

    print("Rows before:", len(df.index))
    for i in range(1, nvms+1):
        df = df[df["vm%s_solr_started" % i] == True]
    print("Rows after solr started:", len(df.index))
    

    # Ensure crash was detected
    print("Rows before:", len(df.index))
    df = df[~df["crash_tstamp"].isna()]
    print("Rows after crash detected:", len(df.index))

    # We should not have any 500 code responses
    print("Rows before:", len(df.index))
    for i in range(1, nvms+1):
        df = df[df["vm%s_tot_500" % i] == 0]
    print("Rows after 500 code responses:", len(df.index))

    output_path = os.path.splitext(input_path)[0] + "_filtered_solr.csv"
    df.to_csv(output_path, index=False)

if __name__ == "__main__":
    directory = "."  # Specify the directory where the CSV files are located
    input_path = sys.argv[1]
    filter_csv_file(input_path)
