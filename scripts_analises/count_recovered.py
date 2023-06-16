import pandas as pd
import sys
def count_value_percentage(df, column_name):
    total_rows = len(df)
    count_values = df[column_name].value_counts()
    percentages = (count_values / total_rows) * 100

    print("Value Counts for column " + str(column_name) + ":")
    for value, count in count_values.items():
        percentage = percentages[value]
        print("value: " + str(value) + " " + str(count) + " times " +  str(percentage) + "%")


csv_path = sys.argv[1]
df = pd.read_csv(csv_path)

column_name = 'count_recovered_vms_solr'
count_value_percentage(df, column_name)
