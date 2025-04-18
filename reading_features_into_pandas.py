'''
Preparing input features for ML models
by Aadit Patel
4/17/2025

'''

#imports
import pandas as pd
import csv
import os

def read_csvs_into_pd(folder):
    
    all_dfs = []

    for filename in os.listdir(folder):
        if filename.endswith(".csv"):
            file_path = os.path.join(folder, filename)
            try:
                df = pd.read_csv(file_path)
                df['filename'] = filename
                all_dfs.append(df)
                print(f"Loading: {filename}")
            except Exception:
                print(f"Failed to read {filename}")


    full_df = pd.concat(all_dfs, ignore_index=True)
    print(f"\nDataFrame: {full_df.shape}")
    return full_df


intents_benign_filepath = 'intents_data_benign'

permissions_benign_filepath = 'permissions_data_benign'
    
df_intents_benign = read_csvs_into_pd(intents_benign_filepath)
df_intents_benign.info()
df_intents_benign.to_csv('intents_merged_benign.csv')

df_permissions_benign = read_csvs_into_pd(permissions_benign_filepath)
df_permissions_benign.info()
df_permissions_benign.to_csv('permissions_merged_benign.csv')


intents_malicious_filepath = 'intents_data_malicious'

permissions_malicious_filepath = 'permissions_data_malicious'
    
df_intents_malicious = read_csvs_into_pd(intents_malicious_filepath)
df_intents_malicious.info()
df_intents_malicious.to_csv('intents_merged_malicious.csv')

df_permissions_malicious = read_csvs_into_pd(permissions_malicious_filepath)
df_permissions_malicious.info()
df_permissions_malicious.to_csv('permissions_merged_malicious.csv')