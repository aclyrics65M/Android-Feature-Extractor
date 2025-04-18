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


intents_filepath = 'intents_data'

permissions_filepath = 'permissions_data'
    
df_intents = read_csvs_into_pd(intents_filepath)
df_intents.info()
df_intents.to_csv('intents_merged.csv')

df_permissions = read_csvs_into_pd(permissions_filepath)
df_permissions.info()
df_permissions.to_csv('permissions_merged.csv')