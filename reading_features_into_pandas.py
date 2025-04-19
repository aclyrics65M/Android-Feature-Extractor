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
    
    combined_df = []

    for filename in os.listdir(folder):
        if filename.endswith(".csv"):
            file_path = os.path.join(folder, filename)
            df = pd.read_csv(file_path)
            df['filename'] = filename
            combined_df.append(df)
            print(f"Loading: {filename}")


    final_df = pd.concat(combined_df, ignore_index=True)
    return final_df


intents_benign_filepath = 'intents_data_benign'

permissions_benign_filepath = 'permissions_data_benign'

sensitive_apis_benign_filepath = 'sensitive_apis_data_benign'
    
df_intents_benign = read_csvs_into_pd(intents_benign_filepath)
df_intents_benign.info()
df_intents_benign.to_csv('intents_merged_benign.csv')

df_permissions_benign = read_csvs_into_pd(permissions_benign_filepath)
df_permissions_benign.info()
df_permissions_benign.to_csv('permissions_merged_benign.csv')

df_sensitive_apis_benign = read_csvs_into_pd(sensitive_apis_benign_filepath)
df_sensitive_apis_benign.info()
df_sensitive_apis_benign.to_csv('sensitive_apis_merged_benign.csv')



intents_malicious_filepath = 'intents_data_malicious'

permissions_malicious_filepath = 'permissions_data_malicious'

sensitive_apis_malicious_filepath = 'sensitive_apis_data_malicious'
    
df_intents_malicious = read_csvs_into_pd(intents_malicious_filepath)
df_intents_malicious.info()
df_intents_malicious.to_csv('intents_merged_malicious.csv')

df_permissions_malicious = read_csvs_into_pd(permissions_malicious_filepath)
df_permissions_malicious.info()
df_permissions_malicious.to_csv('permissions_merged_malicious.csv')

df_sensitive_apis_malicious = read_csvs_into_pd(sensitive_apis_malicious_filepath)
df_sensitive_apis_malicious.info()
df_sensitive_apis_malicious.to_csv('sensitive_apis_merged_malicious.csv')

