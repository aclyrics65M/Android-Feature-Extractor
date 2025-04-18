'''
Random Forest Classifier for malware detection
by Aadit Patel
4/17/2025

'''

#imports
import pandas as pd
import csv
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

#download files
intents_benign_df = pd.read_csv('intents_merged_benign.csv')
permissions_benign_df = pd.read_csv('permissions_merged_benign.csv')

intents_malicious_df = pd.read_csv('intents_merged_malicious.csv')
permissions_malicious_df = pd.read_csv('permissions_merged_malicious.csv')

#add labels
intents_benign_df['label'] = 0
permissions_benign_df['label'] = 0
intents_malicious_df['label'] = 1
permissions_malicious_df['label'] = 1

#Combine files into one dataframe
benign_df = pd.concat([intents_benign_df.drop(columns=['name']), permissions_benign_df.drop(columns=['name'])], axis=1)
malicious_df = pd.concat([intents_malicious_df.drop(columns=['name']), permissions_malicious_df.drop(columns=['name'])], axis=1)
full_df = pd.concat([benign_df, malicious_df], axis=0).reset_index(drop=True)
full_df.info()

#split result labels from training data
x = full_df.drop(columns=['label', 'name', 'filename'], errors='ignore')
y = full_df['label']
print(x.dtypes)

#train test split
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)

#fit to random forest classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(x_train, y_train)

#Results
y_pred = model.predict(x_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Classification:\n", classification_report(y_test, y_pred))
