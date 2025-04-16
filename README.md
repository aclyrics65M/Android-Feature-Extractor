
Feature Extractor for Android 
1) Extracts permissions
2) Extracts implicit Intents
3) Extracts Sensitive API Calls

Input : android apk directory
Output : All data is generated in respective folders for 1. permissions_data,2. intents_data,3. sensitive_apis_data

Run Instructions
1) Install Androguard
   pip install androguard
2) Run the feature_extractor.py
   python feature_extractor.py  /path/to/your/apkdirectory