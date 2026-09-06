import requests

profile = requests.fetch_profile()
print(f"profile bytes: {len(profile)}")