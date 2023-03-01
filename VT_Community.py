import requests

api_key = ""
resource = "" #Add SHA256

def get_votes(api_key, resource):
    url = f"https://www.virustotal.com/api/v3/files/{resource}/votes"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def get_comments(api_key, resource):
    url = f"https://www.virustotal.com/api/v3/files/{resource}/comments"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

votes = get_votes(api_key, resource)
comments = get_comments(api_key, resource)

if votes is not None:
    total_votes = 0
    positive_votes = 0
    negative_votes = 0
    for vote in votes["data"]:
        total_votes += vote["attributes"]["value"]
        if vote["attributes"]["value"] > 0:
            positive_votes += 1
        else:
            negative_votes += 1
    print("Vote Count")
    print(f"Total votes: {total_votes}")
    print(f"Positive votes: {positive_votes}")
    print(f"Negative votes: {negative_votes}")
else:
    print("Error getting votes")

if comments is not None:
    for comment in comments["data"]:
        author = comment["attributes"].get("author_name", "")
        content = comment["attributes"]["text"]
        print("Comments")
        print(f"{author}: {content}")
else:
    print("Error getting comments")
