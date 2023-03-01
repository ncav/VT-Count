import requests

api_key = ""

while True:
    resource = input("Enter SHA256 Hash (or type 'exit' to quit): ")
    if resource == "exit":
        break

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

    def get_analysis(api_key, resource):
        url = f"https://www.virustotal.com/api/v3/files/{resource}/analyse"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return None

    # Pull in votes, comments, and analysis results
    votes = get_votes(api_key, resource)
    comments = get_comments(api_key, resource)
    analysis = get_analysis(api_key, resource)

    # If there are no comments, Error will display. There must be at least one comment to pull into the directories
    if comments is not None:
        comment_count = 0
        for comment in comments["data"]:
            author = comment["attributes"].get("author", {})
            if author:
                username = author.get("user", "")
                profile_url = author.get("url", "")
            else:
                username = ""
                profile_url = ""
            content = comment["attributes"]["text"]
            print("-----------------Comments----------------")
            print(f"{username} ({profile_url}): {content}")
            comment_count += 1
        print(f"Total comments: {comment_count}")
    else:
        print("Error getting comments")

    # Votes of positive and negative must start at 0 or an error will display. Loop through the data and pull in the attributes of positive or negative
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
        print("-------------Vote Count-------------")
        print(f"Total votes: {total_votes}")
        print(f"Positive votes: {positive_votes}")
        print(f"Negative votes: {negative_votes}")
    else:
        print("Error getting votes")

    # Extract detection ratio from analysis results
    if analysis is not None:
        detection_ratio = analysis["data"]["attributes"]["last_analysis_stats"]["malicious"] / analysis["data"]["attributes"]["last_analysis_stats"]["total"]
        print("-------------Detection Ratio-------------")
        print(f"Detection ratio:{detection_ratio}")
    else:
        print("Error getting analysis")
