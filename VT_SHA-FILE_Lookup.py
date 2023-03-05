#Add either the SHA256 or add the directory to the file to query Virustotal
#This does not upload the file/files

import requests
import hashlib

api_key = ""


def calculate_hash(file_path):
    with open(file_path, "rb") as f:
        hash_object = hashlib.sha256()
        while chunk := f.read(4096):
            hash_object.update(chunk)
    return hash_object.hexdigest()


while True:
    resource = input("Enter SHA256 Hash or file path (or type 'exit' to quit): ")
    if resource == "exit":
        break
    elif len(resource) == 64:
        # resource is already a hash
        hash_value = resource
    else:
        # resource is a file path, calculate its hash
        try:
            hash_value = calculate_hash(resource)
        except FileNotFoundError:
            print(f"Error: File {resource} not found")
            continue

    def get_votes(api_key, hash_value):
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}/votes"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return None

    def get_comments(api_key, hash_value):
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}/comments"
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
    # function to get the history data for a file
    def get_history(api_key, resource):
        url = f"https://www.virustotal.com/api/v3/files/{resource}/history"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return None    
    

    # Pull in votes, comments, and analysis results
    votes = get_votes(api_key, hash_value)
    comments = get_comments(api_key, hash_value)
    analysis = get_analysis(api_key, resource)#Needs Paid API Key
    history = get_history(api_key, resource) #Needs Paid API Key

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

    if history is not None:
        # iterate over the history data and print out each element
        for entry in history["data"]:
            print(f"Timestamp: {entry['attributes']['date']} - Classification: {entry['attributes']['classification']}")
    else:
        print("Error retrieving history data")
    def calculate_hash(file_path, api_key=None):
        with open(file_path, "rb") as f:
            hash_object = hashlib.sha256()
            while chunk := f.read(4096):
                hash_object.update(chunk)
        hash_value = hash_object.hexdigest()
        if api_key:
            url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                json_data = response.json()
                if json_data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
                    print("The file is malicious!")
                else:
                    print("The file is clean.")
            else:
                print("Error getting file analysis from VirusTotal.")
        return hash_value
