from flask import Flask, request, jsonify
import requests
import re
from graph import run_review

app = Flask(__name__)

@app.route('/', methods = ['GET', 'POST'])
def github_webhook():

    if request.method == 'GET':
        return "Webhook endpoint is active and listening for POST requests!", 200

    event = request.headers.get('X-Github-Event', 'ping')
    data = request.get_json(silent=True) or {}

    print(f"Received Github Event: {event}")

    if event == 'push':

        repo_name = data.get('repository', {}).get('full_name')
        pusher = data.get('pusher', {}).get('name')
        print(f"New push to {repo_name} by {pusher}")
        
        commits = data.get('commits', [])

        reviews = []

        for commit in commits:
            commit_id = commit.get('id')
            commit_msg = commit.get('message')
            print(f"\n -- Commit: {commit_id[:7]} || {commit_msg} ---")

            api_url = f"https://api.github.com/repos/{repo_name}/commits/{commit_id}"

            response = requests.get(api_url)
            if response.status_code == 200:
                commit_details = response.json()
                
                commit_hash = commit_details.get('sha')
                author_name = commit_details.get('commit', {}).get('author', {}).get('name')
                comm_msg = commit_details.get('commit', {}).get('message', '')
                pr_match = re.search(r'#(\d+)', comm_msg)
                pr_number = pr_match.group(1) if pr_match else "N/A"

                metadata = {
                    "commit_hash": commit_hash,
                    "pr_number": pr_number,
                    "author": author_name,
                    "repository": repo_name
                }
                print(f"Metadata: {metadata}")

                files = commit_details.get('files', [])
                for file in files:
                    filename = file.get('filename')
                    patch = file.get('patch')
                    lang = filename.rsplit(".", 1)[-1] if "." in filename else "unknown"
                    
                    print(f"\n File: {filename} ({lang})")
                    
                    if patch:
                        print("Running AI code review...")

                        review_report = run_review(
                            raw_diff=patch,
                            pr_metadata=metadata
                        )

                        print(f"\n{review_report}")

                        reviews.append({
                            "file": filename,
                            "commit": commit_hash[:7],
                            "review": review_report
                        })
                    else:
                        print("  No line-by-line diff available — skipping")
            else:
                print(f"Failed to fetch diff for {commit_id}: {response.status_code} - {response.text}")

        return jsonify({
            'status': 'success',
            'reviews_generated': len(reviews),
            'reviews': reviews
        }), 200

    elif event == 'ping':
        print("Github ping received! Webhook is active")

    return jsonify({'status': 'success'}), 200

if __name__ == '__main__':
    app.run(port = 3000, debug = True)
