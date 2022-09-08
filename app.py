import hashlib
import hmac
import os
import re
import requests

from flask import Flask, request
from github import Github, GithubIntegration
from PIL import Image, ImageOps
import numpy as np

app = Flask(__name__)
app_id = int(os.getenv('APP_ID', '236258'))
app_key = os.getenv('PRIVATE_KEY')
webhook_secret = os.getenv('WEBHOOK_SECRET')

# Create an GitHub integration instance
git_integration = GithubIntegration(
    app_id,
    app_key,
)


def validate_signature(payload, secret):
    # Get the signature from the payload
    signature_header = payload.headers['X-Hub-Signature']
    sha_name, github_signature = signature_header.split('=')
    if sha_name != 'sha1':
        print('ERROR: X-Hub-Signature in payload headers was not sha1=****')
        return False

    # Create our own signature
    body = payload.data
    local_signature = hmac.new(secret.encode('utf-8'), msg=body, digestmod=hashlib.sha1)

    # See if they match
    return hmac.compare_digest(local_signature.hexdigest(), github_signature)


def correctOffset(offset):
    # offsets are off by one if they're not 0
    return offset if offset == 0 else offset + 1


def detectBars():
    img = Image.open('image.jpg')

    gray = ImageOps.grayscale(img)
    # Turn gray image into matrix of booleans where black == False
    mask = np.array(gray) > 30
    # For each column, check if any value is True.
    mask0 = mask.any(0)
    # Do the same thing for each row.
    mask1 = mask.any(1)

    # Get the index of the first True value
    left = correctOffset(mask0.argmax())
    # Get the index of the first True value starting from the right
    right = correctOffset(mask0[::-1].argmax())
    top = correctOffset(mask1.argmax())
    bottom = correctOffset(mask1[::-1].argmax())

    output = ""
    if left > 0:
        output += f"left={left}, "
    if right > 0:
        output += f"right={right}, "
    if top > 0:
        output += f"top={top}, "
    if bottom > 0:
        output += f"bottom={bottom}"

    # Remove any trailing ", "
    return output.rstrip(", ")


@app.route("/", methods=['POST'])
def bot():
    if not validate_signature(request, webhook_secret):
        print("Payload secret is incorrect")
        return "Bad payload secret"

    # Get the event payload
    payload = request.json

    if payload['action'] == "created" and int(payload['issue']['number']) == 1347:
        comment = str(payload['comment']['body'])
        user = str(payload['comment']['user']['login'])
        match = re.search(r'http(s)?://[^ >]+?\.(png|jpeg|jpg)', comment)
        if match:
            url = match.group()
            response = requests.get(url, allow_redirects=True)
            if response.status_code != 200:
                return "Cannot download image"

            open('image.jpg', 'wb').write(response.content)
            output = detectBars()

            owner = payload['repository']['owner']['login']
            repo_name = payload['repository']['name']

            # Get a git connection as our bot
            # Here is where we are getting the permission to talk as our bot and not
            # as a Python webservice
            installation_id = git_integration.get_installation(
                owner, repo_name
            ).id
            git_connection = Github(
                login_or_token=git_integration.get_access_token(
                    installation_id
                ).token
            )
            repo = git_connection.get_repo(f"{owner}/{repo_name}")

            issue = repo.get_issue(number=payload['issue']['number'])
            issue.create_comment(f"@{user} Your offsets are {output}")
            return "ok"

    return "ok"


if __name__ == "__main__":
    app.run(debug=False, port=5000)
