import hashlib
import hmac
import logging
import os
import re
import requests

from flask import Flask, request
from github import Github, GithubIntegration
from PIL import Image, ImageOps
import numpy as np

logging.basicConfig(encoding='utf-8', level=logging.INFO)
logger = logging.getLogger("custom-game-area")

app = Flask(__name__)
app_id = int(os.getenv('APP_ID', '236258'))
with open(
    os.path.normpath('./private_key.pem'),
    'r'
) as cert_file:
    app_key = cert_file.read()
webhook_secret = os.getenv('WEBHOOK_SECRET')

black_threshold = int(os.getenv('THRESHOLD', 30))

# Create an GitHub integration instance
git_integration = GithubIntegration(
    app_id,
    app_key,
)


def validate_signature(payload, secret):
    if not payload:
        return False

    # Get the signature from the payload
    signature_header = payload.headers['X-Hub-Signature']
    if not signature_header:
        return False

    sha_name, github_signature = signature_header.split('=')
    if sha_name != 'sha1':
        logger.warning('X-Hub-Signature in payload headers was not sha1=****')
        return False

    # Create our own signature
    body = payload.data
    local_signature = hmac.new(
        secret.encode('utf-8'),
        msg=body,
        digestmod=hashlib.sha1
    )

    # See if they match
    return hmac.compare_digest(local_signature.hexdigest(), github_signature)


def detectBars():
    img = Image.open('image.jpg')

    gray = ImageOps.grayscale(img)
    # Turn gray image into matrix of booleans where black == False
    mask = np.array(gray) > black_threshold
    # For each column, check if any value is True.
    mask0 = mask.any(0)
    # Do the same thing for each row.
    mask1 = mask.any(1)

    # Get the index of the first True value
    left = mask0.argmax()
    # Get the index of the first True value starting from the right
    right = mask0[::-1].argmax()
    top = mask1.argmax()
    bottom = mask1[::-1].argmax()

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
    logger.info("Received request")

    if not validate_signature(request, webhook_secret):
        logger.warning("Payload secret is incorrect")
        return "", 400

    # Get the event payload
    payload = request.json

    if not payload:
        logger.warning("No payload")
        return "", 400

    if payload['action'] != "created":
        logger.info("Action was not 'created'")
        return ""

    issue_number = int(payload['issue']['number'])
    if issue_number in [1347, 1377]:
        comment = str(payload['comment']['body'])
        user = str(payload['comment']['user']['login'])
        match = re.search(r'http(s)?://[^ >]+?\.(png|jpeg|jpg)', comment)
        if match:
            logger.info("Found image")
            url = match.group()
            response = requests.get(url, allow_redirects=True)
            if response.status_code != 200:
                logger.warning("Cannot download image")
                return "", 500

            with open('image.jpg', 'wb') as image:
                image.write(response.content)

            output = detectBars()

            os.remove('image.jpg')

            owner = payload['repository']['owner']['login']
            repo_name = payload['repository']['name']

            # Get a git connection as our bot
            installation_id = git_integration.get_installation(
                owner, repo_name
            ).id
            git_connection = Github(
                login_or_token=git_integration.get_access_token(
                    installation_id
                ).token
            )
            repo = git_connection.get_repo(f"{owner}/{repo_name}")

            issue = repo.get_issue(issue_number)
            comment_to_post = f"@{user} "
            if output:
                comment_to_post += f"Your offsets are {output}"
            else:
                comment_to_post += "Could not detect any black bars in your image."
            issue.create_comment(comment_to_post)
            logger.info("Created comment")
        else:
            logger.info("No image found")
    else:
        logger.info("Issue number is not relevant")

    return ""


if __name__ == "__main__":
    app.run(debug=True, port=5000)
