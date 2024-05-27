import requests
import json
import base64
import hashlib
import pyotp

def generate_totp(email):
    shared_secret = "{}HENNGECHALLENGE003".format(email)
    totp = pyotp.TOTP(shared_secret, digest=hashlib.sha512)
    return totp.now()

def main():
    # Define the URL
    url = "https://api.challenge.hennge.com/challenges/003"

    # Define the JSON string
    json_string = '''
    {{
      "github_url": "https://gist.github.com/esulaimanleonard/c4d69779d290cbc9431b49732c65be75",
      "contact_email": "leonardesulaiman@gmail.com",
      "solution_language": "python"
    }}
    '''.format(email)

    # Convert the JSON string to a Python dictionary
    data = json.loads(json_string)

    # Get the email address from the JSON data
    email = data["contact_email"]

    # Generate TOTP password
    password = generate_totp(email)

    # Prepare Basic Auth header
    auth_str = "{}:{}".format(email, password)
    auth_bytes = auth_str.encode('ascii')
    auth_base64 = base64.b64encode(auth_bytes).decode('ascii')
    headers = {
        "Authorization": "Basic {}".format(auth_base64),
        "Content-Type": "application/json"
    }

    # Make the POST request
    response = requests.post(url, headers=headers, json=data)

    # Print the response
    print("Status Code:", response.status_code)
    print("Response Body:", response.text)

if __name__ == "__main__":
    main()
