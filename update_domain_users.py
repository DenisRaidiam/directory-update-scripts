import os
import requests
import json
from dotenv import load_dotenv

ORG_ID = "3ffb8191-13c1-43e3-ac0e-5fbefacc6fc4"
AUTH_DOMAIN = "Ergonomic Frozen Cheese"
BASE_URL = "https://matls-api.sandbox.raidiam.io"

load_dotenv()

ORG = os.getenv('ORG')
ENV = os.getenv('ENV')


def main():
    access_token = f'Bearer {os.getenv("ACCESS_TOKEN")}'

    domain_users_response = get_domain_user(access_token)

    if domain_users_response:
        domain_users = domain_users_response['content']
        for admin in domain_users:
            domain_user_email = admin['Email']
            domain_user_user_id = admin['AuthorisationDomainUserId']
            status = admin['Status']
            if status == 'Active' and 'raidiam' not in domain_user_email:
                print(f"Updating organization admin: {domain_user_email}")
                update_domain_user_status(access_token, domain_user_user_id, domain_user_email)


def get_domain_user(access_token):
    response = requests.get(f'{BASE_URL}/organisations/{ORG_ID}/{AUTH_DOMAIN}/users',
                            headers={'Authorization': access_token},
                            verify=False,
                            cert=(f'certs/{ORG}/{ENV}/transport.pem', f'certs/{ORG}/{ENV}/transport.key'))

    if response.status_code == 200:
        domain_users_response = json.loads(response.content.decode('utf-8'))
        users = domain_users_response.get('content', [])

        active_users = [user for user in users if user.get("Status") == "Active"]
        inactive_users = [user for user in users if user.get("Status") == "Inactive"]

        print(f"Total Number of users: {len(users)}")
        print(f"Number of Active users: {len(active_users)}")
        print(f"Number of Inactive users: {len(inactive_users)}")

        print("\nActive Users:")
        for user in active_users:
            print(f"Email: {user.get('Email', 'No email provided')}")

        print("\nInactive Users:")
        for user in inactive_users:
            print(f"Email: {user.get('Email', 'No email provided')}")
        return domain_users_response
    else:
        print(f"Failed to retrieve organization admins. Status code: {response.status_code}")
        return None


def update_domain_user_status(access_token, domain_user_user_id, domain_user_email):
    url = f'{BASE_URL}/organisations/{ORG_ID}/{AUTH_DOMAIN}/users/{domain_user_email}/{domain_user_user_id}'

    payload = {
        "Status": "Inactive"
    }

    response = requests.put(url,
                            json=payload,
                            headers={'Authorization': access_token},
                            verify=False,
                            cert=(f'certs/{ORG}/{ENV}/transport.pem', f'certs/{ORG}/{ENV}/transport.key'))

    if response.status_code == 200:
        print(f"Successfully updated status for {domain_user_email}")
    else:
        print(f"Failed to update status for {domain_user_email}. Status code: {response.status_code}")


if __name__ == '__main__':
    main()
