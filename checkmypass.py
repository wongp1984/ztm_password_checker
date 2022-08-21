import requests
import hashlib
import sys
from pathlib import Path

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)  # the response returns k-autonimity hash values beginning with the 5 characters of the given hash
    if res.status_code != 200:
        raise RuntimeError(f'Error in fetching: {res.status_code}')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes_split = (line.split(':') for line in hashes.text.splitlines())
    for h,count in hashes_split:
        if h==hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    #check pwd if it exists in api response
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1pwd[:5], sha1pwd[5:]
    response = request_api_data(first5_char)
    return  get_password_leaks_count(response, tail)

def main(file):
    path = Path(file)
    if not path.is_file(): # check the given file exists or not
        return f'The file {file} does not exists!'
    with open(file, mode='r') as myfile:
        list_password = (line.strip() for line in myfile.readlines())
        for password in list_password:
            count = pwned_api_check(password)
            if count:
                print(f'{password} was found {count} times.  You should probably change the password!')
            else:
                print(f'{password} was not found. Carry on.')
    return 'DONE!'

if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1]))
    except IndexError:
        print('''This functions checks whether your password have been pwned.  
        Usage: python checkmypassword.py <path_to_passwords_file>''')

