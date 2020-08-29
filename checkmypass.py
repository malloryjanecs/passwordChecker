'''
username: malloryjb
date: 2020-08-29
project: password checker
description: this script receives a text file to check passwords
	for their exposure in data breaches.
	the text file is used to ensure the checked password isn't logged
'''
import requests
import sys
import hashlib


def request_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}')
	return res


def get_password_leaks_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0


def pwned_api_check(password):
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	api_request, tail = sha1password[:5], sha1password[5:]
	api_response = request_api_data(api_request)
	return get_password_leaks_count(api_response, tail)


def main(pass_list):
	for pw in pass_list:
		pw = pw.strip('\n')
		count = pwned_api_check(pw)
		if count:
			print(f'{"*"*len(pw)} was found {count} times')
		else:
			print(f'{"*"*len(pw)} was not found.')


def read_from_file(file):
	with open(file) as pw_file:
		li = pw_file.readlines()
		return li


if __name__ == '__main__':
	sys.exit(main(read_from_file(sys.argv[1])))
