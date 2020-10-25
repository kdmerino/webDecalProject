import unittest
import requests
import subprocess
import time
import sys

def fail(msg):
    print('error:', msg)

def main():
    print('Running signup tests...')
    test_signup()
    print('Finished signup tests')

    print('Running signin tests...')
    test_signin()
    print('Finished signin tests')

    print('Running logout tests...')
    test_logout()
    print('Finished logout tests')

    print('Running verify tests...')
    test_verify()
    print('Finished verify tests')

def test_signup():
    url = "http://localhost:80/api/auth/signup"
    payload = {'username': 'test_user', 'email': 'test_email@berkeley.edu', 'password': 'test_password'}
    response = requests.post(url, json=payload)
    if response.status_code != 201:
        fail('expected status code 201 but was {}'.format(response.status_code))
    if len(response.cookies) != 2:
        fail('expected 2 cookies but got {}'.format(len(response.cookies)))
    if 'access_token' not in response.cookies:
        fail('access_token not in cookies')
    if 'refresh_token' not in response.cookies:
        fail('refresh_token not in cookies')

    url = "http://localhost:80/api/auth/signup"
    payload = {'username': 'test_user', 'email': 'test_email2@berkeley.edu', 'password': 'test_password'}
    response = requests.post(url, json=payload)
    if response.status_code != 409:
        fail('expected status code 409 but was {}'.format(response.status_code))

    url = "http://localhost:80/api/auth/signup"
    payload = {'username': 'test_user2', 'email': 'test_email@berkeley.edu', 'password': 'test_password'}
    response = requests.post(url, json=payload)
    if response.status_code != 409:
        fail('expected status code 409 but was {}'.format(response.status_code))

def test_signin():
    url = "http://localhost:80/api/auth/signup"
    payload = {'username': 'test_user2', 'email': 'test_email2@berkeley.edu', 'password': 'test_password2'}
    response = requests.post(url, json=payload)

    url = "http://localhost:80/api/auth/signin"
    payload = {'username': 'test_user2', 'email': 'test_email2@berkeley.edu', 'password': 'test_password2'}
    response = requests.post(url, json=payload)
    if response.status_code != 200:
        fail('expected status code 200 but was {}'.format(response.status_code))
    if len(response.cookies) != 2:
        fail('expected 2 cookies but got {}'.format(len(response.cookies)))
    if 'access_token' not in response.cookies:
        fail('access_token not in cookies')
    if 'refresh_token' not in response.cookies:
        fail('refresh_token not in cookies')

def test_logout():
    url = "http://localhost:80/api/auth/signup"
    payload = {'username': 'test_user3', 'email': 'test_email3@berkeley.edu', 'password': 'test_password3'}
    response = requests.post(url, json=payload)

    url = "http://localhost:80/api/auth/logout"
    response = requests.post(url, cookies=dict(response.cookies))
    if response.status_code != 200:
        fail('expected status code 200 but was {}'.format(response.status_code))
    if len(response.cookies) != 0:
        fail('expected 0 cookies but got {}'.format(len(response.cookies)))

def test_verify():
    url = "http://localhost:80/api/auth/verify"
    params = {'token': 'dummy'}
    response = requests.post(url, params=params)
    if response.status_code != 400:
        fail('expected status code 400 but was {}'.format(response.status_code))

if __name__ == '__main__':
    main()
