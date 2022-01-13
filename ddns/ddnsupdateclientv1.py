#!/usr/bin/env python3.9

import json
import requests
import sys

def Convert(lst):
    res_dct = {lst[i]: lst[i + 1] for i in range(0, len(lst), 2)}
    return res_dct

def send_post_request(data, token):
    """ This function takes a data List, converts it to JSON, and sends A POST request
    to the API """
    # Convert to String
    data = json.dumps(data)
    url = "http://30.0.0.20:8000/api/change-ddns/"
    headers = {'Content-type': 'application/json','Authorization': f"Token {token}"}
    # Send POST request
    r = requests.post(url, data=data, headers=headers)
    # Print the response in JSON format to the POST request
    print(r.json())

# Check if arguments have been entered via CLI, if not, use conf file instead
if len(sys.argv) > 1:
    # Convert string arguments into a list
    domain_list_args = list(sys.argv[2:])

    # Convert CLI arguments list to dictionary
    my_dic = Convert(domain_list_args)

    # Initiliaze new list
    new_list = []
    for k, v in my_dic.items():
        print(k, v)
        result = {"ipv4_address": v, "full_domain": k}
        new_list.append(result)
    # print(f"Converted Dict to following List: {new_list}")
    token = sys.argv[1]
    # print(f"Token is: {token}")
    # Add new list to services
    data = [
        {
            "services": new_list
        }
    ]
    # Initiate POST request
    send_post_request(data, token)

else:
    # Location of configuration file on disk
    path = '/home/edepina/Documents/ddnsclient/ddns_client_conf.txt'
    # Open the file as a readonly
    s = open(path, 'r').read()
    # Clean the data
    data = eval(s)
    token = data[0]['token']
    data = [{"services":list(data[1]['services'])}]
    # print(data)
    # Initiate POST request
    send_post_request(data, token)

