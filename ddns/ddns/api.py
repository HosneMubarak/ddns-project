import requests
from .settings import BASE_URL_API, BASE_AUTH_URL_API
from requests.exceptions import HTTPError


def edit_single_service_api(**args):
    try:
        ipv4_address = args['ipv4_address']
        ttl = args['ttl']
        url = BASE_URL_API + "/ddns_service/" + args['id']
        token = args['token']
        response = requests.put(url, headers={"Content-Type": 'application/json',
                                              "Authorization": 'Token' + ' ' + token,
                                              },
                                json={"ipv4_address": ipv4_address,
                                      "ttl": ttl}
                                )

        response.raise_for_status()

    except HTTPError as http_error:
        print(f"edit_single_service_api():{http_error}")
    except Exception as err:
        print(f"edit_single_service_api():{err}")
    else:
        print("edit_single_service_api() success")

    return response


def get_single_service_api(**args):
    try:
        url = BASE_URL_API + "/ddns_service/" + args['id']
        token = args['token']
        response = requests.get(url, headers={"Content-Type": 'application/json',
                                              "Authorization": 'Token' + ' ' + token,
                                              },
                                )

        response.raise_for_status()

    except HTTPError as http_error:
        print(f"get_single_service_api():{http_error}")
    except Exception as err:
        print(f"get_single_service_api():{err}")
    else:
        print("get_single_service_api() success")

    return response


def delete_service_api(**args):
    try:
        url = BASE_URL_API + "/fqdn/" + args['id']
        token = args['token']
        response = requests.delete(url, headers={"Content-Type": 'application/json',
                                                 "Authorization": 'Token' + ' ' + token,
                                                 },
                                   )

        response.raise_for_status()

    except HTTPError as http_error:
        print(f"delete_service_api():{http_error}")
    except Exception as err:
        print(f"delete_service_api():{err}")
    else:
        print("delete_service_api() success")

    return response


def get_all_ddns_services_api(**args):
    try:
        url = BASE_URL_API + "/ddns_service/"
        token = args['token']
        response = requests.get(url, headers={"Content-Type": 'application/json',
                                              "Authorization": 'Token' + ' ' + token,
                                              },
                                )

        response.raise_for_status()

    except HTTPError as http_error:
        print(f"get_all_ddns_services_api():{http_error}")
    except Exception as err:
        print(f"get_all_ddns_services_api():{err}")
    else:
        print("get_all_ddns_services_api() success")

    return response


def create_fqdn_api(**args):
    try:

        hostname = args['hostname']
        top_level_domain_name = args['tld']
        url = BASE_URL_API + "/fqdn/create/"
        token = args['token']
        response = requests.post(url, headers={"Content-Type": 'application/json',
                                               "Authorization": 'Token' + ' ' + token,
                                               },
                                 json={"hostname": hostname,
                                       "top_level_domain_name": top_level_domain_name},
                                 )

        response.raise_for_status()

    except HTTPError as http_error:
        print(f"create_fqdn_api():{http_error}")
    except Exception as err:
        print(f"create_fqdn_api():{err}")
    else:
        print("create_fqdn_api() success")

    return response


def get_all_top_level_domain(**args):
    try:
        token = args['token']
        url = BASE_URL_API + "/tld/"
        response = requests.get(url,
                                headers={"Content-Type": 'application/json', "Authorization": 'Token' + ' ' + token}, )
        response.raise_for_status()

    except HTTPError as http_error:
        print(f"get_all_top_level_domain():{http_error}")
    except Exception as err:
        print(f"get_all_top_level_domain():{err}")
    else:
        print("get_all_top_level_domain() success")

    return response


def get_all_ddns_services(**args):
    try:
        url = BASE_URL_API + "/ddns_service/"
        response = requests.get(url, headers={"Content-Type": 'application/json'}, verify=False)
        response.raise_for_status()

    except HTTPError as http_error:
        print(f"get_all_ddns_service():{http_error}")
    except Exception as err:
        print(f"get_all_ddns_service():{err}")
    else:
        print("get_all_ddns_service() success")

    return response


def user_information_api(**args):
    try:

        url = BASE_AUTH_URL_API + "/auth/users/me"
        token = args['token']
        response = requests.get(url, headers={"Content-Type": 'application/json',
                                              "Authorization": 'Token' + ' ' + token,
                                              }
                                )
        response.raise_for_status()

    except HTTPError as http_error:
        print(f"user_information_api():{http_error}")
    except Exception as err:
        print(f"user_information_api():{err}")
    else:
        print("user_information_api() success")

    return response


def login_api(**args):
    try:

        url = BASE_AUTH_URL_API + "/auth/token/login/"
        response = requests.post(url, headers={"Content-Type": 'application/json'},
                                 json={"username": args['username'],
                                       "password": args['password']}
                                 )
        response.raise_for_status()

    except HTTPError as http_error:
        print(f"login_api():{http_error}")
    except Exception as err:
        print(f"login_api():{err}")
    else:
        print("login_api() success")

    return response


def logout_api(**args):
    try:
        token = args['token']
        url = BASE_AUTH_URL_API + "/auth/token/logout"
        response = requests.post(url, headers={"Content-Type": 'application/json',
                                               "Authorization": 'Token' + ' ' + token,
                                               }
                                 )
        response.raise_for_status()

    except HTTPError as http_error:
        print(f"logout_api():{http_error}")
    except Exception as err:
        print(f"logout_api():{err}")
    else:
        print("logout_api() success")

    return response


def signup_api(**args):
    try:

        url = BASE_AUTH_URL_API + "/auth/users/"
        response = requests.post(url, headers={"Content-Type": 'application/json'},
                                 json={"username": args['username'],
                                       "email": args['email'],
                                       "password": args['password']}
                                 )
        response.raise_for_status()

    except HTTPError as http_error:
        print(f"signup_api():{http_error}")
    except Exception as err:
        print(f"signup_api():{err}")
    else:
        print("signup_api() success")

    return response


def reset_password_api(**args):
    try:
        url = BASE_AUTH_URL_API + "/auth/users/reset_password/"
        response = requests.post(url, headers={"Content-Type": 'application/json'},
                                 json={"email": args['email'],
                                       }
                                 )
        response.raise_for_status()

    except HTTPError as http_error:
        print(f"reset_password_api():{http_error}")
    except Exception as err:
        print(f"reset_password_api():{err}")
    else:
        print("reset_password_api() success")

    return response


def reset_password_confirm_api(**args):
    try:
        url = BASE_AUTH_URL_API + "/auth/users/reset_password_confirm/"
        response = requests.post(url, headers={"Content-Type": 'application/json'},
                                 json={"uid": args['uid'],
                                       "token": args['token'],
                                       "new_password": args['new_password']}
                                 )
        response.raise_for_status()

    except HTTPError as http_error:
        print(f"reset_password_confirm_api():{http_error}")
    except Exception as err:
        print(f"reset_password_confirm_api():{err}")
    else:
        print("reset_password_confirm_api() success")

    return response


def set_password_api(**args):
    try:
        token = args['token']
        url = BASE_AUTH_URL_API + "/auth/users/set_password/"
        response = requests.post(url,
                                 headers={"Content-Type": 'application/json', "Authorization": 'Token' + ' ' + token},
                                 json={"new_password": args['new_password'],
                                       "re_new_password": args['re_new_password'],
                                       "current_password": args['current_password']}
                                 )
        response.raise_for_status()

    except HTTPError as http_error:
        print(f"set_password_api():{http_error}")
    except Exception as err:
        print(f"set_password_api():{err}")
    else:
        print("set_password_api() success")

    return response


def create_contactus_api(**args):
    try:

        fullname = args['fullname']
        email = args['email']
        phone_number = args['phone_number']
        message = args['message']
        url = BASE_URL_API + "/contact-us/"
        response = requests.post(url, headers={"Content-Type": 'application/json',
                                               },
                                 json={"fullname": fullname,
                                       "email": email,
                                       "phone_number": phone_number,
                                       "message": message},
                                 )

        response.raise_for_status()

    except HTTPError as http_error:
        print(f"create_contactus_api():{http_error}")
    except Exception as err:
        print(f"create_contactus_api():{err}")
    else:
        print("create_contactus_api() success")

    return response
