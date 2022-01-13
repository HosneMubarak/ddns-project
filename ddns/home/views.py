from django.shortcuts import render, redirect
from django.http import HttpResponse
from ddns.api import signup_api, login_api, user_information_api, logout_api, reset_password_api, reset_password_confirm_api, set_password_api
from ddns.api import get_all_top_level_domain, create_fqdn_api, get_all_ddns_services_api, delete_service_api, get_single_service_api, edit_single_service_api, create_contactus_api


def root_home_page(request):
    if request.session.get('auth_token', False):
        return redirect('home:home_page')
    else:
        if request.POST:
            fullname = request.POST.get('fullname')
            email = request.POST.get('email')
            phone_number = request.POST.get('phone_number')
            message = request.POST.get('message')
            contactus_response = create_contactus_api(fullname=fullname, email=email, phone_number=phone_number, message=message)
            if contactus_response.status_code == 201:
                return redirect(request.get_full_path())
            else:
                return redirect(request.get_full_path())
        return render(request, 'home_page/home_page.html')


def set_password_page(request):
    if request.session.get('auth_token', False):
        token = request.session['auth_token']
        if request.POST:
            new_password = request.POST.get('new_password')
            re_new_password = request.POST.get('re_new_password')
            current_password = request.POST.get('current_password')
            print(f"New Password: {new_password}", f"Confirm New Password:{re_new_password}", f"Existing Password: {current_password}")
            response = set_password_api(new_password=new_password, re_new_password=re_new_password,current_password=current_password, token=token )
            if response.status_code == 204:
                return redirect('home:home_page')
            else:
                return redirect(request.get_full_path())
        else:
            return render(request, 'auth/set_password.html')
    else:
        return redirect('home:login_page')



def single_service(request, id):
    context = {}
    if request.session.get('auth_token', False):
        token = request.session['auth_token']
        response = get_single_service_api(token=token, id=id)
        if response.status_code == 200:
            context = {
                "single_ddns_service_details": response.json()
            }
        if request.POST:
            ipv4_address = request.POST.get('ipv4_address')
            ttl = request.POST.get('ttl')
            edit_response = edit_single_service_api(ipv4_address=ipv4_address, ttl=ttl, token=token, id=id)
            if edit_response.status_code == 200:
                return redirect('home:services')
            else:
                return redirect(request.get_full_path())


    else:
        return redirect('home:login_page')

    return render(request, 'services/single_service.html', context)



def services(request):
    if request.session.get('auth_token', False):
        token = request.session['auth_token']
        response = get_all_ddns_services_api(token=token)
        if request.POST:
            id = request.POST.get('service_id')
            delete_response = delete_service_api(token=token, id=str(id))
            if delete_response.status_code == 204:
                return redirect(request.get_full_path())
            else:
                return redirect(request.get_full_path())

        context = {
            "all_ddns_services_list": response.json()
        }
    else:
        return redirect('home:login_page')

    return render(request, 'services/services.html', context)

# Create your views here.
def home_page(request):
    if request.session.get('auth_token', False):
        token = request.session['auth_token']
        user_information = user_information_api(token=token)
        request.session['user_information'] = user_information.json()
        all_top_level_domain = get_all_top_level_domain(token=token)
        if request.POST:
            hostname = request.POST.get('hostname')
            tld = request.POST.get('tld')
            response = create_fqdn_api(hostname=hostname, tld=tld, token=token)
            # print(response.json())
            if response.status_code == 201:
                return redirect('home:services')
            else:
                return redirect(request.get_full_path())
            # print(hostname, tld)
        context = {
            "user_information": user_information.json(),
            "all_top_level_domain": all_top_level_domain.json()
        }

    else:
        return redirect('home:login_page')

    return render(request, 'home/home.html', context)

def logout(request):
    token = request.session['auth_token']
    response = logout_api(token=token)
    if response.status_code == 204:
        del request.session['auth_token']
        del request.session['user_information']
        return redirect('home:login_page')
    else:
        return redirect(request.get_full_path())


def login_page(request):
    if request.POST:

        username = request.POST.get('username')
        password = request.POST.get('password')
        # print(username, password)
        response = login_api(username=username, password=password)
        print(response.json())
        if response.status_code == 200:
            request.session['auth_token'] = response.json()['auth_token']
            print(request.session['auth_token'],)
            return redirect('home:home_page')
        else:
            return redirect('home:login_page')

    return render(request, 'auth/login.html')


def signup_page(request):
    if request.POST:
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        print(username, email)
        if password1 == password2:
            response = signup_api(username=username, email=email, password=password1)
            if response.status_code == 201:
                return redirect('home:login_page')
            else:
                return redirect('home:signup_page')
            print(response.json())
        else:
            return redirect('home:signup_page')

    return render(request, 'auth/signup.html')


def signup_page(request):
    if request.POST:
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        print(username, email)
        if password1 == password2:
            response = signup_api(username=username, email=email, password=password1)
            if response.status_code == 201:
                return redirect('home:login_page')
            else:
                return redirect('home:signup_page')
            print(response.json())
        else:
            return redirect('home:signup_page')

    return render(request, 'auth/signup.html')


def forgot_password_page(request):
    if request.POST:
        email = request.POST.get('email')
        response = reset_password_api(email=email)
        if response.status_code == 204:
            return redirect('home:login_page')
        else:
            return redirect(request.get_full_path())
        print(response.json())
    else:
        return render(request, 'auth/forgot_password.html')


def reset_password_confirm(request, uid, token):
    if request.POST:
        new_password = request.POST.get('new_password')
        response = reset_password_confirm_api(uid=uid, token=token, new_password=new_password)
        if response.status_code == 204:
            return redirect('home:login_page')
        else:
            return redirect('home:forgot_password_page')
        print(response.json())
    else:
        return render(request, 'auth/password_reset_confirm.html')