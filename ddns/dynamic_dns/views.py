from django.shortcuts import render
from ddns.api import get_all_ddns_services


def dynamic_dns_home_page(request):
    response = get_all_ddns_services()
    print(response.json())
    context = {'all_ddns_service_list': response.json()}
    return render(request, 'dynamic_dns/dynamic_dns_home_page.html', context)


def dynamic_dns_details(request):
    return render(request, 'dynamic_dns/dynamic_dns_details.html')
