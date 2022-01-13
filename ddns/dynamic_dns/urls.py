from django.urls import path
from .views import dynamic_dns_home_page, dynamic_dns_details

app_name = 'dynamic_dns'

urlpatterns = [
    path('', dynamic_dns_home_page, name='dynamic_dns_home_page'),
    path('ddns_details', dynamic_dns_details, name='dynamic_dns_details')
]
