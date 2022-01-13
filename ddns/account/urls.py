from django.urls import path
from .views import FullyQualifiedDomainNameView, FullyQualifiedDomainNameCreateView, DdnsServiceDelete, \
    ChangeDdnsServiceIP, TopLevelDomainNameCreateView, TopLevelDomainNameUpdateDeleteView, ContactView, DdnsServiceView, \
    TopLevelDomainNameView, TopLevelDomainNameDetails, FullyQualifiedDomainNameDetails, DdnsServiceDetails

urlpatterns = [
    path('tld/', TopLevelDomainNameView.as_view(), name='tld'),
    path('tld/create/', TopLevelDomainNameCreateView.as_view(), name='tld_create'),
    path('tld/<int:pk>', TopLevelDomainNameDetails.as_view(), name='tld_details'),
    path('tld/update_delete/<int:pk>/', TopLevelDomainNameUpdateDeleteView.as_view(), name='tld_update_delete'),
    path('fqdn/', FullyQualifiedDomainNameView.as_view(), name='fqdn'),
    path('fqdn/create/', FullyQualifiedDomainNameCreateView.as_view(), name='fqdn_create'),
    path('fqdn/<int:pk>', FullyQualifiedDomainNameDetails.as_view(), name='fqdn_details'),
    path('ddns_service/', DdnsServiceView.as_view(), name='ddns_service'),
    path('ddns_service/<int:pk>', DdnsServiceDetails.as_view(), name='ddns_service_details'),
    path('ddns_service/delete/<int:pk>', DdnsServiceDelete.as_view(), name='delete'),
    path('change-ddns/', ChangeDdnsServiceIP.as_view(), name='change-ddns'),
    path('contact-us/', ContactView.as_view(), name='contact-us')
]
