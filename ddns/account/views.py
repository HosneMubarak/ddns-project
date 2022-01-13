from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.exceptions import ValidationError
from .models import TopLevelDomainName, FullyQualifiedDomainName, DdnsService
from .serializers import TopLevelDomainNameSerializer, FullyQualifiedDomainNameSerializer, \
    FullyQualifiedDomainNameCreateSerializer, ContactSerializer, DdnsServiceSerializer
import dns.update
import dns.query
import dns.tsigkeyring
import dns.resolver

# Create your views here.
class TopLevelDomainNameView(APIView):
    """ Retrieve all Top Level Domains."""
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        top_level_domain_name_query = TopLevelDomainName.objects.all()
        serializer = TopLevelDomainNameSerializer(top_level_domain_name_query, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = TopLevelDomainNameSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TopLevelDomainNameCreateView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        serializer = TopLevelDomainNameSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ContactView(APIView):

    def post(self, request):
        serializer = ContactSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TopLevelDomainNameDetails(APIView):
    # Check Authentication Credentials, i.e. Token
    permission_classes = (IsAuthenticated,)
    """ Retrieve a single Top Level Domain."""

    def get_object(self, pk):
        try:
            return TopLevelDomainName.objects.get(pk=pk)
        except TopLevelDomainName.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        top_level_domain_name = self.get_object(pk)
        serializer = TopLevelDomainNameSerializer(top_level_domain_name)
        return Response(serializer.data)


class TopLevelDomainNameUpdateDeleteView(APIView):
    """ Update or delete a single Top Level Domain."""
    permission_classes = [IsAdminUser]

    def get_object(self, pk):
        try:
            return TopLevelDomainName.objects.get(pk=pk)
        except TopLevelDomainName.DoesNotExist:
            raise Http404

    def put(self, request, pk):
        top_level_domain_name = self.get_object(pk)
        serializer = TopLevelDomainNameSerializer(top_level_domain_name, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        top_level_domain_name = self.get_object(pk)
        top_level_domain_name.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class FullyQualifiedDomainNameView(APIView):
    """ Retrieve all Fully Qualified Domain Names, e.g. server1.networkgeeks.com """
    # Check Authentication Credentials, i.e. Token
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        # If user is an admin, retrieve all FQDNs
        if request.user.is_staff:
            fully_qualified_domain_name_query = FullyQualifiedDomainName.objects.all()
            serializer = FullyQualifiedDomainNameSerializer(fully_qualified_domain_name_query, many=True)
            return Response(serializer.data)
        # If user is a standard/premium user only retrieve FQDNs related to them
        else:
            user_id = request.user.id
            fully_qualified_domain_name_query = FullyQualifiedDomainName.objects.filter(user_id=user_id)
            serializer = FullyQualifiedDomainNameSerializer(fully_qualified_domain_name_query, many=True)
            return Response(serializer.data)


class FullyQualifiedDomainNameCreateView(APIView):
    """ Create a single FQDN """
    # Check Authentication Credentials, i.e. Token
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        # Get user instance from header
        user = request.user
        # Check if user is a premium user
        user_type = request.user.is_premium
        hostname = request.data['hostname']
        # Get Top Level Domain Name Instance
        top_level_domain_name = TopLevelDomainName.objects.get(id=int(request.data['top_level_domain_name']))
        # Check if domain is a premium domain
        top_level_domain_name_type = top_level_domain_name.premium
        serializer = FullyQualifiedDomainNameCreateSerializer(data=request.data)
        if serializer.is_valid():
            if FullyQualifiedDomainName.objects.filter(hostname=hostname,
                                                       top_level_domain_name=top_level_domain_name).exists():
                raise ValidationError({'error': 'This hostname already exists'})
            elif top_level_domain_name_type:
                if user_type:
                    fullyqualifieddomainame = FullyQualifiedDomainName.objects.create(user=user, hostname=hostname,
                                                                                      top_level_domain_name=top_level_domain_name,
                                                                                      full_domain=f"{hostname}.{top_level_domain_name}")
                    fullyqualifieddomainame.save()
                    return Response(serializer.data, status=status.HTTP_201_CREATED)
                else:
                    raise ValidationError({'error': 'You are not a premium user, please subscribe!'})

            else:
                fullyqualifieddomainame = FullyQualifiedDomainName.objects.create(user=user, hostname=hostname,
                                                                                  top_level_domain_name=top_level_domain_name,
                                                                                  full_domain=f"{hostname}.{top_level_domain_name}")
                fullyqualifieddomainame.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FullyQualifiedDomainNameDetails(APIView):
    """ Retrieve single Fully Qualified Domain Name, e.g. server1.networkgeeks.com """
    # Check Authentication Credentials, i.e. Token
    permission_classes = (IsAuthenticated,)

    def get_object(self, pk, user_id):
        try:
            return FullyQualifiedDomainName.objects.get(pk=pk, user_id=user_id)
        except FullyQualifiedDomainName.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        # If admin user, allow them to retrieve any FQDN
        if request.user.is_staff:
            fully_qualified_domain_name = FullyQualifiedDomainName.objects.get(pk=pk)
            serializer = FullyQualifiedDomainNameCreateSerializer(fully_qualified_domain_name)
            return Response(serializer.data)
        # If user is a standard/premium user only retrieve FQDN related to them
        else:
            user_id = request.user.id
            fully_qualified_domain_name = self.get_object(pk, user_id=user_id)
            serializer = FullyQualifiedDomainNameCreateSerializer(fully_qualified_domain_name)
            return Response(serializer.data)

    def put(self, request, pk):
        top_level_domain_name = TopLevelDomainName.objects.get(id=int(request.data['top_level_domain_name']))
        print(str(top_level_domain_name))
        user_id = request.user.id
        fully_qualified_domain_name = self.get_object(pk, user_id=user_id)
        print(fully_qualified_domain_name)
        serializer = FullyQualifiedDomainNameCreateSerializer(fully_qualified_domain_name, data=request.data)
        if serializer.is_valid():
            serializer.save()
            FullyQualifiedDomainName.objects.filter(user=request.user.id, hostname=request.data['hostname'],
                                                    top_level_domain_name=request.data['top_level_domain_name']).update(
                full_domain=f"{request.data['hostname']}.{str(top_level_domain_name)}")
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        # If admin user, allow them to delete any FQDN
        if request.user.is_staff:
            fully_qualified_domain_name = FullyQualifiedDomainName.objects.get(pk=pk)
            fully_qualified_domain_name.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        # If user is a standard/premium user only allow them to delete their own FQDN
        else:
            user_id = request.user.id
            fully_qualified_domain_name = self.get_object(pk, user_id=user_id)
            fully_qualified_domain_name.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)


class DdnsServiceView(APIView):
    """ Retrieve all DNS Services per user """
    # Check Authentication Credentials, i.e. Token
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        # If admin user, allow them to view any DDNS Service
        if request.user.is_staff:
            ddnsservicequery = DdnsService.objects.all()
            serializer = DdnsServiceSerializer(ddnsservicequery, many=True)
            return Response(serializer.data)
        # If user is a standard/premium user only allow them to view their own DDNS Services
        else:
            user_id = request.user.id
            ddnsservicequery = DdnsService.objects.filter(user_id=user_id)
            serializer = DdnsServiceSerializer(ddnsservicequery, many=True)
            return Response(serializer.data)


class DdnsServiceDetails(APIView):
    """  Retrieve, update or delete a single DNS Service """
    # Check Authentication Credentials, i.e. Token
    permission_classes = (IsAuthenticated,)

    def get_object(self, pk, user_id):
        try:
            return DdnsService.objects.get(pk=pk, user_id=user_id)
        except DdnsService.DoesNotExist:
            raise Http404

    def get(self, request, pk):
        # If admin user, allow them to view any DDNS Service
        if request.user.is_staff:
            ddns_service = DdnsService.objects.get(pk=pk)
            serializer = DdnsServiceSerializer(ddns_service)
            return Response(serializer.data)
        # If user is a standard/premium user only allow them to view their own DDNS Service
        else:
            user_id = request.user.id
            ddns_service = self.get_object(pk, user_id=user_id)
            serializer = DdnsServiceSerializer(ddns_service)
            return Response(serializer.data)

    def put(self, request, pk):
        # If admin user, allow them to change any DDNS Service
        if request.user.is_staff:
            ddns_service = DdnsService.objects.get(pk=pk)
            serializer = DdnsServiceSerializer(ddns_service, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # If user is a standard/premium user only allow them to update their own DDNS Service
        else:
            user_id = request.user.id
            # body_user_id = request.data['user']
            ddns_service = self.get_object(pk, user_id=user_id)
            serializer = DdnsServiceSerializer(ddns_service, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DdnsServiceDelete(APIView):
    def get_object(self, pk):
        try:
            return DdnsService.objects.get(pk=pk)
        except DdnsService.DoesNotExist:
            raise Http404

    def delete(self, request, pk):
        ddns_service = self.get_object(pk)
        ddns_service.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


def new_dns_record(domain, new_hostname, TTL, new_ipaddress, PRIMARY_DNS_SERVER_IP):
    path = '/home/edepina/Documents/ddnsproject/ddns/account/tsig.txt'
    # Open the file as a readonly
    s = open(path, 'r').read()
    # Clean the data
    data = eval(s)
    print(type(data))

    # Format domain correctly
    dns_domain = "%s." % domain

    # get domain and tsig pair from file
    for k, v in data.items():
        if k == dns_domain:
            keyring = dns.tsigkeyring.from_text({k: v})

    # Prepare DNS update
    update = dns.update.Update(
        dns_domain, keyring=keyring,
        keyalgorithm='hmac-md5.sig-alg.reg.int')

    update.replace(new_hostname, TTL, 'A', new_ipaddress)
    response = dns.query.tcp(update, PRIMARY_DNS_SERVER_IP, timeout=5)
    print(response)


class ChangeDdnsServiceIP(APIView):
    """ Method to extract IP address from DDNS Update Client & update DB with new IP address"""

    def post(self, request):

        # Get User ID
        user_id = Token.objects.get(key=request.auth).user.id
        print(user_id)
        # print(content)

        # Create Lists to hold messages to user
        changed_domain_name_list = []
        unchanged_domain_name_list = []
        not_found_domain_name_list = []

        # Getting data from Post request
        data = request.data

        # Get a list of ipv4/domain name
        ddns_service_list = data[0]['services']

        for services in ddns_service_list:
            # Get ipv4 address from packet
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ipv4 = x_forwarded_for.split(',')[0]
                print(ipv4)
            else:
                ipv4 = request.META.get('REMOTE_ADDR')
                print(ipv4)
            # If no ipv4 address supplied in Post Request then use IPv4 address from packet
            if services['ipv4_address'] == 'null':
                ipv4 = ipv4
            # If ipv4 address supplied in Post Request then use
            else:
                ipv4 = services['ipv4_address']
            # Get fully qualified domain name for current IPv4 address
            full_domain = services['full_domain']

            # Check if FQDN exists, if not return an error
            if FullyQualifiedDomainName.objects.filter(user=user_id, full_domain=full_domain).exists():
                # Grab specific domain
                fqdn = FullyQualifiedDomainName.objects.get(user=user_id, full_domain=full_domain)
                # Grab specific domain information
                ddns_service = DdnsService.objects.get(user=user_id, domain=fqdn)
                # Check If Ipv4 address Post Request is different from DB Ipv4 address
                if ddns_service.ipv4_address != ipv4:
                    # Enter this loop only if there is a change in IPv4 address

                    # Update DB Ipv4 address with IPv4 address in Post Request
                    DdnsService.objects.filter(user=user_id, domain=fqdn).update(ipv4_address=ipv4)

                    # Prepare data needed to send a DDNS Update to DNS server @ 30.0.0.10
                    domain = fqdn.top_level_domain_name.top_level_domain_name
                    hostname = fqdn.hostname
                    TTL = "60"
                    PRIMARY_DNS_SERVER_IP = "30.0.0.10"

                    # Send DNS Update to DNS server
                    new_dns_record(domain, hostname, TTL, ipv4, PRIMARY_DNS_SERVER_IP)

                    print(f"IPv4 address change detected for {full_domain}")
                    changed_domain_name_list.append(full_domain)
                # No change in IPv4 address detected
                else:
                    print(f"No IPv4 address change detected for {full_domain}")
                    unchanged_domain_name_list.append(full_domain)
            # If domain supplied in Post Request does not exist do not take any action, and create message to user
            else:
                print(f"{full_domain} has not been found!")
                not_found_domain_name_list.append(full_domain)

        context = {
            "changed_domain_name_list": changed_domain_name_list,
            "unchanged_domain_name_list": unchanged_domain_name_list,
            "not_found_domain_name_list": not_found_domain_name_list,
        }
        return Response(context)
