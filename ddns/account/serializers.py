from rest_framework import serializers
from .models import TopLevelDomainName
from .models import FullyQualifiedDomainName
from .models import DdnsService
from .models import Contact
from rest_framework.exceptions import ValidationError


# this serializer class will convert TopLevelDomainName to a json format
class TopLevelDomainNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = TopLevelDomainName
        fields = "__all__"


# this serializer class will convert Contact to a json format
class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = "__all__"


class FullyQualifiedDomainNameSerializer(serializers.ModelSerializer):
    top_level_domain_name = TopLevelDomainNameSerializer(read_only=True)

    class Meta:
        model = FullyQualifiedDomainName
        fields = "__all__"


class FullyQualifiedDomainNameCreateSerializer(serializers.ModelSerializer):
    # top_level_domain_name = TopLevelDomainNameSerializer(read_only=True)
    class Meta:
        model = FullyQualifiedDomainName
        fields = ["hostname", "top_level_domain_name"]


class DdnsServiceSerializer(serializers.ModelSerializer):
    domain = FullyQualifiedDomainNameSerializer(read_only=True)

    class Meta:
        model = DdnsService
        fields = ["id", "ipv4_address", "ipv6_address", "ttl", "domain", "last_update", "created_at"]
