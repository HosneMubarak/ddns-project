from django.contrib import admin
from .models import User
from .models import TopLevelDomainName, FullyQualifiedDomainName,DdnsService, Contact


# Register your models here.
admin.site.register(TopLevelDomainName)
admin.site.register(FullyQualifiedDomainName)
admin.site.register(DdnsService)
admin.site.register(User)
admin.site.register(Contact)

