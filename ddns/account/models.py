from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.contrib.auth.models import (BaseUserManager, AbstractBaseUser)


# Database Models
class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        if not username:
            raise ValueError('Users must have a username')

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            # date_of_birth=date_of_birth,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            email,
            username,
            password=password,
            # date_of_birth=date_of_birth,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True,
    )
    username = models.CharField(max_length=255, unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_premium = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin


class TopLevelDomainName(models.Model):
    """This class creates a table that holds Top Level Domain Info such as example.com"""
    top_level_domain_name = models.CharField(max_length=255)
    premium = models.BooleanField(default=False)

    def __str__(self):
        return self.top_level_domain_name


class Contact(models.Model):
    """This class creates a table used for the contact form"""
    fullname = models.CharField(max_length=255)
    email = models.EmailField()
    phone_number = models.IntegerField()
    message = models.TextField()
    def __str__(self):
        return f"{self.fullname}"



class FullyQualifiedDomainName(models.Model):
    """This class creates a table holding a fqdn such as hostname.example.com"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    hostname = models.CharField(max_length=255)
    top_level_domain_name = models.ForeignKey(TopLevelDomainName, on_delete=models.CASCADE)
    full_domain = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.hostname}.{self.top_level_domain_name.top_level_domain_name}"


class DdnsService(models.Model):
    """This class creates a table holding all the information on a related to a domain"""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    domain = models.ForeignKey(FullyQualifiedDomainName, on_delete=models.CASCADE)
    ipv4_address = models.GenericIPAddressField(protocol='IPv4', blank=True, null=True)
    ipv6_address = models.GenericIPAddressField(protocol='IPv6', blank=True, null=True)
    ttl = models.IntegerField()
    last_update = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.domain.hostname


# Signal
def create_ddns_service(sender, instance, created, **kwargs):
    """This class automatically creates a ddns service when a fqdn is created"""
    if created:
        DdnsService.objects.create(user=instance.user, domain=instance, ttl=120, ipv4_address='127.0.0.1',
                                   ipv6_address='2001::1')
        print(f'sender:{sender}, created-{created} instance-{instance} kw-{kwargs}')


post_save.connect(create_ddns_service, sender=FullyQualifiedDomainName)
