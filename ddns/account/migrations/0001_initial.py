# Generated by Django 3.2.9 on 2021-11-30 16:06

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('email', models.EmailField(max_length=255, unique=True, verbose_name='email address')),
                ('username', models.CharField(max_length=255, unique=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_admin', models.BooleanField(default=False)),
                ('is_premium', models.BooleanField(default=False)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='TopLevelDomainName',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('top_level_domain_name', models.CharField(max_length=255)),
                ('premium', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='FullyQualifiedDomainName',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('hostname', models.CharField(max_length=255)),
                ('full_domain', models.CharField(blank=True, max_length=255, null=True)),
                ('top_level_domain_name', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='account.topleveldomainname')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='DdnsService',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ipv4_address', models.GenericIPAddressField(blank=True, null=True, protocol='IPv4')),
                ('ipv6_address', models.GenericIPAddressField(blank=True, null=True, protocol='IPv6')),
                ('ttl', models.IntegerField()),
                ('last_update', models.DateTimeField(auto_now=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('domain', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='account.fullyqualifieddomainname')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
