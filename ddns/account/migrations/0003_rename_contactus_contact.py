# Generated by Django 3.2.9 on 2022-01-10 15:39

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0002_contactus'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='ContactUs',
            new_name='Contact',
        ),
    ]