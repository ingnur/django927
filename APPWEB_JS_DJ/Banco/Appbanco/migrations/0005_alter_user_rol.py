# Generated by Django 4.1.7 on 2023-08-09 13:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Appbanco', '0004_alter_cliente_apellido_alter_cliente_celular_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='rol',
            field=models.CharField(max_length=100),
        ),
    ]