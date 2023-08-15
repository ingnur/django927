# Generated by Django 4.1.7 on 2023-08-03 04:14

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('Appbanco', '0002_remove_cliente_user_alter_cliente_documento'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cliente',
            name='documento',
            field=models.TextField(max_length=30, primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='user',
            name='documento',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to='Appbanco.cliente'),
        ),
    ]
