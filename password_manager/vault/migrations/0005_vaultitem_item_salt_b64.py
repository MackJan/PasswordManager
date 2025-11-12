from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vault', '0004_alter_vaultitem_ciphertext_b64_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='vaultitem',
            name='item_salt_b64',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
    ]
