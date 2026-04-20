from .models import Address
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.db.models.signals import pre_save
from core.utils.storages import delete_if_changed, delete_file_fields

CAMPOS_ADDRESS = ['photo']

@receiver(post_delete, sender=Address)
def address_post_delete(sender, instance, **kwargs):
    delete_file_fields(instance, CAMPOS_ADDRESS)

@receiver(pre_save, sender=Address)
def address_pre_save(sender, instance, **kwargs):
    if not instance.pk:
        return
    try:
        anterior = Address.objects.get(pk=instance.pk)
    except Address.DoesNotExist:
        return
    delete_if_changed(anterior, instance, CAMPOS_ADDRESS)