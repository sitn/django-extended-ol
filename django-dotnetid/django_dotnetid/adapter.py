from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth.models import Group
from django.conf import settings

EXTRA_ATTRIBUTES_PREFIX = (
    getattr(settings, "SOCIALACCOUNT_PROVIDERS", {})
        .get("dotnetidprovider", {})
        .get("EXTRA_ATTRIBUTES_PREFIX", "")
)

class DotnetIdAccountAdapter(DefaultSocialAccountAdapter):
    """
    Handles new users with DotnetAccess properties mapped to django properties
    """
    def save_user(self, request, sociallogin, form=None):
        u = super().save_user(request, sociallogin, form)
        social_account = SocialAccount.objects.filter(user=u, provider='dotnetid').first()
        if social_account.extra_data['idp'] == 'nech':
            admin_attr = f"{EXTRA_ATTRIBUTES_PREFIX}.admin"
            groups_attr = f"{EXTRA_ATTRIBUTES_PREFIX}.groups"

            if social_account.extra_data[admin_attr] == 'True':
                u.is_staff = True
                u.is_superuser = True

            groups = social_account.extra_data[groups_attr]
            if isinstance(groups, str):
                groups = social_account.extra_data[groups_attr].split(',')

            for group_name in groups:
                group_name = group_name.strip()
                if group_name.lower() == 'admin':
                    continue
                group_instance = Group.objects.filter(name=group_name).first()
                if not group_instance:
                    group_instance = Group.objects.create(name=group_name)
                group_instance.user_set.add(u)
                group_instance.save()
            u.save()

        return u
