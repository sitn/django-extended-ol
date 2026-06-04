import logging 
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth.models import Group
from django.conf import settings

EXTRA_ATTRIBUTES_PREFIX = (
    getattr(settings, "SOCIALACCOUNT_PROVIDERS", {})
        .get("dotnetidprovider", {})
        .get("EXTRA_ATTRIBUTES_PREFIX", "")
)
LOGGER = logging.getLogger(__name__)

class DotnetIdAccountAdapter(DefaultSocialAccountAdapter):
    """
    Handles new users with DotnetAccess properties mapped to django properties
    """
    def pre_social_login(self, request, sociallogin):
        if sociallogin.is_existing:
            self._sync_user(sociallogin.account, sociallogin.user)
    
    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form)
        social_account = SocialAccount.objects.filter(user=user, provider='dotnetid').first()
        self._sync_user(social_account, user)
        return user
        
    def _sync_user(self, social_account, user):
        """
        Keeps Django user synced with IdP
        """
        if social_account.extra_data.get('idp') != 'nech':
            # Only users from nech are allowed to get mapped to groups
            return

        admin_attr = f"{EXTRA_ATTRIBUTES_PREFIX}.admin"
        groups_attr = f"{EXTRA_ATTRIBUTES_PREFIX}.groups"

        # Admin rights
        is_admin = social_account.extra_data.get(admin_attr) == 'True'
        if user.is_staff != is_admin or user.is_superuser != is_admin:
            user.is_staff = is_admin
            user.is_superuser = is_admin

        # Groups
        raw_groups = social_account.extra_data.get(groups_attr, '')
        if isinstance(raw_groups, str):
            raw_groups = raw_groups.split(',')
            
        idp_group_names = {
            g.strip() for g in raw_groups
            if g.strip() and g.strip().lower() != 'admin'
        }
        
        current_groups = set(user.groups.values_list('name', flat=True))

        to_add = idp_group_names - current_groups
        for group_name in to_add:
            group, created = Group.objects.get_or_create(name=group_name)
            user.groups.add(group)
            LOGGER.info("Added group to %s : %s (nouveau=%s)", user, group_name, created)

        to_remove = current_groups - idp_group_names
        for group_name in to_remove:
            group = Group.objects.filter(name=group_name).first()
            if group:
                user.groups.remove(group)
                LOGGER.info("Removed group from %s : %s", user, group_name)

        user.save()
