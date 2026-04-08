"""
CyberNest SOAR Action -- Active Directory Disable User.

Connects to Active Directory via LDAP and disables a user account by
setting the userAccountControl attribute to 514 (ACCOUNTDISABLE | NORMAL_ACCOUNT).
"""

from __future__ import annotations

import asyncio
import os
from functools import partial
from typing import Any

from ldap3 import (
    ALL,
    MODIFY_REPLACE,
    NTLM,
    SIMPLE,
    Connection,
    Server,
)
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPException,
    LDAPSocketOpenError,
)

from soar.actions import BaseAction, register_action


AD_SERVER = os.environ.get("AD_SERVER", "")
AD_DOMAIN = os.environ.get("AD_DOMAIN", "")
AD_USER = os.environ.get("AD_BIND_USER", "")
AD_PASSWORD = os.environ.get("AD_BIND_PASSWORD", "")
AD_BASE_DN = os.environ.get("AD_BASE_DN", "")
AD_USE_SSL = os.environ.get("AD_USE_SSL", "true").lower() in ("true", "1", "yes")

# userAccountControl flags
UAC_NORMAL_ACCOUNT = 512
UAC_DISABLED = 514  # NORMAL_ACCOUNT + ACCOUNTDISABLE


def _sync_disable_user(
    server_addr: str,
    base_dn: str,
    bind_user: str,
    bind_password: str,
    username: str,
    use_ssl: bool,
    auth_type: str,
) -> dict[str, Any]:
    """Blocking LDAP operation to find and disable a user."""
    server = Server(server_addr, use_ssl=use_ssl, get_info=ALL, connect_timeout=15)

    auth = NTLM if auth_type == "ntlm" else SIMPLE
    conn = Connection(
        server,
        user=bind_user,
        password=bind_password,
        authentication=auth,
        auto_bind=True,
        raise_exceptions=True,
        read_only=False,
    )

    try:
        # Search for the user by sAMAccountName
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            attributes=[
                "distinguishedName",
                "sAMAccountName",
                "userAccountControl",
                "displayName",
                "mail",
                "memberOf",
            ],
        )

        if not conn.entries:
            return {
                "success": False,
                "error": f"User '{username}' not found in Active Directory",
            }

        entry = conn.entries[0]
        user_dn = str(entry.entry_dn)
        current_uac = int(entry.userAccountControl.value) if entry.userAccountControl.value else UAC_NORMAL_ACCOUNT
        display_name = str(entry.displayName.value) if entry.displayName.value else ""
        mail = str(entry.mail.value) if entry.mail.value else ""
        groups = [str(g) for g in entry.memberOf.values] if entry.memberOf.value else []

        # Check if already disabled
        is_already_disabled = bool(current_uac & 0x0002)
        if is_already_disabled:
            return {
                "success": True,
                "output": {
                    "username": username,
                    "user_dn": user_dn,
                    "display_name": display_name,
                    "email": mail,
                    "already_disabled": True,
                    "message": f"User '{username}' was already disabled",
                },
            }

        # Disable the account by setting the ACCOUNTDISABLE bit
        new_uac = current_uac | 0x0002
        conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [new_uac])]})

        if not conn.result.get("description") == "success":
            return {
                "success": False,
                "error": f"Failed to disable user: {conn.result}",
            }

        return {
            "success": True,
            "output": {
                "username": username,
                "user_dn": user_dn,
                "display_name": display_name,
                "email": mail,
                "previous_uac": current_uac,
                "new_uac": new_uac,
                "already_disabled": False,
                "groups": groups[:20],
                "message": f"User '{username}' has been disabled in Active Directory",
            },
        }
    finally:
        conn.unbind()


@register_action
class ADDisableUser(BaseAction):
    """Disable a user account in Active Directory via LDAP."""

    name = "ad_disable_user"
    description = (
        "Connect to Active Directory, find a user by sAMAccountName, and "
        "disable the account by setting userAccountControl to disabled."
    )

    async def execute(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        username: str = params.get("username", "")
        config = context.get("config", {})

        server_addr = params.get("ad_server") or config.get("ad_server") or AD_SERVER
        base_dn = params.get("base_dn") or config.get("ad_base_dn") or AD_BASE_DN
        bind_user = params.get("bind_user") or config.get("ad_bind_user") or AD_USER
        bind_password = params.get("bind_password") or config.get("ad_bind_password") or AD_PASSWORD
        use_ssl = params.get("use_ssl", AD_USE_SSL)
        auth_type = params.get("auth_type", "ntlm")

        if not username:
            return self.result(False, error="Missing required parameter 'username'")
        if not server_addr:
            return self.result(False, error="AD server address not configured")
        if not base_dn:
            return self.result(False, error="AD base DN not configured")
        if not bind_user or not bind_password:
            return self.result(False, error="AD bind credentials not configured")

        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                partial(
                    _sync_disable_user,
                    server_addr,
                    base_dn,
                    bind_user,
                    bind_password,
                    username,
                    use_ssl,
                    auth_type,
                ),
            )
        except LDAPBindError as exc:
            return self.result(False, error=f"LDAP bind failed (bad credentials?): {exc}")
        except LDAPSocketOpenError as exc:
            return self.result(False, error=f"Cannot connect to AD server: {exc}")
        except LDAPException as exc:
            return self.result(False, error=f"LDAP error: {exc}")
        except Exception as exc:
            return self.result(False, error=f"Unexpected error: {exc}")

        if result.get("success"):
            return self.result(True, output=result.get("output", {}))
        return self.result(False, error=result.get("error", "Unknown LDAP error"))
