class VaultError(Exception):
    pass


class AuthError(VaultError):
    pass


class NotFound(VaultError):
    pass


class PermissionDenied(VaultError):
    pass


class IntegrityError(VaultError):
    pass
