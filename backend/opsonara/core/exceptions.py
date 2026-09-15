"""Shared Opsonara exceptions."""


class OpsonaraError(Exception):
    """Base class for all Opsonara errors."""


class NotFoundError(OpsonaraError):
    """A referenced resource (audit record, review) does not exist."""


class AlreadyResolvedError(OpsonaraError):
    """A human review was already decided and cannot be decided again."""
