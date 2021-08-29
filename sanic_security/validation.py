import datetime

from sanic_security.exceptions import (
    NotFoundError,
    DeletedError,
    DisabledError,
    UnverifiedError,
    InvalidError,
    ExpiredError,
)
from sanic_security.models import Account, Session


def validate_account(account: Account):
    """
    Validates an account by determining if an error should be raised due to variable values.

    Args:
        account (Account): Account being validated.

    Raises:
        AccountError
    """
    if not account:
        raise NotFoundError("Account could not be found.")
    elif account.deleted:
        raise DeletedError("Account has been deleted.")
    elif not account.verified:
        raise UnverifiedError()
    elif account.disabled:
        raise DisabledError()


def validate_session(session: Session):
    """
    Validates a session by determining if an error should be raised due to variable values.

    Args:
        session (Session): Session being validated.

    Raises:
        SessionError
    """
    if session is None:
        raise NotFoundError("Session could not be found.")
    elif session.deleted:
        raise DeletedError("Session has been deleted.")
    elif datetime.datetime.now(datetime.timezone.utc) >= session.expiration_date:
        raise ExpiredError()
    elif not session.valid:
        raise InvalidError()
