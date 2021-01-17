import os
import random

import aiofiles
from sanic.request import Request

from amyrose.core.dto import AccountDTO, VerificationSessionDTO
from amyrose.core.models import Account, VerificationSession, Session
from amyrose.core.utils import random_string

session_error_factory = Session.ErrorFactory()
account_dto = AccountDTO()
verification_cache_path = './resources/verification/'
verification_session_dto = VerificationSessionDTO()


async def verification_init():
    """
    Generates up to 100 verification code variations as string and image within their respective folders if empty.
    """
    if not os.path.exists(verification_cache_path):
        os.makedirs(verification_cache_path)
        async with aiofiles.open(verification_cache_path + 'codes.txt', mode="w") as f:
            for i in range(100):
                random_str = random_string(7)
                await f.write(random_str + '\n' if i < 99 else random_str)


async def request_verification(request: Request, account: Account = None):
    """
    Creates a verification session associated with an account. Invalidates all previous verification requests.

    :param request: Sanic request parameter.

    :param account: The account that requires verification.

    :return: account, verification_session
    """
    if account is None:
        verification_session = await VerificationSession().decode(request)
        session_error_factory.raise_error(verification_session)
        account = await account_dto.get(verification_session.parent_uid)
    else:
        account.verified = False
        await account_dto.update(account, ['verified'])
    random_code = await random_cached_code()
    verification_session = await verification_session_dto.create(code=random_code, parent_uid=account.uid,
                                                                 ip=request.ip)
    return account, verification_session


async def _complete_verification(account: Account, verification_session: VerificationSession):
    """
    The last step in the verification process which is too verify the account and invalidate the session after use.

    :param account: account to be verified.

    :param verification_session: session to be invalidated after use.

    :return: account, verification_session
    """
    verification_session.valid = False
    account.verified = True
    await account_dto.update(account, ['verified'])
    await verification_session_dto.update(verification_session, ['valid'])
    return account, verification_session


async def random_cached_code():
    """
    Retrieves a random verification code from the generated captcha list,

    :return: verification_code_str
    """
    async with aiofiles.open(verification_cache_path + 'codes.txt', mode="r") as f:
        return random.choice([line.strip() async for line in f])


async def verify_account(request: Request):
    """
    Verifies an account for use using a code sent via email or text.

    :param request: Sanic request parameter. All request bodies are sent as form-data with the following argument: code.

    :raises SessionError:

    :return: account, verification_session
    """
    verification_session = await VerificationSession().decode(request)
    if verification_session.code != request.form.get('code'):
        raise VerificationSession().VerificationAttemptError()
    else:
        session_error_factory.raise_error(verification_session)
        account = await account_dto.get(verification_session.parent_uid)
    return await _complete_verification(account, verification_session)
