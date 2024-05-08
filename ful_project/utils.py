from typing import Optional, Any

import bcrypt
from session import Session

session = Session()


def hash_password(raw_password: Optional[str] = None):
    assert raw_password, 'Raw Password can not be empty'
    return bcrypt.hashpw(raw_password.encode('utf-8'), salt=bcrypt.gensalt()).decode('utf-8')


def match_password(raw_password: Optional[str] = None,
                   encoded_password: Optional[str] = None) -> bool:
    assert raw_password, 'Raw Password can not be empty'
    assert encoded_password, 'Encoded Password can not be empty'

    return bcrypt.checkpw(raw_password.encode('utf-8'), encoded_password.encode('utf-8'))


class ResponseData:
    def __init__(self, data: Any, status: Optional[bool] = None):
        self.data = data
        self.status = status or False


def is_authenticated(func):
    def wrapper(*args, **kwargs):
        if not session.session:
            raise Exception('Session not found')
        return func(*args, **kwargs)

    return wrapper
